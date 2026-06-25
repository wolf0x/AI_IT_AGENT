use async_trait::async_trait;
use serde_json::{json, Value};
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

/// Type alias for the broadcast channel that pushes notifications to WebSocket clients.
pub type NotifyTx = tokio::sync::broadcast::Sender<String>;

/// Schedule a one-time reminder that delivers a notification to the web chat page
/// (and optionally a Windows toast) after a specified delay.
///
/// Pushes the message directly through the server's broadcast channel to all
/// connected WebSocket clients (no HTTP loopback, so it works regardless of the
/// configured server port).
pub struct SysRemindTool {
    notify_tx: Option<NotifyTx>,
}

impl SysRemindTool {
    pub fn new() -> Self {
        Self { notify_tx: None }
    }

    pub fn with_notify_tx(notify_tx: NotifyTx) -> Self {
        Self { notify_tx: Some(notify_tx) }
    }

    pub fn with_notify_tx_optional(notify_tx: Option<NotifyTx>) -> Self {
        Self { notify_tx }
    }
}

impl Default for SysRemindTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for SysRemindTool {
    fn name(&self) -> &str { "sys_remind" }
    fn description(&self) -> &str {
        "Schedule a one-time reminder. Delivers a notification to the web chat page after the specified delay. Parameters: message (required), delay (e.g. '2m', '30s', '1h', required)."
    }
    fn is_builtin(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "message": { "type": "string", "description": "The reminder message to display" },
                "delay": { "type": "string", "description": "Delay before showing the reminder: e.g. '2m', '30s', '1h', '90s'" }
            },
            "required": ["message", "delay"]
        })
    }
    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let message = args["message"].as_str().ok_or_else(|| "Missing 'message'".to_string())?;
        let delay_str = args["delay"].as_str().ok_or_else(|| "Missing 'delay'".to_string())?;

        let delay_secs = parse_delay(delay_str)?;

        if delay_secs == 0 {
            return Err("Delay must be greater than 0".to_string().into());
        }
        if delay_secs > 86400 {
            return Err("Maximum delay is 24 hours (86400s)".to_string().into());
        }

        let message_owned = message.to_string();

        // Clone the broadcast sender (if any) into the background task so the
        // notification is delivered directly to WebSocket clients without an
        // HTTP loopback (which would break if the server port were changed).
        let notify_tx = self.notify_tx.clone();

        // Spawn a background tokio task that sleeps and then pushes the notification.
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;

            let ws_msg = json!({
                "type": "notification",
                "message": message_owned,
                "timestamp": chrono::Utc::now().to_rfc3339()
            }).to_string();

            let delivered = match &notify_tx {
                Some(tx) => tx.send(ws_msg).is_ok(),
                // No broadcast channel available (e.g. tool used standalone) —
                // fall back to a Windows MessageBox so the reminder is not lost.
                None => {
                    show_fallback_notification(&message_owned);
                    false
                }
            };

            if delivered {
                tracing::info!("Reminder delivered via broadcast: '{}'", message_owned);
            }
        });

        Ok(json!({
            "status": "scheduled",
            "message": message,
            "delay_seconds": delay_secs,
            "delay_human": format_duration(delay_secs),
            "delivery": "web_chat"
        }))
    }
}

/// Fallback: show notification via PowerShell MessageBox if HTTP notify fails.
fn show_fallback_notification(message: &str) {
    let escaped = message.replace("'", "''");
    let ps_cmd = format!(
        "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('{}', 'RustAgent Reminder', 'OK', 'Information')",
        escaped
    );
    // Fire-and-forget: spawn PowerShell detached
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &ps_cmd])
        .creation_flags(0x00000008)
        .spawn();
}

/// Parse delay strings like "2m", "30s", "1h", "90s", "1h30m"
fn parse_delay(s: &str) -> AgentResult<u64> {
    let s = s.trim().to_lowercase();

    // Try plain number (seconds)
    if let Ok(n) = s.parse::<u64>() {
        return Ok(n);
    }

    let mut total_secs: u64 = 0;
    let mut current_num = String::new();

    for ch in s.chars() {
        match ch {
            '0'..='9' => current_num.push(ch),
            's' => {
                let n: u64 = current_num.parse().map_err(|_| format!("Invalid delay: {}", s))?;
                total_secs += n;
                current_num.clear();
            }
            'm' => {
                let n: u64 = current_num.parse().map_err(|_| format!("Invalid delay: {}", s))?;
                total_secs += n * 60;
                current_num.clear();
            }
            'h' => {
                let n: u64 = current_num.parse().map_err(|_| format!("Invalid delay: {}", s))?;
                total_secs += n * 3600;
                current_num.clear();
            }
            _ => {} // ignore other chars
        }
    }

    // If there's a remaining number without unit, treat as seconds
    if !current_num.is_empty() {
        if let Ok(n) = current_num.parse::<u64>() {
            total_secs += n;
        }
    }

    if total_secs == 0 {
        Err(format!("Could not parse delay: '{}'. Use format like '2m', '30s', '1h'", s).into())
    } else {
        Ok(total_secs)
    }
}

fn format_duration(secs: u64) -> String {
    if secs >= 3600 {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        if m > 0 { format!("{}h{}m", h, m) } else { format!("{}h", h) }
    } else if secs >= 60 {
        let m = secs / 60;
        let s = secs % 60;
        if s > 0 { format!("{}m{}s", m, s) } else { format!("{}m", m) }
    } else {
        format!("{}s", secs)
    }
}
