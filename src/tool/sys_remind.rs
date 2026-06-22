use async_trait::async_trait;
use serde_json::{json, Value};
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

/// Schedule a one-time reminder that delivers a notification to the web chat page
/// (and optionally a Windows toast) after a specified delay.
///
/// Uses a server-side tokio timer + HTTP POST to /api/notify to push the message
/// through the WebSocket broadcast channel to all connected clients.
pub struct SysRemindTool;

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

        // Spawn a background tokio task that sleeps and then POSTs to /api/notify
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;

            // POST to the local server's /api/notify endpoint
            let client = reqwest::Client::new();
            let payload = json!({ "message": message_owned });
            match client.post("http://127.0.0.1:7788/api/notify")
                .json(&payload)
                .send()
                .await
            {
                Ok(resp) => {
                    tracing::info!("Reminder delivered: '{}' (status: {})", message_owned, resp.status());
                }
                Err(e) => {
                    tracing::warn!("Failed to deliver reminder '{}': {}", message_owned, e);
                    // Fallback: try to show a Windows MessageBox via PowerShell
                    show_fallback_notification(&message_owned);
                }
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
