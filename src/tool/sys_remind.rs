use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

/// Schedule a one-time reminder that pops up a Windows toast notification after a delay.
pub struct SysRemindTool;

#[async_trait]
impl Tool for SysRemindTool {
    fn name(&self) -> &str { "sys_remind" }
    fn description(&self) -> &str {
        "Schedule a one-time reminder. Shows a Windows toast notification after the specified delay. Parameters: message (required), delay (e.g. '2m', '30s', '1h', required)."
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

        // Escape the message for PowerShell
        let escaped_msg = message
            .replace("'", "''")
            .replace('"', "`\"");

        // Build a PowerShell script that runs in background, sleeps, then shows a toast notification
        let ps_script = format!(
            r#"Start-Process -FilePath "powershell" -ArgumentList "-NoProfile", "-WindowStyle", "Hidden", "-Command", "[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]; $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); $textNodes = $template.GetElementsByTagName('text'); $textNodes.Item(0).AppendChild($template.CreateTextNode('RustAgent Reminder')) | Out-Null; $textNodes.Item(1).AppendChild($template.CreateTextNode('{escaped_msg}')) | Out-Null; $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('RustAgent'); $toast = [Windows.UI.Notifications.ToastNotification]::new($template); $notifier.Show($toast)" -WindowStyle Hidden; Start-Sleep -Seconds {delay_secs}; [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null; [System.Windows.Forms.MessageBox]::Show('{escaped_msg}', 'RustAgent Reminder', 'OK', 'Information')"#,
            escaped_msg = escaped_msg,
            delay_secs = delay_secs,
        );

        // Launch detached PowerShell process
        let mut cmd = Command::new("powershell");
        cmd.args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", &ps_script]);
        cmd.creation_flags(0x00000008); // DETACHED_PROCESS

        match cmd.spawn() {
            Ok(_child) => {
                Ok(json!({
                    "status": "scheduled",
                    "message": message,
                    "delay_seconds": delay_secs,
                    "delay_human": format_duration(delay_secs),
                }))
            }
            Err(e) => Err(format!("Failed to schedule reminder: {}", e).into()),
        }
    }
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
