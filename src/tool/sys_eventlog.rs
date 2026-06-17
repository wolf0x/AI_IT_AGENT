use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct SysEventLogTool;

#[async_trait]
impl Tool for SysEventLogTool {
    fn name(&self) -> &str { "sys_eventlog" }
    fn description(&self) -> &str {
        "Query Windows Event Logs. Filter by log name (System, Application, Security, etc.), level, time range, and max count. Uses Get-WinEvent."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "log_name": { "type": "string", "description": "Event log name (e.g. System, Application, Security)" },
                "level": { "type": "string", "description": "Filter by level: Critical, Error, Warning, Information, Verbose", "enum": ["Critical", "Error", "Warning", "Information", "Verbose"] },
                "max_count": { "type": "integer", "description": "Max events to return (default 20)" },
                "hours_ago": { "type": "integer", "description": "Only events from the last N hours" }
            },
            "required": ["log_name"]
        })
    }
    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let log_name = args["log_name"].as_str().ok_or_else(|| "Missing 'log_name'".to_string())?;
        let max_count = args["max_count"].as_u64().unwrap_or(20);
        let hours_ago = args["hours_ago"].as_u64();
        let level = args["level"].as_str();

        let mut filter_parts = vec![format!("LogName='{}'", log_name)];
        if let Some(level_str) = level {
            let level_num = match level_str {
                "Critical" => "1", "Error" => "2", "Warning" => "3",
                "Information" => "4", "Verbose" => "5", _ => "4",
            };
            filter_parts.push(format!("Level={}", level_num));
        }
        if let Some(hours) = hours_ago {
            filter_parts.push(format!("StartTime=(Get-Date).AddHours(-{})", hours));
        }

        let filter = filter_parts.join(" and ");
        let ps_cmd = format!(
            "Get-WinEvent -FilterHashtable @{{ {} }} -MaxEvents {} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | ConvertTo-Json -Depth 3",
            filter, max_count
        );

        let mut cmd = Command::new("powershell");
        cmd.args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd]);
        cmd.creation_flags(0x08000000);

        match cmd.output().await {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let events: Value = serde_json::from_str(&stdout).unwrap_or_else(|_| json!({ "raw": stdout }));
                Ok(json!({ "events": events, "log_name": log_name }))
            }
            Err(e) => Err(format!("Failed to query event log: {}", e).into()),
        }
    }
}
