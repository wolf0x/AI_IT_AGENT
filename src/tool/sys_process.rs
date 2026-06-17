use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct SysProcessTool;

#[async_trait]
impl Tool for SysProcessTool {
    fn name(&self) -> &str { "sys_process" }
    fn description(&self) -> &str {
        "List, search, or manage running processes. Action: 'list' (default) shows processes, 'search' filters by name, 'kill' stops a process by PID."
    }
    fn is_builtin(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "description": "Action to perform", "enum": ["list", "search", "kill"] },
                "name_filter": { "type": "string", "description": "Process name filter (for search action)" },
                "pid": { "type": "integer", "description": "Process ID (for kill action)" },
                "top_n": { "type": "integer", "description": "Return top N processes by memory (default 20)" }
            }
        })
    }
    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let action = args["action"].as_str().unwrap_or("list");
        match action {
            "list" => {
                let top_n = args["top_n"].as_u64().unwrap_or(20);
                let ps_cmd = format!(
                    "Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First {} Id, ProcessName, CPU, WorkingSet64, StartTime | ConvertTo-Json",
                    top_n
                );
                run_ps(&ps_cmd).await
            }
            "search" => {
                let name = args["name_filter"].as_str().ok_or_else(|| "Missing 'name_filter'".to_string())?;
                let ps_cmd = format!(
                    "Get-Process -Name '*{}*' -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, CPU, WorkingSet64 | ConvertTo-Json",
                    name
                );
                run_ps(&ps_cmd).await
            }
            "kill" => {
                let pid = args["pid"].as_u64().ok_or_else(|| "Missing 'pid'".to_string())?;
                let ps_cmd = format!("Stop-Process -Id {} -Force -ErrorAction SilentlyContinue; 'OK'", pid);
                run_ps(&ps_cmd).await
            }
            _ => Err(format!("Unknown action: {}", action).into()),
        }
    }
}

async fn run_ps(cmd: &str) -> AgentResult<Value> {
    let mut c = Command::new("powershell");
    c.args(["-NoProfile", "-NonInteractive", "-Command", cmd]);
    c.creation_flags(0x08000000);
    match c.output().await {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let parsed: Value = serde_json::from_str(&stdout).unwrap_or_else(|_| json!({ "raw": stdout }));
            Ok(parsed)
        }
        Err(e) => Err(format!("Process command failed: {}", e).into()),
    }
}
