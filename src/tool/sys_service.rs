use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct SysServiceTool;

#[async_trait]
impl Tool for SysServiceTool {
    fn name(&self) -> &str { "sys_service" }
    fn description(&self) -> &str {
        "Query or manage Windows services. Action: 'list' shows running services, 'search' filters by name, 'start'/'stop'/'restart' manages a service."
    }
    fn is_builtin(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "description": "Action to perform", "enum": ["list", "search", "start", "stop", "restart"] },
                "name_filter": { "type": "string", "description": "Service name filter (for search)" },
                "service_name": { "type": "string", "description": "Service name (for start/stop/restart)" }
            }
        })
    }
    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let action = args["action"].as_str().unwrap_or("list");
        match action {
            "list" => {
                let ps_cmd = "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json";
                run_ps_json(ps_cmd).await
            }
            "search" => {
                let name = args["name_filter"].as_str().ok_or_else(|| "Missing 'name_filter'".to_string())?;
                let ps_cmd = format!(
                    "Get-Service -Name '*{}*' -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json",
                    name
                );
                run_ps_json(&ps_cmd).await
            }
            "start" | "stop" | "restart" => {
                let svc = args["service_name"].as_str().ok_or_else(|| "Missing 'service_name'".to_string())?;
                let verb = match action {
                    "start" => "Start-Service",
                    "stop" => "Stop-Service",
                    "restart" => "Restart-Service",
                    _ => unreachable!(),
                };
                let ps_cmd = format!("{} -Name '{}' -Force -ErrorAction SilentlyContinue; Get-Service -Name '{}' | Select-Object Name, Status | ConvertTo-Json", verb, svc, svc);
                run_ps_json(&ps_cmd).await
            }
            _ => Err(format!("Unknown action: {}", action).into()),
        }
    }
}

async fn run_ps_json(cmd: &str) -> AgentResult<Value> {
    let mut c = Command::new("powershell");
    c.args(["-NoProfile", "-NonInteractive", "-Command", cmd]);
    c.creation_flags(0x08000000);
    match c.output().await {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let parsed: Value = serde_json::from_str(&stdout).unwrap_or_else(|_| json!({ "raw": stdout }));
            Ok(parsed)
        }
        Err(e) => Err(format!("Service command failed: {}", e).into()),
    }
}
