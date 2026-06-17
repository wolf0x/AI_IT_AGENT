use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct SysInfoTool;

#[async_trait]
impl Tool for SysInfoTool {
    fn name(&self) -> &str { "sys_info" }
    fn description(&self) -> &str {
        "Query system properties. Returns OS version, hostname, CPU, memory, disk, network adapters, and environment variables. Use category to filter: 'os', 'cpu', 'memory', 'disk', 'network', 'env', or 'all' (default)."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Info category to query",
                    "enum": ["all", "os", "cpu", "memory", "disk", "network", "env"]
                }
            }
        })
    }
    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let cat = args["category"].as_str().unwrap_or("all");
        let mut result = serde_json::Map::new();

        if cat == "all" || cat == "os" {
            let output = run_ps("Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate | ConvertTo-Json").await;
            result.insert("os".to_string(), parse_json_or_string(&output));
        }
        if cat == "all" || cat == "cpu" {
            let output = run_ps("Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed | ConvertTo-Json").await;
            result.insert("cpu".to_string(), parse_json_or_string(&output));
        }
        if cat == "all" || cat == "memory" {
            let output = run_ps("Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory | ConvertTo-Json").await;
            result.insert("memory".to_string(), parse_json_or_string(&output));
        }
        if cat == "all" || cat == "disk" {
            let output = run_ps("Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID, Size, FreeSpace, FileSystem | ConvertTo-Json").await;
            result.insert("disk".to_string(), parse_json_or_string(&output));
        }
        if cat == "all" || cat == "network" {
            let output = run_ps("Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object Name, InterfaceDescription, MacAddress, LinkSpeed | ConvertTo-Json").await;
            result.insert("network".to_string(), parse_json_or_string(&output));
        }
        if cat == "all" || cat == "env" {
            let output = run_ps("$env: | Out-String -Width 200").await;
            result.insert("env".to_string(), Value::String(output));
        }

        Ok(Value::Object(result))
    }
}

async fn run_ps(command: &str) -> String {
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", command]);
    cmd.creation_flags(0x08000000);
    match cmd.output().await {
        Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_string(),
        Err(e) => format!("Error: {}", e),
    }
}

fn parse_json_or_string(s: &str) -> Value {
    serde_json::from_str(s).unwrap_or_else(|_| Value::String(s.to_string()))
}
