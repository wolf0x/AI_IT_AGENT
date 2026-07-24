use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct ShellExecTool;

#[async_trait]
impl Tool for ShellExecTool {
    fn name(&self) -> &str { "shell_exec" }
    fn description(&self) -> &str {
        "Execute a command in PowerShell or CMD. Returns stdout, stderr, and exit code. Use shell='powershell' (default) or shell='cmd'."
    }
    fn is_builtin(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "command": { "type": "string", "description": "Command to execute" },
                "shell": { "type": "string", "description": "Shell to use: 'powershell' (default) or 'cmd'", "enum": ["powershell", "cmd"] },
                "timeout_secs": { "type": "integer", "description": "Timeout in seconds (default 30)" }
            },
            "required": ["command"]
        })
    }
    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let command = args["command"].as_str().ok_or_else(|| "Missing 'command'".to_string())?;
        let shell = args["shell"].as_str().unwrap_or("powershell");
        let timeout = args["timeout_secs"].as_u64().unwrap_or(30);

        // ── Dangerous command detection ──
        // Prevent using shell_exec to bypass permission controls on destructive operations.
        // If the user denied file_delete, the agent must not use shell_exec as a workaround.
        let cmd_lower = command.to_lowercase();
        let destructive_patterns = [
            // PowerShell cmdlets and aliases
            "remove-item", "ri ", "ri`",
            "del ", "del`", "rm ", "rm`",
            "rmdir ", "rmdir`", "rd ", "rd`",
            "erase ", "erase`",
            "format ", "format`",
            // CMD flags
            "rmdir /s", "rd /s", "del /f", "del /q",
            // .NET file/directory deletion methods
            "[system.io.file]::delete",
            "[system.io.directory]::delete",
            "[io.file]::delete",
            "[io.directory]::delete",
            // Encoded command bypass (base64-encoded destructive ops)
            "-encodedcommand", "-enc ",
            // Nested cmd destructive calls
            "cmd /c del", "cmd /c rd", "cmd /c erase", "cmd /c rmdir",
            "cmd /c \"del", "cmd /c \"rd", "cmd /c \"erase",
        ];
        for pattern in &destructive_patterns {
            if cmd_lower.contains(pattern) {
                return Err(format!(
                    "BLOCKED: shell_exec cannot perform destructive file operations. \
                     Detected '{}' in command. Use the `file_delete` tool instead, \
                     which has proper permission controls.",
                    pattern.trim()
                ).into());
            }
        }

        let mut cmd = match shell {
            "cmd" => {
                let mut c = Command::new("cmd");
                c.args(["/C", command]);
                c
            }
            _ => {
                let mut c = Command::new("powershell");
                c.args(["-NoProfile", "-NonInteractive", "-Command", command]);
                c
            }
        };

        cmd.creation_flags(0x08000000);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(timeout),
            cmd.output(),
        )
        .await;

        match result {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let exit_code = output.status.code().unwrap_or(-1);
                Ok(json!({
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": exit_code
                }))
            }
            Ok(Err(e)) => Err(format!("Failed to execute: {}", e).into()),
            Err(_) => Err(format!("Command timed out after {}s", timeout).into()),
        }
    }
}
