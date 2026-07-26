use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;
use crate::policy::{IntentPolicy, IntentVerdict};

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

        // ── Intent Policy evaluation (replaces legacy destructive_patterns) ──
        // This layer operates independently of the Permission system:
        // - Block: catastrophic irreversible ops → hard reject regardless of permissions
        // - Audit: high-risk but legitimate → log and proceed (transparent when pre-authorized)
        // - Pass: normal → silent
        let policy = IntentPolicy::new();
        match policy.evaluate(command, shell) {
            IntentVerdict::Block { reason } => {
                return Err(format!(
                    "BLOCKED (safety interlock): {}. \
                     This operation is irreversible and cannot be executed through RustAgent. \
                     If you truly need this, execute it manually outside the agent.",
                    reason
                ).into());
            }
            IntentVerdict::Audit { reason } => {
                tracing::warn!(
                    "[AUDIT] shell_exec high-risk: {} | shell={} | command={}",
                    reason, shell, command
                );
                // Proceed — user has authorized via Permission gate or accepts risk
            }
            IntentVerdict::Pass => { /* silent */ }
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
