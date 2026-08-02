//! External tool executor — wraps workspace/tools/ executables as LLM-callable tools.
//!
//! Each discovered executable in workspace/tools/ is registered as `ext_{name}`
//! in the ToolRegistry, allowing the LLM to invoke it directly with arguments.

use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::PathBuf;
use tokio::process::Command;
use tracing::info;

use crate::context::ToolContext;
use crate::error::AgentResult;

use super::Tool;

/// Executes an external tool (executable file) from workspace/tools/.
pub struct ExternalToolExecutor {
    /// Tool name as registered (e.g., "ext_Autoruns")
    name: String,
    /// Full path to the executable
    path: PathBuf,
    /// Human-readable description for the LLM
    description: String,
    /// File extension (.exe, .bat, .ps1, .cmd)
    extension: String,
}

impl ExternalToolExecutor {
    pub fn new(name: &str, path: PathBuf, description: &str, extension: &str) -> Self {
        Self {
            name: name.to_string(),
            path,
            description: description.to_string(),
            extension: extension.to_string(),
        }
    }
}

#[async_trait]
impl Tool for ExternalToolExecutor {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "args": {
                    "type": "string",
                    "description": "Command-line arguments to pass to the tool (e.g., \"-accepteula -s\")"
                },
                "timeout_secs": {
                    "type": "integer",
                    "description": "Maximum execution time in seconds (default: 60)"
                }
            },
            "required": []
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value> {
        let cli_args = args["args"].as_str().unwrap_or("");
        let timeout_secs = args["timeout_secs"].as_u64().unwrap_or(60);

        info!(
            "[ext_tool] Executing: {} {} (timeout: {}s)",
            self.path.display(),
            cli_args,
            timeout_secs
        );

        let result = match self.extension.as_str() {
            "ps1" => {
                // PowerShell scripts need to be invoked via powershell -File
                let mut cmd = Command::new("powershell");
                cmd.arg("-NoProfile")
                    .arg("-NonInteractive")
                    .arg("-ExecutionPolicy")
                    .arg("Bypass")
                    .arg("-File")
                    .arg(&self.path);
                // Append user args (split by whitespace for ps1)
                if !cli_args.is_empty() {
                    for arg in shell_words_split(cli_args) {
                        cmd.arg(arg);
                    }
                }
                cmd.current_dir(&ctx.working_dir);
                run_with_timeout(cmd, timeout_secs).await
            }
            "bat" | "cmd" => {
                // Batch scripts via cmd /c
                let mut cmd = Command::new("cmd");
                cmd.arg("/c")
                    .arg(self.path.to_string_lossy().as_ref());
                if !cli_args.is_empty() {
                    cmd.arg(cli_args);
                }
                cmd.current_dir(&ctx.working_dir);
                run_with_timeout(cmd, timeout_secs).await
            }
            _ => {
                // Direct executable (.exe)
                let mut cmd = Command::new(&self.path);
                if !cli_args.is_empty() {
                    for arg in shell_words_split(cli_args) {
                        cmd.arg(arg);
                    }
                }
                cmd.current_dir(&ctx.working_dir);
                run_with_timeout(cmd, timeout_secs).await
            }
        };

        match result {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                let exit_code = output.status.code().unwrap_or(-1);

                // Truncate large outputs to avoid flooding the LLM context
                let stdout_trunc = truncate_output(&stdout, 30000);
                let stderr_trunc = truncate_output(&stderr, 5000);

                Ok(json!({
                    "exit_code": exit_code,
                    "stdout": stdout_trunc,
                    "stderr": stderr_trunc,
                    "tool_path": self.path.to_string_lossy(),
                }))
            }
            Err(e) => Err(format!(
                "External tool '{}' execution failed: {}",
                self.name, e
            )
            .into()),
        }
    }

    fn is_builtin(&self) -> bool {
        false
    }

    fn is_read_only(&self) -> bool {
        false // External tools are assumed to have side effects
    }

    fn category(&self) -> &str {
        "execute" // External tools require endorsement
    }
}

/// Run a command with a timeout, returning the output.
async fn run_with_timeout(
    mut cmd: Command,
    timeout_secs: u64,
) -> Result<std::process::Output, String> {
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    cmd.kill_on_drop(true);

    let child = cmd.spawn().map_err(|e| format!("Failed to spawn: {}", e))?;

    let timeout_duration = std::time::Duration::from_secs(timeout_secs);
    match tokio::time::timeout(timeout_duration, child.wait_with_output()).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(e)) => Err(format!("Process error: {}", e)),
        Err(_) => Err(format!(
            "Timed out after {} seconds",
            timeout_secs
        )),
    }
}

/// Simple shell-word splitting (handles quoted strings).
fn shell_words_split(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut quote_char = ' ';

    for ch in input.chars() {
        if in_quotes {
            if ch == quote_char {
                in_quotes = false;
            } else {
                current.push(ch);
            }
        } else if ch == '"' || ch == '\'' {
            in_quotes = true;
            quote_char = ch;
        } else if ch.is_whitespace() {
            if !current.is_empty() {
                words.push(current.clone());
                current.clear();
            }
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// Truncate output to a maximum character count, appending a note if truncated.
fn truncate_output(s: &str, max_chars: usize) -> String {
    if s.len() <= max_chars {
        return s.to_string();
    }
    let truncated: String = s.chars().take(max_chars).collect();
    format!(
        "{}\n... [truncated, {} total chars]",
        truncated,
        s.len()
    )
}
