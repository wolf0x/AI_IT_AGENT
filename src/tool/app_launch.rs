use async_trait::async_trait;
use serde_json::{json, Value};
use std::os::windows::process::CommandExt;
use std::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct AppLaunchTool;

#[async_trait]
impl Tool for AppLaunchTool {
    fn name(&self) -> &str { "app_launch" }
    fn description(&self) -> &str {
        "Launch an application or open a file/URL with the default handler. Examples: open notepad.exe, open a .docx file in Word, open a folder in Explorer."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_long_running(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "target": { "type": "string", "description": "Application name, file path, or URL to open" },
                "arguments": { "type": "array", "items": { "type": "string" }, "description": "Optional arguments to pass to the application" }
            },
            "required": ["target"]
        })
    }
    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let target = args["target"].as_str().ok_or_else(|| "Missing 'target'".to_string())?;
        let extra_args: Vec<String> = args["arguments"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let mut cmd = Command::new("cmd");
        cmd.arg("/C").arg("start").arg("").arg(target);
        for a in &extra_args {
            cmd.arg(a);
        }
        cmd.creation_flags(0x08000000);

        match cmd.spawn() {
            Ok(_) => Ok(json!({ "status": "launched", "target": target })),
            Err(e) => Err(format!("Failed to launch {}: {}", target, e).into()),
        }
    }
}
