use async_trait::async_trait;
use serde_json::{json, Value};
use std::os::windows::process::CommandExt;
use std::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct BrowserOpenTool;

#[async_trait]
impl Tool for BrowserOpenTool {
    fn name(&self) -> &str { "browser_open" }
    fn description(&self) -> &str {
        "Open a URL in the default web browser. If no URL scheme is provided, 'https://' is prepended."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "url": { "type": "string", "description": "URL to open in browser" }
            },
            "required": ["url"]
        })
    }
    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let mut url = args["url"].as_str().ok_or_else(|| "Missing 'url'".to_string())?.to_string();

        if !url.starts_with("http://") && !url.starts_with("https://") && !url.starts_with("file://") {
            url = format!("https://{}", url);
        }

        let mut cmd = Command::new("cmd");
        cmd.arg("/C").arg("start").arg("").arg(&url);
        cmd.creation_flags(0x08000000);

        match cmd.spawn() {
            Ok(_) => Ok(json!({ "status": "opened", "url": url })),
            Err(e) => Err(format!("Failed to open browser: {}", e).into()),
        }
    }
}
