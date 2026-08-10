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

        // Reject URLs containing cmd.exe metacharacters to prevent command injection
        let dangerous_chars = ['&', '|', '>', '<', '^', '`', ';'];
        if url.chars().any(|c| dangerous_chars.contains(&c)) {
            return Err(format!("URL contains dangerous characters: {:?}. Only http/https URLs with standard characters are allowed.", dangerous_chars).into());
        }

        // Smart URL detection and conversion
        if url.starts_with("http://") || url.starts_with("https://") || url.starts_with("file://") {
            // Already a proper URL, use as-is
        } else if url.chars().next().map(|c| c.is_alphabetic()).unwrap_or(false) && url.chars().nth(1) == Some(':') {
            // Windows absolute path (e.g., C:\path\to\file)
            // Convert to file:/// URL with forward slashes
            let path_normalized = url.replace('\\', "/");
            url = format!("file:///{}", path_normalized);
        } else if url.starts_with("output/") || url.starts_with("workspace/") {
            // Workspace-relative path, convert to workspace URL
            // The workspace is served at http://localhost:7788/workspace/
            let workspace_path = if url.starts_with("output/") {
                format!("workspace/{}", url)
            } else {
                url
            };
            url = format!("http://localhost:7788/{}", workspace_path);
        } else {
            // Assume it's a domain or URL without scheme
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
