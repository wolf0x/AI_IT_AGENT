//! Memory MD tool — manage MEMORY.md (long-term curated memory).
//!
//! Actions:
//! - `write_memory`: Write/overwrite MEMORY.md with curated content
//! - `read_memory`: Read MEMORY.md content

use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::Path;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

/// Tool for managing MEMORY.md — the curated long-term memory file.
pub struct MemoryMdTool {
    workspace_dir: String,
}

impl MemoryMdTool {
    pub fn new(workspace_dir: String) -> Self {
        Self { workspace_dir }
    }

    fn memory_md_path(&self) -> std::path::PathBuf {
        Path::new(&self.workspace_dir).join("MEMORY.md")
    }
}

#[async_trait]
impl Tool for MemoryMdTool {
    fn name(&self) -> &str { "memory_md" }

    fn description(&self) -> &str {
        "Manage long-term curated memory (MEMORY.md). Actions:\n\
         - 'write_memory': Overwrite MEMORY.md with new curated content. Provide 'content'.\n\
         - 'read_memory': Read current MEMORY.md content."
    }

    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { false }
    fn category(&self) -> &str { "write" }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["write_memory", "read_memory"],
                    "description": "Which memory action to perform"
                },
                "content": {
                    "type": "string",
                    "description": "Content to write (required for write_memory)"
                }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let action = args["action"].as_str().ok_or_else(|| "Missing 'action'".to_string())?;

        match action {
            "write_memory" => {
                let content = args["content"].as_str()
                    .ok_or_else(|| "Missing 'content' for write_memory".to_string())?;
                let path = self.memory_md_path();

                match std::fs::write(&path, content) {
                    Ok(_) => Ok(json!({
                        "success": true,
                        "action": "write_memory",
                        "path": path.display().to_string(),
                        "message": format!("MEMORY.md updated ({} chars)", content.len())
                    })),
                    Err(e) => Err(format!("Failed to write MEMORY.md: {}", e).into())
                }
            }

            "read_memory" => {
                let path = self.memory_md_path();

                match std::fs::read_to_string(&path) {
                    Ok(content) => Ok(json!({
                        "success": true,
                        "action": "read_memory",
                        "content": content
                    })),
                    Err(_) => Ok(json!({
                        "success": true,
                        "action": "read_memory",
                        "content": "",
                        "message": "MEMORY.md does not exist yet"
                    }))
                }
            }

            _ => Err(format!(
                "Unknown action '{}'. Valid actions: write_memory, read_memory",
                action
            ).into())
        }
    }
}
