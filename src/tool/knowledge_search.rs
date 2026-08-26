//! Knowledge search tool — pointer-based lookup into the local knowledge base.
//!
//! Returns compact pointers (file + line + summary) so the agent can then read
//! only the relevant chunk, mirroring the skill progressive-reading design.

use async_trait::async_trait;
use serde_json::{json, Value};

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct KnowledgeSearchTool {
    workspace_dir: String,
}

impl KnowledgeSearchTool {
    pub fn new(workspace_dir: String) -> Self {
        Self { workspace_dir }
    }
}

#[async_trait]
impl Tool for KnowledgeSearchTool {
    fn name(&self) -> &str {
        "knowledge_search"
    }

    fn description(&self) -> &str {
        "Search the local knowledge base (workspace/knowledge) for accumulated expertise, \
         lessons, and references. Returns pointers (file:line + summary), not full text — \
         then read the matching file location for details. Use for troubleshooting, \
         operational playbooks, or reusing prior knowledge."
    }

    fn is_builtin(&self) -> bool {
        true
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn category(&self) -> &str {
        "read"
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Keywords to search (Chinese, English, or mixed)."
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results to return. Default 5, max 20."
                }
            },
            "required": ["query"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let query = args["query"].as_str().unwrap_or("").trim().to_string();
        if query.is_empty() {
            return Err("Missing 'query'".into());
        }
        let limit = args["limit"].as_u64().unwrap_or(5).min(20) as usize;

        let ws = self.workspace_dir.clone();
        let q = query.clone();
        let hits = tokio::task::spawn_blocking(move || crate::knowledge::search(&ws, &q, limit))
            .await
            .map_err(|e| format!("knowledge_search task failed: {}", e))?;
        if hits.is_empty() {
            return Ok(json!({
                "success": true,
                "count": 0,
                "hits": [],
                "hint": "No local knowledge matched. Try different keywords, or add a .md file under workspace/knowledge/."
            }));
        }

        let hits_json: Vec<Value> = hits
            .iter()
            .map(|e| {
                json!({
                    "title": e.title,
                    "line_start": e.line,
                    "line_end": e.end_line,
                    "file": e.file,
                    "category": e.category,
                    "tags": e.tags,
                    "summary": e.summary,
                })
            })
            .collect();

        Ok(json!({
            "success": true,
            "count": hits_json.len(),
            "hits": hits_json,
            "usage": "Read the file between line_start and line_end (e.g. file_read with start_line/end_line) to get the full content, then apply it."
        }))
    }
}
