//! Knowledge ingest tool — add external knowledge into the local knowledge base.
//!
//! Accepts either raw `text` (e.g. content already retrieved via web_fetch, which
//! has SSRF protection) or a local `source_path`. Content is sanitized, wrapped in
//! markdown frontmatter, written under workspace/knowledge/<category>/, and the
//! index is refreshed. For remote documents, fetch with web_fetch first, then pass
//! the text here.

use async_trait::async_trait;
use serde_json::{json, Value};

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct KnowledgeIngestTool {
    workspace_dir: String,
}

impl KnowledgeIngestTool {
    pub fn new(workspace_dir: String) -> Self {
        Self { workspace_dir }
    }
}

#[async_trait]
impl Tool for KnowledgeIngestTool {
    fn name(&self) -> &str {
        "knowledge_ingest"
    }

    fn description(&self) -> &str {
        "Add knowledge to the local knowledge base (workspace/knowledge). Pass raw 'text' \
         (for remote content, fetch it first with web_fetch) or a local 'source_path'. \
         Provide an optional 'title', comma-separated 'tags', and 'category'. The content \
         is saved as markdown and indexed, so it becomes findable via knowledge_search."
    }

    fn is_builtin(&self) -> bool {
        true
    }

    fn is_peripheral(&self) -> bool {
        true
    }

    fn is_read_only(&self) -> bool {
        false
    }

    fn category(&self) -> &str {
        "write"
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Raw content to ingest (e.g. from web_fetch or a document)."
                },
                "source_path": {
                    "type": "string",
                    "description": "Local file path to read and ingest, instead of 'text'."
                },
                "title": {
                    "type": "string",
                    "description": "Short title for the entry (defaults from source)."
                },
                "category": {
                    "type": "string",
                    "description": "Knowledge bucket: reference, playbook, runbook, vulns, lessons, etc. Default 'reference'."
                },
                "tags": {
                    "type": "string",
                    "description": "Comma-separated tags, e.g. 'ndr, 检测盲区, network'."
                }
            },
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let text = args["text"].as_str().map(|s| s.to_string());
        let source_path = args["source_path"].as_str().map(|s| s.to_string());

        let mut body = match text {
            Some(t) if !t.trim().is_empty() => t,
            _ => {
                let p = source_path.as_ref().ok_or_else(|| {
                    "Provide either 'text' or a non-empty 'source_path'".to_string()
                })?;
                std::fs::read_to_string(&p)
                    .map_err(|e| format!("Failed to read source_path {}: {}", p, e))?
            }
        };
        body = crate::knowledge::sanitize_body(&body);

        let title = args["title"]
            .as_str()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                source_path
                    .as_ref()
                    .and_then(|p| std::path::Path::new(p).file_stem())
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "Imported knowledge".to_string())
            });

        let category = args["category"]
            .as_str()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "reference".to_string());

        let tags: Vec<String> = args["tags"]
            .as_str()
            .map(|s| {
                s.split(',')
                    .map(|t| t.trim().trim_matches('"').to_string())
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let ws = self.workspace_dir.clone();
        let cat_out = category.clone();
        let title_out = title.clone();
        let body_chars = body.len();
        let path = tokio::task::spawn_blocking(move || {
            crate::knowledge::write_entry(&ws, &category, &title, &tags, &body)
        })
        .await
        .map_err(|e| format!("knowledge_ingest task failed: {}", e))??;

        Ok(json!({
            "success": true,
            "path": path,
            "category": cat_out,
            "title": title_out,
            "chars": body_chars,
            "message": "Knowledge ingested and index refreshed. Use knowledge_search to find it."
        }))
    }
}
