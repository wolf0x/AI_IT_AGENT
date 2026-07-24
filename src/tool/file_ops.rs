use async_trait::async_trait;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

fn resolve_path(ctx: &ToolContext, path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    if p.is_absolute() {
        p
    } else {
        PathBuf::from(&ctx.working_dir).join(p)
    }
}

// --- file_read ---
pub struct FileReadTool;

#[async_trait]
impl Tool for FileReadTool {
    fn name(&self) -> &str { "file_read" }
    fn description(&self) -> &str {
        "Read the contents of a file. Supports optional line range (start_line, end_line)."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "File path to read" },
                "start_line": { "type": "integer", "description": "Start line (1-based, optional)" },
                "end_line": { "type": "integer", "description": "End line (inclusive, optional)" }
            },
            "required": ["path"]
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value> {
        let path = args["path"].as_str().ok_or_else(|| "Missing 'path'".to_string())?;
        let resolved = resolve_path(ctx, path);
        let content = fs::read_to_string(&resolved)
            .map_err(|e| format!("Failed to read {}: {}", resolved.display(), e))?;

        let start = args["start_line"].as_u64().unwrap_or(1) as usize;
        let end = args["end_line"].as_u64().unwrap_or(u64::MAX) as usize;

        if start > 1 || end < usize::MAX {
            let lines: Vec<&str> = content.lines().collect();
            let s = start.saturating_sub(1).min(lines.len());
            let e = end.min(lines.len());
            if s >= e {
                return Ok(json!({ "content": "", "lines": 0 }));
            }
            let sliced: Vec<String> = lines[s..e]
                .iter()
                .enumerate()
                .map(|(i, l)| format!("{}: {}", s + i + 1, l))
                .collect();
            Ok(json!({ "content": sliced.join("\n"), "lines": e - s }))
        } else {
            let line_count = content.lines().count();
            Ok(json!({ "content": content, "lines": line_count }))
        }
    }
}

// --- file_write ---
pub struct FileWriteTool;

#[async_trait]
impl Tool for FileWriteTool {
    fn name(&self) -> &str { "file_write" }
    fn description(&self) -> &str { "Write content to a file. Creates the file and parent directories if they don't exist." }
    fn is_builtin(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "File path to write" },
                "content": { "type": "string", "description": "Content to write" }
            },
            "required": ["path", "content"]
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value> {
        let path = args["path"].as_str().ok_or_else(|| "Missing 'path'".to_string())?;
        let content = args["content"].as_str().ok_or_else(|| "Missing 'content'".to_string())?;
        let resolved = resolve_path(ctx, path);
        if let Some(parent) = resolved.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create dirs: {}", e))?;
        }
        fs::write(&resolved, content).map_err(|e| format!("Failed to write: {}", e))?;
        Ok(json!({ "status": "ok", "path": resolved.to_string_lossy(), "bytes": content.len() }))
    }
}

// --- file_delete ---
pub struct FileDeleteTool;

#[async_trait]
impl Tool for FileDeleteTool {
    fn name(&self) -> &str { "file_delete" }
    fn description(&self) -> &str { "Delete a file or empty directory." }
    fn is_builtin(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "File or directory path to delete" }
            },
            "required": ["path"]
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value> {
        let path = args["path"].as_str().ok_or_else(|| "Missing 'path'".to_string())?;
        let resolved = resolve_path(ctx, path);
        if resolved.is_file() {
            fs::remove_file(&resolved).map_err(|e| format!("Failed to delete: {}", e))?;
        } else if resolved.is_dir() {
            fs::remove_dir(&resolved).map_err(|e| {
                format!("Failed to delete directory (must be empty): {}. Error: {}", resolved.display(), e)
            })?;
        } else {
            return Err(format!("Path does not exist: {}", resolved.display()).into());
        }
        Ok(json!({ "status": "deleted", "path": resolved.to_string_lossy() }))
    }
}

// --- file_modify ---
pub struct FileModifyTool;

#[async_trait]
impl Tool for FileModifyTool {
    fn name(&self) -> &str { "file_modify" }
    fn description(&self) -> &str { "Search and replace text in a file. Replaces all occurrences of 'search' with 'replace'." }
    fn is_builtin(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "File path to modify" },
                "search": { "type": "string", "description": "Text to search for" },
                "replace": { "type": "string", "description": "Replacement text" }
            },
            "required": ["path", "search", "replace"]
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value> {
        let path = args["path"].as_str().ok_or_else(|| "Missing 'path'".to_string())?;
        let search = args["search"].as_str().ok_or_else(|| "Missing 'search'".to_string())?;
        let replace = args["replace"].as_str().ok_or_else(|| "Missing 'replace'".to_string())?;
        let resolved = resolve_path(ctx, path);
        let content = fs::read_to_string(&resolved).map_err(|e| format!("Failed to read: {}", e))?;
        let count = content.matches(search).count();
        let new_content = content.replace(search, replace);
        fs::write(&resolved, &new_content).map_err(|e| format!("Failed to write: {}", e))?;
        Ok(json!({ "status": "ok", "replacements": count }))
    }
}

// --- file_list ---
pub struct FileListTool;

#[async_trait]
impl Tool for FileListTool {
    fn name(&self) -> &str { "file_list" }
    fn description(&self) -> &str { "List directory contents. Optionally filter by glob pattern and recurse into subdirectories." }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "Directory path to list" },
                "pattern": { "type": "string", "description": "Glob pattern filter (e.g. *.rs), optional" },
                "recursive": { "type": "boolean", "description": "Recurse into subdirectories (default false)" }
            },
            "required": ["path"]
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value> {
        let path = args["path"].as_str().ok_or_else(|| "Missing 'path'".to_string())?;
        let pattern = args["pattern"].as_str();
        let recursive = args["recursive"].as_bool().unwrap_or(false);
        let resolved = resolve_path(ctx, path);

        if !resolved.is_dir() {
            return Err(format!("Not a directory: {}", resolved.display()).into());
        }

        let mut entries = Vec::new();
        list_dir_recursive(&resolved, pattern, recursive, &mut entries, 0, 3)?;
        Ok(json!({ "entries": entries, "count": entries.len() }))
    }
}

fn list_dir_recursive(
    dir: &std::path::Path,
    pattern: Option<&str>,
    recursive: bool,
    entries: &mut Vec<Value>,
    depth: usize,
    max_depth: usize,
) -> AgentResult<()> {
    let read_dir = fs::read_dir(dir).map_err(|e| format!("Failed to read dir: {}", e))?;
    for entry in read_dir {
        let entry = entry.map_err(|e| format!("Entry error: {}", e))?;
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();

        let matches_pattern = match pattern {
            Some(pat) => glob_match(&name, pat),
            None => true,
        };

        if matches_pattern || path.is_dir() {
            let kind = if path.is_dir() { "dir" } else { "file" };
            let size = if path.is_file() {
                fs::metadata(&path).map(|m| m.len()).unwrap_or(0)
            } else {
                0
            };
            if matches_pattern {
                entries.push(json!({
                    "name": name,
                    "type": kind,
                    "size": size,
                    "path": path.to_string_lossy()
                }));
            }
        }

        if recursive && path.is_dir() && depth < max_depth {
            list_dir_recursive(&path, pattern, recursive, entries, depth + 1, max_depth)?;
        }
    }
    Ok(())
}

fn glob_match(name: &str, pattern: &str) -> bool {
    if let Ok(pat) = glob::Pattern::new(pattern) {
        pat.matches(name)
    } else {
        name.contains(pattern)
    }
}
