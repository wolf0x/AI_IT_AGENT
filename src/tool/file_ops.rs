use async_trait::async_trait;
use serde_json::{json, Value};
use std::fs;
use std::io::Read;
use std::path::PathBuf;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

/// Files larger than this are considered "oversized" and only partially read.
const MAX_FULL_READ_SIZE: u64 = 300 * 1024 * 1024; // 300 MB
/// For oversized files, read only this many bytes from the beginning.
const TRUNCATED_READ_SIZE: u64 = 1024 * 1024; // 1 MB

fn resolve_path(ctx: &ToolContext, path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    if p.is_absolute() {
        p
    } else {
        PathBuf::from(&ctx.working_dir).join(p)
    }
}

/// Resolve a read path with an Expert-mode fallback. In Expert mode each round
/// writes artifacts into `managed/<contract>/round_NNN/`, so a relative
/// reference like `output/x.json` or a bare filename may live in the current
/// round dir or an earlier round dir of the same contract. Instant mode (no
/// per-round output override) keeps the original behavior unchanged.
fn resolve_read_path(ctx: &ToolContext, path: &str) -> PathBuf {
    let primary = resolve_path(ctx, path);
    let default_output = format!("{}/output", ctx.workspace_dir);
    let eff_output = ctx.output_dir();
    let is_absolute = std::path::Path::new(path).is_absolute();
    if std::fs::metadata(&primary).is_ok()
        || is_absolute
        || eff_output.eq_ignore_ascii_case(&default_output)
    {
        return primary;
    }
    // Expert round context: map workspace-relative shorthand into the round dirs.
    let p = path.replace('\\', "/");
    let rel = p
        .strip_prefix("workspace/output/")
        .or_else(|| p.strip_prefix("output/"))
        .unwrap_or(p.as_str())
        .trim_start_matches("./")
        .trim_start_matches(".\\");
    if rel.is_empty() {
        return primary;
    }
    let round_dir = PathBuf::from(eff_output);
    let candidate = round_dir.join(rel);
    if std::fs::metadata(&candidate).is_ok() {
        return candidate;
    }
    // Sibling rounds of the same contract (managed/<contract>/round_*).
    if let Some(contract_dir) = round_dir.parent() {
        if let Ok(entries) = std::fs::read_dir(contract_dir) {
            for e in entries.flatten() {
                if e.file_name().to_string_lossy().starts_with("round_") {
                    let c = e.path().join(rel);
                    if std::fs::metadata(&c).is_ok() {
                        return c;
                    }
                }
            }
        }
    }
    primary
}

/// Resolve path for file WRITE operations.
/// - Absolute path → use as-is (user explicitly specified)
/// - Relative path with directory component (contains / or \, but not just ./ or .\) → resolve against working_dir
/// - Relative path, filename only (or ./filename, .\filename) → default to workspace/output/ (artifact convention)
fn resolve_write_path(ctx: &ToolContext, path: &str) -> Result<PathBuf, String> {
    let p = PathBuf::from(path);
    if p.is_absolute() {
        // User explicitly specified an absolute path - use as-is.
        return Ok(p);
    }
    // Strip leading ./ or .\ to treat as bare filename
    let stripped = path.strip_prefix("./").or_else(|| path.strip_prefix(".\\")).unwrap_or(path);
    // Reject parent-directory traversal so relative writes can't escape the workspace.
    if std::path::Path::new(stripped).components().any(|c| c == std::path::Component::ParentDir) {
        return Err("Path must stay inside the workspace; '..' traversal is not allowed. Use an absolute path inside the workspace instead.".to_string());
    }
    // Check if remaining path has a directory component
    let has_dir_component = stripped.contains('/') || stripped.contains('\\');
    if has_dir_component {
        // User specified a relative path with directory - respect it
        Ok(PathBuf::from(&ctx.working_dir).join(stripped))
    } else {
        // Just a filename (or ./filename) - default to workspace/output/
        Ok(PathBuf::from(ctx.output_dir()).join(stripped))
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
        let resolved = resolve_read_path(ctx, path);

        let meta = fs::metadata(&resolved)
            .map_err(|e| format!("Failed to stat {}: {}", resolved.display(), e))?;
        if !meta.is_file() {
            return Err(format!("Not a file: {}", resolved.display()).into());
        }

        let file_size = meta.len();
        let truncated = file_size > MAX_FULL_READ_SIZE;

        let content = if truncated {
            // Only read the first TRUNCATED_READ_SIZE bytes to avoid OOM
            let file = fs::File::open(&resolved)
                .map_err(|e| format!("Failed to open {}: {}", resolved.display(), e))?;
            let mut bytes = Vec::new();
            file.take(TRUNCATED_READ_SIZE)
                .read_to_end(&mut bytes)
                .map_err(|e| format!("Read error: {}", e))?;
            String::from_utf8_lossy(&bytes).into_owned()
        } else {
            fs::read_to_string(&resolved)
                .map_err(|e| format!("Failed to read {}: {}", resolved.display(), e))?
        };

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
            let mut result = json!({ "content": sliced.join("\n"), "lines": e - s });
            if truncated {
                result["truncated"] = json!(true);
                result["file_size"] = json!(file_size);
                result["note"] = json!(format!(
                    "File is {:.1} MB (exceeds 300 MB limit). Only the first 1 MB was read.",
                    file_size as f64 / (1024.0 * 1024.0)
                ));
            }
            Ok(result)
        } else {
            let line_count = content.lines().count();
            let mut result = json!({ "content": content, "lines": line_count });
            if truncated {
                result["truncated"] = json!(true);
                result["file_size"] = json!(file_size);
                result["note"] = json!(format!(
                    "File is {:.1} MB (exceeds 300 MB limit). Only the first 1 MB was read.",
                    file_size as f64 / (1024.0 * 1024.0)
                ));
            }
            Ok(result)
        }
    }
}

// --- file_write ---
pub struct FileWriteTool;

#[async_trait]
impl Tool for FileWriteTool {
    fn name(&self) -> &str { "file_write" }
    fn description(&self) -> &str { 
        "Write content to a file. Creates the file and parent directories if they don't exist.\n\
         PATH RESOLUTION: If 'path' is just a filename (e.g. 'report.html'), it will be saved to \
         workspace/output/ by default. To write to a specific location, use an absolute path \
         (e.g. 'C:\\temp\\file.txt') or a relative path with directory (e.g. './file.txt' or 'subdir/file.txt')."
    }
    fn is_builtin(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "File path to write. Bare filename → workspace/output/. Include directory for other locations." },
                "content": { "type": "string", "description": "Content to write" }
            },
            "required": ["path", "content"]
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value> {
        let path = args["path"].as_str().ok_or_else(|| "Missing 'path'".to_string())?;
        let content = args["content"].as_str().ok_or_else(|| "Missing 'content'".to_string())?;
        let resolved = resolve_write_path(ctx, path)?;
        if let Some(parent) = resolved.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create dirs: {}", e))?;
        }
        fs::write(&resolved, content).map_err(|e| format!("Failed to write: {}", e))?;
        // Convert path to forward slashes for markdown/HTML compatibility
        let path_str = resolved.to_string_lossy().replace('\\', "/");
        Ok(json!({ "status": "ok", "path": path_str, "bytes": content.len() }))
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
        Ok(json!({ "status": "deleted", "path": resolved.to_string_lossy().replace('\\', "/") }))
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
                    "path": path.to_string_lossy().replace('\\', "/")
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
