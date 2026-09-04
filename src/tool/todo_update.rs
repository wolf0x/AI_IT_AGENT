//! TODO tracking tool — lightweight task planning for multi-step work.
//!
//! Actions:
//! - `set`: Create/replace the entire TODO list with new items
//! - `update`: Update a specific item's status by index
//! - `clear`: Clear all TODO items
//! - `list`: Show current TODO list (also returned automatically)
//!
//! Stored as JSON in workspace/todos.json

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TodoItem {
    pub description: String,
    pub status: String, // "pending", "in_progress", "completed", "cancelled", "skipped"
    /// Unix epoch seconds when this item moved to "in_progress".
    /// Used by the per-item timeout watchdog to auto-skip stuck items.
    #[serde(default)]
    pub started_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TodoList {
    pub items: Vec<TodoItem>,
}

/// Tool for tracking multi-step task progress via a TODO list.
pub struct TodoUpdateTool {
    workspace_dir: String,
}

impl TodoUpdateTool {
    pub fn new(workspace_dir: String) -> Self {
        Self { workspace_dir }
    }

    /// Session-scoped TODO file path. The main session (and any session with
    /// an empty id, e.g. tools invoked outside a runner) writes to
    /// `todos.json`; sub-agent / cron sessions write to `todos-<session>.json`
    /// so they never clobber the main task contract (session-isolation fuse).
    fn todos_path(&self, session_id: &str) -> PathBuf {
        let main = session_id.trim().is_empty()
            || (!session_id.starts_with("sub-") && !session_id.starts_with("cron-"));
        if main {
            PathBuf::from(&self.workspace_dir).join("todos.json")
        } else {
            let safe: String = session_id
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
                .collect();
            PathBuf::from(&self.workspace_dir).join(format!("todos-{}.json", safe))
        }
    }

    fn load_todos(&self, session_id: &str) -> TodoList {
        let path = self.todos_path(session_id);
        if !path.exists() {
            return TodoList::default();
        }
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save_todos(&self, todos: &TodoList, session_id: &str) -> Result<(), String> {
        let path = self.todos_path(session_id);
        let json = serde_json::to_string_pretty(todos)
            .map_err(|e| format!("Serialize error: {}", e))?;
        std::fs::write(&path, json)
            .map_err(|e| format!("Write error: {}", e))?;
        Ok(())
    }

    fn todos_to_json(todos: &TodoList) -> Value {
        let items: Vec<Value> = todos.items.iter().enumerate().map(|(i, item)| {
            json!({
                "index": i,
                "description": item.description,
                "status": item.status,
                "started_at": item.started_at,
            })
        }).collect();
        json!({ "items": items, "count": items.len() })
    }
}

#[async_trait]
impl Tool for TodoUpdateTool {
    fn name(&self) -> &str { "todo_update" }

    fn description(&self) -> &str {
        "Track multi-step task progress with a TODO list. Use this for complex tasks \
         that involve 3+ steps. Actions:\n\
         - 'set': Create/replace the TODO list. Provide 'items' as array of {description, status}.\n\
         - 'update': Update a specific item's status. Provide 'index' (0-based) and 'status'.\n\
         - 'clear': Remove all TODO items.\n\
         - 'list': Show current TODO list.\n\
         Statuses: pending, in_progress, completed, cancelled"
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
                    "enum": ["set", "update", "clear", "list"],
                    "description": "Which action to perform"
                },
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "description": { "type": "string" },
                            "status": { "type": "string", "enum": ["pending", "in_progress", "completed", "cancelled", "skipped"] }
                        },
                        "required": ["description", "status"]
                    },
                    "description": "TODO items (required for 'set' action)"
                },
                "index": {
                    "type": "integer",
                    "description": "0-based index of the item to update (required for 'update' action)"
                },
                "status": {
                    "type": "string",
                    "enum": ["pending", "in_progress", "completed", "cancelled", "skipped"],
                    "description": "New status (required for 'update' action)"
                }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value> {
        let session_id = ctx.base.base.session_id.clone();
        let action = args["action"].as_str()
            .ok_or_else(|| "Missing 'action'".to_string())?;

        match action {
            "set" => {
                let items_arr = args["items"].as_array()
                    .ok_or_else(|| "Missing 'items' array for set action".to_string())?;

                let mut items = Vec::new();
                for (i, item) in items_arr.iter().enumerate() {
                    let desc = item["description"].as_str()
                        .ok_or_else(|| format!("Item {} missing 'description'", i))?;
                    let status = item["status"].as_str()
                        .unwrap_or("pending");
                    items.push(TodoItem {
                        description: desc.to_string(),
                        status: status.to_string(),
                        started_at: None,
                    });
                }

                let todos = TodoList { items };
                self.save_todos(&todos, &session_id)
                    .map_err(|e| format!("Failed to save TODOs: {}", e))?;

                Ok(json!({
                    "success": true,
                    "action": "set",
                    "message": format!("TODO list set with {} items", todos.items.len()),
                    "todos": Self::todos_to_json(&todos)
                }))
            }

            "update" => {
                let index = args["index"].as_u64()
                    .ok_or_else(|| "Missing 'index' for update action".to_string())? as usize;
                let status = args["status"].as_str()
                    .ok_or_else(|| "Missing 'status' for update action".to_string())?;

                let mut todos = self.load_todos(&session_id);
                if index >= todos.items.len() {
                    return Err(format!("Index {} out of range (have {} items)", index, todos.items.len()).into());
                }

                todos.items[index].status = status.to_string();
                // Track per-item start time for the timeout watchdog: stamp
                // when moving to "in_progress", clear once terminal reached.
                if status == "in_progress" && todos.items[index].started_at.is_none() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    todos.items[index].started_at = Some(now);
                } else if status == "completed" || status == "cancelled" || status == "skipped" {
                    todos.items[index].started_at = None;
                }
                self.save_todos(&todos, &session_id)
                    .map_err(|e| format!("Failed to save TODOs: {}", e))?;

                // Terminal fuse: when this update leaves every item in a terminal
                // state (completed/cancelled/skipped), the task contract is finished —
                // auto-clear instead of leaving a stale list.
                let all_terminal = !todos.items.is_empty()
                    && todos.items.iter().all(|i| i.status == "completed" || i.status == "cancelled" || i.status == "skipped");
                if all_terminal {
                    self.save_todos(&TodoList::default(), &session_id)
                        .map_err(|e| format!("Failed to clear TODOs: {}", e))?;
                    return Ok(json!({
                        "success": true,
                        "action": "update",
                        "message": format!("Item {} terminal — all TODO items done, list auto-cleared", index),
                        "auto_cleared": true,
                    }));
                }

                Ok(json!({
                    "success": true,
                    "action": "update",
                    "message": format!("Item {} updated to '{}'", index, status),
                    "todos": Self::todos_to_json(&todos)
                }))
            }

            "clear" => {
                let todos = TodoList::default();
                self.save_todos(&todos, &session_id)
                    .map_err(|e| format!("Failed to save TODOs: {}", e))?;

                Ok(json!({
                    "success": true,
                    "action": "clear",
                    "message": "TODO list cleared"
                }))
            }

            "list" => {
                let todos = self.load_todos(&session_id);
                Ok(json!({
                    "success": true,
                    "action": "list",
                    "todos": Self::todos_to_json(&todos)
                }))
            }

            _ => Err(format!(
                "Unknown action '{}'. Valid: set, update, clear, list",
                action
            ).into())
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{CallbackContext, ReadonlyContext};

    fn tool(ws: &str) -> TodoUpdateTool {
        TodoUpdateTool::new(ws.to_string())
    }

    fn ctx(ws: &str, session_id: &str) -> ToolContext {
        let base = ReadonlyContext::new("inv".into(), "agent".into(), session_id.to_string());
        ToolContext::new(CallbackContext::new(base), "fc".into(), ws.to_string(), ws.to_string())
    }

    fn tmp_ws(tag: &str) -> String {
        let dir = std::env::temp_dir().join(format!("rustagent_todo_test_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        dir.to_string_lossy().into_owned()
    }

    #[test]
    fn session_path_routing() {
        let ws = tmp_ws("route");
        let t = tool(&ws);
        assert_eq!(t.todos_path("main-123").file_name().unwrap(), "todos.json");
        assert_eq!(t.todos_path("").file_name().unwrap(), "todos.json");
        assert_eq!(t.todos_path("cron-abc").file_name().unwrap(), "todos-cron-abc.json");
        assert_eq!(t.todos_path("sub-def").file_name().unwrap(), "todos-sub-def.json");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[tokio::test]
    async fn execute_session_isolation_writes_separate_files() {
        let ws = tmp_ws("iso");
        let t = tool(&ws);
        let main = t.execute(
            json!({"action": "set", "items": [{"description": "m1", "status": "pending"}]}),
            &ctx(&ws, "main-1"),
        ).await.unwrap();
        let cron = t.execute(
            json!({"action": "set", "items": [{"description": "c1", "status": "pending"}]}),
            &ctx(&ws, "cron-9"),
        ).await.unwrap();
        assert!(main["success"].as_bool().unwrap());
        assert!(cron["success"].as_bool().unwrap());
        assert!(std::path::Path::new(&ws).join("todos.json").exists());
        let main_raw = std::fs::read_to_string(std::path::Path::new(&ws).join("todos.json")).unwrap();
        assert!(main_raw.contains("m1"));
        assert!(!main_raw.contains("c1"));
        assert!(std::path::Path::new(&ws).join("todos-cron-9.json").exists());
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[tokio::test]
    async fn auto_clear_when_all_items_completed() {
        let ws = tmp_ws("clear");
        let t = tool(&ws);
        let c = ctx(&ws, "main-2");
        t.execute(json!({"action": "set", "items": [
            {"description": "a", "status": "pending"},
            {"description": "b", "status": "pending"},
        ]}), &c).await.unwrap();
        let r1 = t.execute(json!({"action": "update", "index": 0, "status": "completed"}), &c).await.unwrap();
        assert_ne!(r1["auto_cleared"].as_bool().unwrap_or(false), true);
        let r2 = t.execute(json!({"action": "update", "index": 1, "status": "completed"}), &c).await.unwrap();
        assert_eq!(r2["auto_cleared"].as_bool().unwrap_or(false), true);
        let list = t.execute(json!({"action": "list"}), &c).await.unwrap();
        assert_eq!(list["todos"]["count"].as_u64().unwrap(), 0);
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[tokio::test]
    async fn no_auto_clear_when_items_pending() {
        let ws = tmp_ws("nclear");
        let t = tool(&ws);
        let c = ctx(&ws, "main-3");
        t.execute(json!({"action": "set", "items": [
            {"description": "a", "status": "pending"},
            {"description": "b", "status": "pending"},
        ]}), &c).await.unwrap();
        let r = t.execute(json!({"action": "update", "index": 0, "status": "completed"}), &c).await.unwrap();
        assert_eq!(r["auto_cleared"].as_bool().unwrap_or(false), false);
        assert_eq!(r["todos"]["count"].as_u64().unwrap(), 2);
        let _ = std::fs::remove_dir_all(&ws);
    }
    #[tokio::test]
    async fn update_stamps_started_at_and_clears_on_terminal() {
        let ws = tmp_ws("stamp");
        let t = tool(&ws);
        let c = ctx(&ws, "main-4");
        t.execute(json!({"action": "set", "items": [
            {"description": "a", "status": "pending"},
            {"description": "b", "status": "pending"},
        ]}), &c).await.unwrap();

        t.execute(json!({"action": "update", "index": 0, "status": "in_progress"}), &c).await.unwrap();
        let raw0 = std::fs::read_to_string(std::path::Path::new(&ws).join("todos.json")).unwrap();
        let v0: Value = serde_json::from_str(&raw0).unwrap();
        let item0 = &v0["items"][0];
        assert_eq!(item0["status"], "in_progress");
        assert!(item0.get("started_at").and_then(|s| s.as_u64()).unwrap_or(0) > 0, "started_at should be stamped");

        // terminal clears
        t.execute(json!({"action": "update", "index": 0, "status": "completed"}), &c).await.unwrap();
        let raw1 = std::fs::read_to_string(std::path::Path::new(&ws).join("todos.json")).unwrap();
        let v1: Value = serde_json::from_str(&raw1).unwrap();
        assert!(v1["items"][0]["started_at"].is_null());
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[tokio::test]
    async fn skipped_is_valid_and_terminal() {
        let ws = tmp_ws("skip");
        let t = tool(&ws);
        let c = ctx(&ws, "main-5");
        t.execute(json!({"action": "set", "items": [
            {"description": "a", "status": "pending"},
            {"description": "b", "status": "pending"},
        ]}), &c).await.unwrap();
        let r = t.execute(json!({"action": "update", "index": 0, "status": "skipped"}), &c).await.unwrap();
        assert_eq!(r["auto_cleared"].as_bool().unwrap_or(false), false);
        assert_eq!(r["todos"]["items"][0]["status"], "skipped");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[tokio::test]
    async fn auto_clear_when_all_terminal_including_skipped() {
        let ws = tmp_ws("clearskip");
        let t = tool(&ws);
        let c = ctx(&ws, "main-6");
        t.execute(json!({"action": "set", "items": [
            {"description": "a", "status": "pending"},
            {"description": "b", "status": "pending"},
        ]}), &c).await.unwrap();
        // skip first, still one pending -> not cleared
        let r1 = t.execute(json!({"action": "update", "index": 0, "status": "skipped"}), &c).await.unwrap();
        assert_ne!(r1["auto_cleared"].as_bool().unwrap_or(false), true);
        // mark last skipped too -> all terminal -> auto-clear
        let r2 = t.execute(json!({"action": "update", "index": 1, "status": "skipped"}), &c).await.unwrap();
        assert_eq!(r2["auto_cleared"].as_bool().unwrap_or(false), true);
        let list = t.execute(json!({"action": "list"}), &c).await.unwrap();
        assert_eq!(list["todos"]["count"].as_u64().unwrap(), 0);
        let _ = std::fs::remove_dir_all(&ws);
    }
}
