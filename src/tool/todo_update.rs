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
    pub status: String, // "pending", "in_progress", "completed", "cancelled"
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

    fn todos_path(&self) -> PathBuf {
        PathBuf::from(&self.workspace_dir).join("todos.json")
    }

    fn load_todos(&self) -> TodoList {
        let path = self.todos_path();
        if !path.exists() {
            return TodoList::default();
        }
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save_todos(&self, todos: &TodoList) -> Result<(), String> {
        let path = self.todos_path();
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
                            "status": { "type": "string", "enum": ["pending", "in_progress", "completed", "cancelled"] }
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
                    "enum": ["pending", "in_progress", "completed", "cancelled"],
                    "description": "New status (required for 'update' action)"
                }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
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
                    });
                }

                let todos = TodoList { items };
                self.save_todos(&todos)
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

                let mut todos = self.load_todos();
                if index >= todos.items.len() {
                    return Err(format!("Index {} out of range (have {} items)", index, todos.items.len()).into());
                }

                todos.items[index].status = status.to_string();
                self.save_todos(&todos)
                    .map_err(|e| format!("Failed to save TODOs: {}", e))?;

                Ok(json!({
                    "success": true,
                    "action": "update",
                    "message": format!("Item {} updated to '{}'", index, status),
                    "todos": Self::todos_to_json(&todos)
                }))
            }

            "clear" => {
                let todos = TodoList::default();
                self.save_todos(&todos)
                    .map_err(|e| format!("Failed to save TODOs: {}", e))?;

                Ok(json!({
                    "success": true,
                    "action": "clear",
                    "message": "TODO list cleared"
                }))
            }

            "list" => {
                let todos = self.load_todos();
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
