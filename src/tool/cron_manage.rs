//! CRON management tool — lets the agent create, list, delete, and toggle
//! scheduled tasks through natural language conversation.

use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;
use crate::scheduler::{CronTask, Scheduler};

/// Tool for managing RustAgent CRON tasks via chat.
pub struct CronManageTool {
    scheduler: Arc<Mutex<Scheduler>>,
}

impl CronManageTool {
    pub fn new(scheduler: Arc<Mutex<Scheduler>>) -> Self {
        Self { scheduler }
    }
}

#[async_trait]
impl Tool for CronManageTool {
    fn name(&self) -> &str { "cron_manage" }

    fn description(&self) -> &str {
        "Create, list, delete, or toggle RustAgent CRON tasks (application-level scheduled tasks). \
         Results are delivered back to the chat. Use schedule format like 'every 5m', 'every 1h', 'every 30s', 'every 1d'."
    }

    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { false }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["create", "list", "delete", "toggle"],
                    "description": "Action to perform"
                },
                "name": {
                    "type": "string",
                    "description": "Task name (required for create)"
                },
                "schedule": {
                    "type": "string",
                    "description": "Schedule: 'every Ns/Nm/Nh/Nd' or 5-field cron (required for create)"
                },
                "message": {
                    "type": "string",
                    "description": "Chat message to send when triggered (required for create)"
                },
                "model": {
                    "type": "string",
                    "description": "Model name (optional, empty = default)"
                },
                "task_id": {
                    "type": "string",
                    "description": "Task ID (required for delete and toggle)"
                }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let action = args["action"].as_str().unwrap_or("");
        let mut sched = self.scheduler.lock().await;

        match action {
            "create" => {
                let name = args["name"].as_str().unwrap_or("").trim().to_string();
                let schedule = args["schedule"].as_str().unwrap_or("").trim().to_string();
                let message = args["message"].as_str().unwrap_or("").trim().to_string();
                let model = args["model"].as_str().unwrap_or("").trim().to_string();

                if name.is_empty() || schedule.is_empty() || message.is_empty() {
                    return Ok(json!({
                        "success": false,
                        "error": "name, schedule, and message are required for create action"
                    }));
                }

                let task = CronTask {
                    id: String::new(),
                    name,
                    schedule,
                    message,
                    model,
                    enabled: true,
                    last_run: None,
                    next_run: None,
                    interval_secs: 0,
                };

                let created = sched.create(task);
                Ok(json!({
                    "success": true,
                    "task": {
                        "id": created.id,
                        "name": created.name,
                        "schedule": created.schedule,
                        "message": created.message,
                        "model": created.model,
                        "enabled": created.enabled,
                        "interval_secs": created.interval_secs,
                        "next_run": created.next_run,
                    }
                }))
            }

            "list" => {
                let tasks: Vec<Value> = sched.list().iter().map(|t| {
                    json!({
                        "id": t.id,
                        "name": t.name,
                        "schedule": t.schedule,
                        "message": t.message,
                        "model": t.model,
                        "enabled": t.enabled,
                        "last_run": t.last_run,
                        "next_run": t.next_run,
                        "interval_secs": t.interval_secs,
                    })
                }).collect();

                Ok(json!({
                    "success": true,
                    "count": tasks.len(),
                    "tasks": tasks,
                }))
            }

            "delete" => {
                let task_id = args["task_id"].as_str().unwrap_or("").trim().to_string();
                if task_id.is_empty() {
                    return Ok(json!({
                        "success": false,
                        "error": "task_id is required for delete action"
                    }));
                }

                if sched.delete(&task_id) {
                    Ok(json!({ "success": true, "deleted": task_id }))
                } else {
                    Ok(json!({ "success": false, "error": "Task not found" }))
                }
            }

            "toggle" => {
                let task_id = args["task_id"].as_str().unwrap_or("").trim().to_string();
                if task_id.is_empty() {
                    return Ok(json!({
                        "success": false,
                        "error": "task_id is required for toggle action"
                    }));
                }

                if sched.toggle(&task_id) {
                    let state = sched.list().iter()
                        .find(|t| t.id == task_id)
                        .map(|t| t.enabled)
                        .unwrap_or(false);
                    Ok(json!({ "success": true, "task_id": task_id, "enabled": state }))
                } else {
                    Ok(json!({ "success": false, "error": "Task not found" }))
                }
            }

            _ => Ok(json!({
                "success": false,
                "error": "Invalid action. Use: create, list, delete, or toggle"
            })),
        }
    }
}
