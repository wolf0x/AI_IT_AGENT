//! Task checkpoint persistence for crash recovery (断点续跑).
//!
//! The `TaskCheckpointer` wraps `MemoryStore` and provides a convenient
//! interface for saving, loading, and deleting agent task checkpoints.
//! Checkpoints capture the full conversation history at each tool-execution
//! round so a task can be resumed after a process restart.

use std::collections::HashSet;
use std::sync::Arc;

use chrono::Utc;

use crate::memory::{MemoryStore, TaskCheckpoint};
use crate::model::ChatMessage;

/// Shared checkpointer type (Send + Sync, safe to clone into spawned tasks).
pub type ATaskCheckpointer = Arc<TaskCheckpointer>;

/// Lightweight wrapper around `MemoryStore` for checkpoint operations.
pub struct TaskCheckpointer {
    store: Arc<MemoryStore>,
}

impl std::fmt::Debug for TaskCheckpointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskCheckpointer").finish()
    }
}

impl TaskCheckpointer {
    pub fn new(store: Arc<MemoryStore>) -> Self {
        Self { store }
    }

    /// Save or update a checkpoint.
    ///
    /// Called by the agent loop after each round of tool execution.
    /// On the first call the row is INSERT-ed; subsequent calls UPDATE
    /// the same row (same `id`) with the latest history.
    pub fn save(
        &self,
        id: &str,
        session_id: &str,
        model: &str,
        user_message: &str,
        history: &[ChatMessage],
        iteration: usize,
    ) -> Result<(), String> {
        let history_json = serde_json::to_string(history)
            .map_err(|e| format!("Failed to serialize history: {}", e))?;

        let tool_summary = build_tool_summary(history);
        let now = Utc::now().to_rfc3339();

        // Preserve original created_at if the checkpoint already exists.
        let created_at = self.store.get_checkpoint(id)
            .ok()
            .flatten()
            .map(|c| c.created_at)
            .unwrap_or_else(|| now.clone());

        let cp = TaskCheckpoint {
            id: id.to_string(),
            session_id: session_id.to_string(),
            model_name: model.to_string(),
            user_message: user_message.to_string(),
            history_json,
            iteration,
            tool_summary,
            created_at,
            updated_at: now,
        };

        self.store.save_checkpoint(&cp)
    }

    /// Delete a checkpoint (called when the task completes normally).
    pub fn delete(&self, id: &str) -> Result<(), String> {
        self.store.delete_checkpoint(id)
    }
}

/// Build a human-readable summary of tools used in the conversation history.
///
/// Example output: `"bash, read_file, write_file (3 rounds)"`
fn build_tool_summary(history: &[ChatMessage]) -> String {
    let mut tool_names: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut rounds = 0usize;

    for msg in history {
        if msg.role == "tool" {
            let name = msg.name.clone().unwrap_or_else(|| "unknown".to_string());
            if seen.insert(name.clone()) {
                tool_names.push(name);
            }
        }
        // Count assistant messages with tool calls as rounds.
        if msg.role == "assistant" && msg.tool_calls.is_some() {
            rounds += 1;
        }
    }

    if tool_names.is_empty() {
        return "(no tools)".to_string();
    }

    let names = tool_names.join(", ");
    if rounds <= 1 {
        names
    } else {
        format!("{} ({} rounds)", names, rounds)
    }
}
