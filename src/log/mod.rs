use chrono::Utc;
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::warn;

use crate::agent::AgentEvent;

pub struct ConversationLogger {
    log_dir: PathBuf,
    file: Mutex<Option<(String, std::fs::File)>>,
}

impl ConversationLogger {
    pub fn new(log_dir: &str) -> Self {
        let dir = PathBuf::from(log_dir);
        let _ = fs::create_dir_all(&dir);
        Self {
            log_dir: dir,
            file: Mutex::new(None),
        }
    }

    fn get_date_str() -> String {
        Utc::now().format("%Y-%m-%d").to_string()
    }

    fn ensure_file(&self) -> Result<(), String> {
        let date = Self::get_date_str();
        let mut guard = self.file.lock().unwrap();

        if let Some((ref current_date, _)) = *guard {
            if current_date == &date {
                return Ok(());
            }
        }

        let path = self.log_dir.join(format!("{}.jsonl", date));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("Failed to open log file: {}", e))?;

        *guard = Some((date, file));
        Ok(())
    }

    pub fn log_user_message(&self, session_id: &str, content: &str) {
        let entry = json!({
            "ts": Utc::now().to_rfc3339(),
            "session": session_id,
            "role": "user",
            "content": content,
        });
        self.write_entry(&entry);
    }

    pub fn log_event(&self, session_id: &str, event: &AgentEvent) {
        let entry = match event {
            AgentEvent::Thinking { content, .. } => json!({
                "ts": Utc::now().to_rfc3339(),
                "session": session_id,
                "role": "assistant",
                "type": "thinking",
                "content": content,
            }),
            AgentEvent::TextDelta { content, .. } => json!({
                "ts": Utc::now().to_rfc3339(),
                "session": session_id,
                "role": "assistant",
                "type": "text",
                "content": content,
            }),
            AgentEvent::ToolCall { name, call_id, args, .. } => json!({
                "ts": Utc::now().to_rfc3339(),
                "session": session_id,
                "role": "assistant",
                "type": "tool_call",
                "tool": name,
                "call_id": call_id,
                "args": args,
            }),
            AgentEvent::ToolResult { name, call_id, result, .. } => json!({
                "ts": Utc::now().to_rfc3339(),
                "session": session_id,
                "role": "tool",
                "tool": name,
                "call_id": call_id,
                "result": result,
            }),
            AgentEvent::Error { message, .. } => json!({
                "ts": Utc::now().to_rfc3339(),
                "session": session_id,
                "role": "system",
                "type": "error",
                "message": message,
            }),
            AgentEvent::PermissionRequest { request_id, tool_name, category, .. } => json!({
                "ts": Utc::now().to_rfc3339(),
                "session": session_id,
                "role": "system",
                "type": "permission_request",
                "request_id": request_id,
                "tool": tool_name,
                "category": category,
            }),
            AgentEvent::PermissionResponse { request_id, allowed, .. } => json!({
                "ts": Utc::now().to_rfc3339(),
                "session": session_id,
                "role": "system",
                "type": "permission_response",
                "request_id": request_id,
                "allowed": allowed,
            }),
            AgentEvent::Done { .. } => return,
        };
        self.write_entry(&entry);
    }

    fn write_entry(&self, entry: &Value) {
        if let Err(e) = self.ensure_file() {
            warn!("Log file error: {}", e);
            return;
        }

        let mut guard = self.file.lock().unwrap();
        if let Some((_, ref mut file)) = *guard {
            let line = serde_json::to_string(entry).unwrap_or_default();
            let _ = writeln!(file, "{}", line);
        }
    }

    pub fn read_logs(&self, date: &str) -> Result<Vec<Value>, String> {
        let path = self.log_dir.join(format!("{}.jsonl", date));
        if !path.exists() {
            return Ok(Vec::new());
        }
        let content = fs::read_to_string(&path).map_err(|e| format!("Read error: {}", e))?;
        let entries: Vec<Value> = content
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        Ok(entries)
    }

    pub fn available_dates(&self) -> Vec<String> {
        let pattern = format!("{}/*.jsonl", self.log_dir.display());
        glob::glob(&pattern)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter_map(|p| {
                p.file_stem()
                    .and_then(|s| s.to_str())
                    .map(String::from)
            })
            .collect()
    }
}
