use chrono::Utc;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::warn;

use crate::agent::AgentEvent;

/// Flush the aggregated text/thinking block once it grows past this many chars,
/// so an abnormal exit mid-stream only ever loses at most one bounded chunk.
const FLUSH_CHARS: usize = 4000;

pub struct ConversationLogger {
    log_dir: PathBuf,
    file: Mutex<Option<(String, std::fs::File)>>,
    // Buffers consecutive streaming deltas (thinking / text) so the JSONL transcript
    // is aggregated into readable blocks instead of one line per token fragment.
    // Keyed by session so concurrent sessions can never mix content into one block.
    pending: Mutex<HashMap<String, PendingBlock>>,
}

/// An in-progress aggregated assistant text/thinking block.
struct PendingBlock {
    kind: &'static str,
    content: String,
    session: String,
    ts: String,
}

fn pending_to_json(p: &PendingBlock) -> Value {
    json!({
        "ts": p.ts,
        "session": p.session,
        "role": "assistant",
        "type": p.kind,
        "content": p.content,
    })
}

impl ConversationLogger {
    pub fn new(log_dir: &str) -> Self {
        let dir = PathBuf::from(log_dir);
        let _ = fs::create_dir_all(&dir);
        Self {
            log_dir: dir,
            file: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
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
        self.flush_pending();
        let entry = json!({
            "ts": Utc::now().to_rfc3339(),
            "session": session_id,
            "role": "user",
            "content": content,
        });
        self.write_entry(&entry);
    }

    pub fn log_event(&self, session_id: &str, event: &AgentEvent) {
        match event {
            // Streaming deltas are buffered and aggregated.
            AgentEvent::Thinking { content, .. } => {
                self.accumulate("thinking", session_id, content);
                return;
            }
            AgentEvent::TextDelta { content, .. } => {
                self.accumulate("text", session_id, content);
                return;
            }
            // Turn boundaries flush whatever text/thinking is still buffered.
            AgentEvent::Done { .. } | AgentEvent::Progress { .. } => {
                self.flush_pending();
                return;
            }
            _ => {}
        }

        // Any non-streaming event delimits a block: write buffered text first.
        self.flush_pending();

        let entry = match event {
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
            AgentEvent::Usage { model, prompt_tokens, completion_tokens, total_tokens, .. } => json!({
                "ts": Utc::now().to_rfc3339(),
                "session": session_id,
                "role": "system",
                "type": "usage",
                "model": model,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
            }),
            _ => return,
        };
        self.write_entry(&entry);
    }

    /// Aggregate a streaming delta into the current text/thinking block for the
    /// given session. When the block type switches (thinking -> text or vice
    /// versa) the previous block is flushed as a single aggregated JSON entry.
    /// Blocks are additionally flushed once they exceed `FLUSH_CHARS` to bound
    /// any loss on abnormal exit. Blocks are keyed by session so concurrent
    /// sessions never mix content into one block.
    fn accumulate(&self, kind: &'static str, session_id: &str, content: &str) {
        let session = session_id.to_string();
        let mut to_write: Vec<PendingBlock> = Vec::new();
        {
            let mut map = self.pending.lock().unwrap();
            // Pull this session's buffered block out (if any) so we can either
            // extend it in place or flush it on a kind switch.
            match map.remove(&session) {
                // Same kind: extend the existing block.
                Some(mut p) if p.kind == kind => {
                    p.content.push_str(content);
                    if p.content.chars().count() >= FLUSH_CHARS {
                        // Flush this block; the next delta starts a fresh one.
                        to_write.push(p);
                    } else {
                        map.insert(session.clone(), p);
                    }
                }
                // Kind switch (thinking -> text or vice versa): flush the old
                // block and begin a new one for this same session.
                Some(p) => {
                    to_write.push(p);
                    map.insert(session.clone(), PendingBlock {
                        kind,
                        content: content.to_string(),
                        session: session.clone(),
                        ts: Utc::now().to_rfc3339(),
                    });
                }
                // No buffered block for this session yet: start one.
                None => {
                    map.insert(session.clone(), PendingBlock {
                        kind,
                        content: content.to_string(),
                        session: session.clone(),
                        ts: Utc::now().to_rfc3339(),
                    });
                }
            }
        }
        for p in to_write {
            self.write_entry(&pending_to_json(&p));
        }
    }

    /// Write any buffered text/thinking blocks (all sessions) as aggregated entries.
    fn flush_pending(&self) {
        let all: Vec<PendingBlock> = {
            let mut map = self.pending.lock().unwrap();
            map.drain().map(|(_k, p)| p).collect()
        };
        for p in all {
            self.write_entry(&pending_to_json(&p));
        }
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

impl Drop for ConversationLogger {
    fn drop(&mut self) {
        // Best-effort flush of any buffered block on graceful teardown.
        self.flush_pending();
    }
}