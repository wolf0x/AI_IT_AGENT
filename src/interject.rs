//! Mid-run interjection queue.
//!
//! Lets the user inject a message into a *running* main-session turn without
//! stopping it. Messages are keyed by session_id so the queue works
//! independently per session. The server pushes user interjections here, and
//! the agent loop drains them at the start of each iteration so the running
//! LLM sees them as the next user turn (fed into history).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

type Queue = Arc<Mutex<HashMap<String, VecDeque<String>>>>;

fn global() -> &'static Queue {
    static Q: OnceLock<Queue> = OnceLock::new();
    Q.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

/// Queue an interjection for a running session. Synchronous and non-blocking.
/// The agent loop will pick it up on its next iteration.
pub fn push(session_id: &str, content: String) {
    global()
        .lock()
        .unwrap()
        .entry(session_id.to_string())
        .or_default()
        .push_back(content);
}

/// Drain all pending interjections for a session (FIFO).
pub fn drain(session_id: &str) -> Vec<String> {
    global()
        .lock()
        .unwrap()
        .remove(session_id)
        .map(|q| q.into_iter().collect())
        .unwrap_or_default()
}
