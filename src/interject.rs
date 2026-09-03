//! Mid-run interjection & follow-up queue.
//!
//! Two independent per-session channels:
//! - **pending follow-ups** (default): messages the user sends while a task is
//!   running. They are NOT injected into the running task. They are held here
//!   and dispatched by the server as the *next* task(s) after the current one
//!   completes (FIFO). The running agent loop never drains this channel.
//! - **insert-now** (explicit button): messages the user chose to inject into
//!   the *current* running task as supplementary context. Only this channel is
//!   drained by the agent loop, so the running LLM sees them as the next user
//!   turns.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

type Queue = Arc<Mutex<HashMap<String, VecDeque<String>>>>;

fn pending() -> &'static Queue {
    static Q: OnceLock<Queue> = OnceLock::new();
    Q.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

fn insert_channel() -> &'static Queue {
    static Q: OnceLock<Queue> = OnceLock::new();
    Q.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

/// Queue a follow-up task to run after the current task finishes (default
/// path when the user does not press "insert"). Synchronous and non-blocking.
pub fn push_pending(session_id: &str, content: String) {
    pending()
        .lock()
        .unwrap()
        .entry(session_id.to_string())
        .or_default()
        .push_back(content);
}

/// Pop the next queued follow-up for a session (FIFO). Returns `None` when the
/// queue is empty. The server dispatches these as sequential tasks after the
/// current run completes.
pub fn pop_pending(session_id: &str) -> Option<String> {
    let mut q = pending().lock().unwrap();
    let entry = q.get_mut(session_id)?;
    let item = entry.pop_front();
    if entry.is_empty() {
        q.remove(session_id);
    }
    item
}

/// Inject a message into the CURRENT running task (explicit "insert" button).
/// Picked up by the agent loop on its next iteration.
pub fn push_insert(session_id: &str, content: String) {
    insert_channel()
        .lock()
        .unwrap()
        .entry(session_id.to_string())
        .or_default()
        .push_back(content);
}

/// Drain all insert-now messages for a session (FIFO). Called by the agent
/// loop at the start of each iteration so the running LLM sees them as the
/// next user turns.
pub fn drain_insert(session_id: &str) -> Vec<String> {
    insert_channel()
        .lock()
        .unwrap()
        .remove(session_id)
        .map(|q| q.into_iter().collect())
        .unwrap_or_default()
}


#[cfg(test)]
mod tests {
    use super::*;

    // Queued follow-ups pop in FIFO order and the queue empties.
    #[test]
    fn pending_queue_is_fifo_and_empties() {
        let sid = "test-pending-1";
        for m in ["task-a", "task-b", "task-c"] {
            push_pending(sid, m.to_string());
        }
        assert_eq!(pop_pending(sid).as_deref(), Some("task-a"));
        assert_eq!(pop_pending(sid).as_deref(), Some("task-b"));
        assert_eq!(pop_pending(sid).as_deref(), Some("task-c"));
        assert_eq!(pop_pending(sid), None);
        assert_eq!(pop_pending(sid), None, "empty queue keeps returning None");
    }

    // Insert-now messages drain in FIFO order.
    #[test]
    fn insert_channel_drains_fifo() {
        let sid = "test-insert-1";
        push_insert(sid, "ctx-1".to_string());
        push_insert(sid, "ctx-2".to_string());
        let drained = drain_insert(sid);
        assert_eq!(drained, vec!["ctx-1".to_string(), "ctx-2".to_string()]);
        assert!(drain_insert(sid).is_empty(), "after drain the insert channel is empty");
    }

    // The two channels are isolated: a pending follow-up is NOT visible to the
    // insert drain and vice versa (running loop must never see pending items).
    #[test]
    fn channels_are_isolated() {
        let sid = "test-iso-1";
        push_pending(sid, "follow-up".to_string());
        push_insert(sid, "insert-now".to_string());
        let drained = drain_insert(sid);
        assert_eq!(drained, vec!["insert-now".to_string()]);
        assert!(drain_insert(sid).is_empty());
        // The pending follow-up is untouched by draining inserts.
        assert_eq!(pop_pending(sid).as_deref(), Some("follow-up"));
        assert_eq!(pop_pending(sid), None);
    }
}
