//! Session management inspired by ADK-RUST's SessionService trait.
//!
//! Provides session persistence with InMemory backend.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::{AgentError, AgentResult};
use crate::model::ChatMessage;

/// A single session representing a conversation.
/// Modeled after ADK-RUST's Session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub app_name: String,
    pub user_id: String,
    pub state: HashMap<String, Value>,
    pub conversation_history: Vec<ChatMessage>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Session {
    pub fn new(id: String, app_name: String, user_id: String) -> Self {
        let now = Utc::now();
        Self {
            id,
            app_name,
            user_id,
            state: HashMap::new(),
            conversation_history: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Append a message to conversation history.
    pub fn append_message(&mut self, message: ChatMessage) {
        self.conversation_history.push(message);
        self.updated_at = Utc::now();
    }

    /// Get conversation history (full or truncated).
    pub fn conversation_history(&self, max_events: Option<usize>) -> &[ChatMessage] {
        match max_events {
            Some(max) if max < self.conversation_history.len() => {
                &self.conversation_history[self.conversation_history.len() - max..]
            }
            _ => &self.conversation_history,
        }
    }

    /// Get a state value.
    pub fn get_state(&self, key: &str) -> Option<&Value> {
        self.state.get(key)
    }

    /// Set a state value.
    pub fn set_state(&mut self, key: String, value: Value) {
        self.state.insert(key, value);
        self.updated_at = Utc::now();
    }
}

/// Session service trait — manages session lifecycle.
/// Modeled after ADK-RUST's SessionService trait.
pub trait SessionService: Send + Sync {
    fn create(&self, app_name: &str, user_id: &str) -> AgentResult<Session>;
    fn get(&self, session_id: &str) -> AgentResult<Session>;
    fn list(&self, app_name: &str, user_id: &str) -> AgentResult<Vec<Session>>;
    fn delete(&self, session_id: &str) -> AgentResult<()>;
    fn append_message(&self, session_id: &str, message: ChatMessage) -> AgentResult<()>;
}

/// In-memory session service — sessions live in RAM, lost on restart.
/// Modeled after ADK-RUST's InMemorySessionService.
pub struct InMemorySessionService {
    sessions: Mutex<HashMap<String, Session>>,
}

impl InMemorySessionService {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemorySessionService {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionService for InMemorySessionService {
    fn create(&self, app_name: &str, user_id: &str) -> AgentResult<Session> {
        let id = uuid::Uuid::new_v4().to_string();
        let session = Session::new(id, app_name.to_string(), user_id.to_string());
        let mut sessions = self.sessions.lock().map_err(|e| AgentError::session(format!("Lock: {}", e)))?;
        sessions.insert(session.id.clone(), session.clone());
        Ok(session)
    }

    fn get(&self, session_id: &str) -> AgentResult<Session> {
        let sessions = self.sessions.lock().map_err(|e| AgentError::session(format!("Lock: {}", e)))?;
        sessions.get(session_id).cloned().ok_or_else(|| AgentError::not_found(
            crate::error::ErrorComponent::Session,
            format!("Session '{}' not found", session_id),
        ))
    }

    fn list(&self, app_name: &str, user_id: &str) -> AgentResult<Vec<Session>> {
        let sessions = self.sessions.lock().map_err(|e| AgentError::session(format!("Lock: {}", e)))?;
        Ok(sessions.values()
            .filter(|s| s.app_name == app_name && s.user_id == user_id)
            .cloned()
            .collect())
    }

    fn delete(&self, session_id: &str) -> AgentResult<()> {
        let mut sessions = self.sessions.lock().map_err(|e| AgentError::session(format!("Lock: {}", e)))?;
        sessions.remove(session_id);
        Ok(())
    }

    fn append_message(&self, session_id: &str, message: ChatMessage) -> AgentResult<()> {
        let mut sessions = self.sessions.lock().map_err(|e| AgentError::session(format!("Lock: {}", e)))?;
        let session = sessions.get_mut(session_id).ok_or_else(|| AgentError::not_found(
            crate::error::ErrorComponent::Session,
            format!("Session '{}' not found", session_id),
        ))?;
        session.append_message(message);
        Ok(())
    }
}
