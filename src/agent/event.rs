//! Event system with metadata, inspired by ADK-RUST's Event structure.
//!
//! Events flow from agent → runner → server → client.
//! Each event carries identity metadata (id, timestamp, author, invocation_id).

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

/// A single event in the agent pipeline, carrying metadata.
/// Modeled after ADK-RUST's Event struct with id, timestamp, author, invocation_id.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
#[allow(dead_code)]
pub enum AgentEvent {
    #[serde(rename = "thinking")]
    Thinking {
        #[serde(flatten)]
        meta: EventMeta,
        content: String,
    },

    #[serde(rename = "text")]
    TextDelta {
        #[serde(flatten)]
        meta: EventMeta,
        content: String,
    },

    #[serde(rename = "tool_call")]
    ToolCall {
        #[serde(flatten)]
        meta: EventMeta,
        name: String,
        #[serde(rename = "call_id")]
        call_id: String,
        args: Value,
    },

    #[serde(rename = "tool_result")]
    ToolResult {
        #[serde(flatten)]
        meta: EventMeta,
        name: String,
        #[serde(rename = "call_id")]
        call_id: String,
        result: Value,
    },

    /// Heartbeat / progress event sent during long-running tool execution.
    #[serde(rename = "progress")]
    Progress {
        #[serde(flatten)]
        meta: EventMeta,
        /// Name of the tool being executed
        tool_name: String,
        /// Human-readable status message
        message: String,
        /// Seconds elapsed since tool execution started
        elapsed_secs: u64,
    },

    #[serde(rename = "error")]
    Error {
        #[serde(flatten)]
        meta: EventMeta,
        message: String,
    },

    #[serde(rename = "permission_request")]
    PermissionRequest {
        #[serde(flatten)]
        meta: EventMeta,
        request_id: String,
        tool_name: String,
        category: String,
        args: Value,
    },

    #[serde(rename = "permission_response")]
    PermissionResponse {
        #[serde(flatten)]
        meta: EventMeta,
        request_id: String,
        allowed: bool,
    },

    #[serde(rename = "done")]
    Done {
        #[serde(flatten)]
        meta: EventMeta,
    },
}

/// Event metadata — identity, timing, and provenance.
/// Modeled after ADK-RUST's Event fields.
#[derive(Debug, Clone, Serialize)]
pub struct EventMeta {
    /// Unique event ID (UUID v4).
    pub id: String,
    /// When the event was created.
    pub timestamp: DateTime<Utc>,
    /// The invocation this event belongs to.
    pub invocation_id: String,
    /// Who authored this event (agent name or "user").
    pub author: String,
}

impl EventMeta {
    pub fn new(invocation_id: &str, author: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            invocation_id: invocation_id.to_string(),
            author: author.to_string(),
        }
    }

    /// Create a minimal meta (for simple/internal events).
    pub fn minimal() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            invocation_id: String::new(),
            author: "system".to_string(),
        }
    }
}

impl AgentEvent {
    // --- Serialization ---

    pub fn to_ws_message(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    // --- Convenience constructors ---

    pub fn thinking(content: &str, invocation_id: &str, author: &str) -> Self {
        AgentEvent::Thinking {
            meta: EventMeta::new(invocation_id, author),
            content: content.to_string(),
        }
    }

    pub fn text(content: &str, invocation_id: &str, author: &str) -> Self {
        AgentEvent::TextDelta {
            meta: EventMeta::new(invocation_id, author),
            content: content.to_string(),
        }
    }

    pub fn tool_call(name: &str, call_id: &str, args: Value, invocation_id: &str, author: &str) -> Self {
        AgentEvent::ToolCall {
            meta: EventMeta::new(invocation_id, author),
            name: name.to_string(),
            call_id: call_id.to_string(),
            args,
        }
    }

    pub fn tool_result(name: &str, call_id: &str, result: Value, invocation_id: &str, author: &str) -> Self {
        AgentEvent::ToolResult {
            meta: EventMeta::new(invocation_id, author),
            name: name.to_string(),
            call_id: call_id.to_string(),
            result,
        }
    }

    pub fn progress(tool_name: &str, message: &str, elapsed_secs: u64, invocation_id: &str, author: &str) -> Self {
        AgentEvent::Progress {
            meta: EventMeta::new(invocation_id, author),
            tool_name: tool_name.to_string(),
            message: message.to_string(),
            elapsed_secs,
        }
    }

    pub fn error(message: &str, invocation_id: &str, author: &str) -> Self {
        AgentEvent::Error {
            meta: EventMeta::new(invocation_id, author),
            message: message.to_string(),
        }
    }

    pub fn permission_request(request_id: &str, tool_name: &str, category: &str, args: Value, invocation_id: &str, author: &str) -> Self {
        AgentEvent::PermissionRequest {
            meta: EventMeta::new(invocation_id, author),
            request_id: request_id.to_string(),
            tool_name: tool_name.to_string(),
            category: category.to_string(),
            args,
        }
    }

    pub fn permission_response(request_id: &str, allowed: bool, invocation_id: &str, author: &str) -> Self {
        AgentEvent::PermissionResponse {
            meta: EventMeta::new(invocation_id, author),
            request_id: request_id.to_string(),
            allowed,
        }
    }

    pub fn done(invocation_id: &str, author: &str) -> Self {
        AgentEvent::Done {
            meta: EventMeta::new(invocation_id, author),
        }
    }

    // --- Getters ---

    pub fn meta(&self) -> &EventMeta {
        match self {
            Self::Thinking { meta, .. }
            | Self::TextDelta { meta, .. }
            | Self::ToolCall { meta, .. }
            | Self::ToolResult { meta, .. }
            | Self::Progress { meta, .. }
            | Self::Error { meta, .. }
            | Self::PermissionRequest { meta, .. }
            | Self::PermissionResponse { meta, .. }
            | Self::Done { meta } => meta,
        }
    }

    pub fn is_done(&self) -> bool {
        match self {
            Self::Done { .. } => true,
            _ => false,
        }
    }

    /// Get the text content if this is a TextDelta event.
    pub fn text_content(&self) -> Option<&str> {
        match self {
            Self::TextDelta { content, .. } => Some(content.as_str()),
            _ => None,
        }
    }
}
