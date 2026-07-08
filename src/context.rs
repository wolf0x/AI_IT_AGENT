//! Context hierarchy inspired by ADK-RUST.
//!
//! Provides identity and environment data that flows through the agent execution pipeline.
//!
//! Hierarchy: ReadonlyContext → CallbackContext → ToolContext
//!            ReadonlyContext → InvocationContext

use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::model::ChatMessage;
use crate::permission::PendingMap;
use crate::checkpoint::ATaskCheckpointer;

/// Base identity context — immutable, passed through the entire pipeline.
/// Modeled after ADK-RUST's ReadonlyContext.
#[derive(Debug, Clone)]
pub struct ReadonlyContext {
    pub invocation_id: String,
    pub agent_name: String,
    pub session_id: String,
    pub created_at: DateTime<Utc>,
}

impl ReadonlyContext {
    pub fn new(invocation_id: String, agent_name: String, session_id: String) -> Self {
        Self {
            invocation_id,
            agent_name,
            session_id,
            created_at: Utc::now(),
        }
    }
}

/// Extended context for callbacks — adds mutable shared state.
/// Modeled after ADK-RUST's CallbackContext.
#[derive(Debug, Clone)]
pub struct CallbackContext {
    pub base: ReadonlyContext,
    pub shared_state: HashMap<String, Value>,
}

impl CallbackContext {
    pub fn new(base: ReadonlyContext) -> Self {
        Self {
            base,
            shared_state: HashMap::new(),
        }
    }

    pub fn get_state(&self, key: &str) -> Option<&Value> {
        self.shared_state.get(key)
    }

    pub fn set_state(&mut self, key: String, value: Value) {
        self.shared_state.insert(key, value);
    }
}

/// Context passed to tool execution.
/// Modeled after ADK-RUST's ToolContext.
#[derive(Debug, Clone)]
pub struct ToolContext {
    pub base: CallbackContext,
    pub function_call_id: String,
    pub working_dir: String,
}

impl ToolContext {
    pub fn new(base: CallbackContext, function_call_id: String, working_dir: String) -> Self {
        Self {
            base,
            function_call_id,
            working_dir,
        }
    }

    /// Create a minimal ToolContext for simple use cases.
    pub fn simple(working_dir: String) -> Self {
        let ctx = ReadonlyContext::new(
            String::new(),
            String::new(),
            String::new(),
        );
        let cb_ctx = CallbackContext::new(ctx);
        Self {
            base: cb_ctx,
            function_call_id: String::new(),
            working_dir,
        }
    }
}

/// Context for an entire agent invocation.
/// Modeled after ADK-RUST's InvocationContext.
#[derive(Debug)]
pub struct InvocationContext {
    pub base: ReadonlyContext,
    pub agent_name: String,
    pub model_name: String,
    pub fallback_model: Option<String>,
    pub max_iterations: usize,
    pub rabbit_hole_threshold: usize,
    /// Model context window size in tokens
    pub context_window: usize,
    /// Context usage threshold percentage (e.g. 80 = trim at 80%)
    pub context_window_threshold: usize,
    /// Tool execution timeout in seconds
    pub tool_timeout_secs: u64,
    pub conversation_history: Vec<ChatMessage>,
    pub shared_state: HashMap<String, Value>,
    /// Permission settings (category -> allowed)
    pub permissions: Arc<Mutex<HashMap<String, bool>>>,
    /// Shared pending map for permission requests
    pub permission_pending: PendingMap,
    /// History restored from a checkpoint (resume mode — skips adding user message).
    pub resume_history: Option<Vec<ChatMessage>>,
    /// Starting iteration when resuming from a checkpoint.
    pub resume_iteration: Option<usize>,
    /// Checkpoint ID for save/delete operations during this invocation.
    pub checkpoint_id: Option<String>,
    /// Checkpointer for persisting task state.
    pub checkpointer: Option<ATaskCheckpointer>,
    ended: Arc<AtomicBool>,
}

impl InvocationContext {
    pub fn new(
        base: ReadonlyContext,
        agent_name: String,
        model_name: String,
        max_iterations: usize,
    ) -> Self {
        let (resolver, pending) = crate::permission::PermissionResolver::new();
        let _ = resolver; // resolver is used by server, stored separately
        Self {
            base,
            agent_name,
            model_name,
            fallback_model: None,
            max_iterations,
            rabbit_hole_threshold: 5,
            context_window: 128000,
            context_window_threshold: 80,
            tool_timeout_secs: 300,
            conversation_history: Vec::new(),
            shared_state: HashMap::new(),
            permissions: Arc::new(Mutex::new(crate::permission::default_permissions())),
            permission_pending: pending,
            resume_history: None,
            resume_iteration: None,
            checkpoint_id: None,
            checkpointer: None,
            ended: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Set permissions for tool execution.
    pub fn with_permissions(mut self, permissions: Arc<Mutex<HashMap<String, bool>>>) -> Self {
        self.permissions = permissions;
        self
    }

    /// Set the shared pending map for permission resolution.
    pub fn with_permission_pending(mut self, pending: PendingMap) -> Self {
        self.permission_pending = pending;
        self
    }

    /// Set conversation history for multi-turn context.
    pub fn with_history(mut self, history: Vec<ChatMessage>) -> Self {
        self.conversation_history = history;
        self
    }

    /// Set fallback model name.
    pub fn with_fallback_model(mut self, model: Option<String>) -> Self {
        self.fallback_model = model;
        self
    }

    /// Set rabbit hole detection threshold.
    pub fn with_rabbit_hole_threshold(mut self, threshold: usize) -> Self {
        self.rabbit_hole_threshold = threshold;
        self
    }

    /// Set context window size in tokens.
    pub fn with_context_window(mut self, tokens: usize) -> Self {
        self.context_window = tokens;
        self
    }

    /// Set context window usage threshold percentage.
    pub fn with_context_window_threshold(mut self, percent: usize) -> Self {
        self.context_window_threshold = percent;
        self
    }

    /// Set tool execution timeout in seconds.
    pub fn with_tool_timeout_secs(mut self, secs: u64) -> Self {
        self.tool_timeout_secs = secs;
        self
    }

    /// Set resume state from a checkpoint (history + starting iteration).
    pub fn with_resume_state(mut self, history: Vec<ChatMessage>, start_iteration: usize) -> Self {
        self.resume_history = Some(history);
        self.resume_iteration = Some(start_iteration);
        self
    }

    /// Set the checkpoint ID for this invocation.
    pub fn with_checkpoint_id(mut self, id: String) -> Self {
        self.checkpoint_id = Some(id);
        self
    }

    /// Set the checkpointer for persisting task state.
    pub fn with_checkpointer(mut self, cp: ATaskCheckpointer) -> Self {
        self.checkpointer = Some(cp);
        self
    }

    /// Signal that the invocation should end (e.g., ExitLoopTool called).
    pub fn end_invocation(&self) {
        self.ended.store(true, Ordering::SeqCst);
    }

    /// Check if the invocation has been signaled to end.
    pub fn is_ended(&self) -> bool {
        self.ended.load(Ordering::SeqCst)
    }
}
