//! Callback hooks system inspired by ADK-RUST's layered callback architecture.
//!
//! Supports before/after hooks at model, tool, and agent boundaries.

use std::sync::Arc;

use crate::context::CallbackContext;
use crate::error::AgentResult;
use crate::model::{LlmRequest, LlmResponse};

/// Result of a callback — either continue or short-circuit with a response.
pub enum CallbackResult<T> {
    /// Continue with possibly-modified value.
    Continue(T),
    /// Short-circuit: skip the next step and use this value instead.
    Override(T),
}

// --- Model Callbacks ---

/// Called before sending request to the LLM.
/// Can modify the request or short-circuit with a fake response.
#[async_trait::async_trait]
pub trait BeforeModelCallback: Send + Sync {
    async fn call(
        &self,
        ctx: &CallbackContext,
        request: &mut LlmRequest,
    ) -> AgentResult<CallbackResult<()>>;
}

/// Called after receiving a response chunk from the LLM.
#[async_trait::async_trait]
pub trait AfterModelCallback: Send + Sync {
    async fn call(
        &self,
        ctx: &CallbackContext,
        response: &LlmResponse,
    ) -> AgentResult<()>;
}

// --- Tool Callbacks ---

/// Called before executing a tool.
/// Can modify args or short-circuit with a fake result.
#[async_trait::async_trait]
pub trait BeforeToolCallback: Send + Sync {
    async fn call(
        &self,
        ctx: &CallbackContext,
        tool_name: &str,
        args: &mut serde_json::Value,
    ) -> AgentResult<CallbackResult<serde_json::Value>>;
}

/// Called after a tool executes successfully.
#[async_trait::async_trait]
pub trait AfterToolCallback: Send + Sync {
    async fn call(
        &self,
        ctx: &CallbackContext,
        tool_name: &str,
        args: &serde_json::Value,
        result: &serde_json::Value,
    ) -> AgentResult<()>;
}

/// Called when a tool execution fails.
#[async_trait::async_trait]
pub trait OnToolErrorCallback: Send + Sync {
    async fn call(
        &self,
        ctx: &CallbackContext,
        tool_name: &str,
        error: &crate::error::AgentError,
    ) -> AgentResult<()>;
}

// --- Agent Callbacks ---

/// Called before the agent starts its loop.
#[async_trait::async_trait]
pub trait BeforeAgentCallback: Send + Sync {
    async fn call(&self, ctx: &CallbackContext) -> AgentResult<()>;
}

/// Called after the agent completes its loop.
#[async_trait::async_trait]
pub trait AfterAgentCallback: Send + Sync {
    async fn call(&self, ctx: &CallbackContext) -> AgentResult<()>;
}

/// Container for all callback hooks on an agent.
/// Modeled after ADK-RUST's layered callback system.
#[derive(Default, Clone)]
pub struct AgentCallbacks {
    pub before_agent: Vec<Arc<dyn BeforeAgentCallback>>,
    pub after_agent: Vec<Arc<dyn AfterAgentCallback>>,
    pub before_model: Vec<Arc<dyn BeforeModelCallback>>,
    pub after_model: Vec<Arc<dyn AfterModelCallback>>,
    pub before_tool: Vec<Arc<dyn BeforeToolCallback>>,
    pub after_tool: Vec<Arc<dyn AfterToolCallback>>,
    pub on_tool_error: Vec<Arc<dyn OnToolErrorCallback>>,
}

impl AgentCallbacks {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_before_model(mut self, cb: Arc<dyn BeforeModelCallback>) -> Self {
        self.before_model.push(cb);
        self
    }

    pub fn with_after_model(mut self, cb: Arc<dyn AfterModelCallback>) -> Self {
        self.after_model.push(cb);
        self
    }

    pub fn with_before_tool(mut self, cb: Arc<dyn BeforeToolCallback>) -> Self {
        self.before_tool.push(cb);
        self
    }

    pub fn with_after_tool(mut self, cb: Arc<dyn AfterToolCallback>) -> Self {
        self.after_tool.push(cb);
        self
    }

    pub fn with_on_tool_error(mut self, cb: Arc<dyn OnToolErrorCallback>) -> Self {
        self.on_tool_error.push(cb);
        self
    }

    pub fn with_before_agent(mut self, cb: Arc<dyn BeforeAgentCallback>) -> Self {
        self.before_agent.push(cb);
        self
    }

    pub fn with_after_agent(mut self, cb: Arc<dyn AfterAgentCallback>) -> Self {
        self.after_agent.push(cb);
        self
    }
}
