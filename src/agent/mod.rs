pub mod event;
pub mod llm_agent;

pub use event::AgentEvent;
pub use llm_agent::LlmAgent;

use async_trait::async_trait;
use futures::Stream;
use std::pin::Pin;
use std::sync::Arc;

use crate::context::InvocationContext;
use crate::error::AgentResult;

/// Event stream returned by agents — the core streaming interface.
/// Modeled after ADK-RUST's EventStream type.
pub type EventStream = Pin<Box<dyn Stream<Item = AgentResult<AgentEvent>> + Send>>;

/// The Agent trait — core abstraction for all agent types.
/// Modeled after ADK-RUST's Agent trait.
///
/// All agents (LLM-powered, custom, workflow) implement this single trait.
/// The runtime calls `run()` and consumes the returned `EventStream`.
#[async_trait]
pub trait Agent: Send + Sync {
    /// Agent name (unique identifier).
    fn name(&self) -> &str;

    /// Human-readable description of what this agent does.
    fn description(&self) -> &str;

    /// Sub-agents that this agent can delegate to.
    fn sub_agents(&self) -> &[Arc<dyn Agent>] {
        &[]
    }

    /// Run the agent and return a stream of events.
    /// The agent loop runs inside this method, producing events as it goes.
    /// `images` is a list of base64 data URIs or URLs for multi-modal input.
    async fn run(&self, ctx: &InvocationContext, user_message: &str, images: Vec<String>) -> AgentResult<EventStream>;
}
