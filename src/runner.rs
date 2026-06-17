//! Runner — separates orchestration from the agent loop.
//! Modeled after ADK-RUST's Runner which handles session management,
//! plugin hooks, and agent dispatch.

use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;
use tracing::info;

use crate::agent::{Agent, EventStream};
use crate::context::{InvocationContext, ReadonlyContext};
use crate::error::{AgentError, AgentResult};
use crate::log::ConversationLogger;
use crate::model::ChatMessage;
use crate::permission::PendingMap;
use crate::session::{InMemorySessionService, SessionService};

/// The Runner is the outer orchestration runtime.
/// It manages sessions, builds context, dispatches to the agent, and persists events.
/// Modeled after ADK-RUST's Runner.
pub struct Runner {
    agent: Arc<dyn Agent>,
    session_service: Arc<dyn SessionService>,
    logger: Arc<ConversationLogger>,
    app_name: String,
}

/// Builder for Runner (modeled after ADK-RUST's RunnerConfig builder).
pub struct RunnerBuilder {
    agent: Option<Arc<dyn Agent>>,
    session_service: Option<Arc<dyn SessionService>>,
    logger: Option<Arc<ConversationLogger>>,
    app_name: String,
}

impl RunnerBuilder {
    pub fn new() -> Self {
        Self {
            agent: None,
            session_service: None,
            logger: None,
            app_name: "rust-agent".to_string(),
        }
    }

    pub fn agent(mut self, agent: Arc<dyn Agent>) -> Self {
        self.agent = Some(agent);
        self
    }

    pub fn session_service(mut self, service: Arc<dyn SessionService>) -> Self {
        self.session_service = Some(service);
        self
    }

    pub fn logger(mut self, logger: Arc<ConversationLogger>) -> Self {
        self.logger = Some(logger);
        self
    }

    pub fn app_name(mut self, name: &str) -> Self {
        self.app_name = name.to_string();
        self
    }

    pub fn build(self) -> AgentResult<Runner> {
        let agent = self.agent.ok_or_else(|| AgentError::config("Runner requires an agent"))?;
        let session_service = self.session_service
            .unwrap_or_else(|| Arc::new(InMemorySessionService::new()));
        let logger = self.logger
            .ok_or_else(|| AgentError::config("Runner requires a logger"))?;

        Ok(Runner {
            agent,
            session_service,
            logger,
            app_name: self.app_name,
        })
    }
}

impl Runner {
    pub fn builder() -> RunnerBuilder {
        RunnerBuilder::new()
    }

    /// Run the agent for a given user message and return the event stream.
    /// The runner handles session creation, context building, and event persistence.
    pub async fn run(
        &self,
        user_message: &str,
        session_id: &str,
        model_name: &str,
        max_iterations: usize,
        history: Vec<ChatMessage>,
        permissions: Arc<Mutex<HashMap<String, bool>>>,
        permission_pending: PendingMap,
    ) -> AgentResult<EventStream> {
        info!("Runner dispatching to agent '{}' (session: {})", self.agent.name(), session_id);

        // Build invocation context
        let invocation_id = uuid::Uuid::new_v4().to_string();
        let base_ctx = ReadonlyContext::new(
            invocation_id,
            self.agent.name().to_string(),
            session_id.to_string(),
        );
        let ctx = InvocationContext::new(
            base_ctx,
            self.agent.name().to_string(),
            model_name.to_string(),
            max_iterations,
        ).with_history(history)
         .with_permissions(permissions)
         .with_permission_pending(permission_pending);

        // Log user message
        self.logger.log_user_message(session_id, user_message);

        // Dispatch to agent
        let event_stream = self.agent.run(&ctx, user_message).await?;

        // Wrap the stream to log events
        let logger = self.logger.clone();
        let sid = session_id.to_string();
        let wrapped_stream = async_stream::stream! {
            tokio::pin!(event_stream);
            while let Some(result) = event_stream.next().await {
                match &result {
                    Ok(event) => {
                        logger.log_event(&sid, event);
                    }
                    Err(e) => {
                        tracing::warn!("Event stream error: {}", e);
                    }
                }
                yield result;
            }
        };

        Ok(Box::pin(wrapped_stream))
    }

    pub fn agent(&self) -> &dyn Agent {
        self.agent.as_ref()
    }

    pub fn session_service(&self) -> &dyn SessionService {
        self.session_service.as_ref()
    }
}

use futures::StreamExt;
