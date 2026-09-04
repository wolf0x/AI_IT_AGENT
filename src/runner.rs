//! Runner — separates orchestration from the agent loop.
//! Modeled after ADK-RUST's Runner which handles session management,
//! plugin hooks, and agent dispatch.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::collections::HashMap;
use tokio::sync::Mutex;
use tracing::info;

use crate::agent::{Agent, EventStream};
use crate::checkpoint::ATaskCheckpointer;
use crate::context::{InvocationContext, ReadonlyContext};
use crate::error::{AgentError, AgentResult};
use crate::log::ConversationLogger;
use crate::model::ChatMessage;
use crate::permission::PendingMap;
use crate::managed::permission_profile::PermissionProfile;
use crate::session::{InMemorySessionService, SessionService};

/// State restored from a checkpoint for resuming an interrupted task.
pub struct ResumeState {
    pub history: Vec<ChatMessage>,
    pub start_iteration: usize,
}

/// The Runner is the outer orchestration runtime.
/// It manages sessions, builds context, dispatches to the agent, and persists events.
/// Modeled after ADK-RUST's Runner.
pub struct Runner {
    agent: Arc<dyn Agent>,
    session_service: Arc<dyn SessionService>,
    logger: Arc<ConversationLogger>,
    app_name: String,
    checkpointer: Option<ATaskCheckpointer>,
    trim_redundant_tool_calls: Arc<AtomicBool>,
    knowledge_pre_retrieval: Arc<AtomicBool>,
    enable_context_scaling: Arc<AtomicBool>,
    max_inline_chars: Arc<AtomicUsize>,
    skill_listing_strategy: Arc<AtomicUsize>,
    skill_max_inline_chars: Arc<AtomicUsize>,
    skill_catalog_max: Arc<AtomicUsize>,
    skill_hot_top_k: Arc<AtomicUsize>,
}

/// Builder for Runner (modeled after ADK-RUST's RunnerConfig builder).
pub struct RunnerBuilder {
    agent: Option<Arc<dyn Agent>>,
    session_service: Option<Arc<dyn SessionService>>,
    logger: Option<Arc<ConversationLogger>>,
    app_name: String,
    checkpointer: Option<ATaskCheckpointer>,
    knowledge_pre_retrieval: Arc<AtomicBool>,
    trim_redundant_tool_calls: Arc<AtomicBool>,
    enable_context_scaling: Arc<AtomicBool>,
    max_inline_chars: Arc<AtomicUsize>,
    skill_listing_strategy: Arc<AtomicUsize>,
    skill_max_inline_chars: Arc<AtomicUsize>,
    skill_catalog_max: Arc<AtomicUsize>,
    skill_hot_top_k: Arc<AtomicUsize>,
}

impl RunnerBuilder {
    pub fn new() -> Self {
        Self {
            agent: None,
            session_service: None,
            logger: None,
            app_name: "RustAgent".to_string(),
            checkpointer: None,
            trim_redundant_tool_calls: Arc::new(AtomicBool::new(true)),
            knowledge_pre_retrieval: Arc::new(AtomicBool::new(true)),
            enable_context_scaling: Arc::new(AtomicBool::new(true)),
            max_inline_chars: Arc::new(AtomicUsize::new(120_000)),
            skill_listing_strategy: Arc::new(AtomicUsize::new(0)),
            skill_max_inline_chars: Arc::new(AtomicUsize::new(6000)),
            skill_catalog_max: Arc::new(AtomicUsize::new(40)),
            skill_hot_top_k: Arc::new(AtomicUsize::new(3)),
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

    pub fn checkpointer(mut self, cp: ATaskCheckpointer) -> Self {
        self.checkpointer = Some(cp);
        self
    }

    pub fn trim_redundant_tool_calls(mut self, v: Arc<AtomicBool>) -> Self {
        self.trim_redundant_tool_calls = v;
        self
    }

    pub fn knowledge_pre_retrieval(mut self, v: Arc<AtomicBool>) -> Self {
        self.knowledge_pre_retrieval = v;
        self
    }

    pub fn enable_context_scaling(mut self, v: Arc<AtomicBool>) -> Self {
        self.enable_context_scaling = v;
        self
    }

    pub fn max_inline_chars(mut self, v: Arc<AtomicUsize>) -> Self {
        self.max_inline_chars = v;
        self
    }

    pub fn skill_listing_strategy(mut self, v: Arc<AtomicUsize>) -> Self {
        self.skill_listing_strategy = v;
        self
    }

    pub fn skill_max_inline_chars(mut self, v: Arc<AtomicUsize>) -> Self {
        self.skill_max_inline_chars = v;
        self
    }

    pub fn skill_catalog_max(mut self, v: Arc<AtomicUsize>) -> Self {
        self.skill_catalog_max = v;
        self
    }

    pub fn skill_hot_top_k(mut self, v: Arc<AtomicUsize>) -> Self {
        self.skill_hot_top_k = v;
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
            checkpointer: self.checkpointer,
            trim_redundant_tool_calls: self.trim_redundant_tool_calls,
            knowledge_pre_retrieval: self.knowledge_pre_retrieval,
            enable_context_scaling: self.enable_context_scaling,
            max_inline_chars: self.max_inline_chars,
            skill_listing_strategy: self.skill_listing_strategy,
            skill_max_inline_chars: self.skill_max_inline_chars,
            skill_catalog_max: self.skill_catalog_max,
            skill_hot_top_k: self.skill_hot_top_k,
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
        preauth_profile: Option<Arc<PermissionProfile>>,
        fallback_model: Option<String>,
        rabbit_hole_threshold: usize,
        context_window: usize,
        context_window_threshold: usize,
        tool_timeout_secs: u64,
        max_tool_retries: usize,
        images: Vec<String>,
        checkpoint_id: Option<String>,
        resume_checkpoint: Option<ResumeState>,
        output_dir: Option<String>,
    ) -> AgentResult<EventStream> {
        info!("Runner dispatching to agent '{}' (session: {})", self.agent.name(), session_id);

        // Build invocation context
        let invocation_id = uuid::Uuid::new_v4().to_string();
        let base_ctx = ReadonlyContext::new(
            invocation_id,
            self.agent.name().to_string(),
            session_id.to_string(),
        );
        let mut ctx = InvocationContext::new(
            base_ctx,
            self.agent.name().to_string(),
            model_name.to_string(),
            max_iterations,
        ).with_history(history)
         .with_permissions(permissions)
         .with_permission_pending(permission_pending)
         .with_preauth_profile(preauth_profile)
         .with_fallback_model(fallback_model)
         .with_rabbit_hole_threshold(rabbit_hole_threshold)
         .with_trim_redundant_tool_calls(self.trim_redundant_tool_calls.load(Ordering::SeqCst))
         .with_knowledge_pre_retrieval(self.knowledge_pre_retrieval.load(Ordering::SeqCst))
         .with_context_window(context_window)
         .with_context_window_threshold(context_window_threshold)
         .with_enable_context_scaling(self.enable_context_scaling.load(Ordering::SeqCst))
         .with_max_inline_chars(self.max_inline_chars.load(Ordering::SeqCst))
         .with_skill_listing_strategy(crate::skill::SkillListingStrategy::from_index(self.skill_listing_strategy.load(Ordering::SeqCst)))
         .with_skill_max_inline_chars(self.skill_max_inline_chars.load(Ordering::SeqCst))
         .with_skill_catalog_max(self.skill_catalog_max.load(Ordering::SeqCst))
         .with_skill_hot_top_k(self.skill_hot_top_k.load(Ordering::SeqCst))
         .with_tool_timeout_secs(tool_timeout_secs)
         .with_max_tool_retries(max_tool_retries)
         .with_tool_output_dir(output_dir);

        // Wire checkpoint/resume state if provided.
        if let Some(resume) = resume_checkpoint {
            ctx = ctx.with_resume_state(resume.history, resume.start_iteration);
        }
        if let Some(cp_id) = checkpoint_id {
            ctx = ctx.with_checkpoint_id(cp_id);
        }
        if let Some(ref cp) = self.checkpointer {
            ctx = ctx.with_checkpointer(cp.clone());
        }

        // Log user message
        self.logger.log_user_message(session_id, user_message);

        // Dispatch to agent
        let event_stream = self.agent.run(&ctx, user_message, images).await?;

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


    /// Run a predefined sub-agent as an isolated clean-session job with a
    /// custom system prompt and its own dedicated working directory.
    pub async fn run_sub_agent(
        &self,
        params: SubAgentRunParams,
        permissions: Arc<Mutex<HashMap<String, bool>>>,
        permission_pending: PendingMap,
        preauth: Option<Arc<PermissionProfile>>,
    ) -> AgentResult<EventStream> {
        let invocation_id = uuid::Uuid::new_v4().to_string();
        let base_ctx = ReadonlyContext::new(invocation_id, self.agent.name().to_string(), params.session_id.clone());
        let ctx = InvocationContext::new(base_ctx, self.agent.name().to_string(), params.model, params.max_iterations)
            .with_history(Vec::new())
            .with_permissions(permissions)
            .with_permission_pending(permission_pending)
            .with_rabbit_hole_threshold(params.rabbit_hole_threshold)
            .with_trim_redundant_tool_calls(self.trim_redundant_tool_calls.load(Ordering::SeqCst))
            .with_knowledge_pre_retrieval(self.knowledge_pre_retrieval.load(Ordering::SeqCst))
            .with_context_window(params.context_window)
            .with_context_window_threshold(params.context_window_threshold)
            .with_enable_context_scaling(self.enable_context_scaling.load(Ordering::SeqCst))
            .with_max_inline_chars(self.max_inline_chars.load(Ordering::SeqCst))
            .with_tool_timeout_secs(params.tool_timeout_secs)
            .with_max_tool_retries(params.max_tool_retries)
            .with_system_prompt_override(Some(params.system_prompt))
            .with_tool_output_dir(Some(params.output_dir));
        let ctx = if let Some(pa) = preauth { ctx.with_preauth_profile(Some(pa)) } else { ctx };
        self.logger.log_user_message(&params.session_id, &params.message);
        let event_stream = self.agent.run(&ctx, &params.message, Vec::new()).await?;
        let logger = self.logger.clone();
        let sid = params.session_id;
        let wrapped_stream = async_stream::stream! {
            tokio::pin!(event_stream);
            while let Some(result) = event_stream.next().await {
                match &result {
                    Ok(event) => { logger.log_event(&sid, event); }
                    Err(e) => { tracing::warn!("Event stream error: {}", e); }
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

/// Parameters to run a predefined sub-agent as an isolated job.
pub struct SubAgentRunParams {
    pub message: String,
    pub session_id: String,
    pub model: String,
    /// The sub-agent's own system prompt (persona / expertise).
    pub system_prompt: String,
    /// Dedicated working directory for the sub-agent's outputs.
    pub output_dir: String,
    pub max_iterations: usize,
    pub rabbit_hole_threshold: usize,
    pub context_window: usize,
    pub context_window_threshold: usize,
    pub tool_timeout_secs: u64,
    pub max_tool_retries: usize,
}

use futures::StreamExt;
