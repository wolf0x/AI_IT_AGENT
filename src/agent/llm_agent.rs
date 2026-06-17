use std::sync::Arc;
use async_trait::async_trait;
use tracing::{error, info};

use crate::agent::{Agent, AgentEvent, EventStream};
use crate::callbacks::AgentCallbacks;
use crate::config::ModelConfig;
use crate::context::{InvocationContext, ToolContext};
use crate::error::{AgentError, AgentResult};
use crate::model::openai::OpenAiProvider;
use crate::model::ChatMessage;
use crate::permission::{PermissionChecker, PendingMap};
use crate::skill::SkillManager;
use crate::tool::{ToolExecutionStrategy, ToolRegistry};

/// The core LLM-powered agent.
/// Implements the Agent trait (modeled after ADK-RUST's LlmAgent).
///
/// The agent loop is lightweight and LLM-driven:
/// 1. Build system prompt (with skill context)
/// 2. Send messages + tool schemas to LLM (streaming)
/// 3. If LLM returns tool_calls → execute tools → loop back
/// 4. If LLM returns text → done
pub struct LlmAgent {
    name: String,
    description: String,
    provider: Arc<OpenAiProvider>,
    tools: Arc<ToolRegistry>,
    skill_manager: Arc<SkillManager>,
    max_iterations: usize,
    working_dir: String,
    model_configs: Vec<ModelConfig>,
    #[allow(dead_code)]
    callbacks: AgentCallbacks,
    tool_execution_strategy: ToolExecutionStrategy,
}

/// Builder for LlmAgent (modeled after ADK-RUST's LlmAgentBuilder).
pub struct LlmAgentBuilder {
    name: String,
    description: String,
    provider: Option<Arc<OpenAiProvider>>,
    tools: Option<Arc<ToolRegistry>>,
    skill_manager: Option<Arc<SkillManager>>,
    max_iterations: usize,
    working_dir: String,
    model_configs: Vec<ModelConfig>,
    callbacks: AgentCallbacks,
    tool_execution_strategy: ToolExecutionStrategy,
}

impl LlmAgentBuilder {
    pub fn new() -> Self {
        Self {
            name: "rust-agent".to_string(),
            description: "Local AI agent with Windows system tools".to_string(),
            provider: None,
            tools: None,
            skill_manager: None,
            max_iterations: 20,
            working_dir: ".".to_string(),
            model_configs: Vec::new(),
            callbacks: AgentCallbacks::new(),
            tool_execution_strategy: ToolExecutionStrategy::Sequential,
        }
    }

    pub fn name(mut self, name: &str) -> Self { self.name = name.to_string(); self }
    pub fn description(mut self, desc: &str) -> Self { self.description = desc.to_string(); self }
    pub fn provider(mut self, provider: Arc<OpenAiProvider>) -> Self { self.provider = Some(provider); self }
    pub fn tools(mut self, tools: Arc<ToolRegistry>) -> Self { self.tools = Some(tools); self }
    pub fn skill_manager(mut self, sm: Arc<SkillManager>) -> Self { self.skill_manager = Some(sm); self }
    pub fn max_iterations(mut self, n: usize) -> Self { self.max_iterations = n; self }
    pub fn working_dir(mut self, dir: &str) -> Self { self.working_dir = dir.to_string(); self }
    pub fn model_configs(mut self, configs: Vec<ModelConfig>) -> Self { self.model_configs = configs; self }
    pub fn callbacks(mut self, cb: AgentCallbacks) -> Self { self.callbacks = cb; self }
    pub fn tool_execution_strategy(mut self, strategy: ToolExecutionStrategy) -> Self {
        self.tool_execution_strategy = strategy; self
    }

    pub fn build(self) -> AgentResult<LlmAgent> {
        let provider = self.provider.ok_or_else(|| AgentError::config("LlmAgent requires a provider"))?;
        let tools = self.tools.ok_or_else(|| AgentError::config("LlmAgent requires tools"))?;
        let skill_manager = self.skill_manager
            .unwrap_or_else(|| Arc::new(SkillManager::new("skills")));

        Ok(LlmAgent {
            name: self.name,
            description: self.description,
            provider,
            tools,
            skill_manager,
            max_iterations: self.max_iterations,
            working_dir: self.working_dir,
            model_configs: self.model_configs,
            callbacks: self.callbacks,
            tool_execution_strategy: self.tool_execution_strategy,
        })
    }
}

impl LlmAgent {
    pub fn builder() -> LlmAgentBuilder {
        LlmAgentBuilder::new()
    }

    fn build_system_prompt(&self, user_message: &str) -> String {
        let mut prompt = String::from(
            "You are RustAgent, a powerful local AI assistant running on the user's Windows machine. \
You have FULL ACCESS to the user's system via built-in tools.\n\n\
## CRITICAL: Tool Usage Rules\n\
- When the user asks about their system (IP address, processes, services, files, disk space, etc.), \
  you **MUST** use the appropriate tool to get REAL data. Do NOT guess or provide hypothetical answers.\n\
- Available tools include:\n\
  - `shell_exec` — Run any PowerShell/CMD command (e.g., `ipconfig`, `Get-Process`, `systeminfo`)\n\
  - `sys_info` — Get system hardware/OS information\n\
  - `sys_process` — List and manage processes\n\
  - `sys_service` — List and manage Windows services\n\
  - `sys_eventlog` — Query Windows event logs\n\
  - `file_read` / `file_write` / `file_list` / `file_delete` / `file_modify` — File operations\n\
  - `app_launch` — Launch applications\n\
  - `browser_open` — Open URLs in the browser\n\
- If the user asks 'what is my IP' or similar, call `shell_exec` with `ipconfig` or `Get-NetIPAddress`.\n\
- Always call tools FIRST, then explain the results to the user.\n\
- Never say 'I can't check' or 'I don't have access' — you DO have access via tools!\n\n\
## Response Guidelines\n\
- Provide **detailed, comprehensive** responses with real data from tools.\n\
- Use **Markdown formatting**: headers, bullet points, code blocks, tables.\n\
- Explain what you did and interpret the results for the user.\n\
- If a task requires multiple steps, call tools sequentially and explain each step.\n\
- Be thorough — don't stop at surface-level observations.\n",
        );

        let matching_skills = self.skill_manager.find_matching(user_message);
        if !matching_skills.is_empty() {
            prompt.push_str("\n## Active Skills Context\n");
            for skill_content in &matching_skills {
                prompt.push_str(&format!("\n{}\n", skill_content));
            }
            prompt.push('\n');
        }

        prompt
    }
}

#[async_trait]
impl Agent for LlmAgent {
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { &self.description }

    async fn run(&self, ctx: &InvocationContext, user_message: &str) -> AgentResult<EventStream> {
        let model = &ctx.model_name;
        let invocation_id = &ctx.base.invocation_id;
        let author = &ctx.agent_name;
        let _session_id = &ctx.base.session_id;
        let max_iter = ctx.max_iterations;

        // Use an mpsc channel to produce events, then convert to a Stream
        let (tx, rx) = tokio::sync::mpsc::channel::<AgentResult<AgentEvent>>(200);

        // Build system prompt and history in the spawned task
        let system_prompt = self.build_system_prompt(user_message);
        let tool_defs = self.tools.definitions();
        info!("Agent sending {} tool definitions to LLM", tool_defs.len());
        let provider = self.provider.clone();
        let tools = self.tools.clone();
        let working_dir = self.working_dir.clone();
        let model = model.to_string();
        let invocation_id = invocation_id.to_string();
        let author = author.to_string();
        let user_message = user_message.to_string();
        let strategy = self.tool_execution_strategy;
        let prev_history = ctx.conversation_history.clone();
        let permissions = ctx.permissions.clone();
        let permission_pending: PendingMap = ctx.permission_pending.clone();

        tokio::spawn(async move {
            let mut history: Vec<ChatMessage> = prev_history;
            history.push(ChatMessage::user(&user_message));

            for iteration in 0..max_iter {
                info!("Agent loop iteration {}", iteration + 1);

                let mut messages = vec![ChatMessage::system(&system_prompt)];
                messages.extend(history.clone());

                // Call LLM via legacy chat_stream (uses mpsc for text deltas)
                let result = provider
                    .chat_stream(&model, &messages, &tool_defs, tx.clone(), &invocation_id, &author)
                    .await;

                match result {
                    Ok((content, tool_calls)) => {
                        if tool_calls.is_empty() {
                            // Text response - done
                            info!("Agent completed with text response ({} chars, {} tool calls)", content.len(), tool_calls.len());
                            if content.len() < 100 {
                                info!("Short response content: {}", content);
                            }
                            history.push(ChatMessage::assistant(&content));
                            let _ = tx.send(Ok(AgentEvent::done(&invocation_id, &author))).await;
                            return;
                        }

                        // Tool calls - execute them
                        info!("Agent returned {} tool call(s)", tool_calls.len());
                        history.push(ChatMessage::assistant_with_tool_calls(tool_calls.clone()));

                        // Create permission checker for this iteration
                        let checker = PermissionChecker::new(
                            permission_pending.clone(),
                            tx.clone(),
                            permissions.clone(),
                            invocation_id.clone(),
                            author.clone(),
                        );

                        // Execute based on strategy
                        match strategy {
                            ToolExecutionStrategy::Sequential => {
                                for tc in &tool_calls {
                                    execute_tool_call(
                                        &tools, tc, &working_dir, &invocation_id, &author, &tx, &mut history, &checker,
                                    ).await;
                                }
                            }
                            ToolExecutionStrategy::Parallel | ToolExecutionStrategy::Auto => {
                                // For simplicity, still sequential but could be parallelized
                                for tc in &tool_calls {
                                    execute_tool_call(
                                        &tools, tc, &working_dir, &invocation_id, &author, &tx, &mut history, &checker,
                                    ).await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("LLM error: {}", e);
                        let _ = tx.send(Ok(AgentEvent::error(&e, &invocation_id, &author))).await;
                        let _ = tx.send(Ok(AgentEvent::done(&invocation_id, &author))).await;
                        return;
                    }
                }
            }

            let _ = tx.send(Ok(AgentEvent::error("Max iterations reached", &invocation_id, &author))).await;
            let _ = tx.send(Ok(AgentEvent::done(&invocation_id, &author))).await;
        });

        // Convert mpsc Receiver into a Stream
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Box::pin(stream))
    }
}

/// Execute a single tool call and emit events.
async fn execute_tool_call(
    tools: &ToolRegistry,
    tc: &crate::model::ToolCallDelta,
    working_dir: &str,
    invocation_id: &str,
    author: &str,
    tx: &tokio::sync::mpsc::Sender<AgentResult<AgentEvent>>,
    history: &mut Vec<ChatMessage>,
    permission: &PermissionChecker,
) {
    let tool_name = tc.function.name.as_deref().unwrap_or("unknown");
    let args_str = tc.function.arguments.as_deref().unwrap_or("{}");
    let args: serde_json::Value = serde_json::from_str(args_str).unwrap_or(serde_json::json!({}));

    // Emit tool_call event
    let call_event = AgentEvent::tool_call(tool_name, &tc.id, args.clone(), invocation_id, author);
    let _ = tx.send(Ok(call_event)).await;

    // Check permission before executing
    let allowed = permission.check(tool_name, &args).await;

    let result = if !allowed {
        // Permission denied by user
        info!("Tool '{}' denied by user permission", tool_name);
        serde_json::json!({ "error": "Permission denied by user" })
    } else {
        // Execute
        let ctx = ToolContext::simple(working_dir.to_string());
        match tools.get(tool_name) {
            Some(tool) => match tool.execute(args.clone(), &ctx).await {
                Ok(val) => val,
                Err(e) => {
                    error!("Tool {} error: {}", tool_name, e);
                    serde_json::json!({ "error": e.to_string() })
                }
            },
            None => serde_json::json!({ "error": format!("Unknown tool: {}", tool_name) }),
        }
    };

    // Emit tool_result event
    let result_event = AgentEvent::tool_result(tool_name, &tc.id, result.clone(), invocation_id, author);
    let _ = tx.send(Ok(result_event)).await;

    // Add to history
    let result_str = serde_json::to_string(&result).unwrap_or_default();
    history.push(ChatMessage::tool_result(&tc.id, tool_name, &result_str));
}
