use std::sync::Arc;
use async_trait::async_trait;
use serde_json::Value;
use tracing::{error, info, warn};

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

/// Check if a character is a CJK (Chinese/Japanese/Korean) character.
fn is_cjk_char(c: char) -> bool {
    matches!(c,
        '\u{4e00}'..='\u{9fff}'
        | '\u{3400}'..='\u{4dbf}'
        | '\u{f900}'..='\u{faff}'
        | '\u{2e80}'..='\u{2eff}'
        | '\u{3000}'..='\u{303f}'
        | '\u{3040}'..='\u{309f}'
        | '\u{30a0}'..='\u{30ff}'
        | '\u{ac00}'..='\u{d7af}'
    )
}

/// Estimate token count from text content.
/// CJK text: ~1.5 chars per token (each CJK char ≈ 1-2 tokens).
/// Latin text: ~4 chars per token (English average).
fn estimate_tokens(text: &str) -> usize {
    let mut cjk_count = 0usize;
    let mut other_count = 0usize;
    for ch in text.chars() {
        if is_cjk_char(ch) { cjk_count += 1; }
        else { other_count += 1; }
    }
    ((cjk_count as f64 / 1.5) + (other_count as f64 / 4.0)).ceil() as usize
}

/// Trim history messages to fit within a token budget using priority-based strategy:
/// - System prompt (not in history) is always preserved
/// - Recent messages (last 6) are never trimmed
/// - Phase 1: Trim old tool results to 100 chars
/// - Phase 2: Trim old assistant responses to 200 chars
/// - Phase 3: Trim old user messages to 100 chars
/// - Phase 4: Trim old tool results further to 50 chars
fn trim_history_to_budget(history: &mut Vec<ChatMessage>, max_tokens: usize) {
    let calc_tokens = |h: &[ChatMessage]| -> usize {
        h.iter().map(|m| estimate_tokens(m.content_as_text().as_deref().unwrap_or(""))).sum()
    };

    if calc_tokens(history.as_slice()) <= max_tokens { return; }

    let keep_recent = (history.len().saturating_sub(6)).max(3).min(history.len());

    // Phase 1: Trim old tool results to 100 chars
    for i in 0..keep_recent {
        if history[i].role == "tool" {
            let content = history[i].content_as_text().unwrap_or_default();
            if content.len() > 100 {
                let name = history[i].name.as_deref().unwrap_or("tool");
                let preview: String = content.chars().take(100).collect();
                history[i].content = Some(Value::String(
                    format!("[Earlier {} result truncated: {}...]", name, preview)));
            }
        }
    }
    if calc_tokens(history.as_slice()) <= max_tokens { return; }

    // Phase 2: Trim old assistant responses to 200 chars
    for i in 0..keep_recent {
        if history[i].role == "assistant" {
            let content = history[i].content_as_text().unwrap_or_default();
            if content.len() > 200 {
                let preview: String = content.chars().take(200).collect();
                history[i].content = Some(Value::String(
                    format!("[Earlier assistant response truncated: {}...]", preview)));
            }
        }
    }
    if calc_tokens(history.as_slice()) <= max_tokens { return; }

    // Phase 3: Trim old user messages to 100 chars
    for i in 0..keep_recent {
        if history[i].role == "user" {
            let content = history[i].content_as_text().unwrap_or_default();
            if content.len() > 100 {
                let preview: String = content.chars().take(100).collect();
                history[i].content = Some(Value::String(
                    format!("[Earlier user message truncated: {}...]", preview)));
            }
        }
    }
    if calc_tokens(history.as_slice()) <= max_tokens { return; }

    // Phase 4: Aggressive — trim old tool results to 50 chars
    for i in 0..keep_recent {
        if history[i].role == "tool" {
            let content = history[i].content_as_text().unwrap_or_default();
            if content.len() > 50 {
                let name = history[i].name.as_deref().unwrap_or("tool");
                let preview: String = content.chars().take(50).collect();
                history[i].content = Some(Value::String(
                    format!("[{} summary: {}...]", name, preview)));
            }
        }
    }

    let final_tokens = calc_tokens(history.as_slice());
    if final_tokens > max_tokens {
        warn!("History still exceeds budget after all trimming phases: {} tokens (limit: {})", final_tokens, max_tokens);
    }
}

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
    tools: Arc<tokio::sync::RwLock<ToolRegistry>>,
    skill_manager: Arc<SkillManager>,
    max_iterations: usize,
    working_dir: String,
    workspace_dir: String,
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
    tools: Option<Arc<tokio::sync::RwLock<ToolRegistry>>>,
    skill_manager: Option<Arc<SkillManager>>,
    max_iterations: usize,
    working_dir: String,
    workspace_dir: String,
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
            max_iterations: 100,
            working_dir: ".".to_string(),
            workspace_dir: String::new(),
            model_configs: Vec::new(),
            callbacks: AgentCallbacks::new(),
            tool_execution_strategy: ToolExecutionStrategy::Sequential,
        }
    }

    pub fn name(mut self, name: &str) -> Self { self.name = name.to_string(); self }
    pub fn description(mut self, desc: &str) -> Self { self.description = desc.to_string(); self }
    pub fn provider(mut self, provider: Arc<OpenAiProvider>) -> Self { self.provider = Some(provider); self }
    pub fn tools(mut self, tools: Arc<tokio::sync::RwLock<ToolRegistry>>) -> Self { self.tools = Some(tools); self }
    pub fn skill_manager(mut self, sm: Arc<SkillManager>) -> Self { self.skill_manager = Some(sm); self }
    pub fn max_iterations(mut self, n: usize) -> Self { self.max_iterations = n; self }
    pub fn working_dir(mut self, dir: &str) -> Self { self.working_dir = dir.to_string(); self }
    pub fn workspace_dir(mut self, dir: &str) -> Self { self.workspace_dir = dir.to_string(); self }
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
            workspace_dir: self.workspace_dir,
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
        let today = chrono::Local::now().format("%Y-%m-%d (%A)").to_string();
        let mut prompt = format!(
            "You are RustAgent, a powerful local AI assistant running on the user's Windows machine. \
You have FULL ACCESS to the user's system via built-in tools.\n\
**Current date: {today}**\n\n\
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
  - `cron_manage` — Create, list, delete, or toggle scheduled CRON tasks\n\
  - `list_skills` — List all available skills\n\
  - `install_skill` — Create a new skill\n\
  - `remove_skill` — Delete a skill\n\
  - `memory_md` — Manage long-term curated memory: read/write MEMORY.md\n\
  - `todo_update` — Track multi-step task progress with a TODO list\n\
  - `browser_cdp` — Control Chrome browser: navigate, click, type, screenshot, get text/HTML, execute JS. \
    For screenshots: use the returned `url` field (e.g. `/workspace/output/xxx.png`) in markdown image syntax `![desc](url)` to display. NEVER use local file paths.\n\
  - `browser_skill` — Browser automation via BrowserSkill (bsk CLI). Uses the user's existing browser sessions with login state. \
    Actions: navigate, snapshot (accessibility tree), screenshot, click, fill, press, select, evaluate JS, tab management. \
    Session is auto-managed. Use this when you need the user's logged-in browser context.\n\
- If the user asks 'what is my IP' or similar, call `shell_exec` with `ipconfig` or `Get-NetIPAddress`.\n\
- Always call tools FIRST, then explain the results to the user.\n\
- Never say 'I can't check' or 'I don't have access' — you DO have access via tools!\n\n\
## How to Call Tools (IMPORTANT)\n\
When you need to use a tool, you **MUST actually emit the tool call** — do NOT just say \"let me check\" \
or \"I'll use a tool\" without actually calling it. If your API supports native function calling, use that. \
If it does NOT, output a JSON code block in this exact format:\n\
```json\n{{\"name\": \"shell_exec\", \"arguments\": {{\"command\": \"ipconfig\"}}}}\n```\n\
The system will detect this block, execute the tool, and return the result. You MUST output the JSON block — \
saying \"let me check\" without the actual JSON block does nothing.\n\n\
**CRITICAL: When emitting a tool call, output ONLY the JSON code block — nothing else.** \
Do NOT write narrative text like \"let me open the calculator\" before or alongside the tool call. \
Do NOT repeat yourself. The tool call IS your action — explain the result AFTER you receive it, not before.\n\
Wrong: \"Let me open the calculator for you! ```json ... ```\"\n\
Right: ```json\n{{\"name\": \"app_launch\", ...}}\n```\n\
(Then after the tool result comes back, say \"Calculator has been opened.\")\n\n\
## Response Guidelines\n\
- Provide **detailed, comprehensive** responses with real data from tools.\n\
- Use **Markdown formatting**: headers, bullet points, code blocks, tables.\n\
- Explain what you did and interpret the results for the user.\n\
- If a task requires multiple steps, call tools sequentially and explain each step.\n\
- Be thorough — don't stop at surface-level observations.\n\
- **Do NOT repeat yourself.** Once you have answered a question or completed an action, stop. \
  Do not add follow-up narration like \"now let me verify\" or \"let me double-check\" unless the user asks.\n\
- **Do NOT announce what you are about to do.** Just do it. If you need to call a tool, emit the tool call \
  directly. Explain results AFTER the tool returns, not before.\n\n\
## CRITICAL: You Have Long-Term Memory\n\
This assistant is connected to a LOCAL MEMORY STORE (SQLite). Past conversations with this user are persisted and \
injected into your context as SYSTEM messages labeled **[Memory Context]** or **[Memory Recall]**.\n\
- When such a block is present in the conversation, you **MUST** treat it as real memory of prior interactions and \
  use it to answer questions about previous topics, what was discussed yesterday/last time, etc.\n\
- You are **STRICTLY FORBIDDEN** from claiming any of the following when a [Memory Context]/[Memory Recall] block \
  is present:\n\
    - \"我只能记住当前对话窗口的内容\" / \"I can only remember the current conversation window\"\n\
    - \"我无法访问之前的对话历史\" / \"I can't access previous conversations\"\n\
    - \"每次对话对我来说都是全新的开始\" / \"every conversation is a fresh start\"\n\
    - \"我没有记录或查询之前聊天内容的能力\" / \"I have no ability to query past chats\"\n\
- Instead, summarize and reference what the memory block contains. If the user asks about a topic not covered in \
  the memory block, say you don't have a record of that specific topic (not that you lack memory entirely).\n\
- If and only if NO [Memory Context]/[Memory Recall] block is present, you may honestly say you have no stored \
  record of past conversations.\n\
- The memory block is already the authoritative output of the local memory system. Unless the user EXPLICITLY asks \
  you to inspect memory files / SQLite / logs, you must NOT call tools like `file_read` or `shell_exec` to inspect \
  `memory.db`, logs, or config files just to answer a memory question. Use the injected memory block instead.\n\
- **STRICTLY PROHIBITED**: After answering a memory question using the injected data, do NOT then say things like \
  \"let me check the memory files\" or \"let me look at MEMORY.md\" and then call tools. You already have the data — \
  use it and stop. Do not express intent to re-verify what you already know.\n\
- **STRICTLY PROHIBITED**: Do NOT narrate your tool-calling intentions. If you need to call a tool, just call it \
  (output the JSON block). Never write \"let me check X\" as text AND also call the tool in the same response.\n\
- For casual new messages like \"hello\", greetings, or simple follow-ups, do NOT resume unrelated unfinished topics \
  from old sessions on your own. Use memory only as background context unless the user explicitly asks to recall \
  earlier conversations.\n",
        );

        // ── Permission Respect Rules ──
        prompt.push_str(
            "\n## CRITICAL: Permission Denial Rules\n\
When the user DENIES a tool permission (you receive 'PERMISSION DENIED'):\n\
- The denial is FINAL. Do NOT retry the same tool.\n\
- Do NOT attempt to achieve the same result through alternative tools. For example:\n\
  - If `file_delete` is denied, do NOT use `shell_exec` with `Remove-Item`, `del`, `rm`, or any other command to delete the file.\n\
  - If `file_write` is denied, do NOT use `shell_exec` with `echo`, `Set-Content`, or `Out-File` to write the file.\n\
  - If any tool is denied, do NOT circumvent it via PowerShell, CMD, or any other indirect method.\n\
- Simply inform the user that the action was denied and ask if they want to do something else.\n\
- A permission denial means the user does NOT want this action to happen — regardless of which tool performs it.\n",
        );

        // ── Scheduled Tasks: RustAgent CRON vs Windows Schtasks ──
        prompt.push_str(
            "\n## Scheduled Tasks: CRON vs System Tasks\n\
You have TWO ways to create scheduled tasks. You MUST distinguish between them:\n\n\
### RustAgent CRON Tasks (Application-Level)\n\
- Results are fed back into the chat as notifications\n\
- Run within RustAgent's context with access to all AI tools\n\
- Use for: periodic monitoring, reports, data collection that the user wants to SEE in chat\n\
- **Use the `cron_manage` tool to create/list/delete/toggle these tasks directly from chat**\n\
- Schedule format: 'every Ns' (seconds), 'every Nm' (minutes), 'every Nh' (hours), 'every Nd' (days)\n\
- Examples:\n\
  - User: '每小时检查一次磁盘空间' → cron_manage create, schedule='every 1h', message='Check disk space and report if usage is above 80%'\n\
  - User: '每天早上9点汇报系统状态' → cron_manage create, schedule='every 1d', message='Run systeminfo and summarize system health'\n\
  - User: '每30秒ping一下google.com' → cron_manage create, schedule='every 30s', message='Ping google.com and report latency'\n\
  - User: '列出所有定时任务' → cron_manage list\n\
  - User: '删除那个磁盘检查任务' → cron_manage delete, task_id=<id from list>\n\
  - User: '暂停那个任务' → cron_manage toggle, task_id=<id>\n\n\
### Windows Task Scheduler (System-Level)\n\
- Managed via `schtasks.exe` command-line tool\n\
- Run independently of RustAgent (even when RustAgent is closed)\n\
- Results are NOT automatically fed back to chat\n\
- Use for: system maintenance, cleanup, backups, scripts that should run regardless of RustAgent\n\
- Example: 'Create a scheduled task to clean temp files every Sunday at 2 AM'\n\
- To create: use `shell_exec` with schtasks commands:\n\
  - Create: `schtasks /Create /TN \"TaskName\" /TR \"command\" /SC DAILY /ST 02:00 /F`\n\
  - List:   `schtasks /Query /FO LIST`\n\
  - Delete: `schtasks /Delete /TN \"TaskName\" /F`\n\n\
**Decision guide:**\n\
- User wants to **see results in chat** → RustAgent CRON (use `cron_manage` tool)\n\
- Task should **run independently** or **survive RustAgent restarts** → Windows Schtasks\n\
- Task requires **AI capabilities** → RustAgent CRON\n\
- Simple **system command** → Windows Schtasks\n",
        );

        // ── TODO Task Planning ──
        prompt.push_str(
            "\n## Task Planning with TODO Lists\n\
When you receive a **complex, multi-step request** (3+ distinct steps), use the `todo_update` tool \
to create a TODO list BEFORE starting work. This helps you track progress and avoid forgetting steps.\n\n\
### When to use:\n\
- User asks you to do multiple things in one message\n\
- A task requires sequential tool calls with dependencies\n\
- You need to track which subtasks are done vs pending\n\n\
### When NOT to use:\n\
- Simple single-step requests ('what time is it?', 'open calculator')\n\
- Quick questions that need one tool call at most\n\n\
### How to use:\n\
1. At the START of a complex task: call `todo_update` with action='set' and an items array\n\
2. As you complete each step: call `todo_update` with action='update' to mark it 'completed'\n\
3. When starting a step: mark it 'in_progress'\n\
4. When entirely done: call `todo_update` with action='clear'\n\n\
Example:\n\
```json\n{\"name\": \"todo_update\", \"arguments\": {\"action\": \"set\", \"items\": [\n  {\"description\": \"Check disk space\", \"status\": \"in_progress\"},\n  {\"description\": \"List large files\", \"status\": \"pending\"},\n  {\"description\": \"Generate cleanup report\", \"status\": \"pending\"}\n]}}\n```\n",
        );

        // ── Workspace Configuration Files ──
        const MAX_FILE_CHARS: usize = 8000;
        let workspace = &self.workspace_dir;
        if !workspace.is_empty() {
            let config_files = [
                ("AGENTS.md", "Agent Behavior & Rules"),
                ("SOUL.md", "Personality, Tone & Boundaries"),
                ("TOOLS.md", "Local Tool Usage Conventions"),
                ("MEMORY.md", "Curated Long-Term Memory"),
            ];
            let mut injected = Vec::new();
            for (filename, description) in &config_files {
                if let Some((content, was_truncated)) = Self::read_workspace_file(workspace, filename, MAX_FILE_CHARS) {
                    let mut section = format!("\n## {} ({})\n", description, filename);
                    section.push_str(&content);
                    if was_truncated {
                        section.push_str("\n*[Note: This file was auto-truncated due to size. Keep it concise to save tokens.]*");
                    }
                    section.push('\n');
                    injected.push(section);
                }
            }
            if !injected.is_empty() {
                prompt.push_str("\n# Workspace Configuration\n\
The following files are loaded from your workspace. They define your behavior, personality, and tool conventions.\n");
                for section in &injected {
                    prompt.push_str(section);
                }
            }

            // ── Memory System Documentation ──
            prompt.push_str(
                "\n# Memory System\n\
You have two layers of memory:\n\n\
## Automatic Memory (memory.db — SQLite)\n\
- Every conversation is automatically persisted\n\
- Recent summaries are injected into your context as [Memory Context] or [Memory Recall]\n\
- You do NOT need to do anything — this works automatically\n\n\
## Curated Long-Term Memory: MEMORY.md\n\
- High-signal, distilled knowledge — facts, preferences, lessons learned\n\
- Automatically injected into your system prompt each session\n\
- Use `memory_md` tool with action 'write_memory' to update (overwrite with new content)\n\
- Use `memory_md` tool with action 'read_memory' to read current content\n\
- Keep it concise and well-organized — it is loaded every session (truncated at 8000 chars)\n\
- Only write things worth remembering long-term — user preferences, key decisions, project conventions\n\n\
## Guidelines\n\
- When you notice patterns or lasting preferences from conversations, distill them into MEMORY.md\n\
- MEMORY.md is curated — quality over quantity\n\
- The automatic SQLite memory handles day-to-day recall; MEMORY.md is for lasting insights\n",
            );
        }

        // ── Active Skills (weighted scoring, top-K) ──
        let matching_skills = self.skill_manager.find_matching(user_message);
        if !matching_skills.is_empty() {
            prompt.push_str("\n## Active Skills Context\n");
            for (skill_content, score) in &matching_skills {
                tracing::debug!("Skill matched with score {:.3}", score);
                prompt.push_str(&format!("\n{}\n", skill_content));
            }
            prompt.push('\n');
        }

        prompt
    }

    /// Read a file from the workspace directory. Returns None if missing or empty.
    /// If the file exceeds `max_chars`, it is truncated and the flag is set.
    fn read_workspace_file(workspace_dir: &str, filename: &str, max_chars: usize) -> Option<(String, bool)> {
        let path = std::path::Path::new(workspace_dir).join(filename);
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                if content.trim().is_empty() {
                    return None;
                }
                let truncated = content.len() > max_chars;
                let result = if truncated {
                    content.chars().take(max_chars).collect::<String>()
                } else {
                    content
                };
                Some((result, truncated))
            }
            Err(_) => None,
        }
    }
}

#[async_trait]
impl Agent for LlmAgent {
    fn name(&self) -> &str { &self.name }
    fn description(&self) -> &str { &self.description }

    async fn run(&self, ctx: &InvocationContext, user_message: &str, images: Vec<String>) -> AgentResult<EventStream> {
        let model = &ctx.model_name;
        let invocation_id = &ctx.base.invocation_id;
        let author = &ctx.agent_name;
        let max_iter = ctx.max_iterations;

        // Use an mpsc channel to produce events, then convert to a Stream
        let (tx, rx) = tokio::sync::mpsc::channel::<AgentResult<AgentEvent>>(200);

        // Build system prompt and history in the spawned task
        let system_prompt = self.build_system_prompt(user_message);
        let tool_defs = self.tools.read().await.definitions();
        let session_id = ctx.base.session_id.clone();
        info!("[session:{}] Agent sending {} tool definitions to LLM", session_id, tool_defs.len());
        let provider = self.provider.clone();
        let tools = self.tools.clone();
        let working_dir = self.working_dir.clone();
        let model = model.to_string();
        let invocation_id = invocation_id.to_string();
        let author = author.to_string();
        let user_message = user_message.to_string();
        let images = images;  // move into spawn
        let strategy = self.tool_execution_strategy;
        let prev_history = ctx.conversation_history.clone();
        let permissions = ctx.permissions.clone();
        let permission_pending: PendingMap = ctx.permission_pending.clone();
        let fallback_model = ctx.fallback_model.clone();
        let rabbit_hole_threshold = ctx.rabbit_hole_threshold;
        let tool_timeout_secs = ctx.tool_timeout_secs;
        let max_tool_retries = ctx.max_tool_retries;
        let context_window = ctx.context_window;
        let context_window_threshold = ctx.context_window_threshold;
        // Calculate max history tokens: context_window * threshold%
        let max_history_tokens: usize = context_window * context_window_threshold / 100;
        let checkpointer = ctx.checkpointer.clone();
        let checkpoint_id = ctx.checkpoint_id.clone();
        let resume_history = ctx.resume_history.clone();
        let resume_iteration = ctx.resume_iteration;

        tokio::spawn(async move {
            let mut effective_system_prompt = system_prompt.clone();
            let mut history: Vec<ChatMessage> = prev_history;

            // ── Resume from checkpoint ──
            let is_resumed = resume_history.is_some();
            if let Some(resumed_hist) = resume_history {
                info!("[session:{}] Resuming from checkpoint ({} history messages, start iter {:?})",
                      session_id, resumed_hist.len(), resume_iteration);
                history = resumed_hist;
            }

            // Some OpenAI-compatible / local models strongly prioritize only the
            // FIRST system prompt. Fold injected memory blocks into that first
            // system message so the model cannot ignore them as trailing system
            // or chat messages.
            let mut memory_blocks = Vec::new();
            history.retain(|msg| {
                if msg.role == "system" {
                    if let Some(content) = msg.content_as_text() {
                        if content.starts_with("[Memory Context") || content.starts_with("[Memory Recall") {
                            memory_blocks.push(content);
                            return false;
                        }
                    }
                }
                true
            });
            if !memory_blocks.is_empty() {
                effective_system_prompt.push_str("\n\n## Injected Memory From Local Store\n");
                for block in &memory_blocks {
                    effective_system_prompt.push_str("\n");
                    effective_system_prompt.push_str(block);
                    effective_system_prompt.push_str("\n");
                }
            }

            // Account for system prompt size in the token budget.
            // System prompt is NOT part of history but consumes context window.
            let system_tokens = estimate_tokens(&effective_system_prompt);
            let history_budget = max_history_tokens.saturating_sub(system_tokens);
            if system_tokens > max_history_tokens / 2 {
                warn!("[session:{}] System prompt uses {} tokens ({}% of budget {}), history budget reduced to {} tokens",
                      session_id, system_tokens, system_tokens * 100 / max_history_tokens, max_history_tokens, history_budget);
            }
            info!("[session:{}] Context budget: system={} tokens, history_budget={} tokens (model={} tokens @ {}%)",
                  session_id, system_tokens, history_budget, context_window, context_window_threshold);

            if !is_resumed {
                if !images.is_empty() {
                    history.push(ChatMessage::user_with_images(&user_message, &images));
                } else {
                    history.push(ChatMessage::user(&user_message));
                }
            }

            // Rabbit hole detection: track identical tool calls (same name + same args)
            let mut call_signatures: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
            // Track which model we're using (for fallback)
            let mut active_model = model.clone();
            let mut used_fallback = false;
            let mut has_executed_tools = false;
            let mut reprompt_count = 0u32;

            let start_iter = resume_iteration.unwrap_or(0);
            for iteration in start_iter..max_iter {
                info!("[session:{}] Agent loop iteration {} (model: {})", session_id, iteration + 1, active_model);

                // If the consumer (WebSocket client) dropped the event stream —
                // e.g. user clicked Stop or the connection closed — abort the
                // agent loop immediately so we don't keep streaming from the
                // LLM into a dead channel.
                if tx.is_closed() {
                    info!("[session:{}] Consumer channel closed, aborting agent loop", session_id);
                    return;
                }

                // Trim history if approaching context limit using token-based budget
                let total_tokens: usize = history.iter().map(|m| estimate_tokens(m.content_as_text().as_deref().unwrap_or(""))).sum();
                if total_tokens > history_budget {
                    warn!("[session:{}] History too large ({} est. tokens, budget: {} tokens), trimming with priority strategy",
                          session_id, total_tokens, history_budget);
                    trim_history_to_budget(&mut history, history_budget);
                    let new_tokens: usize = history.iter().map(|m| estimate_tokens(m.content_as_text().as_deref().unwrap_or(""))).sum();
                    info!("[session:{}] History trimmed from {} to {} est. tokens", session_id, total_tokens, new_tokens);
                }

                let mut messages = Vec::with_capacity(1 + history.len());
                messages.push(ChatMessage::system(&effective_system_prompt));
                messages.extend(history.iter().cloned());

                // Call LLM via legacy chat_stream (uses mpsc for text deltas)
                let result = provider
                    .chat_stream(&active_model, &messages, &tool_defs, tx.clone(), &invocation_id, &author)
                    .await;

                match result {
                    Ok((content, reasoning, tool_calls, usage)) => {
                        // Emit token usage event if available
                        if let Some(ref u) = usage {
                            let prompt_t = u.prompt_tokens.unwrap_or(0);
                            let completion_t = u.completion_tokens.unwrap_or(0);
                            let total_t = u.total_tokens.unwrap_or(prompt_t + completion_t);
                            let _ = tx.send(Ok(AgentEvent::usage(&active_model, prompt_t, completion_t, total_t, &invocation_id, &author))).await;
                        }
                        // If the consumer disappeared mid-stream, don't continue
                        // executing tools or making further LLM calls.
                        if tx.is_closed() {
                            info!("[session:{}] Consumer closed during LLM response, stopping", session_id);
                            return;
                        }
                        // If the model didn't emit native tool_calls, try to
                        // extract them from the text content AND from the
                        // reasoning_content (DeepSeek thinking mode puts
                        // everything in reasoning_content, leaving content
                        // empty).
                        let tool_calls = if tool_calls.is_empty() {
                            info!("[session:{}] No native tool_calls from API, attempting text extraction (content={} chars, reasoning={} chars)",
                                  session_id, content.len(), reasoning.len());
                            let mut extracted = extract_tool_calls_from_content(&content);
                            if extracted.is_empty() && !reasoning.is_empty() {
                                info!("[session:{}] Content extraction found nothing, scanning reasoning_content for tool calls", session_id);
                                extracted = extract_tool_calls_from_content(&reasoning);
                                if extracted.is_empty() {
                                    let reasoning_preview: String = reasoning.chars().take(200).collect();
                                    warn!("[session:{}] Extraction from reasoning_content found no tool calls. Preview: {}...", session_id, reasoning_preview);
                                }
                            }
                            if !extracted.is_empty() {
                                info!("[session:{}] Extracted {} tool call(s) from text/reasoning", session_id, extracted.len());
                            }
                            extracted
                        } else {
                            tool_calls
                        };
                        // Re-prompt fallback: ONLY when no tools have been
                        // executed yet in this session. If the model returned
                        // text without any tool calls, but tools ARE available
                        // and the response looks like it *wanted* to use a tool
                        // (mentions a tool name, is in thinking mode with empty
                        // content, or uses intent phrases like "let me check"),
                        // push a correction and loop again.
                        // Once tools have been executed, never re-prompt — the
                        // model is summarizing results, not trying to call tools.
                        let combined = if content.trim().is_empty() { &reasoning } else { &content };
                        info!("[session:{}] Response analysis: content={} chars, reasoning={} chars, native_tool_calls={}",
                              session_id, content.len(), reasoning.len(), tool_calls.len());
                        if tool_calls.is_empty() && !tool_defs.is_empty() && !has_executed_tools && reprompt_count < 2 && !combined.trim().is_empty() {
                            // Check BOTH content AND reasoning for tool name mentions.
                            let check_text = format!("{}\n{}", &content, &reasoning).to_lowercase();
                            let mentions_tool = tool_defs.iter().any(|t| check_text.contains(&t.function.name.to_lowercase()));

                            // Detect intent phrases in both Chinese and English that suggest
                            // the model intends to take an action (call a tool) but didn't.
                            // Only specific action phrases — generic words like "运行" or "i'll"
                            // cause false positives on greetings and casual chat.
                            let intent_phrases = [
                                "查一下", "看一下", "检查一下", "让我查", "让我看看", "让我来",
                                "使用工具", "调用工具",
                                "let me check", "let me run", "let me use", "let me look",
                                "allow me to",
                            ];
                            let has_intent = intent_phrases.iter().any(|p| check_text.contains(p));

                            // Skip re-prompt for simple greetings — the model should
                            // just respond naturally without being forced to call tools.
                            let user_trimmed = user_message.trim().to_lowercase();
                            let is_greeting = ["hi", "hello", "hey", "你好", "嗨", "哈喽", "早上好", "下午好", "晚上好"]
                                .iter().any(|g| user_trimmed == *g);

                            if !is_greeting && (mentions_tool || has_intent) {
                                reprompt_count += 1;
                                let reason = if mentions_tool {
                                    "tool name mentioned"
                                } else {
                                    "intent phrase detected"
                                };
                                info!("[session:{}] Re-prompting model to emit tool call JSON (iter {}, attempt {}, reason: {})", session_id, iteration, reprompt_count, reason);

                                // Notify the user that the system is retrying the tool call
                                let _ = tx.send(Ok(AgentEvent::text(
                                    "\n\n*[正在重新组织工具调用...]*",
                                    &invocation_id, &author
                                ))).await;

                                history.push(ChatMessage::assistant(combined));

                                // Build a tool list hint so the model knows which tools are available
                                let tool_list_hint = tool_defs.iter()
                                    .map(|t| format!("- `{}`: {}", t.function.name, t.function.description.chars().take(80).collect::<String>()))
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                let correction = format!(
                                    "You said you would take an action, but you did NOT output a tool call.\n\n\
                                    Available tools:\n{}\n\n\
                                    Output ONLY the tool call JSON code block — NO narrative text, NO explanation, NO preamble.\n\
                                    Format:\n\
                                    ```json\n{{\"name\": \"shell_exec\", \"arguments\": {{\"command\": \"ipconfig\"}}}}\n```\n\
                                    Replace the tool name and arguments with what you actually need.\n\n\
                                    CRITICAL: Your entire response must be ONLY the ```json ... ``` block. Nothing before it, nothing after it.",
                                    tool_list_hint
                                );
                                history.push(ChatMessage::user(&correction));
                                continue;
                            }
                        }
                        if tool_calls.is_empty() {
                            // Text response - done
                            info!("[session:{}] Agent completed with text response ({} chars, {} tool calls)", session_id, content.len(), tool_calls.len());
                            if content.len() < 100 {
                                info!("[session:{}] Short response content: {}", session_id, content);
                            }
                            // Handle empty response - request a final summary from LLM
                            let (final_content, already_streamed) = if content.trim().is_empty() && iteration > 0 {
                                warn!("[session:{}] LLM returned empty response after {} iterations, requesting summary", session_id, iteration + 1);
                                // Add a summary request to history and ask LLM one more time
                                let summary_prompt = "Please provide a final summary of the task. Include:\n\
                                    1. Whether the task succeeded or failed\n\
                                    2. If succeeded: summarize what was accomplished\n\
                                    3. If failed: explain what went wrong and what additional conditions, tools, or information would be needed to retry\n\
                                    Be specific and helpful.".to_string();
                                history.push(ChatMessage::user(&summary_prompt));
                                let mut summary_msgs = vec![ChatMessage::system(&system_prompt)];
                                summary_msgs.extend(history.clone());
                                // One more LLM call for summary (no tools) - streams to client
                                match provider.chat_stream(&active_model, &summary_msgs, &[], tx.clone(), &invocation_id, &author).await {
                                    Ok((summary_content, _, _, _)) => {
                                        if summary_content.trim().is_empty() {
                                            (generate_static_summary(&history, iteration + 1), false)
                                        } else {
                                            (summary_content, true) // already streamed
                                        }
                                    }
                                    Err(e2) => {
                                        warn!("Summary request also failed: {}", e2);
                                        (generate_static_summary(&history, iteration + 1), false)
                                    }
                                }
                            } else {
                                (content, true) // normal response, already streamed
                            };
                            history.push(ChatMessage::assistant(&final_content));
                            // Only send text event if NOT already streamed to client
                            if !already_streamed && !final_content.trim().is_empty() {
                                let _ = tx.send(Ok(AgentEvent::text(&final_content, &invocation_id, &author))).await;
                            }
                            // Task completed normally — delete checkpoint
                            if let Some(ref cp) = checkpointer {
                                if let Some(ref cp_id) = checkpoint_id {
                                    let _ = cp.delete(cp_id);
                                    info!("[session:{}] Checkpoint deleted (task completed)", session_id);
                                }
                            }
                            let _ = tx.send(Ok(AgentEvent::done(&invocation_id, &author))).await;
                            return;
                        }

                        // Tool calls - execute them
                        info!("[session:{}] Agent returned {} tool call(s)", session_id, tool_calls.len());
                        has_executed_tools = true;
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
                                    let tool_name = tc.function.name.as_deref().unwrap_or("unknown");
                                    let args_str = tc.function.arguments.as_deref().unwrap_or("{}");
                                    let sig = format!("{}:{}", tool_name, args_str);
                                    if let Some((count, warning_msg)) = rabbit_hole_check(
                                        &mut call_signatures, &sig, tool_name, rabbit_hole_threshold,
                                    ) {
                                        warn!("[session:{}] Rabbit hole: '{}' called with same args {} times: {}", session_id, tool_name, count, args_str);
                                        history.push(ChatMessage::user(&warning_msg));
                                        let _ = tx.send(Ok(AgentEvent::text(
                                            &format!("\n\n*[Rabbit hole: {} repeated {} times with same args]*\n\n", tool_name, count),
                                            &invocation_id, &author
                                        ))).await;
                                    }
                                    let msg = execute_tool_call(
                                        &tools, tc, &working_dir, &invocation_id, &author, &tx, &checker, tool_timeout_secs, max_tool_retries,
                                    ).await;
                                    history.push(msg);
                                }
                            }
                            ToolExecutionStrategy::Parallel | ToolExecutionStrategy::Auto => {
                                // Rabbit-hole bookkeeping runs first (cheap, sequential).
                                for tc in &tool_calls {
                                    let tool_name = tc.function.name.as_deref().unwrap_or("unknown");
                                    let args_str = tc.function.arguments.as_deref().unwrap_or("{}");
                                    let sig = format!("{}:{}", tool_name, args_str);
                                    if let Some((count, warning_msg)) = rabbit_hole_check(
                                        &mut call_signatures, &sig, tool_name, rabbit_hole_threshold,
                                    ) {
                                        warn!("[session:{}] Rabbit hole: '{}' called with same args {} times: {}", session_id, tool_name, count, args_str);
                                        history.push(ChatMessage::user(&warning_msg));
                                        let _ = tx.send(Ok(AgentEvent::text(
                                            &format!("\n\n*[Rabbit hole: {} repeated {} times with same args]*\n\n", tool_name, count),
                                            &invocation_id, &author
                                        ))).await;
                                    }
                                }

                                // `Auto` only runs concurrently when every call in
                                // the batch is read-only; otherwise it falls back to
                                // sequential to avoid racing mutable operations.
                                // `Parallel` always runs concurrently (caller's
                                // responsibility to pass safe tools).
                                let registry = tools.read().await;
                                let all_read_only = strategy == ToolExecutionStrategy::Parallel
                                    || tool_calls.iter().all(|tc| {
                                        let n = tc.function.name.as_deref().unwrap_or("");
                                        registry.get(n).map(|t| t.is_read_only()).unwrap_or(false)
                                    });
                                drop(registry);

                                if all_read_only && tool_calls.len() > 1 {
                                    info!("[session:{}] Executing {} tool call(s) concurrently", session_id, tool_calls.len());
                                    let msgs = execute_tools_concurrent(
                                        &*tools, &tool_calls, &working_dir, &invocation_id, &author, &tx, &checker, tool_timeout_secs, max_tool_retries,
                                    ).await;
                                    history.extend(msgs);
                                } else {
                                    for tc in &tool_calls {
                                        let msg = execute_tool_call(
                                            &*tools, tc, &working_dir, &invocation_id, &author, &tx, &checker, tool_timeout_secs, max_tool_retries,
                                        ).await;
                                        history.push(msg);
                                    }
                                }
                            }
                        }

                        // ── Save checkpoint after tool execution ──
                        if let Some(ref cp) = checkpointer {
                            if let Some(ref cp_id) = checkpoint_id {
                                if let Err(e) = cp.save(
                                    cp_id, &session_id, &active_model,
                                    &user_message, &history, iteration,
                                ) {
                                    warn!("[session:{}] Failed to save checkpoint: {}", session_id, e);
                                } else {
                                    info!("[session:{}] Checkpoint saved at iteration {}", session_id, iteration);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("[session:{}] LLM error (model: {}): {}", session_id, active_model, e);
                        // Try fallback model if available and not already used
                        if !used_fallback {
                            if let Some(ref fb) = fallback_model {
                                warn!("[session:{}] Switching to fallback model: {}", session_id, fb);
                                let _ = tx.send(Ok(AgentEvent::text(
                                    &format!("\n\n*[Primary model failed, switching to {}]*\n\n", fb),
                                    &invocation_id, &author
                                ))).await;
                                active_model = fb.clone();
                                used_fallback = true;
                                continue; // Retry with fallback model
                            }
                        }
                        let _ = tx.send(Ok(AgentEvent::error(&e, &invocation_id, &author))).await;
                        let _ = tx.send(Ok(AgentEvent::done(&invocation_id, &author))).await;
                        return;
                    }
                }
            }

            // Max iterations reached - request final summary
            warn!("[session:{}] Max iterations ({}) reached", session_id, max_iter);
            let summary_prompt = format!(
                "The agent has reached the maximum number of iterations ({}) without completing. \
                 Please provide a final summary:\n\
                 1. What was accomplished so far\n\
                 2. What remains to be done\n\
                 3. What additional conditions, tools, or information would be needed to complete the task\n\
                 Be specific and helpful.",
                max_iter
            );
            history.push(ChatMessage::user(&summary_prompt));
            let mut summary_msgs = vec![ChatMessage::system(&system_prompt)];
            summary_msgs.extend(history.clone());
            match provider.chat_stream(&active_model, &summary_msgs, &[], tx.clone(), &invocation_id, &author).await {
                Ok((summary_content, _, _, _)) => {
                    if summary_content.trim().is_empty() {
                        // LLM returned empty, send static summary
                        let fallback = generate_static_summary(&history, max_iter);
                        let _ = tx.send(Ok(AgentEvent::text(&fallback, &invocation_id, &author))).await;
                    }
                    // else: non-empty content was already streamed via chat_stream, don't re-send
                }
                Err(_) => {
                    let fallback = generate_static_summary(&history, max_iter);
                    let _ = tx.send(Ok(AgentEvent::text(&fallback, &invocation_id, &author))).await;
                }
            }
            let _ = tx.send(Ok(AgentEvent::done(&invocation_id, &author))).await;
        });

        // Convert mpsc Receiver into a Stream
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Box::pin(stream))
    }
}

/// Extract tool calls from the model's text content when it doesn't support
/// native function calling. Looks for:
/// 1. JSON code blocks: ```json {"name": "...", "arguments": {...}} ```
/// 2. Inline JSON objects: {"name": "...", "arguments": {...}}
fn extract_tool_calls_from_content(content: &str) -> Vec<crate::model::ToolCallDelta> {
    use crate::model::{FunctionCallDelta, ToolCallDelta};
    let mut calls = Vec::new();
    let mut id_counter = 0u32;

    // Helper: try to parse a JSON string into a ToolCallDelta.
    // If strict parse fails, attempts to repair incomplete JSON (truncated by max_tokens).
    let try_parse = |json_str: &str, id_counter: &mut u32| -> Option<ToolCallDelta> {
        let trimmed = json_str.trim();
        let val: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                // Attempt repair: add missing closing braces/brackets
                let mut repaired = trimmed.to_string();
                let mut open_braces = 0i32;
                let mut open_brackets = 0i32;
                let mut in_str = false;
                let mut esc = false;
                for c in repaired.chars() {
                    if esc { esc = false; continue; }
                    if c == '\\' && in_str { esc = true; continue; }
                    if c == '"' { in_str = !in_str; continue; }
                    if in_str { continue; }
                    match c {
                        '{' => open_braces += 1,
                        '[' => open_brackets += 1,
                        '}' => open_braces -= 1,
                        ']' => open_brackets -= 1,
                        _ => {}
                    }
                }
                if in_str { repaired.push('"'); }
                for _ in 0..open_brackets { repaired.push(']'); }
                for _ in 0..open_braces { repaired.push('}'); }
                serde_json::from_str(&repaired).ok()?
            }
        };
        let name = val
            .get("name")
            .or_else(|| val.get("tool"))
            .or_else(|| val.get("function"))
            .and_then(|v| v.as_str())?;
        let args = val
            .get("arguments")
            .or_else(|| val.get("args"))
            .or_else(|| val.get("parameters"));
        let args_str = match args {
            Some(a) => serde_json::to_string(a).unwrap_or_else(|_| "{}".to_string()),
            None => "{}".to_string(),
        };
        let call_id = format!("textcall_{}", *id_counter);
        *id_counter += 1;
        info!("[text-tool-call] Extracted: {} ({})", name, args_str);
        Some(ToolCallDelta {
            id: call_id,
            call_type: "function".to_string(),
            function: FunctionCallDelta {
                name: Some(name.to_string()),
                arguments: Some(args_str),
            },
        })
    };

    // 1. Scan for ```json ... ``` code blocks
    let mut remaining = content;
    while let Some(start) = remaining.find("```") {
        remaining = &remaining[start + 3..];
        // Trim whitespace BEFORE checking for the json label — the model
        // often outputs ```\njson\n{...} (newline after backticks).
        remaining = remaining.trim_start();
        if remaining.starts_with("json") {
            remaining = &remaining[4..];
            remaining = remaining.trim_start();
        } else if remaining.starts_with("JSON") {
            remaining = &remaining[4..];
            remaining = remaining.trim_start();
        }
        if let Some(end) = remaining.find("```") {
            let json_str = &remaining[..end];
            if let Some(tc) = try_parse(json_str, &mut id_counter) {
                calls.push(tc);
            }
            remaining = &remaining[end + 3..];
        } else {
            // No closing fence — output may be truncated. Try to parse
            // whatever remains as JSON (with repair for incomplete braces).
            let json_str = remaining.trim();
            if !json_str.is_empty() {
                if let Some(tc) = try_parse(json_str, &mut id_counter) {
                    calls.push(tc);
                }
            }
            break;
        }
    }

    // 2. Scan for inline JSON objects like {"name": "...", "arguments": {...}}
    for marker in &["{\"name\"", "{\"tool\"", "{\"function\""] {
        let mut search_from = 0;
        while let Some(pos) = content[search_from..].find(marker) {
            let abs_pos = search_from + pos;
            if let Some(json_str) = extract_json_object(&content[abs_pos..]) {
                let is_in_codeblock = content[..abs_pos].rfind("```")
                    .map(|cb_start| {
                        let between = &content[cb_start..abs_pos];
                        between.matches("```").count() % 2 == 1
                    })
                    .unwrap_or(false);
                if !is_in_codeblock {
                    if let Some(tc) = try_parse(&json_str, &mut id_counter) {
                        calls.push(tc);
                    }
                }
                search_from = abs_pos + json_str.len();
            } else {
                search_from = abs_pos + marker.len();
            }
        }
    }

    calls
}

/// Extract a complete JSON object starting at the beginning of `text`.
/// Tracks brace depth and string state to handle nested objects.
/// If braces don't balance (truncated output), returns the text as-is
/// so the caller can attempt repair.
fn extract_json_object(text: &str) -> Option<String> {
    if !text.starts_with('{') {
        return None;
    }
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    let mut last_pos = 0usize;
    for (i, c) in text.char_indices() {
        last_pos = i;
        if escape {
            escape = false;
            continue;
        }
        if c == '\\' && in_string {
            escape = true;
            continue;
        }
        if c == '"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(text[..=i].to_string());
                }
            }
            _ => {}
        }
    }
    // Braces didn't balance — return what we have (may be truncated)
    if depth > 0 && last_pos > 0 {
        Some(text[..=last_pos].to_string())
    } else {
        None
    }
}

/// Classification of tool errors for retry decisions.
#[derive(Debug, Clone, PartialEq)]
enum ToolErrorClass {
    /// Transient error — worth retrying (timeout, network, resource busy).
    Retryable,
    /// Permanent error — retrying won't help (bad args, permission denied, not found).
    NonRetryable,
    /// User cancelled or consumer disconnected — do NOT retry.
    Cancelled,
}

/// Classify a tool execution error to decide whether to retry.
fn classify_tool_error(error_msg: &str) -> ToolErrorClass {
    let lower = error_msg.to_lowercase();

    // User-initiated cancellations — never retry
    if lower.contains("cancelled by user") || lower.contains("consumer disconnected") {
        return ToolErrorClass::Cancelled;
    }

    // Permission / auth errors — not retryable
    if lower.contains("permission denied") || lower.contains("unauthorized")
        || lower.contains("not allowed") || lower.contains("access denied") {
        return ToolErrorClass::NonRetryable;
    }

    // Argument / input errors — not retryable (same args will fail again)
    if lower.contains("missing") && lower.contains("parameter") {
        return ToolErrorClass::NonRetryable;
    }
    if lower.contains("unknown tool") || lower.contains("invalid argument") {
        return ToolErrorClass::NonRetryable;
    }

    // Timeout — retryable (transient resource contention)
    if lower.contains("timed out") || lower.contains("timeout") {
        return ToolErrorClass::Retryable;
    }

    // Network / IO transient errors — retryable
    if lower.contains("connection") || lower.contains("network")
        || lower.contains("temporarily unavailable") || lower.contains("resource busy")
        || lower.contains("too many open files") || lower.contains("deadlock")
        || lower.contains("broken pipe") || lower.contains("connection reset") {
        return ToolErrorClass::Retryable;
    }

    // Panics — retryable (might be transient state issue)
    if lower.contains("panicked") || lower.contains("panic") {
        return ToolErrorClass::Retryable;
    }

    // File not found — not retryable (file won't appear by itself)
    if lower.contains("not found") || lower.contains("does not exist") || lower.contains("no such file") {
        return ToolErrorClass::NonRetryable;
    }

    // Default: treat unknown errors as non-retryable to avoid wasted work
    ToolErrorClass::NonRetryable
}

/// Execute a single tool call with automatic retry for transient failures.
///
/// Spawns the tool's `execute()` as a child task and races it against:
/// - A heartbeat interval (sends `progress` events to the UI every 5s)
/// - A timeout (aborts the tool after `tool_timeout_secs`)
/// - Consumer disconnect (aborts immediately if the UI stops reading events)
///
/// On retryable errors (timeouts, network issues, panics), retries up to
/// `max_retries` times with exponential backoff (1s, 2s, 4s...). The LLM
/// receives enriched error messages indicating retry attempts.
/// Non-retryable errors (permission denied, bad arguments, not found) are
/// returned immediately without retry.
async fn execute_tool_call(
    tools: &tokio::sync::RwLock<ToolRegistry>,
    tc: &crate::model::ToolCallDelta,
    working_dir: &str,
    invocation_id: &str,
    author: &str,
    tx: &tokio::sync::mpsc::Sender<AgentResult<AgentEvent>>,
    permission: &PermissionChecker,
    tool_timeout_secs: u64,
    max_retries: usize,
) -> ChatMessage {
    let tool_name = tc.function.name.as_deref().unwrap_or("unknown");
    let args_str = tc.function.arguments.as_deref().unwrap_or("{}");
    let args: serde_json::Value = match serde_json::from_str(args_str) {
        Ok(v) => v,
        Err(e) => {
            warn!("Tool '{}' arguments JSON parse failed ({} chars, likely truncated): {}. Returning error to LLM.",
                  tool_name, args_str.len(), e);
            // Return parse error as tool result so the LLM can retry with correct JSON
            let _ = tx.send(Ok(AgentEvent::tool_call(tool_name, &tc.id, serde_json::json!({}), invocation_id, author))).await;
            let err_msg = format!(
                "ERROR: Tool call arguments could not be parsed (JSON malformed, likely truncated by output token limit). \
                 Error: {}. For large content, use file_write to save content to a file first, then pass the file path \
                 via 'content_file' parameter instead of inline 'content'.",
                e
            );
            let err_result = serde_json::json!({ "error": err_msg });
            let result_msg = ChatMessage::tool_result(&tc.id, tool_name, &err_result.to_string());
            return result_msg;
        }
    };

    // Emit tool_call event
    let call_event = AgentEvent::tool_call(tool_name, &tc.id, args.clone(), invocation_id, author);
    let _ = tx.send(Ok(call_event)).await;

    // Check permission before executing
    let allowed = permission.check(tool_name, &args).await;

    let result = if !allowed {
        info!("Tool '{}' denied by user permission", tool_name);
        serde_json::json!({
            "error": format!(
                "PERMISSION DENIED: The user has denied the tool '{}' for this action. \
                 This decision is FINAL. You MUST NOT attempt to achieve the same result \
                 through alternative tools (e.g., shell_exec, PowerShell, CMD, or any other method). \
                 Respect the user's decision and inform them that the action was denied.",
                tool_name
            )
        })
    } else {
        // Retry loop for transient failures
        let mut attempt = 0usize;

        loop {
            // Look up the tool while holding the read lock briefly
            let tool = tools.read().await.get(tool_name);
            let tool_result = match tool {
                Some(tool) => {
                    let ctx = ToolContext::simple(working_dir.to_string());
                    let args_clone = args.clone();

                    // Spawn the actual tool execution as a separate task
                    let mut tool_handle = tokio::spawn(async move {
                        tool.execute(args_clone, &ctx).await
                    });

                    // Race: tool execution vs heartbeat vs timeout vs consumer disconnect
                    let timeout_duration = std::time::Duration::from_secs(tool_timeout_secs);
                    let heartbeat_interval = std::time::Duration::from_secs(5);
                    let start = std::time::Instant::now();
                    let mut interval = tokio::time::interval(heartbeat_interval);
                    interval.tick().await; // consume the immediate first tick

                    loop {
                        tokio::select! {
                            // Tool execution completed
                            tool_result = &mut tool_handle => {
                                match tool_result {
                                    Ok(Ok(val)) => break Some(val),
                                    Ok(Err(e)) => {
                                        error!("Tool {} error: {}", tool_name, e);
                                        break Some(serde_json::json!({ "error": e.to_string() }));
                                    }
                                    Err(e) => {
                                        error!("Tool {} panicked: {}", tool_name, e);
                                        break Some(serde_json::json!({ "error": format!("Tool execution panicked: {}", e) }));
                                    }
                                }
                            }

                            // Heartbeat: send progress event every 5 seconds
                            _ = interval.tick() => {
                                let elapsed = start.elapsed().as_secs();
                                let progress = AgentEvent::progress(
                                    tool_name,
                                    &format!("Still running... ({}s)", elapsed),
                                    elapsed,
                                    invocation_id,
                                    author,
                                );
                                if tx.send(Ok(progress)).await.is_err() {
                                    info!("[session] Consumer disconnected during tool '{}', aborting", tool_name);
                                    tool_handle.abort();
                                    break Some(serde_json::json!({ "error": "Cancelled by user (consumer disconnected)" }));
                                }
                            }

                            // Consumer disconnected (STOP button)
                            _ = tx.closed() => {
                                info!("Consumer disconnected during tool '{}', aborting", tool_name);
                                tool_handle.abort();
                                break Some(serde_json::json!({ "error": "Cancelled by user" }));
                            }

                            // Timeout
                            _ = tokio::time::sleep(timeout_duration) => {
                                warn!("Tool '{}' timed out after {}s", tool_name, timeout_duration.as_secs());
                                tool_handle.abort();
                                break Some(serde_json::json!({ "error": format!("Tool execution timed out after {}s", timeout_duration.as_secs()) }));
                            }
                        }
                    }
                }
                None => {
                    // Unknown tool — never retry
                    break serde_json::json!({ "error": format!("Unknown tool: {}", tool_name) });
                }
            };

            let result_val = match tool_result {
                Some(v) => v,
                None => serde_json::json!({ "error": "Tool execution returned no result" }),
            };

            // Check if this is an error that should be retried
            if let Some(err_val) = result_val.get("error") {
                let err_msg = err_val.as_str().unwrap_or("unknown error").to_string();
                let classification = classify_tool_error(&err_msg);

                match classification {
                    ToolErrorClass::Cancelled => {
                        // Never retry cancellations
                        break result_val;
                    }
                    ToolErrorClass::NonRetryable => {
                        // Don't retry, but enrich the error with context if we already retried
                        if attempt > 0 {
                            break serde_json::json!({
                                "error": err_msg,
                                "retry_info": format!("Failed after {} attempt(s). This error is not retryable.", attempt + 1)
                            });
                        }
                        break result_val;
                    }
                    ToolErrorClass::Retryable => {
                        attempt += 1;
                        if attempt > max_retries {
                            warn!("Tool '{}' failed after {} attempts, giving up", tool_name, attempt);
                            break serde_json::json!({
                                "error": err_msg,
                                "retry_info": format!("Exhausted {} retry attempt(s). Last error: {}", max_retries, err_msg)
                            });
                        }
                        let backoff_secs = 1u64 << (attempt - 1); // 1s, 2s, 4s, ...
                        warn!("Tool '{}' failed (attempt {}/{}), retrying in {}s: {}",
                              tool_name, attempt, max_retries, backoff_secs, err_msg);
                        // Notify the UI about the retry
                        let retry_event = AgentEvent::progress(
                            tool_name,
                            &format!("Retry {}/{} after {}s (error: {})", attempt, max_retries, backoff_secs, err_msg),
                            0,
                            invocation_id,
                            author,
                        );
                        let _ = tx.send(Ok(retry_event)).await;
                        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                        // Continue the loop to retry
                        continue;
                    }
                }
            } else {
                // Success — no error field
                break result_val;
            }
        }
    };

    // Emit tool_result event (full result to UI)
    let result_event = AgentEvent::tool_result(tool_name, &tc.id, result.clone(), invocation_id, author);
    let _ = tx.send(Ok(result_event)).await;

    // Build the history entry with size cap (max ~15000 chars per result to prevent context overflow)
    let result_str = serde_json::to_string(&result).unwrap_or_default();
    let history_str = if result_str.len() > 15_000 {
        let preview: String = result_str.chars().take(15_000).collect();
        format!("{}\n\n... [truncated, original size: {} chars]", preview, result_str.len())
    } else {
        result_str
    };
    ChatMessage::tool_result(&tc.id, tool_name, &history_str)
}

/// Run a batch of tool calls concurrently and return their result messages in
/// the original (input) order. Only safe for read-only / concurrency-safe tools.
async fn execute_tools_concurrent<'a>(
    tools: &'a tokio::sync::RwLock<ToolRegistry>,
    tool_calls: &'a [crate::model::ToolCallDelta],
    working_dir: &'a str,
    invocation_id: &'a str,
    author: &'a str,
    tx: &'a tokio::sync::mpsc::Sender<AgentResult<AgentEvent>>,
    permission: &'a PermissionChecker,
    tool_timeout_secs: u64,
    max_retries: usize,
) -> Vec<ChatMessage> {
    use futures::future::join_all;
    let futs = tool_calls.iter().map(|tc| {
        execute_tool_call(tools, tc, working_dir, invocation_id, author, tx, permission, tool_timeout_secs, max_retries)
    });
    join_all(futs).await
}

/// Rabbit-hole detection: tracks how many times a tool was called with the same
/// signature. Returns `Some((count, warning_text))` when the threshold is
/// reached (and resets the counter so it can trigger again later).
fn rabbit_hole_check(
    call_signatures: &mut std::collections::HashMap<String, usize>,
    signature: &str,
    tool_name: &str,
    threshold: usize,
) -> Option<(usize, String)> {
    let count = call_signatures.entry(signature.to_string()).or_insert(0);
    *count += 1;
    if *count >= threshold {
        let c = *count;
        *count = 0;
        Some((c, format!(
            "WARNING: You have called {} with the SAME arguments {} times and the task is not completing. \
             You must try a DIFFERENT approach, use different arguments, or explain what went wrong and stop.",
            tool_name, c
        )))
    } else {
        None
    }
}

/// Generate a static summary from tool results in history (fallback when LLM summary also fails).
fn generate_static_summary(history: &[ChatMessage], iterations: usize) -> String {
    let mut tool_results: Vec<(String, String)> = Vec::new();
    let mut has_errors = false;
    let mut has_denied = false;

    for msg in history {
        if msg.role == "tool" {
            let content_str = msg.content_as_text().unwrap_or_default();
            let name = msg.name.as_deref().unwrap_or("tool");
            let preview: String = content_str.chars().take(200).collect();
            if content_str.contains("error") || content_str.contains("Error") {
                has_errors = true;
            }
            if content_str.contains("denied") || content_str.contains("Denied") {
                has_denied = true;
            }
            tool_results.push((name.to_string(), preview));
        }
    }

    let mut parts: Vec<String> = Vec::new();

    if tool_results.is_empty() {
        parts.push(format!("**Task Status: Incomplete** — Processed {} iterations with no tool activity.\n\nThe task could not be completed. You may need to:\n- Provide more specific instructions\n- Check that the required tools are available\n- Verify API connectivity", iterations));
    } else {
        // Determine overall status
        if has_errors || has_denied {
            parts.push("## \u{274c} Task Failed\n".to_string());
            parts.push(format!("The task was not completed successfully after {} iterations and {} tool call(s).\n", iterations, tool_results.len()));
            parts.push("### What happened:\n".to_string());
            for (i, (name, preview)) in tool_results.iter().enumerate() {
                parts.push(format!("{}. **{}**: {}", i + 1, name, preview));
            }
            parts.push("\n### What you may need to retry:\n".to_string());
            if has_errors {
                parts.push("- Some tool executions returned errors. Review the results above for specific failure reasons.".to_string());
            }
            if has_denied {
                parts.push("- Some operations were denied by permission settings. Adjust permissions in Settings if needed.".to_string());
            }
            parts.push("- Consider providing more context or breaking the task into smaller steps.".to_string());
        } else {
            parts.push("## \u{2705} Task Completed\n".to_string());
            parts.push(format!("Processed across {} iterations with {} tool call(s).\n", iterations, tool_results.len()));
            parts.push("### Results:\n".to_string());
            for (i, (name, preview)) in tool_results.iter().enumerate() {
                parts.push(format!("{}. **{}**: {}", i + 1, name, preview));
            }
        }
    }

    parts.join("\n")
}
