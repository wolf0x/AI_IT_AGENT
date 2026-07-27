# RustAgent — Technical Specification

## 1. Overview

**RustAgent** is a local AI agent built as a single Rust binary with WebSocket gateway, multi-model LLM support, and Windows system tools. It implements an ADK-RUST inspired architecture with an agentic loop that autonomously executes tools, manages context windows, and provides crash recovery.

**Core Philosophy**: Lightweight, LLM-driven agent loop where the model decides which tools to call, when to stop, and how to respond. The system provides infrastructure (tools, memory, permissions) while the LLM provides intelligence.

**Key Features**:
- Single binary deployment with embedded workspace files
- Multi-model support (OpenAI-compatible APIs, DeepSeek, Qwen, Ollama)
- Streaming SSE with reasoning_content (thinking mode) support
- MCP (Model Context Protocol) hot-swappable external tools
- SQLite memory with FTS5 full-text search and CJK bigram tokenization
- Knowledge distillation at session end
- YARA malware scanning with 500+ embedded rules
- Incident Response (IR) tools ported from yinghuo
- Permission system with async user endorsement gates
- Checkpoint/resume for crash recovery
- Skill system with weighted token overlap scoring
- CRON scheduler and heartbeat monitoring
- AES-256-GCM encryption for secrets at rest

---

## 2. Architecture Overview

### 2.1 Module Dependency Graph

```
main.rs (entry point)
  ├─► config.rs (configuration loading)
  ├─► server.rs (WebSocket gateway + REST API)
  │     ├─► runner.rs (orchestration)
  │     │     └─► agent/llm_agent.rs (core agent loop)
  │     │           ├─► model/openai.rs (LLM provider)
  │     │           ├─► tool/mod.rs (tool registry)
  │     │           ├─► skill/mod.rs (skill matching)
  │     │           └─► permission.rs (permission gates)
  │     ├─► memory.rs (SQLite memory store)
  │     ├─► scheduler.rs (CRON tasks)
  │     └─► distill.rs (knowledge extraction)
  ├─► tool/mcp_client.rs (MCP protocol)
  └─► crypto.rs (encryption utilities)
```

### 2.2 Core Abstractions (ADK-RUST Inspired)

**Agent trait** (`agent/mod.rs`):
```rust
pub trait Agent: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn sub_agents(&self) -> Vec<Arc<dyn Agent>> { vec![] }
    async fn run(&self, ctx: &InvocationContext, user_message: &str, images: Vec<String>) 
        -> AgentResult<EventStream>;
}
```

**Llm trait** (`model/mod.rs`):
```rust
#[async_trait]
pub trait Llm: Send + Sync {
    fn name(&self) -> &str;
    async fn generate_content(&self, request: LlmRequest, stream: bool) 
        -> AgentResult<LlmResponseStream>;
    fn available_models(&self) -> Vec<String>;
}
```

**Tool trait** (`tool/mod.rs`):
```rust
#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn parameters_schema(&self) -> Value;
    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value>;
    
    // Metadata methods with defaults
    fn is_builtin(&self) -> bool { false }
    fn is_read_only(&self) -> bool { false }
    fn category(&self) -> &str { crate::permission::tool_category(self.name()) }
    fn is_concurrency_safe(&self) -> bool { true }
    fn is_long_running(&self) -> bool { false }
    fn to_definition(&self) -> ToolDefinition { ... }
}
```

---

## 3. Agent System

### 3.1 LlmAgent Structure

**Location**: `src/agent/llm_agent.rs` (1461 lines)

**Fields**:
```rust
pub struct LlmAgent {
    name: String,
    description: String,
    provider: Arc<OpenAiProvider>,
    tools: Arc<tokio::sync::RwLock<ToolRegistry>>,
    skill_manager: Arc<SkillManager>,
    max_iterations: usize,              // default: 100
    working_dir: String,
    workspace_dir: String,
    model_configs: Vec<ModelConfig>,
    callbacks: AgentCallbacks,
    tool_execution_strategy: ToolExecutionStrategy,  // Sequential/Parallel/Auto
}
```

**Builder Pattern** (ADK-RUST style):
```rust
let agent = LlmAgent::builder()
    .name("RustAgent")
    .description("Local AI agent with Windows system tools")
    .provider(provider)
    .tools(shared_tools)
    .skill_manager(skill_manager)
    .max_iterations(config.agent.max_iterations)
    .working_dir(&working_dir)
    .workspace_dir(&workspace_dir)
    .build()?;
```

### 3.2 System Prompt Construction

**Method**: `build_system_prompt(&self, user_message: &str) -> String`

**Injection Order** (critical for model behavior):

1. **Identity & Date**:
   ```
   You are RustAgent, a powerful local AI assistant running on the user's Windows machine.
   You have FULL ACCESS to the user's system via built-in tools.
   **Current date: {today}**
   ```

2. **Tool Usage Rules** (CRITICAL section):
   - Must use tools for system queries (IP, processes, files, etc.)
   - Never guess or provide hypothetical answers
   - Lists all available tools with descriptions
   - JSON tool call format instructions:
     ```json
     {"name": "shell_exec", "arguments": {"command": "ipconfig"}}
     ```
   - **CRITICAL**: Output ONLY the JSON block, no narrative text before/after

3. **Response Guidelines**:
   - Provide detailed, comprehensive responses with real data
   - Use Markdown formatting
   - Do NOT repeat yourself
   - Do NOT announce what you are about to do — just do it

4. **Long-Term Memory Rules**:
   - Memory blocks injected as `[Memory Context]` or `[Memory Recall]`
   - STRICTLY FORBIDDEN to claim "I can only remember the current conversation"
   - Must use injected memory block instead of calling tools to inspect memory.db
   - After answering from memory, do NOT re-verify by calling tools

5. **Permission Denial Rules**:
   - When user DENIES a tool, the denial is FINAL
   - Do NOT retry via alternative tools (e.g., if `file_delete` denied, don't use `shell_exec` with `del`)
   - A permission denial means the user does NOT want this action regardless of which tool performs it

6. **Scheduled Tasks: CRON vs Schtasks**:
   - **RustAgent CRON** (application-level): results fed to chat, runs within agent context
   - **Windows Task Scheduler** (system-level): runs independently, no chat integration
   - Decision guide: user wants to see results → CRON; task should run independently → schtasks

7. **TODO Task Planning**:
   - Use `todo_update` tool for complex multi-step requests (3+ steps)
   - Actions: `set`, `update`, `clear`
   - Status: `pending`, `in_progress`, `completed`

8. **Workspace Configuration Files** (injected at 8000 chars each):
   - `AGENTS.md` — Agent Behavior & Rules
   - `SOUL.md` — Personality, Tone & Boundaries
   - `TOOLS.md` — Local Tool Usage Conventions
   - `MEMORY.md` — Curated Long-Term Memory

9. **Memory System Documentation**:
   - Automatic Memory (memory.db — SQLite)
   - Curated Long-Term Memory (MEMORY.md)
   - Guidelines for distilling patterns into MEMORY.md

10. **Active Skills Context**:
    - Skills matched by weighted token overlap scoring
    - Top-K skills injected into system prompt

### 3.3 Agent Loop Implementation

**Method**: `async fn run(&self, ctx: &InvocationContext, user_message: &str, images: Vec<String>) -> AgentResult<EventStream>`

**Flow**:

1. **Initialization**:
   - Build system prompt via `build_system_prompt()`
   - Get tool definitions from registry
   - Create mpsc channel (capacity: 200) for event streaming
   - Spawn async task for agent loop

2. **Checkpoint Resume** (if applicable):
   ```rust
   if let Some(resumed_hist) = resume_history {
       history = resumed_hist;
       // Skip adding user message (already in history)
   }
   ```

3. **Memory Block Folding**:
   - Extract `[Memory Context]` and `[Memory Recall]` blocks from history
   - Fold them into the first system prompt (models prioritize first system message)
   ```rust
   history.retain(|msg| {
       if msg.role == "system" {
           if content.starts_with("[Memory Context") || content.starts_with("[Memory Recall") {
               memory_blocks.push(content);
               return false;  // Remove from history
           }
       }
       true
   });
   if !memory_blocks.is_empty() {
       effective_system_prompt.push_str("\n\n## Injected Memory From Local Store\n");
       for block in &memory_blocks { ... }
   }
   ```

4. **Token Budget Calculation**:
   ```rust
   let max_history_tokens = context_window * context_window_threshold / 100;
   let system_tokens = estimate_tokens(&effective_system_prompt);
   let history_budget = max_history_tokens.saturating_sub(system_tokens);
   ```

5. **Main Loop** (iterations 0..max_iterations):
   
   a. **Consumer Close Detection**:
      ```rust
      if tx.is_closed() {
          // WebSocket client disconnected, abort loop
          return;
      }
      ```
   
   b. **History Trimming** (if exceeding budget):
      - Call `trim_history_to_budget()` with 4-phase priority strategy
   
   c. **LLM Streaming Call**:
      ```rust
      let result = provider.chat_stream(
          &active_model, &messages, &tool_defs, tx.clone(), &invocation_id, &author
      ).await;
      ```
   
   d. **Tool Call Extraction** (if no native tool_calls):
      - Try extracting from `content` (text response)
      - If empty, try extracting from `reasoning_content` (DeepSeek thinking mode)
      - Extraction logic:
        1. Scan for ```` ```json ... ``` ```` code blocks
        2. Parse JSON, attempt repair if truncated (add missing braces/brackets)
        3. Support multiple key names: `name`/`tool`/`function`, `arguments`/`args`/`parameters`
   
   e. **Re-Prompt Logic** (max 2 attempts, only before first tool execution):
      - **Trigger conditions**:
        - No tool calls returned
        - Tools are available (`!tool_defs.is_empty()`)
        - No tools executed yet in this session (`!has_executed_tools`)
        - Reprompt count < 2
        - Response is not empty
        - Not a greeting (hi, hello, 你好, etc.)
        - EITHER: tool name mentioned in response
        - OR: intent phrase detected (查一下, 看一下, let me check, let me run, etc.)
      - **Action**:
        - Inject correction message with tool list hint
        - Push assistant response + user correction to history
        - Continue loop (retry LLM call)
   
   f. **Rabbit Hole Detection**:
      - Track identical tool calls (same name + same args)
      - Signature: `"{tool_name}:{args_json}"`
      - If count >= threshold (default: 5):
        - Inject warning message into history
        - Send text event to client: `*[Rabbit hole: {tool} repeated {N} times with same args]*`
   
   g. **Tool Execution** (by strategy):
      - **Sequential**: Execute tools one at a time
      - **Parallel**: Execute all tools concurrently (only if all are read-only)
      - **Auto**: Concurrent if all read-only, otherwise sequential
      - Permission check before each tool:
        ```rust
        let checker = PermissionChecker::new(...);
        if !checker.check(tool_name, &args).await {
            // Tool denied, skip execution
        }
        ```
      - Execute via `execute_tool_call()` or `execute_tools_concurrent()`
      - Push tool result to history
   
   h. **Checkpoint Save** (after tool execution):
      ```rust
      checkpointer.save(cp_id, &session_id, &active_model, &user_message, &history, iteration)?;
      ```
   
   i. **Text Response** (if no tool calls):
      - If empty response after iterations > 0: request final summary from LLM
      - If still empty: generate static summary from history
      - Delete checkpoint (task completed)
      - Send `Done` event
      - Return

6. **Max Iterations Reached**:
   - Request final summary from LLM (no tools)
   - If empty: generate static summary
   - Send `Done` event

### 3.4 History Trimming Algorithm

**Function**: `trim_history_to_budget(history: &mut Vec<ChatMessage>, max_tokens: usize)`

**Token Estimation** (CJK-aware):
```rust
fn estimate_tokens(text: &str) -> usize {
    let mut cjk_count = 0usize;
    let mut other_count = 0usize;
    for ch in text.chars() {
        if is_cjk_char(ch) { cjk_count += 1; }
        else { other_count += 1; }
    }
    ((cjk_count as f64 / 1.5) + (other_count as f64 / 4.0)).ceil() as usize
}
```
- CJK text: ~1.5 chars per token (each CJK char ≈ 1-2 tokens)
- Latin text: ~4 chars per token (English average)

**4-Phase Priority Trimming**:
- **Protected zone**: Last 6 messages never trimmed (minimum 3)
- **Phase 1**: Trim old tool results to 100 chars
  ```rust
  if history[i].role == "tool" && content.len() > 100 {
      history[i].content = Some(Value::String(
          format!("[Earlier {} result truncated: {}...]", name, preview)));
  }
  ```
- **Phase 2**: Trim old assistant responses to 200 chars
- **Phase 3**: Trim old user messages to 100 chars
- **Phase 4**: Aggressive — trim old tool results to 50 chars
- After each phase, recalculate tokens; stop if within budget

### 3.5 Tool Call Extraction from Text

**Function**: `extract_tool_calls_from_content(content: &str) -> Vec<ToolCallDelta>`

**Algorithm**:
1. Scan for ```` ```json ... ``` ```` code blocks
2. For each block:
   - Trim whitespace, skip optional `json` or `JSON` label
   - Extract JSON string until closing ```` ``` ````
   - If no closing fence (truncated output): attempt repair
3. **JSON Repair** (for truncated responses):
   ```rust
   let mut repaired = trimmed.to_string();
   // Count open braces/brackets
   for c in repaired.chars() {
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
   ```
4. Parse JSON, extract:
   - `name` (or `tool` or `function`)
   - `arguments` (or `args` or `parameters`)
5. Generate synthetic call ID: `textcall_{counter}`

### 3.6 Rabbit Hole Detection

**Purpose**: Prevent infinite loops when model repeatedly calls same tool with same args

**Implementation**:
```rust
let mut call_signatures: HashMap<String, usize> = HashMap::new();

for tc in &tool_calls {
    let tool_name = tc.function.name.as_deref().unwrap_or("unknown");
    let args_str = tc.function.arguments.as_deref().unwrap_or("{}");
    let sig = format!("{}:{}", tool_name, args_str);
    
    let count = call_signatures.entry(sig).or_insert(0);
    *count += 1;
    
    if *count >= rabbit_hole_threshold {
        // Inject warning
        let warning_msg = format!(
            "The tool '{}' has been called {} times with the same arguments but is not making progress. \
             Please try a different approach or explain why the task cannot be completed.",
            tool_name, count
        );
        history.push(ChatMessage::user(&warning_msg));
        // Send text event to client
    }
}
```

---

## 4. Model Layer

### 4.1 OpenAiProvider

**Location**: `src/model/openai.rs` (504 lines)

**Structure**:
```rust
pub struct OpenAiProvider {
    client: Client,  // reqwest::Client with 180s timeout
    models: Arc<tokio::sync::RwLock<Vec<ModelConfig>>>,
}
```

**Model Compatibility**:
- **max_tokens key**: GPT-5/o1/o3/o4 use `max_completion_tokens`, others use `max_tokens`
  ```rust
  fn max_tokens_key(model_name: &str) -> &'static str {
      if lower.starts_with("gpt-5") || lower.starts_with("o1") || 
         lower.starts_with("o3") || lower.starts_with("o4") {
          "max_completion_tokens"
      } else {
          "max_tokens"
      }
  }
  ```

**Two Call Modes**:

1. **chat_simple()** (non-streaming):
   - Used for knowledge distillation
   - temperature: 0.3, max_tokens: 4096
   - Returns: `Result<String, String>`

2. **chat_stream()** (streaming SSE):
   - Used for agent loop
   - Sends text deltas via mpsc channel
   - Returns: `(content, reasoning_content, tool_calls, usage)`
   - **Streaming Parser**:
     ```rust
     while let Some(chunk_result) = s.next().await {
         // Parse SSE: "data: {...}"
         if let Some(data) = line.strip_prefix("data: ") {
             let chunk: StreamChunk = serde_json::from_str(data)?;
             for choice in chunk.choices {
                 // Handle reasoning_content (thinking phase)
                 if let Some(reasoning) = &choice.delta.reasoning_content {
                     full_reasoning.push_str(reasoning);
                     tx.send(AgentEvent::thinking(reasoning, ...)).await?;
                 }
                 // Handle content (actual response)
                 if let Some(content) = &choice.delta.content {
                     full_content.push_str(content);
                     tx.send(AgentEvent::text(content, ...)).await?;
                 }
                 // Accumulate tool calls
                 if let Some(tool_calls) = &choice.delta.tool_calls {
                     for tc in tool_calls {
                         // Accumulate by index (streaming chunks are partial)
                         tool_calls_map[tc.index].accumulate(tc);
                     }
                 }
             }
         }
     }
     ```
   - **Tool Call Accumulation**:
     ```rust
     struct ToolCallAccum {
         id: Option<String>,
         name: Option<String>,
         arguments: String,  // Accumulate partial JSON strings
     }
     ```
   - **Synthetic ID Generation**: If API omits tool call IDs, generate `call_{index}`
   - **Consumer Gone Detection**: If `tx.send()` fails, abort stream reading

**Supported Models** (from config.toml):
- llmgw-qwen3.6 (default)
- gpt-4o
- deepseek-v4-flash
- deepseek-v4-pro
- ollama-llama3

---

## 5. Tool System

### 5.1 Tool Trait

**Location**: `src/tool/mod.rs` (309 lines)

**Core Methods**:
```rust
#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn parameters_schema(&self) -> Value;
    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value>;
    
    // Metadata with defaults
    fn is_builtin(&self) -> bool { false }
    fn is_read_only(&self) -> bool { false }
    fn category(&self) -> &str { crate::permission::tool_category(self.name()) }
    fn is_concurrency_safe(&self) -> bool { true }
    fn is_long_running(&self) -> bool { false }
    fn response_schema(&self) -> Option<Value> { None }
    fn enhanced_description(&self) -> String { self.description().to_string() }
    fn required_scopes(&self) -> Vec<String> { vec![] }
    
    fn to_definition(&self) -> ToolDefinition {
        ToolDefinition {
            tool_type: "function".to_string(),
            function: FunctionDefinition {
                name: self.name().to_string(),
                description: self.enhanced_description(),
                parameters: self.parameters_schema(),
            },
        }
    }
}
```

### 5.2 Tool Execution Strategy

```rust
pub enum ToolExecutionStrategy {
    Sequential,   // Execute tools one at a time
    Parallel,     // Execute all tools concurrently (only safe for read-only)
    Auto,         // Concurrent if all read-only, otherwise sequential
}
```

**Auto Strategy Logic**:
```rust
let all_read_only = strategy == ToolExecutionStrategy::Parallel
    || tool_calls.iter().all(|tc| {
        let n = tc.function.name.as_deref().unwrap_or("");
        registry.get(n).map(|t| t.is_read_only()).unwrap_or(false)
    });

if all_read_only && tool_calls.len() > 1 {
    // Execute concurrently
    execute_tools_concurrent(...).await
} else {
    // Execute sequentially
    for tc in &tool_calls { execute_tool_call(...).await }
}
```

#### 5.2.1 Parallel IR Collection (Configurable)

When `parallel_ir_tools = true` (default), the agent detects IR collection batches and executes them concurrently:

```rust
pub const IR_COLLECTION_TOOLS: &[&str] = &[
    "ir_scan", "ir_process", "ir_account", "ir_persistence",
    "ir_network", "ir_eventlog", "ir_file", "ir_driver", "ir_timeline",
];

pub fn is_ir_collection_batch(tool_calls: &[ToolCallDelta]) -> bool {
    tool_calls.len() >= 2
        && tool_calls.iter().all(|tc|
            tc.function.name.as_deref().map(is_ir_collection_tool).unwrap_or(false)
        )
}
```

**Behavior**: When the LLM emits 2+ tool_calls and ALL are from the IR collection set, they execute via `futures::join_all` instead of sequentially. This yields 3-4x faster incident triage. All tools in this set are read-only (safe for parallel execution).

**Config** (`config.toml`):
```toml
[agent]
parallel_ir_tools = true  # Set false for sequential debugging
```

### 5.3 Tool Registry

```rust
pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn Tool>>,
}

impl ToolRegistry {
    pub fn build_default(working_dir: &str, notify_tx: Option<NotifyTx>) -> Self {
        let mut registry = Self::new();
        // Register 22+ built-in tools
        registry.register(Arc::new(ShellExecTool::new(working_dir)));
        registry.register(Arc::new(FileReadTool::new()));
        registry.register(Arc::new(FileWriteTool::new()));
        registry.register(Arc::new(FileListTool::new()));
        registry.register(Arc::new(FileDeleteTool::new()));
        registry.register(Arc::new(FileModifyTool::new()));
        registry.register(Arc::new(SysInfoTool::new()));
        registry.register(Arc::new(SysProcessTool::new()));
        registry.register(Arc::new(SysServiceTool::new()));
        registry.register(Arc::new(SysEventlogTool::new()));
        registry.register(Arc::new(AppLaunchTool::new()));
        registry.register(Arc::new(BrowserOpenTool::new()));
        registry.register(Arc::new(WebFetchTool::new()));
        registry.register(Arc::new(SysRemindTool::new(notify_tx)));
        // IR tools (11 tools ported from yinghuo + timeline)
        registry.register(Arc::new(IrScanTool::new()));
        registry.register(Arc::new(IrProcessTool::new()));
        registry.register(Arc::new(IrAccountTool::new()));
        registry.register(Arc::new(IrPersistenceTool::new()));
        registry.register(Arc::new(IrNetworkTool::new()));
        registry.register(Arc::new(IrEventlogTool::new()));
        registry.register(Arc::new(IrFileTool::new()));
        registry.register(Arc::new(IrDriverTool::new()));
        registry.register(Arc::new(IrAnalyzerTool::new()));
        registry.register(Arc::new(IrReportTool::new()));
        registry.register(Arc::new(IrTimelineTool::new()));
        // Malware tools
        registry.register(Arc::new(MalwareScanTool::new()));
        registry.register(Arc::new(MalwareAnalysisTool::new()));
        registry.register(Arc::new(MalwareDeepTool::new()));
        registry
    }
    
    pub fn register(&mut self, tool: Arc<dyn Tool>) { ... }
    pub fn unregister(&mut self, name: &str) -> bool { ... }
    pub fn get(&self, name: &str) -> Option<&Arc<dyn Tool>> { ... }
    pub fn definitions(&self) -> Vec<ToolDefinition> { ... }
    pub fn tool_names(&self) -> Vec<&str> { ... }
}
```

**Late-Bound Tools** (registered after Runner built):
- `cron_manage` — needs Scheduler (which depends on Runner)
- `memory_md` — file-based daily logs + long-term memory
- `todo_update` — lightweight task planning/tracking
- `browser_cdp` — CDP browser automation via chromiumoxide
- `browser_skill` — Browser automation via BrowserSkill (bsk CLI)

**Binary Resolution** (3-tier):
```rust
fn resolve_binary(name: &str, working_dir: &str) -> Option<PathBuf> {
    // 1. Check exe directory
    let exe_dir = std::env::current_exe().ok()?.parent()?;
    let path = exe_dir.join(name);
    if path.exists() { return Some(path); }
    
    // 2. Check workspace/tools directory
    let tools_dir = Path::new(working_dir).join("tools");
    let path = tools_dir.join(name);
    if path.exists() { return Some(path); }
    
    // 3. Check PATH
    which::which(name).ok()
}
```

### 5.4 MCP Client (Model Context Protocol)

**Location**: `src/tool/mcp_client.rs` (511 lines)

**Purpose**: Hot-swappable external tool servers via stdio or HTTP transport

**Structure**:
```rust
pub struct McpClientManager {
    servers: Vec<McpServerHandle>,
    persist_path: Option<PathBuf>,
}

struct McpServerHandle {
    config: McpServerConfig,
    status: McpStatus,  // Connected/Disconnected/Error
    service: Option<Box<dyn McpService>>,
    tools: Vec<Arc<McpProxyTool>>,
}
```

**Transport Types**:

1. **stdio** (default):
   ```rust
   async fn connect_stdio(config: &McpServerConfig) -> Result<Box<dyn McpService>> {
       let mut cmd = Command::new(&config.command);
       cmd.args(&config.args);
       // Windows: hide console window
       #[cfg(target_os = "windows")]
       {
           use std::os::windows::process::CommandExt;
           const CREATE_NO_WINDOW: u32 = 0x08000000;
           cmd.creation_flags(CREATE_NO_WINDOW);
       }
       let child = TokioChildProcess::new(cmd)?;
       let service = rmcp::connect(child).await?;
       Ok(Box::new(service))
   }
   ```

2. **HTTP** (SSE transport):
   ```rust
   async fn connect_http(config: &McpServerConfig) -> Result<Box<dyn McpService>> {
       let mut transport_config = StreamableHttpClientTransportConfig::new(config.url.clone());
       if let Some(auth) = &config.auth_token {
           transport_config = transport_config.with_auth_header(format!("Bearer {}", auth));
       }
       let transport = StreamableHttpClientTransport::new(transport_config);
       let service = rmcp::connect(transport).await?;
       Ok(Box::new(service))
   }
   ```

**Tool Discovery**:
```rust
async fn discover_tools(service: &dyn McpService) -> Result<Vec<Arc<McpProxyTool>>> {
    let tools = service.list_all_tools().await?;
    tools.into_iter().map(|t| Arc::new(McpProxyTool::new(t, service.clone()))).collect()
}
```

**McpProxyTool** (implements Tool trait):
```rust
struct McpProxyTool {
    tool: rmcp::Tool,
    service: Box<dyn McpService>,
}

#[async_trait]
impl Tool for McpProxyTool {
    fn name(&self) -> &str { &self.tool.name }
    fn description(&self) -> &str { &self.tool.description }
    fn parameters_schema(&self) -> Value { self.tool.input_schema.clone() }
    
    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value> {
        let result = self.service.call_tool(&self.tool.name, args).await?;
        Ok(result)
    }
    
    fn is_builtin(&self) -> bool { false }  // MCP tools are not built-in
}
```

**Persistence**:
```rust
pub fn save_configs(&self) -> Result<()> {
    // Encrypt auth tokens before saving
    let configs: Vec<McpServerConfig> = self.servers.iter().map(|h| {
        let mut config = h.config.clone();
        if let Some(auth) = &config.auth_token {
            config.auth_token = Some(crypto::encrypt(auth));
        }
        config
    }).collect();
    let json = serde_json::to_string_pretty(&configs)?;
    std::fs::write(&self.persist_path, json)?;
    Ok(())
}

pub fn load_configs(&self) -> Vec<McpServerConfig> {
    let content = std::fs::read_to_string(&self.persist_path).ok()?;
    let configs: Vec<McpServerConfig> = serde_json::from_str(&content).ok()?;
    // Decrypt auth tokens
    configs.into_iter().map(|mut c| {
        if let Some(auth) = &c.auth_token {
            c.auth_token = Some(crypto::decrypt(auth));
        }
        c
    }).collect()
}
```

### 5.5 File Operations Tools

**Location**: `src/tool/file_ops.rs` (249 lines)

**5 tools**: `file_read`, `file_write`, `file_delete`, `file_modify`, `file_list`

**Path Resolution**:
```rust
fn resolve_path(ctx: &ToolContext, path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    if p.is_absolute() { p } else { PathBuf::from(&ctx.working_dir).join(p) }
}
```

**file_read** (read-only):
- Parameters: `path` (required), `start_line` (1-based, optional), `end_line` (inclusive, optional)
- Returns: `{ content: string, lines: number }`
- Line-range mode prefixes each line with its line number: `"LINE_NUM: content"`

**file_write** (write category):
- Parameters: `path` (required), `content` (required)
- Auto-creates parent directories via `fs::create_dir_all`
- Returns: `{ status: "ok", path: string, bytes: number }`

**file_delete** (delete category):
- Parameters: `path` (required)
- Handles both files (`remove_file`) and directories (`remove_dir_all`)
- Returns error if path doesn't exist

**file_modify** (modify category):
- Parameters: `path` (required), `search` (required), `replace` (required)
- Replaces ALL occurrences via `content.replace(search, replace)`
- Returns: `{ status: "ok", replacements: number }`

**file_list** (read-only):
- Parameters: `path` (required), `pattern` (glob, optional), `recursive` (bool, default false)
- Max recursion depth: 3 levels
- Uses `glob::Pattern` for matching; falls back to substring match on invalid glob
- Returns: `{ entries: [{name, type, size, path}], count: number }`

### 5.6 Shell Execution Tool

**Location**: `src/tool/shell_exec.rs` (97 lines)

**shell_exec** (execute category):
- Parameters: `command` (required), `shell` ("powershell"|"cmd", default "powershell"), `timeout_secs` (default 30)
- Returns: `{ stdout: string, stderr: string, exit_code: number }`

**Intent Policy Integration** — replaces legacy destructive_patterns with the full `IntentPolicy` engine (see Section 13.5):
```rust
let policy = IntentPolicy::new();
match policy.evaluate(command, shell) {
    IntentVerdict::Block { reason } => {
        // Hard reject — irreversible operation, cannot be overridden
        return Err("BLOCKED (safety interlock): ...");
    }
    IntentVerdict::Audit { reason } => {
        // Log warning but proceed (user has authorized via Permission gate)
        tracing::warn!("[AUDIT] shell_exec high-risk: ...");
    }
    IntentVerdict::Pass => { /* silent */ }
}
```

**Windows specifics**:
- `creation_flags(0x08000000)` — hides console window (`CREATE_NO_WINDOW`)
- PowerShell: `-NoProfile -NonInteractive -Command`
- CMD: `/C`
- Timeout via `tokio::time::timeout`

### 5.7 System Information Tools

**Location**: `src/tool/sys_info.rs` (76 lines), `sys_process.rs` (70 lines), `sys_service.rs` (71 lines), `sys_eventlog.rs` (68 lines)

All are read-only, builtin tools that execute PowerShell commands:

| Tool | Category | Description |
|------|----------|-------------|
| `sys_info` | read | System info: OS, CPU, memory, disk, network adapters |
| `sys_process` | read | Process listing with CPU, memory, path |
| `sys_service` | read | Windows service enumeration (running, stopped, auto-start) |
| `sys_eventlog` | read | Recent Windows event logs (System, Security, Application) |

### 5.8 Reminder Tool

**Location**: `src/tool/sys_remind.rs` (190 lines)

**sys_remind** (write category):
- Parameters: `message` (required), `delay` (required, e.g. "2m", "30s", "1h", "1h30m")
- Delivery: WebSocket broadcast channel → all connected clients receive `{type: "notification", message, timestamp}`
- Fallback: If no broadcast channel, spawns PowerShell `MessageBox` (fire-and-forget)
- Max delay: 86400s (24 hours)

**Delay Parser**:
```rust
// Supports: "2m", "30s", "1h", "1h30m", "90s", plain number (= seconds)
// Parses character-by-character, accumulating digits then applying unit multiplier
// s=×1, m=×60, h=×3600
```

### 5.9 Application & Browser Tools

**Location**: `src/tool/app_launch.rs` (49 lines), `src/tool/browser_open.rs` (45 lines)

| Tool | Category | Description |
|------|----------|-------------|
| `app_launch` | execute | Launch a Windows application by path or name |
| `browser_open` | execute | Open URL in the system's default browser |

### 5.10 Browser CDP Tool (Chrome DevTools Protocol)

**Location**: `src/tool/browser_cdp.rs` (407 lines)

**browser_cdp** (write category): Full Chrome automation via `chromiumoxide` crate.

**Architecture**:
```rust
pub struct BrowserSession {
    inner: Mutex<Option<BrowserInner>>,  // Lazy-initialized
    workspace_dir: String,
}
struct BrowserInner {
    browser: Browser,
    page: Page,
}
```
- Lazy initialization: Chrome launched on first action (not at startup)
- Viewport: 1920×1080, device_scale=1.0, landscape, no touch
- `MAX_TEXT_LEN = 5000` — truncation limit for get_text/get_html
- Screenshots saved to `workspace/output/`

**10 Actions**:

| Action | Parameters | Description |
|--------|-----------|-------------|
| `navigate` | `url` | Go to URL, wait for navigation, return title |
| `get_text` | `selector?` | Page or element text (CSS selector) |
| `click` | `selector` | Click element, 500ms settle delay |
| `type_text` | `selector`, `text` | Click to focus, then type text |
| `screenshot` | `path?` | PNG screenshot → workspace/output/ |
| `get_url` | — | Current URL + page title |
| `get_html` | `selector?` | Page or element HTML |
| `execute_js` | `js` | `evaluate_expression()`, return JSON result |
| `find_element` | `selector` | Element attributes (flat vec → map) + text (500 char limit) |
| `close` | — | Close browser session |

### 5.11 Browser Skill Tool (bsk CLI)

**Location**: `src/tool/browser_skill.rs` (413 lines)

**browser_skill** (write category): Automates user's existing Chrome sessions via Tencent BrowserSkill CLI.

**Key differences from browser_cdp**:
- Uses the user's real browser with existing login sessions
- Requires `bsk` CLI installed + daemon running + Chrome extension
- Coexists with `browser_cdp` — different use cases
- 3-tier binary resolution: app dir → workspace/tools/ → system PATH

**Session Management**:
```rust
pub struct BrowserSkillTool {
    session_id: Mutex<Option<String>>,  // Auto-managed
    workspace_dir: String,
}
```
- Auto-starts session on first use if none active
- `BSK_TIMEOUT_SECS = 60`
- `MAX_SNAPSHOT_LEN = 8000`, `MAX_HTML_LEN = 5000`

**17 Actions**:

| Action | Parameters | Description |
|--------|-----------|-------------|
| `status` | — | Check bsk daemon + browser connection |
| `session_start` | — | Start new browser session |
| `session_stop` | — | Stop current session |
| `navigate` | `url` | Go to URL |
| `snapshot` | — | Accessibility tree with @eN element refs |
| `screenshot` | `path?` | Screenshot → workspace/output/ |
| `get_html` | `ref?`/`selector?` | Page or element HTML |
| `click` | `ref`/`selector` | Click element |
| `fill` | `ref`/`selector` + `text` | Fill input field |
| `press` | `key` | Press key (Enter, Tab, Escape) |
| `select_option` | `ref`/`selector` + `text` | Select dropdown option |
| `evaluate` | `js` | Run JavaScript expression |
| `tab_list` | — | List all tabs |
| `tab_create` | `url?` | Create new tab |
| `tab_close` | `tab_id` | Close tab |
| `tab_select` | `tab_id` | Switch to tab |
| `request_help` | `text` | Pause and ask user for help |

**bsk Error Codes**: 1=User error, 2=Protocol error, 3=Browser error, 4=Timeout, 5=Version mismatch

### 5.12 Web Fetch Tool

**Location**: `src/tool/web_fetch.rs` (142 lines)

**web_fetch** (read-only):
- Fetches web page content via HTTP GET
- Parameters: `url` (required)
- Returns page text content for LLM consumption

### 5.13 Agent Utility Tools

**cron_manage** (`src/tool/cron_manage.rs`, 182 lines):
- Parameters: `action` (create|list|delete|toggle), `name`, `schedule`, `message`, `model`, `task_id`
- Wraps `Scheduler` behind `Arc<Mutex<Scheduler>>`
- Schedule format: "every Ns/Nm/Nh/Nd" or basic 5-field cron
- Returns task details including `interval_secs`, `next_run`

**memory_md** (`src/tool/memory_md.rs`, 107 lines):
- Parameters: `action` (write_memory|read_memory), `content`
- Reads/writes `workspace/MEMORY.md` — the curated long-term memory file
- Returns content or success confirmation

**todo_update** (`src/tool/todo_update.rs`, 214 lines):
- Parameters: `action` (set|update|clear|list), `items`, `index`, `status`
- Persistence: `workspace/todos.json`
- Statuses: pending, in_progress, completed, cancelled
- Returns full TODO list after each mutation

### 5.14 External Tools Manager

**Location**: `src/external_tools.rs` (228 lines)

**Purpose**: Auto-discover executable files in `workspace/tools/` directory.

**Discovery**:
```rust
pub struct ExternalToolsManager {
    tools_dir: PathBuf,
    tools: Vec<ExternalTool>,
    state_path: PathBuf,  // tools_state.json
}
```

**Supported extensions**: `.exe`, `.bat`, `.ps1`, `.cmd`

**Sidecar metadata**: Optional `.json` file alongside executable:
```json
{ "description": "Custom tool description", "name": "Friendly Name" }
```

**State persistence** (`tools_state.json`):
```rust
struct ToolsState {
    tools: HashMap<String, ToolStateEntry>,  // enabled, description overrides
}
```

**Tool handle generation**: Enabled tools registered as `ext_{name}` in the ToolRegistry.

### 5.15 Incident Response (IR) Tools Overview

**11 tools** ported from yinghuo + timeline reconstruction, all using PowerShell with UTF8 encoding prefix:
```rust
const PS_PREFIX: &str = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ";
```

All IR tools are builtin + read-only (except `ir_process` kill action).

| Tool | Location | Lines | Description |
|------|----------|-------|-------------|
| `ir_scan` | `ir_scan.rs` | 339 | 17-category collection scanner |
| `ir_process` | `ir_process.rs` | 291 | Process enumeration + risk classification + kill |
| `ir_account` | `ir_account.rs` | 143 | Account audit with hidden account detection |
| `ir_persistence` | `ir_persistence.rs` | 158 | Autoruns, tasks, services, WMI, startup enumeration |
| `ir_network` | `ir_network.rs` | 175 | Connections, DNS, routes, proxy, firewall, lateral movement |
| `ir_eventlog` | `ir_eventlog.rs` | 389 | Security/System/PowerShell event log collection |
| `ir_file` | `ir_file.rs` | 263 | File hashing + signature verification |
| `ir_driver` | `ir_driver.rs` | 140 | Driver signature scanning |
| `ir_analyzer` | `ir_analyzer.rs` | 594 | Rule-based anomaly detection engine (17 rules + MITRE ATT&CK) |
| `ir_report` | `ir_report.rs` | 266 | HTML report generation from findings |
| `ir_timeline` | `ir_timeline.rs` | 743 | Chronological event reconstruction from 7 sources |

#### 5.15.1 ir_scan — 17 Collection Categories

**Parameters**: `category` (all|basic|processes|network|autoruns|tasks|services|wmi|files|security-events|system-events|powershell-events|web-logs|defender|defender-history|sysmon|lateral|drivers), `days` (default 7), `max_events` (default 500)

**Category scripts**:
- **basic**: OS info, hotfixes (last 20), disk usage, network adapters
- **processes**: Top 30 by memory + processes in Temp/AppData/Downloads/Public
- **network**: Established TCP, DNS cache (50), routes (30), firewall profiles
- **autoruns**: HKCU/HKLM Run keys, RunOnce, startup folders
- **tasks**: Non-Microsoft scheduled tasks + recently created
- **services**: Non-Microsoft running + suspicious path services
- **wmi**: Event filters, consumers, bindings, startup commands
- **files**: Recently modified executables (7 days) + suspicious locations
- **security-events**: Failed logons (4625), successful logons (4624), account changes, log cleared (1102)
- **system-events**: Boot/shutdown (6005/6006/6008), service install (7045)
- **powershell-events**: Script block logs (4104), module logs (4103)
- **web-logs**: IIS access logs (last 100 lines), IIS sites
- **defender**: Status, threat history, exclusions
- **defender-history**: Scan history, recent threats
- **sysmon**: Service status, process creates (Event 1), network (Event 3)
- **lateral**: SMB shares, open files, sessions, connections, mappings, PsExec traces, RDP users
- **drivers**: Authenticode signature scan (unsigned, non-MS, revoked) + loaded kernel drivers

#### 5.15.2 ir_process — Risk Classification Engine

**Actions**: `list` (classify), `kill` (terminate by PID)

**Risk classification rules** (applied per-process):

| Rule | Condition | Risk Level |
|------|-----------|------------|
| Suspicious path | Path contains \Temp\, \AppData\, \Downloads\, \Users\Public\ | medium |
| ProgramData exe | Path in \ProgramData\ and ends with .exe | medium |
| System process spoof | Name matches svchost/lsass/csrss/services/smss/wininit/winlogon/lsm but path NOT in System32/SysWOW64 | high |
| EncodedCommand | Command line contains -EncodedCommand or -enc; auto-decodes base64→UTF-16LE | high |
| LOLBin pattern | Process name matches mshta/rundll32/certutil/bitsadmin/regsvr32/cmstp + suspicious indicators (http, temp, appdata, downloadstring, invoke-expression) | high |
| Dangerous pattern | Command contains -enc/downloadstring/invoke-expression/iex(/meterpreter/cobalt/mimikatz | high |
| High resource | CPU ≥ 60% or memory ≥ 2048MB | low |

**Base64 EncodedCommand decoder**:
```rust
fn try_decode_encoded(cmdline: &str) -> Option<String> {
    // Find -EncodedCommand/-enc marker → extract base64 chars → decode → UTF-16LE → String
}
```

**Parameters**: `action` (list|kill), `pid` (for kill), `risk_filter` (all|high|medium|low)

#### 5.15.3 ir_account — Hidden Account Detection

**PowerShell script** enumerates all local users with:
- Administrator group membership via `Get-LocalGroupMember`
- Hidden account detection via registry `SpecialAccounts\UserList`
- Dollar-suffix accounts (`$`) detection

**Anomaly flagging**:
| Condition | Anomaly |
|-----------|---------|
| `hidden == true` | "hidden account" |
| `enabled && !passwordRequired && name != "Guest"` | "enabled without password requirement" |
| `admin && hidden` | "hidden admin account (HIGH RISK)" |
| `enabled && lastLogon empty && not system account` | "enabled but never logged on (possible backdoor)" |

**Returns**: `{ summary: {total, enabled, admins, hidden, flagged}, flagged_accounts, all_accounts }`

#### 5.15.4 ir_persistence — 5 Enumeration Categories

| Category | Checks |
|----------|--------|
| autoruns | HKCU/HKLM Run, RunOnce (both hives), Boot Execute, Known DLLs |
| tasks | Non-Microsoft tasks, suspicious commands (powershell/cmd/wscript/cscript/mshta/rundll32/certutil/bitsadmin), recently created (30 days) |
| services | Non-MS running, suspicious paths, recently installed (Event 7045, 30 days) |
| wmi | Event filters, consumers, bindings, startup commands |
| startup | User/AllUsers startup folders, Shell Folders, Image File Execution Options (Debugger) |

#### 5.15.5 ir_network — 6 Categories

| Category | Checks |
|----------|--------|
| connections | Established TCP, listening ports, UDP listeners with process names |
| dns | DNS cache (100 entries), client settings, server addresses |
| routes | IPv4 route table, default gateway, ARP table |
| proxy | WinHTTP proxy, IE/system proxy (ProxyEnable/ProxyServer/AutoConfigURL) |
| firewall | Profiles, recently added rules (30 days), allow rules with programs |
| lateral | SMB shares/open files/sessions/connections/mappings, PsExec traces, RDP/DCom users |

#### 5.15.6 ir_analyzer — Rule-Based Anomaly Detection Engine

**Input**: JSON object with category keys → raw text values
**Output**: Structured findings with severity ratings

**15+ Detection Rules**:

| Rule ID | Category | Severity | Detection Logic |
|---------|----------|----------|----------------|
| `win.suspicious_path` | processes/services/autoruns/tasks | high | Executable in \AppData\, \Temp\, \Windows\Temp\, \Users\Public\, \Downloads\, \ProgramData\ with ext .exe/.dll/.ps1/.vbs/.js/.bat/.cmd |
| `win.lolbin_exec` | processes/tasks/autoruns/eventlogs | high | LOLBin name (mshta/rundll32/regsvr32/wscript/cscript/certutil/bitsadmin/wmic) + indicator (http/\appdata\/\temp\/-enc/downloadstring/iex() |
| `win.encoded_powershell` | processes/eventlogs/tasks | high | "powershell" + (-enc/-encodedcommand/downloadstring/frombase64string/invoke-expression/iex() |
| `win.eventlog_cleared` | eventlogs | critical | Event ID 1102 or "audit log was cleared" |
| `win.service_install` | eventlogs | high | Event ID 7045 |
| `win.account_change` | eventlogs | high | Events 4720/4722/4726 |
| `win.bruteforce_many` | eventlogs | high | ≥50 occurrences of Event ID 4625 |
| `win.bruteforce_some` | eventlogs | medium | 10-49 occurrences of Event ID 4625 |
| `win.wmi_persistence` | wmi | high | __EventFilter/CommandLineEventConsumer/ActiveScriptEventConsumer/__FilterToConsumerBinding |
| `win.external_established` | network | medium | Non-RFC1918 IPs in established TCP connections |
| `win.defender_disabled` | defender | high | RealTimeProtectionEnabled=False |
| `win.defender_exclusion` | defender | medium | ExclusionPath/ExclusionProcess present |
| `win.unsigned_driver` | drivers | high | NotSigned/Unsigned/未签名 |
| `win.psexec_service` | lateral | high | PSEXESVC service found |
| `web.suspicious_request` | web-logs | high | Web ext (.jsp/.aspx/.php) + danger cmd/eval/base64/whoami/powershell |
| `win.dns_suspicious_cache` | network | medium | DNS cache contains ngrok/frp/dnslog/burp/interactsh/duckdns/no-ip/serveo/pastebin/telegram/tor2web/onion |
| `win.hidden_account` | accounts | high | `"hidden":true` in account data |
| `win.unquoted_service_path` | services | medium | Service with unquoted path containing spaces + auto start |
| `collector.no_hit` | overall | pass | No rules matched |

**Finding structure** (with MITRE ATT&CK mapping):
```json
{ "id": "F-001", "rule_id": "win.suspicious_path", "severity": "high",
  "category": "processes", "title": "...", "evidence": "...", "recommendation": "...",
  "mitre_techniques": [
    { "id": "T1036", "name": "Masquerading", "tactic": "Defense Evasion" }
  ]
}
```

**MITRE ATT&CK Coverage** (17 rules → 30+ techniques):

| Rule ID | ATT&CK Techniques |
|---------|------------------|
| `win.suspicious_path` | T1036 Masquerading, T1564 Hide Artifacts |
| `win.lolbin_exec` | T1218 System Binary Proxy Execution |
| `win.encoded_powershell` | T1059.001 PowerShell, T1027 Obfuscated Files |
| `win.eventlog_cleared` | T1070.001 Indicator Removal: Clear Windows Event Logs |
| `win.service_install` | T1543.003 Create or Modify System Process: Windows Service |
| `win.bruteforce_*` | T1110 Brute Force |
| `win.wmi_persistence` | T1546.003 Event Triggered Execution: WMI |
| `win.defender_disabled` | T1562.001 Impair Defenses: Disable Tools |
| `win.unsigned_driver` | T1014 Rootkit, T1068 Exploitation for Privilege Escalation |
| `win.psexec_service` | T1021.002 Remote Services: SMB/Windows Admin Shares |
| `win.hidden_account` | T1136 Create Account |
| `win.dns_suspicious_cache` | T1071 Application Layer Protocol |
| `win.external_established` | T1071 Application Layer Protocol |
| `web.suspicious_request` | T1190 Exploit Public-Facing Application |
| `win.unquoted_service_path` | T1574.001 Hijack Execution Flow: Service Permissions Weakness |

#### 5.15.7 ir_timeline — Chronological Event Reconstruction

**Location**: `src/tool/ir_timeline.rs` (743 lines)

Reconstructs a unified chronological timeline from 7 Windows data sources with per-event risk scoring.

**Parameters**: `hours` (lookback, default 24), `risk_filter` (all|low|medium|high|critical), `max_events` (default 500), `sources` (all|process|logon|service|network|persistence|powershell|defender)

**Data Sources**:

| Source | Event IDs / Method | Risk Scoring |
|--------|-------------------|---------------|
| Processes | Sysmon EID 1 / Security 4688 | Suspicious path, encoded commands, LOLBins |
| Logons | Security 4624/4625/4672 | RDP, failed attempts, admin logon |
| Services | System 7045/7036 | Non-MS service install, suspicious paths |
| Network | `Get-NetTCPConnection` | External IPs, unusual ports |
| Persistence | Security 4698 + Run keys | Scheduled tasks, autorun entries |
| PowerShell | Script Block 4104 | Encoded commands, suspicious functions |
| Defender | 1116-1119 | Threat detections, scan failures |

**Risk Scoring** (0-100 per event):

| Indicator | Score |
|-----------|-------|
| Suspicious path (Temp/AppData/Downloads) | +30 |
| Encoded PowerShell command | +50 |
| LOLBin execution | +40 |
| Failed logon from external IP | +25 |
| Non-MS service install | +35 |
| Defender detection | +60 |
| Admin logon with high risk | +45 |

**Output**: Sorted timeline with `{ timestamp, source, event_type, description, risk_score, details }`

#### 5.15.8 ir_report — HTML Report Generator

**Input**: Findings JSON from ir_analyzer + optional title + output_path
**Output**: Self-contained HTML file with:
- Summary cards (critical/high/medium/total counts)
- Severity filter dropdown + text search
- Findings table with color-coded badges
- Priority advice section
- Print-friendly CSS
- Default path: `workspace/output/ir_report_TIMESTAMP.html`

### 5.16 Malware Analysis Tools Overview

**3 tools** + shared analysis module:

| Tool | Location | Lines | Description |
|------|----------|-------|-------------|
| `malware_scan` | `malware_scan.rs` | 131 | Quick static analysis (risk score + summary) |
| `malware_deep` | `malware_deep.rs` | 237 | Deep analysis (full PE detail + strings + disassembly) |
| — | `malware_analysis/mod.rs` | 753 | Core analysis pipeline |
| — | `malware_analysis/basic.rs` | 229 | Hash, entropy, string extraction |
| — | `malware_analysis/pe.rs` | 530 | PE header parsing via goblin |
| — | `malware_analysis/models.rs` | 285 | Data models |

#### 5.16.1 Analysis Pipeline

**Entry point**: `analyze_file(path, rules_dir) -> AnalysisResult`

**Parallel execution** via `std::thread::scope`:
```rust
let (basic_result, entropy_graph, pe_result, yara_matches) = std::thread::scope(|s| {
    let basic_handle = s.spawn(|| basic::analyze(data));
    let entropy_handle = s.spawn(|| compute_entropy_graph(data, 64));
    let pe_handle = s.spawn(|| if file_type == FileType::PE { pe::analyze(data).ok() } else { None });
    let yara_handle = s.spawn(|| load_or_compile_yara(data, rules_dir));
    // ... join all
});
```

**File type detection** via magic bytes:
- `0x4D5A` → PE
- `0x7F454C46` → ELF
- `0xFEEDFACE/CF` or `0xCEFAEDFE/FF` → Mach-O

#### 5.16.2 Basic Analysis (`basic.rs`)

**Parallel computation** via `rayon::join`:
- **Hashes**: MD5, SHA1, SHA256 (via sha2/md5/sha1 crates)
- **Shannon entropy**: `H = -Σ p(x) × log₂(p(x))` over 256-byte frequency distribution
- **String extraction**: Min length 4, ASCII graphic chars + space; categorized into:
  - `Url`, `IpAddress`, `FilePath`, `RegistryKey`, `Command`, `Suspicious`, `Normal`
- **Base64 auto-decode**: Strings that look like base64 are automatically decoded
- **Packer detection**: `is_packed = entropy > 7.0`

#### 5.16.3 PE Analysis (`pe.rs`)

Uses `goblin` crate for PE parsing:

**Extracted data**:
- COFF header: machine type, timestamp, characteristics
- Optional header: entry point, image base, subsystem, linker version
- Sections: name, virtual/raw size, entropy, flags (R/W/X), anomalies
- Imports: DLL → functions with **API risk classification** (Critical/High/Medium/Low)
- Exports, data directories
- Overlay (appended data after PE structure)
- Authenticode signature presence

**Anomaly detection per section**:
- W+X (writable + executable)
- High entropy (>7.0) — likely packed/encrypted
- Raw size 0 with non-zero virtual size
- Suspicious names: .upx, .themida, .vmp, .aspack, .adata, .nsp

**Timestamp analysis**:
- Zeroed timestamp → suspicious
- Future timestamp → suspicious
- Compilation age calculation

#### 5.16.4 Risk Scoring Algorithm

**5 components**, total capped at 100:

| Component | Max Score | Logic |
|-----------|-----------|-------|
| Entropy | 25 | >7.5→25, >7.0→15, >6.5→5, else 0 |
| Packing | 15 | is_packed→15, else 0 |
| Strings | 15 | Count of non-Normal strings, capped at 15 |
| API Risk | 25 | Critical→8, High→4, Medium→1 per function, capped at 25 |
| Anomaly | 25 | Critical→12, Warning→4 per anomaly, capped at 25 |

**Risk levels**: Clean (0-20), Low (21-40), Medium (41-60), High (61-80), Critical (81-100)

#### 5.16.5 Detection Checks (23 boolean checks)

| Check | Severity | Condition |
|-------|----------|----------|
| High entropy (>7.0) | High | `basic.entropy > 7.0` |
| Very high entropy (>7.5) | High | `basic.entropy > 7.5` |
| Packed binary | High | `basic.is_packed` |
| Suspicious strings | Low | Any non-Normal string category |
| URLs in strings | Medium | StringCategory::Url present |
| IP addresses | Medium | StringCategory::IpAddress present |
| Commands | Medium | StringCategory::Command present |
| Registry keys | Low | StringCategory::RegistryKey present |
| Suspicious keywords | Low | StringCategory::Suspicious present |
| Process injection APIs | Critical | VirtualAllocEx + WriteProcessMemory + CreateRemoteThread (all three) |
| Anti-debug APIs | High | IsDebuggerPresent/CheckRemoteDebuggerPresent/NtQueryInformationProcess/OutputDebugStringA |
| Network APIs | Medium | InternetOpen/WSAStartup/HttpOpenRequest/URLDownloadToFile |
| Crypto APIs | Medium | CryptEncrypt/CryptDecrypt/CryptAcquireContext/CryptGenKey |
| Service manipulation APIs | Low | CreateService/OpenService/StartService/ChangeServiceConfig |
| W+X section | Critical | Any section with both writable + executable flags |
| High entropy section | High | Any section with entropy > 7.0 |
| Suspicious section name | High | .upx/.themida/.vmp/.aspack/.nsp/.enigma prefix |
| Zeroed timestamp | Low | `pe.timestamp == 0` |
| Future timestamp | Low | `pe.timestamp_suspicious && timestamp > 0` |
| No imports | Info | `pe.imports.is_empty()` |
| Entry point anomaly | Low | Entry point outside first section |
| Known packer detected | High | `pe.packer_detected.is_some()` |
| File paths in strings | Info | StringCategory::FilePath present |

#### 5.16.6 Malware Pattern Matching (6 patterns)

| Pattern | Confidence | Conditions |
|---------|------------|------------|
| Trojan.Injector | High | Process injection APIs (all 3) + network APIs |
| Ransomware.Generic | Medium | Crypto APIs + ransom strings (ransom/bitcoin/wallet/encrypt/decrypt/.onion) |
| Packed.Evasive | Medium | Anti-debug APIs + is_packed + entropy > 7.0 |
| Trojan.Downloader | Medium | Network APIs + command strings + URLs |
| Spyware.Keylogger | Low | Keylogger strings + network APIs |
| Trojan.Persistence | Medium | Service APIs + registry keys + auto-run paths |

#### 5.16.7 YARA Scanning

**Rule management**:
- Embedded at compile time via `build.rs` → `rules_embedded.rs`
- Extracted to `workspace/rules/` on first use if directory empty
- Binary cache (`.yara_cache`): 32-byte SHA-256 fingerprint + serialized scanner
- Cache invalidation: fingerprint recomputed over all rule file paths + contents

**Scanning**: Uses `boreal` crate for YARA rule compilation and memory scanning.

#### 5.16.8 Entropy Graph

- Computed via `rayon` parallel chunks: 64 chunks across file
- Each chunk: Shannon entropy × 100 → u64
- Used for visual analysis of file structure

#### 5.16.9 malware_scan vs malware_deep

| Feature | malware_scan | malware_deep |
|---------|-------------|-------------|
| Risk score + level | ✓ | ✓ |
| Hashes (MD5/SHA1/SHA256) | ✓ | ✓ |
| YARA matches | ✓ | ✓ |
| Triggered checks (names only) | ✓ | ✓ |
| Malware pattern | ✓ | ✓ |
| PE summary (brief) | ✓ | — |
| Full detection checks (with severity) | — | ✓ |
| All extracted strings (categorized) | — | ✓ |
| Entropy graph data points | — | ✓ |
| PE sections (detail per section) | — | ✓ |
| PE imports (with risk per function) | — | ✓ |
| PE exports | — | ✓ |
| Data directories | — | ✓ |
| PE anomalies (detail) | — | ✓ |
| Entry point hex dump | — | ✓ |
| Entry point disassembly (iced-x86, NASM, 30 instructions) | — | ✓ |
| Overlay info | ✓ | ✓ |

### 5.17 Complete Tool Quick Reference

| # | Tool Name | Category | Read-Only | Source File | Description |
|---|-----------|----------|-----------|-------------|-------------|
| 1 | `file_read` | read | ✓ | file_ops.rs | Read file contents with optional line range |
| 2 | `file_write` | write | — | file_ops.rs | Write content to file (auto-creates dirs) |
| 3 | `file_delete` | delete | — | file_ops.rs | Delete file or directory |
| 4 | `file_modify` | modify | — | file_ops.rs | Search and replace text in file |
| 5 | `file_list` | read | ✓ | file_ops.rs | List directory with glob filter + recursion |
| 6 | `shell_exec` | execute | — | shell_exec.rs | Execute PowerShell/CMD commands |
| 7 | `sys_info` | read | ✓ | sys_info.rs | System information |
| 8 | `sys_process` | read | ✓ | sys_process.rs | Process listing |
| 9 | `sys_service` | read | ✓ | sys_service.rs | Windows service enumeration |
| 10 | `sys_eventlog` | read | ✓ | sys_eventlog.rs | Recent event logs |
| 11 | `sys_remind` | write | — | sys_remind.rs | Schedule reminder notification |
| 12 | `app_launch` | execute | — | app_launch.rs | Launch application |
| 13 | `browser_open` | execute | — | browser_open.rs | Open URL in default browser |
| 14 | `web_fetch` | read | ✓ | web_fetch.rs | Fetch web page content |
| 15 | `browser_cdp` | write | — | browser_cdp.rs | Chrome DevTools Protocol automation (10 actions) |
| 16 | `browser_skill` | write | — | browser_skill.rs | Browser automation via bsk CLI (17 actions) |
| 17 | `cron_manage` | write | — | cron_manage.rs | Manage CRON scheduled tasks |
| 18 | `memory_md` | write | — | memory_md.rs | Read/write MEMORY.md long-term memory |
| 19 | `todo_update` | write | — | todo_update.rs | Track multi-step task progress |
| 20 | `ir_scan` | read | ✓ | ir_scan.rs | 17-category IR collection |
| 21 | `ir_process` | read* | ✓ | ir_process.rs | Process risk classification + kill |
| 22 | `ir_account` | read | ✓ | ir_account.rs | Account audit + hidden detection |
| 23 | `ir_persistence` | read | ✓ | ir_persistence.rs | Persistence mechanism enumeration |
| 24 | `ir_network` | read | ✓ | ir_network.rs | Network analysis (6 categories) |
| 25 | `ir_eventlog` | read | ✓ | ir_eventlog.rs | Event log collection |
| 26 | `ir_file` | read | ✓ | ir_file.rs | File hashing + verification |
| 27 | `ir_driver` | read | ✓ | ir_driver.rs | Driver signature scanning |
| 28 | `ir_analyzer` | read | ✓ | ir_analyzer.rs | Rule-based anomaly detection (17 rules + ATT&CK) |
| 29 | `ir_report` | read | ✓ | ir_report.rs | HTML IR report generation |
| 30 | `ir_timeline` | read | ✓ | ir_timeline.rs | Chronological event reconstruction (7 sources) |
| 31 | `malware_scan` | read | ✓ | malware_scan.rs | Quick static malware analysis |
| 32 | `malware_deep` | read | ✓ | malware_deep.rs | Deep PE analysis + disassembly |
| 33 | `ext_{name}` | execute | — | external_exec.rs | External tools from workspace/tools/ (dynamic) |
| 34+ | MCP tools | varies | varies | mcp_client.rs | Dynamic from connected MCP servers |
| 35+ | Skill tools | varies | varies | skill/mod.rs | install_skill, list_skills, remove_skill |

---

## 6. Memory System

### 6.1 SQLite Schema

**Location**: `src/memory.rs` (1030 lines)

**4 Schema Versions**:

**v1** (core tables):
```sql
CREATE TABLE conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,
    session_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    tool_name TEXT,
    timestamp TEXT NOT NULL
);
CREATE INDEX idx_conv_date ON conversations(date);
CREATE INDEX idx_conv_session ON conversations(session_id);

CREATE TABLE summaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL UNIQUE,
    summary TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE schema_version (version INTEGER NOT NULL);
```

**v2** (FTS5 full-text search):
```sql
CREATE VIRTUAL TABLE conversations_fts USING fts5(
    content,
    tokenize='unicode61 remove_diacritics 0'
);
-- Backfill existing conversations with CJK preprocessing
```

**v3** (task checkpoints):
```sql
CREATE TABLE task_checkpoints (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    model_name TEXT NOT NULL,
    user_message TEXT NOT NULL,
    history_json TEXT NOT NULL,  -- Serialized Vec<ChatMessage>
    iteration INTEGER NOT NULL DEFAULT 0,
    tool_summary TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

**v4** (usage tracking):
```sql
CREATE TABLE usage_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    model_name TEXT NOT NULL,
    session_id TEXT,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_usage_ts ON usage_stats(timestamp);
CREATE INDEX idx_usage_model ON usage_stats(model_name);
```

**WAL Mode**: Enabled for better concurrent performance
```rust
conn.execute_batch("PRAGMA journal_mode=WAL;")?;
```

### 6.2 CJK Full-Text Search

**Problem**: FTS5's `unicode61` tokenizer doesn't handle CJK text well (no word boundaries)

**Solution**: CJK bigram tokenization with preprocessing

**Preprocessing** (before indexing):
```rust
fn preprocess_for_fts(text: &str) -> String {
    // Insert spaces between consecutive CJK characters
    let mut result = String::new();
    let mut prev_cjk = false;
    for ch in text.chars() {
        if is_cjk_char(ch) {
            if prev_cjk { result.push(' '); }
            result.push(ch);
            prev_cjk = true;
        } else {
            if prev_cjk { result.push(' '); }
            result.push(ch);
            prev_cjk = false;
        }
    }
    result
}
```

**Query Tokenization**:
```rust
fn build_fts_query_tokens(query: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    for word in query.split_whitespace() {
        let chars: Vec<char> = word.to_lowercase().chars().collect();
        let has_cjk = chars.iter().copied().any(is_cjk_char);
        
        if has_cjk {
            // Generate CJK bigram phrase queries
            for window in chars.windows(2) {
                let c0 = window[0];
                let c1 = window[1];
                if is_cjk_char(c0) || is_cjk_char(c1) {
                    let s = format!("{} {}", c0, c1);
                    tokens.push(format!("\"{}\"", s));  // Quoted phrase
                }
            }
            // Single-char queries
            if chars.len() == 1 && is_cjk_char(chars[0]) {
                tokens.push(format!("\"{}\"", chars[0]));
            }
        } else {
            // Latin word — quoted exact match
            tokens.push(format!("\"{}\"", word.to_lowercase()));
        }
    }
    tokens  // Joined with " OR " for FTS5 MATCH
}
```

**Search with BM25 Ranking**:
```rust
pub fn search_entries(&self, query: &str, days: usize) -> Result<Vec<ConversationEntry>> {
    let tokens = build_fts_query_tokens(query);
    let fts_query = tokens.join(" OR ");
    let since = (Utc::now() - chrono::Duration::days(days as i64)).format("%Y-%m-%d");
    
    let mut stmt = conn.prepare(
        "SELECT c.* FROM conversations_fts f
         JOIN conversations c ON c.rowid = f.rowid
         WHERE conversations_fts MATCH ?1 AND c.date >= ?2
         ORDER BY bm25(conversations_fts)
         LIMIT 30"
    )?;
    // ...
}
```

**Fallback**: If FTS5 table missing, linear scan with keyword matching

### 6.3 Memory Recall

**Trigger Detection** (in server.rs):
```rust
fn is_recall_query(query: &str) -> bool {
    let lower = query.to_lowercase();
    // Chinese keywords
    let zh_keywords = ["昨天", "上次", "之前", "记得", "回忆", "过去", "历史", "以前"];
    // English keywords
    let en_keywords = ["yesterday", "last time", "before", "remember", "recall", "history", "previously"];
    
    zh_keywords.iter().any(|k| lower.contains(k)) || 
    en_keywords.iter().any(|k| lower.contains(k))
}
```

**Recall Context Building**:
```rust
pub fn build_recall_context(&self, query: &str, days: usize) -> Result<String> {
    let entries = self.search_entries(query, days)?;
    if entries.is_empty() { return Ok("No relevant memories found.".to_string()); }
    
    let mut context = String::from("[Memory Recall]\n");
    for entry in &entries {
        context.push_str(&format!(
            "- [{} {}] {}: {}\n",
            entry.date, entry.timestamp, entry.role, 
            entry.content.chars().take(200).collect::<String>()
        ));
    }
    Ok(context)
}
```

---

## 7. Skill System

### 7.1 Skill Structure

**Location**: `src/skill/mod.rs` (625 lines)

**Directory Layout**:
```
workspace/skills/
  ├── skill_name_1/
  │   ├── SKILL.md          # YAML frontmatter + markdown body
  │   └── additional_files  # Optional
  ├── skill_name_2/
  │   └── SKILL.md
  └── skills_state.json     # Enabled/disabled state
```

**SKILL.md Format**:
```markdown
---
name: "Vulnerability Prioritization"
description: "Prioritize vulnerabilities based on CVSS score and exploitability"
triggers:
  - "prioritize vulnerabilities"
  - "vulnerability scoring"
---

# Vulnerability Prioritization Skill

This skill helps you prioritize vulnerabilities...
```

**Parsing**:
```rust
fn parse_skill_file(path: &Path, skill_dir: String) -> Result<Skill> {
    let content = std::fs::read_to_string(path)?;
    let (frontmatter, body) = split_frontmatter(&content)?;
    let metadata: SkillMetadata = serde_yaml::from_str(&frontmatter)?;
    Ok(Skill { metadata, content: body.trim().to_string(), ... })
}
```

### 7.2 Weighted Token Overlap Scoring

**Algorithm** (inspired by adk-skill's lexical overlap model):

```rust
pub fn find_matching_with(&self, user_message: &str, policy: &SelectionPolicy) -> Vec<(String, f32)> {
    let query_tokens = Self::tokenize(user_message);
    
    let mut scored: Vec<(String, f32)> = skills.iter()
        .filter(|s| s.metadata.enabled)
        .filter_map(|s| {
            let score = Self::score_skill(s, &query_tokens, user_message);
            if score >= policy.min_score { Some((s.content.clone(), score)) }
            else { None }
        }).collect();
    
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
    scored.truncate(policy.top_k);  // Default: top 3
    scored
}

fn score_skill(skill: &Skill, query_tokens: &[String], message: &str) -> f32 {
    let mut score: f32 = 0.0;
    let msg_lower = message.to_lowercase();
    
    // Name match: ×4.0
    let name_tokens = Self::tokenize(&skill.metadata.name);
    let name_hits = query_tokens.iter().filter(|t| name_tokens.contains(t)).count();
    score += name_hits as f32 * 4.0;
    
    // Description match: ×2.5
    let desc_tokens = Self::tokenize(&skill.metadata.description);
    let desc_hits = query_tokens.iter().filter(|t| desc_tokens.contains(t)).count();
    score += desc_hits as f32 * 2.5;
    
    // Trigger token match: ×2.0
    for trigger in &skill.metadata.triggers {
        let trigger_tokens = Self::tokenize(trigger);
        let trigger_hits = query_tokens.iter().filter(|t| trigger_tokens.contains(t)).count();
        score += trigger_hits as f32 * 2.0;
        // Bonus: full trigger phrase appears as substring
        if !trigger.is_empty() && msg_lower.contains(&trigger.to_lowercase()) {
            score += 10.0;
        }
    }
    
    // Body token overlap: ×1.0
    let body_tokens = Self::tokenize(&skill.content);
    let body_hits = query_tokens.iter().filter(|t| body_tokens.contains(t)).count();
    score += body_hits as f32 * 1.0;
    
    // Normalize: prevent large documents from dominating
    let body_token_count = body_tokens.len().max(1);
    score / (body_token_count as f32).sqrt()
}
```

**Tokenizer** (CJK-aware):
```rust
fn tokenize(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            current.push(ch.to_ascii_lowercase());
        } else if !ch.is_ascii() && ch.is_alphanumeric() {
            // CJK: emit as individual tokens
            if current.len() >= 3 { tokens.push(mem::take(&mut current)); }
            else { current.clear(); }
            tokens.push(ch.to_lowercase().to_string());
        } else {
            if current.len() >= 3 { tokens.push(mem::take(&mut current)); }
            else { current.clear(); }
        }
    }
    if current.len() >= 3 { tokens.push(current); }
    tokens
}
```

### 7.3 Meta-Tools

**install_skill**:
```rust
struct InstallSkillTool { skills_dir: PathBuf, skills: Arc<RwLock<Vec<Skill>>> }

async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value> {
    let name = args["name"].as_str().ok_or("Missing name")?;
    let description = args["description"].as_str().unwrap_or("");
    let triggers: Vec<String> = args["triggers"].as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let content = args["content"].as_str().unwrap_or("");
    
    // Support additional files
    let files: Option<Vec<(String, String)>> = args["files"].as_array().map(|arr| {
        arr.iter().filter_map(|f| {
            let path = f["path"].as_str()?;
            let content = f["content"].as_str()?;
            Some((path.to_string(), content.to_string()))
        }).collect()
    });
    
    self.create_skill_with_files(name, description, &triggers, content, files)?;
    Ok(json!({"status": "installed", "name": name}))
}
```

**list_skills**: Returns JSON array of skill metadata
**remove_skill**: Deletes skill directory and reloads

### 7.4 Built-in IR Workflow Skills

Three pre-built skill playbooks for structured incident response:

| Skill | Directory | Phases | Description |
|-------|-----------|--------|-------------|
| **IncidentTriage** | `skills/IncidentTriage/` | 5 | Parallel Collection → Rule Analysis → Conditional Deep-Dive → Timeline → Report |
| **MalwareAnalysis** | `skills/MalwareAnalysis/` | 5 | Identify Target → Static Analysis → Behavioral Context → IOC Extraction → Verdict |
| **FullHunt** | `skills/FullHunt/` | 6 | Full Collection → Malware Sweep → Analysis → Log Deep-Dive → Timeline → Report |

**IncidentTriage** workflow leverages parallel IR collection (Section 5.2.1) to execute all collection tools concurrently in Phase 1, then uses `ir_analyzer` for rule-based scoring, `ir_timeline` for chronological reconstruction, and `ir_report` for final output.

---

## 8. Server & WebSocket Protocol

### 8.1 AppState

**Location**: `src/server.rs` (1435 lines)

```rust
pub struct AppState {
    pub runner: Arc<Runner>,
    pub skill_manager: Arc<SkillManager>,
    pub mcp_manager: Arc<Mutex<McpClientManager>>,
    pub tools: Arc<tokio::sync::RwLock<ToolRegistry>>,
    pub logger: Arc<ConversationLogger>,
    pub memory_store: Arc<MemoryStore>,
    pub external_tools: Arc<Mutex<ExternalToolsManager>>,
    pub password: String,
    pub model_configs: Arc<tokio::sync::RwLock<Vec<ModelConfig>>>,
    pub model_store_path: String,
    pub max_iterations: usize,
    pub rabbit_hole_threshold: usize,
    pub context_window_threshold: usize,
    pub tool_timeout_secs: usize,
    pub max_tool_retries: usize,
    pub sessions: Mutex<HashMap<String, Vec<ChatMessage>>>,
    pub permissions: Arc<Mutex<HashMap<String, bool>>>,
    pub permission_resolver: PermissionResolver,
    pub permission_pending: PendingMap,
    pub scheduler: Arc<Mutex<Scheduler>>,
    pub notify_tx: NotifyTx,
    pub workspace_dir: String,
    pub provider: Arc<OpenAiProvider>,
}
```

### 8.2 REST API Routes

```rust
Router::new()
    .route("/", get(index_handler))
    .route("/static/{*path}", get(static_handler))
    .route("/ws", get(ws_handler))
    // Models
    .route("/api/models", get(models_handler))
    .route("/api/providers", get(providers_handler))
    .route("/api/providers", post(providers_create_handler))
    .route("/api/providers/{name}", put(providers_update_handler))
    .route("/api/providers/{name}", delete(providers_delete_handler))
    // Skills
    .route("/api/skills", get(skills_handler))
    .route("/api/skills", post(skills_create_handler))
    .route("/api/skills/reload", post(skills_reload_handler))
    .route("/api/skills/{name}", delete(skills_delete_handler))
    .route("/api/skills/{name}/toggle", post(skills_toggle_handler))
    // MCP
    .route("/api/mcp", get(mcp_handler))
    .route("/api/mcp", post(mcp_create_handler))
    .route("/api/mcp/{name}", delete(mcp_delete_handler))
    .route("/api/mcp/{name}/toggle", post(mcp_toggle_handler))
    .route("/api/mcp/{name}/restart", post(mcp_restart_handler))
    // Logs
    .route("/api/logs", get(logs_handler))
    .route("/api/logs/dates", get(log_dates_handler))
    // CRON
    .route("/api/cron", get(cron_list_handler))
    .route("/api/cron", post(cron_create_handler))
    .route("/api/cron/{id}", put(cron_update_handler))
    .route("/api/cron/{id}", delete(cron_delete_handler))
    .route("/api/cron/{id}/toggle", post(cron_toggle_handler))
    // Notifications
    .route("/api/notify", post(notify_handler))
    // Memory
    .route("/api/memory/dates", get(memory_dates_handler))
    .route("/api/memory/summaries", get(memory_summaries_handler))
    .route("/api/memory", get(memory_entries_handler))
    .route("/api/memory/summarize", post(memory_summarize_handler))
    // History & Usage
    .route("/api/history", get(history_handler))
    .route("/api/usage", get(usage_handler))
    .route("/api/usage/today", get(usage_today_handler))
    // Tools
    .route("/api/tools", get(tools_handler))
    .route("/api/tools/{name}/toggle", post(tools_toggle_handler))
    .route("/api/tools/{name}/description", post(tools_desc_handler))
    // Config files
    .route("/api/config/files", get(config_files_handler))
    .route("/api/config/files/{name}", put(config_file_save_handler))
    // Checkpoints
    .route("/api/checkpoints", get(checkpoints_list_handler))
    .route("/api/checkpoints/{id}", delete(checkpoints_delete_handler))
    // Workspace files
    .route("/workspace/{*path}", get(workspace_file_handler))
```

### 8.3 WebSocket Protocol

**Connection Flow**:

1. **Auth Phase** (30s timeout):
   ```
   Client → Server: {"type": "auth", "password": "123456"}
   Server → Client: {"type": "auth_ok"} or {"type": "auth_fail"}
   ```

2. **Chat Phase**:
   ```
   Client → Server: {
     "type": "chat",
     "message": "What's my IP?",
     "session_id": "abc123",
     "model": "llmgw-qwen3.6",
     "images": []  // Optional base64 data URIs
   }
   ```

3. **Server Event Stream** (JSON messages):
   ```
   // Thinking (reasoning_content)
   {"type": "thinking", "content": "Let me check the IP...", "meta": {...}}
   
   // Text delta
   {"type": "text", "content": "Your IP is", "meta": {...}}
   
   // Tool call
   {"type": "tool_call", "name": "shell_exec", "call_id": "call_1", "args": {"command": "ipconfig"}, "meta": {...}}
   
   // Tool result
   {"type": "tool_result", "name": "shell_exec", "call_id": "call_1", "result": {...}, "meta": {...}}
   
   // Progress (long-running tools)
   {"type": "progress", "tool_name": "malware_scan", "message": "Scanning...", "elapsed_secs": 5, "meta": {...}}
   
   // Permission request
   {"type": "permission_request", "request_id": "req_1", "tool_name": "file_delete", "category": "delete", "args": {...}, "meta": {...}}
   
   // Permission response (from client)
   Client → Server: {"type": "permission_response", "request_id": "req_1", "allowed": true}
   
   // Error
   {"type": "error", "message": "Tool execution failed", "meta": {...}}
   
   // Token usage
   {"type": "usage", "model": "llmgw-qwen3.6", "prompt_tokens": 1500, "completion_tokens": 200, "total_tokens": 1700, "meta": {...}}
   
   // Done
   {"type": "done", "meta": {...}}
   ```

4. **Checkpoint Resume**:
   ```
   Client → Server: {"type": "resume_checkpoint", "checkpoint_id": "cp_123"}
   Server → Client: (streams remaining events from checkpoint)
   ```

5. **Notifications** (broadcast to all clients):
   ```
   Server → All Clients: {
     "type": "notification",
     "message": "⚙️ **CRON: Disk Check** (5s)\n\nDisk usage: 75%",
     "timestamp": "2026-07-20T10:30:00Z"
   }
   ```

**Event Metadata** (EventMeta):
```rust
pub struct EventMeta {
    pub id: String,              // UUID v4
    pub timestamp: DateTime<Utc>,
    pub invocation_id: String,
    pub author: String,          // Agent name or "user"
}
```

---

## 9. Permission System

### 9.1 Permission Categories

**Location**: `src/permission.rs` (214 lines)

```rust
pub fn tool_category(name: &str) -> &'static str {
    match name {
        // Read — pure information gathering, no side effects
        "file_read" | "file_list" | "sys_info" | "sys_eventlog" | "browser_open" | "web_fetch"
        | "ir_scan" | "ir_account" | "ir_persistence" | "ir_network" | "ir_eventlog"
        | "ir_file" | "ir_driver" | "ir_analyzer" | "ir_report"
        | "ir_weblog_scan" | "ir_evtx_parse" | "ir_log_parse" | "ir_pcap_analyze"
        | "malware_scan" | "malware_deep" => "read",
        // Write — creates/overwrites content
        "file_write" | "memory_md" | "todo_update" => "write",
        // Delete
        "file_delete" => "delete",
        // Modify — changes state of existing resources
        "file_modify" | "sys_process" | "sys_service" | "ir_process"
        | "browser_cdp" | "browser_skill" | "cron_manage" => "modify",
        // Execute — arbitrary code execution
        "shell_exec" | "app_launch" => "execute",
        // Default: unknown tools (MCP, external) require endorsement
        _ => "execute",
    }
}
```

**Default Permissions**:
```rust
pub fn default_permissions() -> HashMap<String, bool> {
    let mut m = HashMap::new();
    m.insert("read".to_string(), true);     // Allowed
    m.insert("write".to_string(), true);    // Allowed
    m.insert("delete".to_string(), false);  // Requires endorsement
    m.insert("modify".to_string(), true);   // Allowed
    m.insert("execute".to_string(), false); // Requires endorsement
    m
}
```

### 9.2 Cross-Category Bypass Detection

**Purpose**: Prevent the LLM from using `shell_exec` (execute category) to bypass `file_delete` (delete category) denial.

```rust
fn detect_intent_category(tool_name: &str, args: &Value) -> Option<&'static str> {
    if tool_name != "shell_exec" && tool_name != "app_launch" {
        return None;
    }
    let command = args["command"].as_str().unwrap_or("");
    let shell = args["shell"].as_str().unwrap_or("powershell");
    let intent = crate::policy::parse::parse_intent(command, shell);

    match intent.verb {
        Verb::Delete => Some("delete"),   // Deletion via shell bypasses file_delete permission
        Verb::Format => Some("modify"),   // Format/disk ops bypass modify permission
        _ => None,
    }
}
```

**Flow**: If `shell_exec` is pre-authorized (execute=allowed) but the command's intent maps to a DENIED category (e.g., delete), the system escalates to user confirmation instead of silently allowing.

### 9.3 Async Permission Gate

**Flow**:

1. **PermissionChecker** (agent-side):
   ```rust
   pub async fn check(&self, tool_name: &str, args: &Value) -> bool {
       let category = tool_category(tool_name);
       
       // Check if auto-allowed
       {
           let perms = self.permissions.lock().await;
           if perms.get(category).copied().unwrap_or(false) {
               return true;
           }
       }
       
       // Requires endorsement — pause and ask user
       let request_id = uuid::Uuid::new_v4().to_string();
       let (tx_resp, rx_resp) = oneshot::channel::<bool>();
       
       // Store sender in pending map
       {
           let mut pending = self.pending.lock().await;
           pending.insert(request_id.clone(), tx_resp);
       }
       
       // Emit permission_request event to client
       let event = AgentEvent::permission_request(&request_id, tool_name, category, args, ...);
       let _ = self.tx.send(Ok(event)).await;
       
       // Wait for user response
       match rx_resp.await {
           Ok(allowed) => allowed,
           Err(_) => false,  // Channel dropped, deny by default
       }
   }
   ```

2. **PermissionResolver** (server-side):
   ```rust
   pub async fn resolve(&self, request_id: &str, allowed: bool) {
       let sender = {
           let mut pending = self.pending.lock().await;
           pending.remove(request_id)
       };
       if let Some(sender) = sender {
           let _ = sender.send(allowed);
       }
   }
   ```

3. **Client Response**:
   ```
   Client → Server: {"type": "permission_response", "request_id": "req_1", "allowed": true}
   ```

---

## 10. Checkpoint/Resume System

### 10.1 Checkpoint Structure

```rust
pub struct TaskCheckpoint {
    pub id: String,
    pub session_id: String,
    pub model_name: String,
    pub user_message: String,
    pub history_json: String,  // Serialized Vec<ChatMessage>
    pub iteration: usize,
    pub tool_summary: String,  // Human-readable: "bash, read_file (3 rounds)"
    pub created_at: String,
    pub updated_at: String,
}
```

### 10.2 Checkpoint Save Flow

**When**: After each tool execution in agent loop

```rust
if let Some(ref cp) = checkpointer {
    if let Some(ref cp_id) = checkpoint_id {
        cp.save(cp_id, &session_id, &active_model, &user_message, &history, iteration)?;
    }
}
```

**Implementation**:
```rust
pub fn save(&self, id: &str, session_id: &str, model_name: &str, 
            user_message: &str, history: &[ChatMessage], iteration: usize) -> Result<()> {
    let history_json = serde_json::to_string(history)?;
    let tool_summary = Self::build_tool_summary(history);
    let now = Utc::now().to_rfc3339();
    
    let conn = self.memory_store.conn().lock().unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO task_checkpoints 
         (id, session_id, model_name, user_message, history_json, iteration, tool_summary, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![id, session_id, model_name, user_message, history_json, iteration, tool_summary, now, now],
    )?;
    Ok(())
}
```

### 10.3 Checkpoint Resume Flow

**Trigger**: Client sends `{"type": "resume_checkpoint", "checkpoint_id": "cp_123"}`

**Server Handler**:
```rust
async fn resume_checkpoint(state: &AppState, checkpoint_id: &str) -> Result<EventStream> {
    let checkpoint = state.memory_store.get_checkpoint(checkpoint_id)?;
    let history: Vec<ChatMessage> = serde_json::from_str(&checkpoint.history_json)?;
    
    let resume_state = ResumeState {
        history,
        start_iteration: checkpoint.iteration,
    };
    
    state.runner.run(
        &checkpoint.user_message,
        &checkpoint.session_id,
        &checkpoint.model_name,
        state.max_iterations,
        vec![],  // Empty (history in resume_state)
        state.permissions.clone(),
        state.permission_pending.clone(),
        None,  // No fallback model
        state.rabbit_hole_threshold,
        128000,  // Default context window
        state.context_window_threshold,
        state.tool_timeout_secs as u64,
        state.max_tool_retries,
        vec![],  // No images
        Some(checkpoint_id.to_string()),
        Some(resume_state),
    ).await
}
```

**Agent Loop Resume**:
```rust
if let Some(resumed_hist) = resume_history {
    history = resumed_hist;
    // Skip adding user message (already in history)
}
let start_iter = resume_iteration.unwrap_or(0);
for iteration in start_iter..max_iter { ... }
```

**Cleanup**:
- On task completion: checkpoint deleted
- On startup: stale checkpoints (>24 hours) cleaned up

---

## 11. Knowledge Distillation

### 11.1 Overview

**Location**: `src/distill.rs` (265 lines)

**Purpose**: Extract valuable knowledge from completed sessions and persist in structured markdown files

**Trigger**: End-of-session (WebSocket connection closed)

**Categories**:
- `facts` — Environment facts, user preferences
- `decisions` — Technical decisions made
- `lessons` — Lessons learned from errors
- `preferences` — User workflow preferences
- `skill_hints` — Hints for skill creation

### 11.2 Distillation Flow

```rust
pub async fn distill_session(
    session_id: &str,
    history: &[ChatMessage],
    provider: Arc<OpenAiProvider>,
    model_name: &str,
    workspace_dir: &str,
) -> Result<usize> {
    // Filter to user+assistant messages only
    let relevant: Vec<&ChatMessage> = history.iter()
        .filter(|m| m.role == "user" || m.role == "assistant")
        .collect();
    
    if relevant.len() < MIN_MESSAGES { return Ok(0); }  // MIN_MESSAGES = 4
    
    // Build compact summary (500 chars/msg, 8000 total)
    let summary = build_summary(&relevant);
    
    // Build distillation prompt
    let messages = build_distillation_messages(&summary);
    
    // Call LLM (non-streaming, temp=0.3, max_tokens=4096)
    let response = provider.chat_simple(model_name, &messages).await?;
    
    // Parse JSON response
    let entries = parse_distillation_response(&response)?;
    
    // Append to category files
    let knowledge_dir = Path::new(workspace_dir).join("knowledge");
    for entry in &entries {
        let file_path = knowledge_dir.join(format!("{}.md", entry.category));
        let block = format!(
            "\n## {} — {}\n\
             - **Content:** {}\n\
             - **Trigger:** {}\n\
             - **Context:** {}\n\
             - **Source:** {}\n\
             - **Confidence:** {}\n",
            today, entry.title, entry.content, entry.trigger, entry.context, entry.source, entry.confidence
        );
        // Append to file
    }
    
    Ok(entries.len())
}
```

### 11.3 Distillation Prompt

**System Message**:
```
You are a knowledge extraction assistant. Review the following conversation 
and extract valuable knowledge worth preserving for future sessions. 
Focus on: user preferences, environment facts, technical decisions, lessons from errors, 
and workflow patterns.

For each item, output a JSON object with these fields:
- "category": one of "facts", "decisions", "lessons", "preferences", "skill_hints"
- "title": short descriptive title (5-10 words, like a heading)
- "content": the core knowledge (1-2 sentences, in the user's language)
- "trigger": what triggered this knowledge (e.g. "user reported error X", "user stated preference", "tool failed because...")
- "context": why it happened / background (root cause, circumstances, 1-2 sentences)
- "source": brief reference (e.g. "user stated", "error occurred", "debugging session")
- "confidence": "high", "medium", or "low"

Rules:
- Skip trivial exchanges (greetings, simple confirmations).
- Merge related items into one entry.
- Output ONLY a valid JSON array. No markdown, no explanation.
- If nothing is worth preserving, return [].
```

**User Message**:
```
Extract knowledge from this conversation:

{summary}
```

---

## 12. Scheduler & Heartbeat

### 12.1 CRON Scheduler

**Location**: `src/scheduler.rs` (360 lines)

**Task Structure**:
```rust
pub struct CronTask {
    pub id: String,
    pub name: String,
    pub schedule: String,       // "every 5m", "every 1h", or basic cron
    pub message: String,        // Chat message to send
    pub model: String,          // Model to use (empty = default)
    pub enabled: bool,
    pub last_run: Option<String>,
    pub next_run: Option<String>,
    pub interval_secs: u64,
}
```

**Schedule Parsing**:
```rust
pub fn parse_interval(schedule: &str) -> u64 {
    let s = schedule.trim().to_lowercase();
    
    if let Some(rest) = s.strip_prefix("every ") {
        let rest = rest.trim();
        let (num_str, unit) = rest.split_at(
            rest.find(|c: char| c.is_alphabetic()).unwrap_or(rest.len())
        );
        
        if let Ok(n) = num_str.trim().parse::<u64>() {
            let unit = unit.trim();
            if unit.is_empty() || unit == "s" || unit.starts_with("sec") {
                return n;
            } else if unit == "m" || unit.starts_with("min") {
                return n * 60;
            } else if unit == "h" || unit.starts_with("hour") {
                return n * 3600;
            } else if unit == "d" || unit.starts_with("day") {
                return n * 86400;
            }
        }
    }
    
    // Basic 5-field cron: default to 60s
    if s.contains('*') || s.split_whitespace().count() == 5 {
        return 60;
    }
    
    60  // Default fallback
}
```

**Scheduler Loop**:
```rust
pub async fn run_loop(self_arc: Arc<Mutex<Self>>) {
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;  // Check every 30s
        let mut scheduler = self_arc.lock().await;
        scheduler.tick().await;
    }
}

pub async fn tick(&mut self) {
    let now = Utc::now();
    let mut due_indices = Vec::new();
    
    for (i, task) in self.tasks.iter().enumerate() {
        if !task.enabled { continue; }
        if let Some(ref next_run) = task.next_run {
            if now >= DateTime::parse_from_rfc3339(next_run)? {
                due_indices.push(i);
            }
        }
    }
    
    for &i in &due_indices {
        let task = &self.tasks[i];
        // Update last_run and next_run
        self.tasks[i].last_run = Some(now.to_rfc3339());
        self.tasks[i].next_run = Some(Self::compute_next_run(task.interval_secs));
        
        // Spawn independent sub-agent
        let runner = self.runner.clone();
        let session_id = format!("cron-{}", Uuid::new_v4());
        tokio::spawn(async move {
            let stream = runner.run(&task.message, &session_id, ...).await?;
            // Collect text, broadcast to clients
            let _ = notify_tx.send(json!({
                "type": "notification",
                "message": format!("⚙️ **CRON: {}**\n\n{}", task.name, text),
            }).to_string());
        });
    }
}
```

### 12.2 Heartbeat System

**Location**: `src/heartbeat.rs` (207 lines)

**Purpose**: Periodically read HEARTBEAT.md and execute checklist via agent

**Interval**: 30 minutes (default)

**Flow**:
```rust
pub async fn run_loop(self) {
    tokio::time::sleep(Duration::from_secs(self.interval_secs)).await;  // Wait before first check
    
    loop {
        self.run_once().await;
        tokio::time::sleep(Duration::from_secs(self.interval_secs)).await;
    }
}

async fn run_once(&self) {
    let heartbeat_content = self.read_heartbeat_file()?;  // Read HEARTBEAT.md
    
    let message = format!(
        "This is an automated HEARTBEAT check. Execute the following checklist items 
         and report ONLY items that need attention (alerts/warnings). 
         If everything is normal, respond with just 'All clear'.\n\n\
         Checklist:\n{}",
        heartbeat_content
    );
    
    let session_id = format!("heartbeat-{}", Uuid::new_v4());
    let stream = self.runner.run(&message, &session_id, ...).await?;
    
    // Collect text
    let text_lower = text.to_lowercase();
    let is_all_clear = text_lower.contains("all clear")
        || text_lower.contains("一切正常")
        || text_lower.contains("全部正常")
        || text_lower.contains("没有异常")
        || text_lower.contains("no issues")
        || text_lower.contains("no alerts");
    
    if !is_all_clear && text.trim().len() > 20 {
        // Send alert to clients
        let _ = self.notify_tx.send(json!({
            "type": "notification",
            "message": format!("🩺 **Heartbeat Alert** ({}s)\n\n{}", elapsed, text),
        }).to_string());
    }
}
```

---

## 13. Security & Encryption

### 13.1 AES-256-GCM Encryption

**Location**: `src/crypto.rs` (222 lines)

**Purpose**: Protect sensitive config values (API keys, auth tokens) at rest

**Key Derivation**:
```rust
fn derive_key() -> [u8; 32] {
    let machine_id = get_machine_guid().unwrap_or_else(|| "rust-agent-fallback-key".to_string());
    
    let mut hasher = Sha256::new();
    hasher.update(b"rust-agent-mcp-auth-");
    hasher.update(machine_id.as_bytes());
    hasher.finalize().into()
}

#[cfg(target_os = "windows")]
fn get_machine_guid() -> Option<String> {
    // Read from registry: HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
    let output = Command::new("reg")
        .args(["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
        .output().ok()?;
    // Parse output
}
```

**Encryption Format**:
```
ENC:<base64(nonce‖ciphertext‖tag)>
```

**API**:
```rust
pub fn encrypt(plaintext: &str) -> String {
    let key = derive_key();
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce_bytes = generate_random_bytes(12);  // Random 96-bit nonce
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())?;
    
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    
    format!("ENC:{}", base64_encode(&combined))
}

pub fn decrypt(maybe_encrypted: &str) -> String {
    if !maybe_encrypted.starts_with("ENC:") {
        return maybe_encrypted.to_string();  // Plaintext passthrough
    }
    let encoded = &maybe_encrypted[4..];
    let combined = base64_decode(encoded)?;
    
    if combined.len() < 12 { return maybe_encrypted.to_string(); }
    
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let key = derive_key();
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    
    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext_bytes) => String::from_utf8(plaintext_bytes)?,
        Err(_) => maybe_encrypted.to_string(),  // Decryption failed
    }
}
```

**Usage**: MCP auth tokens, API keys in models.json

### 13.2 Command Intent Policy

**Location**: `src/policy/mod.rs` (154 lines), `src/policy/parse.rs` (415 lines), `src/policy/rules.rs` (298 lines)

**Purpose**: Safety interlock layer for `shell_exec` that operates **independently** of the Permission system. While Permission answers "is this tool allowed?", IntentPolicy answers "is this specific command catastrophically dangerous?"

**Design Principles**:
- **Absolute Block**: irreversible operations with NO legitimate IR use case (the "fuse")
- **Audit**: high-risk but legitimate operations — logged, not blocked
- **Pass**: normal operations — silent
- Stateless and thread-safe; does NOT depend on permission state

#### 13.2.1 Verdict Types

```rust
pub enum IntentVerdict {
    Pass,                          // Normal operation — proceed silently
    Audit { reason: String },      // High-risk but legitimate — log, do NOT block
    Block { reason: String },      // Catastrophic irreversible — hard block regardless of permissions
}
```

#### 13.2.2 Command Intent Parser (`parse.rs`)

Parses PowerShell and CMD commands into structured intent without a full AST parser:

```rust
pub struct ParsedIntent {
    pub verb: Verb,              // Primary action verb
    pub targets: Vec<String>,    // Target paths/names extracted
    pub raw_lower: String,       // Lowercased command for matching
    pub raw: String,             // Original command (preserved case)
    pub shell: String,           // "powershell" or "cmd"
    pub confidence: f64,         // 0.0 (guess) to 1.0 (clear cmdlet match)
    pub is_encoded: bool,        // Contains encoded/obfuscated content
    pub has_nested_shell: bool,  // Uses nested shell invocation
}
```

**Verb Categories**:
| Verb | Meaning | Examples |
|------|---------|----------|
| `Delete` | Delete/remove files, dirs, registry | Remove-Item, del, rm, rmdir, [IO.File]::Delete |
| `Format` | Format/clear disk or volume | Format-Volume, Clear-Disk, format C: |
| `Stop` | Stop/kill process or service | Stop-Process, Stop-Service, taskkill, net stop |
| `Disable` | Disable adapter, feature, service | Disable-NetAdapter, Disable-LocalUser |
| `Write` | Write/modify content | Set-Content, Set-ItemProperty, reg add |
| `Read` | Read/query information | Get-*, Select-*, Where-*, dir, netstat |
| `Execute` | Execute/run a program | (generic) |
| `ClearLog` | Clear event logs | Clear-EventLog, wevtutil cl |
| `Unknown` | Could not determine | (fallback, confidence=0.3) |

**Encoded Command Detection**:
```rust
fn detect_encoded(cmd_lower: &str) -> bool {
    cmd_lower.contains("-encodedcommand")
        || cmd_lower.contains("-enc ")
        || cmd_lower.contains("-e ")
        || cmd_lower.contains("frombase64string")
        || cmd_lower.contains("invoke-expression")
        || cmd_lower.contains("iex ")
        || cmd_lower.contains("iex(")
}
```

**Nested Shell Detection**: `cmd /c`, `cmd.exe /c`, `powershell -command`, `powershell -c`

**Target Extraction**: Quoted strings + drive-letter paths (e.g., `C:\...`) + CMD keyword arguments

#### 13.2.3 Block Rules (Absolute Interlock)

Admission criteria: (1) IRREVERSIBLE, (2) NO legitimate IR/admin use case through AI agent, (3) Near-zero false positive probability.

| Rule Name | Pattern | Explanation |
|-----------|---------|-------------|
| `format_volume` | `Format-Volume` | Irreversible disk/volume operation |
| `clear_disk` | `Clear-Disk` | Irreversible disk/volume operation |
| `initialize_disk` | `Initialize-Disk` | Irreversible disk/volume operation |
| `cmd_format` | `format ` | Disk format operation |
| `diskpart_clean` | `clean all` | Diskpart full disk wipe |
| `clear_security_log` | `Clear-EventLog` + `security` | Destruction of security audit trail |
| `wevtutil_clear_security` | `wevtutil cl security` | Security event log destruction |
| `wevtutil_clear_security2` | `wevtutil clear-log security` | Security event log destruction |
| `bcdedit_delete` | `bcdedit /delete` | Boot configuration destruction |
| `bootrec_wipe` | `bootrec /wipe` | Boot record destruction |
| `physical_drive` | `\\\\?\\physicaldrive` | Direct physical disk access |
| `harddisk_device` | `\\device\\harddisk` | Direct disk device access |
| `encoded_command` | `is_encoded == true` | Cannot verify safety of obfuscated commands |

**Key design choice**: Only Security log clearing is blocked. System/Application log clearing is audit-level (legitimate IR use case).

#### 13.2.4 Audit Rules (High-Risk Logging)

These log high-risk operations but NEVER block them:

| Category | Matcher | Description |
|----------|---------|-------------|
| `file_deletion` | `verb == Delete` | File/directory deletion |
| `process_service_stop` | `verb == Stop` | Process/service termination |
| `disable_operation` | `verb == Disable` | Network/system feature disable |
| `write_operation` | `verb == Write` | Registry/file write operations |
| `log_clear` | `verb == ClearLog` | Event log clearing (non-security) |
| `unparseable_command` | `confidence < 0.5 && verb == Unknown` | Low-confidence commands |
| `nested_shell` | `has_nested_shell == true` | Potential indirection |

#### 13.2.5 Evaluation Flow

```rust
pub fn evaluate(&self, command: &str, shell: &str) -> IntentVerdict {
    let intent = parse::parse_intent(command, shell);

    // Phase 1: Absolute block check (narrow, cannot be overridden)
    for rule in &self.block_rules {
        if rule.matches(&intent) {
            return IntentVerdict::Block { reason: rule.explain(&intent) };
        }
    }

    // Phase 2: Audit-level check (high-risk but legitimate)
    for rule in &self.audit_rules {
        if rule.matches(&intent) {
            return IntentVerdict::Audit { reason: rule.explain(&intent) };
        }
    }

    // Phase 3: Normal
    IntentVerdict::Pass
}
```

### 13.3 External Tool Executor

**Location**: `src/tool/external_exec.rs` (224 lines)

**Purpose**: Wraps workspace/tools/ executables as LLM-callable tools registered as `ext_{name}`.

```rust
pub struct ExternalToolExecutor {
    name: String,          // e.g., "ext_Autoruns"
    path: PathBuf,         // Full path to executable
    description: String,   // For LLM tool description
    extension: String,     // .exe, .bat, .ps1, .cmd
}
```

**Parameters**: `args` (string, optional), `timeout_secs` (integer, default 60)

**Execution by extension**:
| Extension | Invocation |
|-----------|------------|
| `.ps1` | `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <path> [args]` |
| `.bat` / `.cmd` | `cmd /c <path> [args]` |
| `.exe` (default) | Direct execution with args |

**Safety features**:
- Output truncation: stdout max 30,000 chars, stderr max 5,000 chars
- Timeout enforcement via `tokio::time::timeout`
- Category: `execute` (requires user endorsement)
- `is_read_only() = false` (assumed to have side effects)
- Shell-word splitting handles quoted arguments

**Returns**: `{ exit_code, stdout, stderr, tool_path }`

---

## 14. Configuration

### 14.1 Config Structure

**Location**: `src/config.rs` (196 lines)

```rust
pub struct Config {
    pub server: ServerConfig,
    pub agent: AgentConfig,
}

pub struct ServerConfig {
    pub host: String,  // default: "0.0.0.0"
    pub port: u16,     // default: 7788
}

pub struct AgentConfig {
    pub working_dir: String,              // default: "."
    pub workspace_dir: String,            // default: "%USERPROFILE%\.RustAgent\workspace"
    pub max_iterations: usize,            // default: 100
    pub rabbit_hole_threshold: usize,     // default: 5
    pub context_window_threshold: usize,  // default: 80 (percent)
    pub tool_timeout_secs: usize,         // default: 300
    pub max_tool_retries: usize,          // default: 2
}
```

### 14.2 Model Config

```rust
pub struct ModelConfig {
    pub name: String,
    pub api_base: String,
    pub api_key: Option<String>,
    pub api_key_env: Option<String>,       // Environment variable name
    pub context_window: usize,             // default: 128000
    pub max_tokens: u32,                   // default: 16384
    pub temperature: f64,                  // default: 0.7
    pub supports_vision: bool,             // default: false
}
```

**API Key Resolution**:
```rust
pub fn resolved_api_key(&self) -> String {
    if let Some(ref key) = self.api_key { return key.clone(); }
    if let Some(ref env_var) = self.api_key_env {
        return std::env::var(env_var).unwrap_or_default();
    }
    String::new()
}
```

### 14.3 MCP Server Config

```rust
pub struct McpServerConfig {
    pub name: String,
    pub transport: String,          // "stdio" or "sse"
    pub command: Option<String>,    // For stdio
    pub args: Vec<String>,          // For stdio
    pub url: Option<String>,        // For SSE
    pub auth_token: Option<String>, // For SSE (encrypted at rest)
    pub enabled: bool,              // default: true
}
```

---

## 15. Build System

### 15.1 Build Script

**Location**: `build.rs` (75 lines)

**Purpose**: Embed workspace files and YARA rules into binary

**Embedded Files**:
```rust
// Workspace template files (AGENTS.md, SOUL.md, TOOLS.md)
const EMBEDDED_FILES: &[(&str, &str)] = include!(concat!(env!("OUT_DIR"), "/embedded_files.rs"));

// YARA rules (500+ files)
const YARA_RULES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/yara_rules.bin"));
```

**Build Process**:
1. Read workspace files from project root
2. Generate `embedded_files.rs` with file contents
3. Compile YARA rules into binary
4. Output to `OUT_DIR` for `include!` macros

### 15.2 Release Profile

```toml
[profile.release]
strip = true      # Strip debug symbols
opt-level = 3     # Maximum optimization
lto = true        # Link-time optimization
```

---

## 16. Supporting Modules

This section documents infrastructure modules that support the core agent but are not part of the main architectural layers.

### 16.1 Callback System (`src/callbacks.rs`, 146 lines)

**Purpose**: ADK-inspired extensible hook system for intercepting agent lifecycle events.

**Core types**:
```rust
pub enum CallbackResult {
    Continue,                                    // Proceed normally
    Override { response: String, skip: bool },   // Replace model/tool response
}
```

**7 Callback Traits**:

| Trait | Method Signature | Use Case |
|-------|-----------------|----------|
| `BeforeModelCallback` | `async fn call(&self, ctx, agent, request) -> CallbackResult` | Intercept/modify LLM requests before sending |
| `AfterModelCallback` | `async fn call(&self, ctx, agent, response) -> CallbackResult` | Process/modify LLM responses |
| `BeforeToolCallback` | `async fn call(&self, ctx, agent, tool, args) -> CallbackResult` | Gate/filter tool calls |
| `AfterToolCallback` | `async fn call(&self, ctx, agent, tool, result) -> CallbackResult` | Post-process tool results |
| `OnToolErrorCallback` | `async fn call(&self, ctx, agent, tool, error) -> CallbackResult` | Handle tool failures |
| `BeforeAgentCallback` | `async fn call(&self, ctx, agent) -> CallbackResult` | Intercept before agent runs |
| `AfterAgentCallback` | `async fn call(&self, ctx, agent, result) -> CallbackResult` | Process agent output |

**Container**:
```rust
pub struct AgentCallbacks {
    before_model: Vec<Arc<dyn BeforeModelCallback>>,
    after_model: Vec<Arc<dyn AfterModelCallback>>,
    before_tool: Vec<Arc<dyn BeforeToolCallback>>,
    after_tool: Vec<Arc<dyn AfterToolCallback>>,
    on_tool_error: Vec<Arc<dyn OnToolErrorCallback>>,
    before_agent: Vec<Arc<dyn BeforeAgentCallback>>,
    after_agent: Vec<Arc<dyn AfterAgentCallback>>,
}
```

**Invocation in agent loop** (`llm_agent.rs`):
- Before each model call → iterate `before_model` callbacks → if any returns `Override`, skip model call
- After model response → iterate `after_model` callbacks
- Before each tool execution → iterate `before_tool` callbacks → if `Override{skip: true}`, skip tool
- After tool execution → iterate `after_tool` callbacks
- On tool error → iterate `on_tool_error` callbacks

### 16.2 Session Management (`src/session.rs`, 140 lines)

**Purpose**: Track conversation state across interactions.

```rust
pub struct Session {
    pub id: String,
    pub messages: Vec<ChatMessage>,
    pub metadata: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

**SessionService trait**:
```rust
pub trait SessionService: Send + Sync {
    fn create_session(&self) -> Result<Session>;
    fn get_session(&self, id: &str) -> Result<Option<Session>>;
    fn update_session(&self, session: &Session) -> Result<()>;
    fn delete_session(&self, id: &str) -> Result<()>;
}
```

**InMemorySessionService**: Default implementation using `DashMap<String, Session>` for concurrent access.

### 16.3 Conversation Logger (`src/log/mod.rs`, 176 lines)

**Purpose**: Persist all conversation events as daily JSONL files.

```rust
pub struct ConversationLogger {
    log_dir: PathBuf,           // workspace/logs/
    current_date: Mutex<String>, // "YYYY-MM-DD"
    current_file: Mutex<Option<File>>,
}
```

**Features**:
- Daily rotation: New file per date (`2026-07-20.jsonl`)
- Each line: `{"timestamp": "...", "event_type": "...", "data": {...}}`
- Event type mapping from `AgentEvent` variants
- Auto-flush after each write
- Lazy file creation (only when first event logged)

**Event types logged**: `user_message`, `assistant_message`, `tool_call`, `tool_result`, `error`, `system_prompt`, `reasoning`, `thought`

### 16.4 Model Store (`src/model_store.rs`, 65 lines)

**Purpose**: Persist model configurations with encrypted API keys.

```rust
pub struct ModelStore {
    path: PathBuf,  // workspace/model_store.json
}
```

**Storage format**: JSON file with encrypted API keys:
```json
{
  "models": [
    {
      "name": "gpt-4",
      "provider": "openai",
      "api_key": "ENCRYPTED_BASE64...",
      "base_url": "https://api.openai.com/v1",
      "model": "gpt-4"
    }
  ]
}
```

**Security**: API keys encrypted via `crypto::encrypt()` (AES-256-GCM, machine-bound key).

### 16.5 Web Assets Server (`src/web/mod.rs`, 83 lines)

**Purpose**: Serve the web UI for the WebSocket gateway.

**Dual-mode operation**:
- **Debug build**: Serves files from `static/` directory on disk (hot-reload during development)
- **Release build**: Serves files embedded at compile time via `include_str!()` (zero filesystem dependencies)

**Embedded files** (from `static/`):
- `index.html` — Main web UI
- `app.js` — Application logic
- `styles.css` — Styling
- `favicon.ico` — Browser icon
- `logo.svg` — Logo graphic

### 16.6 Checkpoint Manager (`src/checkpoint.rs`, 115 lines)

**Purpose**: Persist task state for crash recovery.

```rust
pub struct TaskCheckpointer {
    store: Arc<MemoryStore>,
}
```

**Operations**:
- `save(task_id, history, context)` → Serializes conversation history + tool context to SQLite
- `delete(task_id)` → Removes checkpoint after successful completion
- `build_tool_summary()` → Creates compact summary of tool execution history for context management

**Storage**: Uses the same SQLite database as the memory system (separate table).

### 16.7 Context Hierarchy (`src/context.rs`, 248 lines)

**Purpose**: Provide hierarchical context propagation through agent tree.

```rust
pub struct Context {
    parent: Option<Arc<Context>>,
    values: HashMap<String, Value>,
}
```

**Lookup**: Child contexts inherit parent values; child values override parent values.

**Usage**: The `InvocationContext` passed to tools and agents carries:
- Working directory
- Session ID
- Task ID
- Parent agent reference
- Permission mode
- Custom key-value pairs

---

## 17. Workspace Structure

### 17.1 Directory Layout

```
%USERPROFILE%\.RustAgent\workspace\
  ├── AGENTS.md              # Agent behavior rules (embedded, extracted on first run)
  ├── SOUL.md                # Personality & tone (embedded, extracted on first run)
  ├── TOOLS.md               # Tool usage conventions (embedded, extracted on first run)
  ├── MEMORY.md              # Curated long-term memory (user-managed)
  ├── HEARTBEAT.md           # Heartbeat checklist (user-managed)
  ├── config.toml            # Server & agent configuration
  ├── models.json            # Model configs (API keys encrypted)
  ├── mcp_servers.json       # MCP server configs (auth tokens encrypted)
  ├── cron_tasks.json        # CRON task definitions
  ├── memory/
  │   └── memory.db          # SQLite memory store (WAL mode)
  ├── logs/
  │   └── 2026-07-20.jsonl   # Conversation logs (JSONL format)
  ├── skills/
  │   ├── skill_name/
  │   │   ├── SKILL.md       # Skill definition
  │   │   └── ...            # Additional files
  │   └── skills_state.json  # Enabled/disabled state
  ├── tools/                 # External tools (3-tier binary resolution)
  ├── knowledge/             # Distilled knowledge (auto-generated)
  │   ├── facts.md
  │   ├── decisions.md
  │   ├── lessons.md
  │   ├── preferences.md
  │   └── skill_hints.md
  ├── static/                # Web UI static files
  └── output/                # Tool output files (screenshots, etc.)
```

### 16.2 First-Run Initialization

**main.rs**:
```rust
// Create workspace directory and subdirectories
let workspace_dir = format!("{}\\.RustAgent\\workspace", userprofile);
let ws_subdirs = ["memory", "tools", "skills", "logs", "static", "output", "knowledge"];
for sub in &ws_subdirs {
    std::fs::create_dir_all(Path::new(&workspace_dir).join(sub))?;
}

// Extract embedded files (first-run only)
for &(name, content) in EMBEDDED_FILES {
    let path = Path::new(&workspace_dir).join(name);
    if !path.exists() {
        std::fs::write(&path, content)?;
    }
}

// Generate random password (persisted to .password)
let password = {
    let pwd_file = Path::new(&workspace_dir).join(".password");
    if pwd_file.exists() {
        std::fs::read_to_string(&pwd_file)?.trim().to_string()
    } else {
        let mut bytes = [0u8; 3];
        getrandom::fill(&mut bytes)?;
        let num = ((bytes[0] as u32) << 16 | (bytes[1] as u32) << 8 | bytes[2] as u32) % 1000000;
        let password = format!("{:06}", num);
        std::fs::write(&pwd_file, &password)?;
        password
    }
};
```

---

## 18. Error Handling

### 18.1 Error Structure

**Location**: `src/error.rs` (209 lines)

```rust
pub struct AgentError {
    pub component: ErrorComponent,  // Agent/Model/Tool/Session/Config/Server/Mcp/Skill/Internal
    pub category: ErrorCategory,    // InvalidInput/Unauthorized/NotFound/RateLimited/Timeout/...
    pub code: &'static str,         // e.g., "agent.internal", "tool.error"
    pub message: String,
    pub retry: RetryHint,
}

pub struct RetryHint {
    pub should_retry: bool,
    pub retry_after_ms: Option<u64>,
    pub max_attempts: Option<u32>,
}
```

**Convenience Constructors**:
```rust
impl AgentError {
    pub fn agent(message: impl Into<String>) -> Self { ... }
    pub fn model(message: impl Into<String>) -> Self { ... }
    pub fn tool(tool_name: &str, message: impl Into<String>) -> Self { ... }
    pub fn config(message: impl Into<String>) -> Self { ... }
    pub fn timeout(component: ErrorComponent, message: impl Into<String>) -> Self { ... }
    pub fn not_found(component: ErrorComponent, message: impl Into<String>) -> Self { ... }
}
```

---

## 19. Data Flow

### 19.1 Chat Message Flow

```
User (Web UI)
  ↓ WebSocket: {"type": "chat", "message": "..."}
Server (ws_handler)
  ↓ Build InvocationContext
Runner.run()
  ↓ Dispatch to agent
LlmAgent.run()
  ↓ Build system prompt
  ↓ Spawn async task
Agent Loop (iteration 0..max)
  ↓ Trim history to budget
  ↓ Call LLM (streaming SSE)
OpenAiProvider.chat_stream()
  ↓ HTTP POST to /chat/completions
  ↓ Parse SSE chunks
  ↓ Send text deltas via mpsc
  ↓ Accumulate tool calls
  ↓ Return (content, reasoning, tool_calls, usage)
Agent Loop (continued)
  ↓ Extract tool calls from text (if no native calls)
  ↓ Re-prompt if needed (max 2 attempts)
  ↓ Rabbit hole detection
  ↓ Permission check
  ↓ Execute tools
  ↓ Save checkpoint
  ↓ Push tool results to history
  ↓ Loop back to LLM call
  ↓ (until text response or max iterations)
  ↓ Send Done event
Server (ws_handler)
  ↓ Log conversation to memory.db
  ↓ Trigger knowledge distillation (async)
  ↓ Broadcast events to WebSocket client
User (Web UI)
  ↓ Receive streaming events
  ↓ Display text, tool calls, results
```

### 18.2 Event Stream Flow

```
LlmAgent (mpsc::Sender)
  ↓ AgentEvent::Thinking
  ↓ AgentEvent::TextDelta
  ↓ AgentEvent::ToolCall
  ↓ AgentEvent::ToolResult
  ↓ AgentEvent::Progress
  ↓ AgentEvent::PermissionRequest
  ↓ AgentEvent::PermissionResponse
  ↓ AgentEvent::Usage
  ↓ AgentEvent::Done
  ↓ AgentEvent::Error
Runner (wraps stream with logging)
  ↓ Log each event
Server (ws_handler)
  ↓ Serialize to JSON
  ↓ Send via WebSocket
Client (Web UI)
  ↓ Parse JSON
  ↓ Update UI
```

---

## 20. Dependencies

### 20.1 Key Dependencies

**Async Runtime**:
- `tokio` — Async runtime with multi-threaded scheduler
- `async-trait` — Async trait support
- `futures` — Stream utilities

**Web Framework**:
- `axum` — Web framework (WebSocket, REST API)
- `reqwest` — HTTP client (LLM API calls)

**Database**:
- `rusqlite` — SQLite bindings (memory store)

**Serialization**:
- `serde` / `serde_json` — JSON serialization
- `serde_yaml` — YAML frontmatter parsing
- `toml` — Config file parsing

**MCP Protocol**:
- `rmcp` — Model Context Protocol client

**Browser Automation**:
- `chromiumoxide` — CDP browser control

**Encryption**:
- `aes-gcm` — AES-256-GCM authenticated encryption
- `sha2` — SHA-256 hashing
- `getrandom` — Random number generation

**Malware Analysis**:
- `boreal` — YARA rule engine
- `goblin` — ELF/PE binary parsing
- `iced-x86` — x86/x64 disassembler

**Logging**:
- `tracing` / `tracing-subscriber` — Structured logging

**Utilities**:
- `chrono` — Date/time handling
- `uuid` — UUID generation
- `which` — Binary resolution
- `glob` — File pattern matching
- `mime_guess` — MIME type detection

---

## 21. Platform Support

**Primary Target**: Windows (x86_64-pc-windows-msvc)

**Platform-Specific Features**:
- Windows registry access for MachineGuid
- Windows console hiding for MCP stdio processes
- Windows path separators
- Windows service/process management tools

**Cross-Platform Considerations**:
- MachineGuid fallback to `/etc/machine-id` on Linux
- Path handling uses `PathBuf` for cross-platform compatibility
- Most features work on Linux/macOS with minor adjustments

---

## 22. Performance Characteristics

### 22.1 Context Window Management

- **Token Estimation**: CJK-aware (1.5 chars/token for CJK, 4 chars/token for Latin)
- **Trimming Threshold**: 80% of model context window (configurable)
- **Trimming Phases**: 4-phase priority-based (tool results → assistant → user → aggressive)
- **Protected Zone**: Last 6 messages never trimmed

### 21.2 Streaming Performance

- **SSE Parsing**: Line-by-line with buffer accumulation
- **Tool Call Accumulation**: By index (handles partial JSON chunks)
- **Consumer Gone Detection**: Abort stream reading if WebSocket closed
- **mpsc Channel Capacity**: 200 events (backpressure handling)

### 21.3 Memory Usage

- **SQLite WAL Mode**: Better concurrent read performance
- **FTS5 Index**: Separate table with CJK preprocessing
- **Checkpoint Cleanup**: Stale checkpoints (>24h) removed on startup
- **History Trimming**: Prevents unbounded memory growth

---

## 23. Testing Strategy

### 23.1 Unit Tests

**Crypto Module** (`crypto.rs`):
```rust
#[test]
fn round_trip() {
    let plaintext = "sk-my-secret-token-12345";
    let encrypted = encrypt(plaintext);
    assert!(encrypted.starts_with("ENC:"));
    assert_ne!(encrypted, plaintext);
    let decrypted = decrypt(&encrypted);
    assert_eq!(decrypted, plaintext);
}

#[test]
fn plaintext_passthrough() {
    let plain = "not-encrypted";
    assert_eq!(decrypt(plain), plain);
}
```

### 22.2 Integration Tests

- WebSocket connection flow (auth → chat → events → done)
- Tool execution with permission gates
- Checkpoint save/resume flow
- MCP server connection and tool discovery
- Skill matching and scoring

---

## 24. Future Enhancements

### 24.1 Planned Features

- Multi-agent orchestration (sub-agents)
- Advanced tool execution strategies (batching, caching)
- Enhanced memory summarization (LLM-based)
- Skill versioning and marketplace
- Plugin system for custom tools
- Metrics and observability (OpenTelemetry)

### 24.2 Known Limitations

- CRON parser: basic interval syntax only (no full 5-field cron)
- FTS5: no stemming or synonym support
- Tool execution: no timeout per-tool (global timeout only)
- Checkpoint: no incremental checkpoints (full history serialized)

---

## 25. Source File Index

Complete mapping of all source files to their responsibilities:

### 25.1 Core Framework

| File | Lines | Responsibility |
|------|-------|---------------|
| `src/main.rs` | 417 | Entry point, workspace setup, model loading, MCP connection, server startup |
| `src/config.rs` | 195 | Configuration with defaults (port, model, max_tokens, context_window, etc.) |
| `src/error.rs` | 209 | Error types: Config, Tool, Model, Permission, Memory, Crypto, etc. |
| `src/crypto.rs` | 221 | AES-256-GCM encryption with machine-bound key derivation |
| `src/runner.rs` | 195 | Runner orchestration: agent selection, tool execution, streaming |
| `src/context.rs` | 248 | Context hierarchy with parent-child value inheritance |
| `src/session.rs` | 140 | Session struct + SessionService trait + InMemorySessionService |
| `src/callbacks.rs` | 146 | 7 callback traits + AgentCallbacks container |
| `src/policy/mod.rs` | 154 | IntentPolicy engine: Block/Audit/Pass verdicts |
| `src/policy/parse.rs` | 415 | Command intent parser: verb classification, target extraction |
| `src/policy/rules.rs` | 298 | Block rules (13 absolute interlocks) + Audit rules (7 categories) |

### 25.2 Agent System

| File | Lines | Responsibility |
|------|-------|---------------|
| `src/agent/mod.rs` | 41 | Agent trait definition |
| `src/agent/llm_agent.rs` | 1460 | Core agent loop, CJK token estimation, history trimming, system prompt, rabbit hole detection |
| `src/agent/event.rs` | 267 | AgentEvent enum with serde serialization |

### 25.3 Model Layer

| File | Lines | Responsibility |
|------|-------|---------------|
| `src/model/mod.rs` | 204 | Llm trait, ChatMessage, ToolDefinition, ModelConfig, ModelRegistry |
| `src/model/openai.rs` | 503 | OpenAI-compatible streaming SSE provider with reasoning_content |

### 25.4 Tool System

| File | Lines | Responsibility |
|------|-------|---------------|
| `src/tool/mod.rs` | 309 | Tool trait, ToolRegistry, build_default, ToolExecutionStrategy |
| `src/tool/file_ops.rs` | 249 | file_read, file_write, file_delete, file_modify, file_list |
| `src/tool/shell_exec.rs` | 97 | shell_exec with IntentPolicy integration |
| `src/tool/sys_info.rs` | 76 | System information via PowerShell |
| `src/tool/sys_process.rs` | 70 | Process listing via PowerShell |
| `src/tool/sys_service.rs` | 71 | Windows service enumeration |
| `src/tool/sys_eventlog.rs` | 68 | Recent event log collection |
| `src/tool/sys_remind.rs` | 190 | WebSocket notification + MessageBox fallback + delay parser |
| `src/tool/app_launch.rs` | 49 | Launch Windows applications |
| `src/tool/browser_open.rs` | 45 | Open URL in default browser |
| `src/tool/web_fetch.rs` | 142 | HTTP GET web page content |
| `src/tool/browser_cdp.rs` | 407 | Chrome DevTools Protocol (10 actions) via chromiumoxide |
| `src/tool/browser_skill.rs` | 413 | BrowserSkill CLI wrapper (17 actions) via bsk |
| `src/tool/cron_manage.rs` | 182 | CRON task management (create/list/delete/toggle) |
| `src/tool/memory_md.rs` | 107 | MEMORY.md read/write |
| `src/tool/todo_update.rs` | 214 | TODO list management (set/update/clear/list) |
| `src/tool/mcp_client.rs` | 295 | MCP client: stdio + HTTP transport, tool proxy, hot-swap |
| `src/tool/external_exec.rs` | 224 | External tool executor: wraps workspace/tools/ as ext_{name} tools |

### 25.5 Incident Response Tools

| File | Lines | Responsibility |
|------|-------|---------------|
| `src/tool/ir_scan.rs` | 339 | 17-category collection scanner |
| `src/tool/ir_process.rs` | 291 | Process risk classification + kill |
| `src/tool/ir_account.rs` | 143 | Account audit + hidden account detection |
| `src/tool/ir_persistence.rs` | 158 | Autoruns, tasks, services, WMI, startup enumeration |
| `src/tool/ir_network.rs` | 175 | Connections, DNS, routes, proxy, firewall, lateral movement |
| `src/tool/ir_eventlog.rs` | 389 | Security/System/PowerShell event log collection |
| `src/tool/ir_file.rs` | 263 | File hashing + signature verification |
| `src/tool/ir_driver.rs` | 140 | Driver signature scanning |
| `src/tool/ir_analyzer.rs` | 594 | Rule-based anomaly detection (17 rules + MITRE ATT&CK) |
| `src/tool/ir_report.rs` | 266 | HTML report generation |
| `src/tool/ir_timeline.rs` | 743 | Chronological event reconstruction from 7 sources with risk scoring |

### 25.6 Malware Analysis Tools

| File | Lines | Responsibility |
|------|-------|---------------|
| `src/tool/malware_scan.rs` | 131 | Quick static analysis (risk score + summary) |
| `src/tool/malware_deep.rs` | 237 | Deep analysis (strings + disassembly + entropy graph) |
| `src/tool/malware_analysis/mod.rs` | 753 | Core pipeline: parallel analysis, risk scoring, detection, YARA |
| `src/tool/malware_analysis/basic.rs` | 229 | Parallel hashing, entropy, string extraction + categorization |
| `src/tool/malware_analysis/pe.rs` | 530 | PE parsing via goblin: sections, imports, exports, anomalies |
| `src/tool/malware_analysis/models.rs` | 285 | Data models: AnalysisResult, PeAnalysis, ExtractedString, etc. |

### 25.7 Infrastructure Modules

| File | Lines | Responsibility |
|------|-------|---------------|
| `src/memory.rs` | 1029 | SQLite memory: WAL, FTS5, CJK preprocessing, BM25 search |
| `src/skill/mod.rs` | 624 | Skill matching: YAML frontmatter + weighted token overlap |
| `src/skill/types.rs` | 45 | Skill type definitions |
| `src/server.rs` | 1434 | WebSocket gateway + REST API + SSE streaming |
| `src/permission.rs` | 214 | Permission system: 5 categories + user endorsement + cross-category bypass detection |
| `src/checkpoint.rs` | 115 | Task checkpoint save/delete via SQLite |
| `src/distill.rs` | 264 | Knowledge distillation: end-of-session LLM extraction |
| `src/scheduler.rs` | 359 | CRON scheduler with interval parser |
| `src/heartbeat.rs` | 206 | Heartbeat monitoring with configurable interval |
| `src/external_tools.rs` | 228 | External tool discovery from workspace/tools/ |
| `src/log/mod.rs` | 176 | JSONL conversation logger with daily rotation |
| `src/model_store.rs` | 65 | Model config persistence with encrypted API keys |
| `src/web/mod.rs` | 83 | Static file server (debug=disk, release=embedded) |

### 25.8 Build System

| File | Lines | Responsibility |
|------|-------|---------------|
| `build.rs` | 88 | Embed YARA rules + workspace files + Windows icon (winresource) |
| `Cargo.toml` | — | Dependencies, features, metadata |
| `.cargo/config.toml` | — | Build configuration |

---

## 26. Conclusion

RustAgent implements a production-ready AI agent with:
- **Robust Architecture**: ADK-RUST inspired abstractions (Agent, Llm, Tool traits)
- **Advanced Features**: Streaming SSE, reasoning_content, MCP, FTS5, checkpoint/resume
- **Security**: Permission gates, AES-256-GCM encryption, path traversal protection, MITRE ATT&CK mapping
- **Performance**: CJK-aware token estimation, 4-phase history trimming, consumer-gone detection, parallel IR collection (3-4x faster triage)
- **Extensibility**: Skill system with IR workflow playbooks, MCP protocol, external tools
- **Reliability**: Checkpoint/resume, rabbit hole detection, re-prompt logic
- **IR Capabilities**: 11 incident response tools with 17 anomaly detection rules, timeline reconstruction from 7 sources, MITRE ATT&CK technique mapping
- **Malware Analysis**: Parallel PE analysis, YARA scanning, risk scoring, pattern matching
- **Browser Automation**: Dual approach (CDP + bsk CLI) covering isolated and session-aware scenarios
- **Windows Native**: Embedded application icon via winresource, PowerShell-based system tools

The codebase demonstrates careful attention to edge cases (CJK text, truncated JSON, consumer disconnects) and provides a solid foundation for building local AI agents with Windows system integration.