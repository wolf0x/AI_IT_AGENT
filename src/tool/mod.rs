pub mod file_ops;
pub mod shell_exec;
pub mod sys_info;
pub mod sys_eventlog;
pub mod sys_process;
pub mod sys_service;
pub mod sys_remind;
pub mod app_launch;
pub mod browser_open;
pub mod mcp_client;
pub mod web_fetch;
pub mod cron_manage;
pub mod memory_md;
pub mod todo_update;
pub mod browser_cdp;
pub mod ir_scan;
pub mod ir_process;
pub mod ir_account;
pub mod ir_persistence;
pub mod ir_network;
pub mod ir_eventlog;
pub mod ir_file;
pub mod ir_driver;
pub mod ir_analyzer;
pub mod ir_report;

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use crate::context::ToolContext;
use crate::error::AgentResult;
use crate::model::ToolDefinition;

// ============================================================
// Tool trait — enriched interface modeled after ADK-RUST
// ============================================================

/// The Tool trait — core abstraction for all callable tools.
/// Modeled after ADK-RUST's Tool trait with rich metadata methods.
///
/// Default implementations return sensible values so most tools
/// only need to implement name(), description(), parameters_schema(), execute().
#[async_trait]
pub trait Tool: Send + Sync {
    /// Tool name (unique identifier, used by the LLM).
    fn name(&self) -> &str;

    /// Human-readable description for the LLM.
    fn description(&self) -> &str;

    /// JSON Schema for the tool's parameters.
    fn parameters_schema(&self) -> Value;

    /// Execute the tool with given arguments and context.
    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value>;

    // --- ADK-RUST inspired metadata methods (defaults provided) ---

    /// Whether this tool is a built-in tool (vs user-provided or MCP).
    fn is_builtin(&self) -> bool { false }

    /// Whether this tool only reads data without modifying anything.
    /// Read-only tools can be executed concurrently in Parallel strategy.
    fn is_read_only(&self) -> bool { false }

    /// Permission category for this tool: read, write, delete, modify, or execute.
    fn category(&self) -> &str {
        crate::permission::tool_category(self.name())
    }

    /// Whether this tool is safe for concurrent execution.
    fn is_concurrency_safe(&self) -> bool { true }

    /// Whether this tool is long-running (e.g., file downloads, installs).
    fn is_long_running(&self) -> bool { false }

    /// JSON Schema for the tool's response (optional).
    fn response_schema(&self) -> Option<Value> { None }

    /// Enhanced description with additional context (e.g., platform info).
    fn enhanced_description(&self) -> String { self.description().to_string() }

    /// Required scopes for authorization (empty = no auth required).
    fn required_scopes(&self) -> Vec<String> { vec![] }

    /// Convert to a ToolDefinition for LLM function-calling protocol.
    fn to_definition(&self) -> ToolDefinition {
        ToolDefinition {
            tool_type: "function".to_string(),
            function: crate::model::FunctionDefinition {
                name: self.name().to_string(),
                description: self.enhanced_description(),
                parameters: self.parameters_schema(),
            },
        }
    }
}

// ============================================================
// Tool execution strategy — modeled after ADK-RUST
// ============================================================

/// How tools should be executed within a single agent iteration.
/// Modeled after ADK-RUST's ToolExecutionStrategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolExecutionStrategy {
    /// Execute tools one at a time, in order.
    Sequential,
    /// Execute all tools concurrently (only safe for read-only/concurrency-safe tools).
    Parallel,
    /// Automatically choose: concurrent for read-only tools, sequential for mutable ones.
    Auto,
}

impl Default for ToolExecutionStrategy {
    fn default() -> Self {
        Self::Sequential
    }
}

// ============================================================
// Toolset abstraction — modeled after ADK-RUST
// ============================================================

/// A collection of tools that can be resolved dynamically.
/// Modeled after ADK-RUST's Toolset trait.
pub trait Toolset: Send + Sync {
    /// Get all tools in this toolset.
    fn tools(&self) -> Vec<Arc<dyn Tool>>;
}

/// Basic toolset — a fixed list of tools.
pub struct BasicToolset {
    tools: Vec<Arc<dyn Tool>>,
}

impl BasicToolset {
    pub fn new(tools: Vec<Arc<dyn Tool>>) -> Self {
        Self { tools }
    }
}

impl Toolset for BasicToolset {
    fn tools(&self) -> Vec<Arc<dyn Tool>> {
        self.tools.clone()
    }
}

/// Merged toolset — combines multiple toolsets.
pub struct MergedToolset {
    toolsets: Vec<Box<dyn Toolset>>,
}

impl MergedToolset {
    pub fn new(toolsets: Vec<Box<dyn Toolset>>) -> Self {
        Self { toolsets }
    }
}

impl Toolset for MergedToolset {
    fn tools(&self) -> Vec<Arc<dyn Tool>> {
        self.toolsets.iter().flat_map(|ts| ts.tools()).collect()
    }
}

// ============================================================
// Tool registry — name-to-instance lookup
// ============================================================

/// Registry of tools — provides name-based lookup and definition generation.
/// Modeled after ADK-RUST's ToolRegistry.
pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    pub fn register(&mut self, tool: Arc<dyn Tool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    /// Remove a tool by name. Returns true if a tool was removed.
    pub fn unregister(&mut self, name: &str) -> bool {
        self.tools.remove(name).is_some()
    }

    /// Remove multiple tools by name.
    pub fn unregister_many(&mut self, names: &[String]) {
        for name in names {
            self.tools.remove(name.as_str());
        }
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Tool>> {
        self.tools.get(name).cloned()
    }

    pub fn definitions(&self) -> Vec<ToolDefinition> {
        self.tools.values().map(|t| t.to_definition()).collect()
    }

    pub fn tool_names(&self) -> Vec<String> {
        self.tools.keys().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.tools.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Build the default registry with all built-in Windows tools.
    /// `notify_tx` is the broadcast channel used by `sys_remind` to push
    /// reminders to WebSocket clients (pass `None` when unavailable).
    pub fn build_default(working_dir: &str, notify_tx: Option<crate::tool::sys_remind::NotifyTx>) -> Self {
        let mut registry = Self::new();
        registry.register(Arc::new(file_ops::FileReadTool));
        registry.register(Arc::new(file_ops::FileWriteTool));
        registry.register(Arc::new(file_ops::FileDeleteTool));
        registry.register(Arc::new(file_ops::FileModifyTool));
        registry.register(Arc::new(file_ops::FileListTool));
        registry.register(Arc::new(shell_exec::ShellExecTool));
        registry.register(Arc::new(sys_info::SysInfoTool));
        registry.register(Arc::new(sys_eventlog::SysEventLogTool));
        registry.register(Arc::new(sys_process::SysProcessTool));
        registry.register(Arc::new(sys_service::SysServiceTool));
        registry.register(Arc::new(sys_remind::SysRemindTool::with_notify_tx_optional(notify_tx)));
        registry.register(Arc::new(app_launch::AppLaunchTool));
        registry.register(Arc::new(browser_open::BrowserOpenTool));
        registry.register(Arc::new(web_fetch::WebFetchTool));
        // IR (Incident Response) tools — ported from yinghuo
        registry.register(Arc::new(ir_scan::IrScanTool));
        registry.register(Arc::new(ir_process::IrProcessTool));
        registry.register(Arc::new(ir_account::IrAccountTool));
        registry.register(Arc::new(ir_persistence::IrPersistenceTool));
        registry.register(Arc::new(ir_network::IrNetworkTool));
        registry.register(Arc::new(ir_eventlog::IrEventLogTool));
        registry.register(Arc::new(ir_file::IrFileTool));
        registry.register(Arc::new(ir_driver::IrDriverTool));
        registry.register(Arc::new(ir_analyzer::IrAnalyzerTool));
        registry.register(Arc::new(ir_report::IrReportTool));
        let _ = working_dir;
        registry
    }

    /// Add all tools from a toolset.
    pub fn add_toolset(&mut self, toolset: &dyn Toolset) {
        for tool in toolset.tools() {
            self.register(tool);
        }
    }
}
