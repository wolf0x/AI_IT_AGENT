use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub agent: AgentConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentConfig {
    #[serde(default = "default_working_dir")]
    pub working_dir: String,
    /// Agent workspace directory — the agent's "home" where AGENTS.md, SOUL.md, TOOLS.md live.
    /// Defaults to %USERPROFILE%\.RustAgent\workspace
    #[allow(dead_code)]
    #[serde(default = "default_workspace_dir")]
    pub workspace_dir: String,
    #[serde(default = "default_max_iterations")]
    pub max_iterations: usize,
    #[serde(default = "default_rabbit_hole_threshold")]
    pub rabbit_hole_threshold: usize,
    /// Drop trailing tool calls that exactly repeat work already executed in
    /// this session when the model has already produced a final text answer.
    /// Narrow, conservative guard: only exact-duplicate calls are removed.
    #[serde(default = "default_trim_redundant_tool_calls")]
    pub trim_redundant_tool_calls: bool,
    /// Context window usage threshold percentage (default: 80 = trim at 80% of model context)
    #[serde(default = "default_context_window_threshold")]
    pub context_window_threshold: usize,
    /// When true, per-tool inline result caps scale up with the model's context
    /// window (bounded by max_inline_chars). When false, legacy conservative
    /// limits are used regardless of context size.
    #[serde(default = "default_enable_context_scaling")]
    pub enable_context_scaling: bool,
    /// Absolute protection cap (chars) for how much of a single tool result or
    /// inline web body is injected into the model context. Guards against one
    /// huge result blowing the whole window even with scaling enabled.
    #[serde(default = "default_max_inline_chars")]
    pub max_inline_chars: usize,
    /// Skill catalog listing strategy for the system prompt
    /// (query | names-only | discover-tool-only).
    #[serde(default = "default_skill_listing_strategy")]
    pub skill_listing_strategy: String,
    /// Max chars of a single hot skill body inlined into the prompt.
    #[serde(default = "default_skill_max_inline_chars")]
    pub skill_max_inline_chars: usize,
    /// Max number of cold skills listed (name:desc) in the catalog.
    #[serde(default = "default_skill_catalog_max")]
    pub skill_catalog_max: usize,
    /// Top-K fuzzy-matched skills inlined (hot) per turn.
    #[serde(default = "default_skill_hot_top_k")]
    pub skill_hot_top_k: usize,
    /// Maximum seconds allowed for a single tool execution (default: 300)
    #[serde(default = "default_tool_timeout_secs")]
    pub tool_timeout_secs: usize,
    /// Maximum automatic retries for retryable tool failures (default: 2)
    #[serde(default = "default_max_tool_retries")]
    pub max_tool_retries: usize,
    /// Enable parallel execution for read-only IR collection tools.
    /// When true, tools like ir_scan, ir_process, ir_account, ir_persistence, ir_network
    /// will execute concurrently via futures::join_all instead of sequentially.
    /// This significantly speeds up incident triage (3-4x faster for full collection).
    /// Default: true (enabled for IR workflow optimization)
    #[serde(default = "default_parallel_ir_tools")]
    pub parallel_ir_tools: bool,
    /// Enable Computer Use (GUI control) tools — screenshot, mouse, keyboard, window management.
    /// Default: false (disabled). Can be toggled at runtime via Settings UI.
    #[serde(default)]
    pub computer_use: bool,
    /// Primary model name (selected in Settings UI)
    #[serde(default)]
    pub primary_model: Option<String>,
    /// Fallback model name (used if primary fails)
    #[serde(default)]
    pub fallback_model: Option<String>,
    /// Timezone offset in hours (e.g., 8 = UTC+8)
    #[serde(default = "default_timezone_offset")]
    pub timezone_offset: i8,
    /// Tool permissions: category -> allowed (true) or denied (false)
    #[serde(default)]
    pub tool_permissions: HashMap<String, bool>,
    /// Expert mode: max iterations per Executor round (default: 200)
    #[serde(default = "default_expert_max_iterations")]
    pub expert_max_iterations: usize,
    /// Expert mode: tool timeout in seconds (default: 600)
    #[serde(default = "default_expert_tool_timeout_secs")]
    pub expert_tool_timeout_secs: usize,
    /// Expert mode: max tool retries (default: 3)
    #[serde(default = "default_expert_max_tool_retries")]
    pub expert_max_tool_retries: usize,
    /// Expert mode: max managed rounds (default: 50)
    #[serde(default = "default_expert_max_managed_rounds")]
    pub expert_max_managed_rounds: usize,
    /// Expert mode: per-role model overrides (Manager/Auditor/Executor) and their
    /// optional fallbacks. When a role model is set it overrides the session/primary
    /// model for that role; otherwise the role uses the primary model. Each role's
    /// fallback falls back to the global fallback_model when unset.
    #[serde(default)]
    pub expert_role_models: RoleModelsConfig,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RoleModelsConfig {
    #[serde(default)]
    pub manager: Option<String>,
    #[serde(default)]
    pub manager_fallback: Option<String>,
    #[serde(default)]
    pub auditor: Option<String>,
    #[serde(default)]
    pub auditor_fallback: Option<String>,
    #[serde(default)]
    pub executor: Option<String>,
    #[serde(default)]
    pub executor_fallback: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ModelConfig {
    /// Human-readable unique label; the CRUD key (defaults to `name`).
    /// `name` may repeat across different api_base endpoints; give each a distinct title.
    #[serde(default)]
    pub title: String,
    pub name: String,
    pub api_base: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// Context window size in tokens (default: 128000)
    #[serde(default = "default_context_window")]
    pub context_window: usize,
    /// Maximum output tokens per response (default: 16384).
    /// Increase for reasoning models that produce long thinking chains.
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    /// Sampling temperature (default: 0.7)
    #[serde(default = "default_temperature")]
    pub temperature: f64,
    /// Whether this model supports image/vision input (default: false)
    #[serde(default)]
    pub supports_vision: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct McpServerConfig {
    pub name: String,
    /// Transport type: "stdio" (default) or "sse"
    #[serde(default = "default_transport")]
    pub transport: String,
    /// Command to run (for stdio transport)
    #[serde(default)]
    pub command: Option<String>,
    /// Arguments for the command (for stdio transport)
    #[serde(default)]
    pub args: Vec<String>,
    /// URL for SSE transport
    #[serde(default)]
    pub url: Option<String>,
    /// Optional Bearer auth token for SSE transport requests
    #[serde(default)]
    pub auth_token: Option<String>,
    /// Whether this server is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_transport() -> String { "stdio".to_string() }
fn default_enabled() -> bool { true }

impl ModelConfig {
    pub fn resolved_api_key(&self) -> String {
        if let Some(ref key) = self.api_key {
            return key.clone();
        }
        if let Some(ref env_var) = self.api_key_env {
            return std::env::var(env_var).unwrap_or_default();
        }
        String::new()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: default_host(),
                port: default_port(),
            },
            agent: AgentConfig {
                working_dir: default_working_dir(),
                workspace_dir: default_workspace_dir(),
                max_iterations: default_max_iterations(),
                rabbit_hole_threshold: default_rabbit_hole_threshold(),
                trim_redundant_tool_calls: default_trim_redundant_tool_calls(),
                context_window_threshold: default_context_window_threshold(),
                enable_context_scaling: default_enable_context_scaling(),
                max_inline_chars: default_max_inline_chars(),
                skill_listing_strategy: default_skill_listing_strategy(),
                skill_max_inline_chars: default_skill_max_inline_chars(),
                skill_catalog_max: default_skill_catalog_max(),
                skill_hot_top_k: default_skill_hot_top_k(),
                tool_timeout_secs: default_tool_timeout_secs(),
                max_tool_retries: default_max_tool_retries(),
                parallel_ir_tools: default_parallel_ir_tools(),
                computer_use: false,
                primary_model: None,
                fallback_model: None,
                timezone_offset: default_timezone_offset(),
                tool_permissions: HashMap::new(),
                expert_max_iterations: default_expert_max_iterations(),
                expert_tool_timeout_secs: default_expert_tool_timeout_secs(),
                expert_max_tool_retries: default_expert_max_tool_retries(),
                expert_max_managed_rounds: default_expert_max_managed_rounds(),
                expert_role_models: RoleModelsConfig::default(),
            },
        }
    }
}

fn default_host() -> String { "127.0.0.1".to_string() }
fn default_port() -> u16 { 7788 }
fn default_working_dir() -> String { ".".to_string() }
fn default_workspace_dir() -> String {
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        format!("{}\\.RustAgent\\Workspace", userprofile)
    } else {
        ".Workspace".to_string()
    }
}
fn default_max_iterations() -> usize { 100 }
fn default_rabbit_hole_threshold() -> usize { 5 }
fn default_trim_redundant_tool_calls() -> bool { true }
fn default_context_window() -> usize { 128000 }
fn default_context_window_threshold() -> usize { 80 }
fn default_enable_context_scaling() -> bool { true }
fn default_max_inline_chars() -> usize { 120_000 }
fn default_skill_listing_strategy() -> String { "query".to_string() }
fn default_skill_max_inline_chars() -> usize { 6000 }
fn default_skill_catalog_max() -> usize { 40 }
fn default_skill_hot_top_k() -> usize { 3 }
fn default_tool_timeout_secs() -> usize { 300 }
fn default_max_tool_retries() -> usize { 2 }
fn default_parallel_ir_tools() -> bool { true }
fn default_max_tokens() -> u32 { 16384 }
fn default_temperature() -> f64 { 0.7 }
fn default_timezone_offset() -> i8 { 8 }
fn default_expert_max_iterations() -> usize { 200 }
fn default_expert_tool_timeout_secs() -> usize { 600 }
fn default_expert_max_tool_retries() -> usize { 3 }
fn default_expert_max_managed_rounds() -> usize { 50 }

/// Detect the user's Given Name from Windows.
/// 
/// Strategy:
/// 1. Use `whoami::realname()` to get the user's display name (cross-platform, no PowerShell)
/// 2. Parse the name to extract Given Name:
///    - "Last, First" format → take part after comma
///    - "First Last" format → take first word
///    - CJK names (no spaces) → use as-is
/// 3. If running as built-in Administrator → return "Admin"
/// 4. Fallback to `whoami::username()`
pub fn detect_user_given_name() -> String {
    // Use whoami crate to get the user's real/display name (cross-platform)
    let full_name = whoami::realname();
    let username = whoami::username();
    
    if !full_name.is_empty() {
        return extract_given_name(&full_name);
    }

    // Fallback: check if running as Administrator
    if username.eq_ignore_ascii_case("Administrator") {
        return "Admin".to_string();
    }

    // Final fallback: use username itself
    if !username.is_empty() {
        return username;
    }

    "User".to_string()
}

/// System / reserved account names that must NOT be treated as a real given name.
/// When detection returns one of these, the caller should fall back to the
/// placeholder "Master" unless the user explicitly declared a different name.
pub const SYSTEM_ACCOUNT_NAMES: &[&str] = &[
    "admin", "administrator", "guest", "user", "wdagutilityaccount",
    "defaultaccount", "defaultuser0", "system", "localsystem", "local system",
    "network", "localservice", "local service", "networkservice", "network service",
    "homeuser",
];

/// Whether a detected name is a real given name (non-empty and not a system/
/// reserved account name). Fallbacks returned by `detect_user_given_name`
/// ("User", "Admin") are covered by the system-name set.
pub fn is_real_given_name(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_lowercase();
    !SYSTEM_ACCOUNT_NAMES.iter().any(|s| *s == lower)
}
/// Extract Given Name from a FullName string.
/// 
/// Handles common formats:
/// - "Smith, John" → "John"
/// - "John Smith" → "John"  
/// - "张三" (CJK, no spaces) → "张三"
/// - "John" → "John"
fn extract_given_name(full_name: &str) -> String {
    let name = full_name.trim();
    if name.is_empty() {
        return "User".to_string();
    }

    // Check for "Last, First" format (common in enterprise/AD environments)
    if let Some((_last, first)) = name.split_once(',') {
        let given = first.trim();
        if !given.is_empty() {
            return given.to_string();
        }
    }

    // Check if it's likely a CJK name (no spaces, contains CJK characters)
    let has_cjk = name.chars().any(is_cjk_char);
    let has_spaces = name.contains(' ');
    
    if has_cjk && !has_spaces {
        // CJK name without spaces — return as-is (typically the full name is used)
        return name.to_string();
    }

    // "First Last" format — take the first word
    if let Some(first_word) = name.split_whitespace().next() {
        let given = first_word.trim();
        if !given.is_empty() {
            return given.to_string();
        }
    }

    name.to_string()
}

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

impl Config {
    /// Load config from the workspace directory. If no config exists, check the
    /// exe directory for backward compatibility, then generate a minimal default
    /// config.toml in the workspace.
    pub fn load(workspace_dir: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config_path = std::path::Path::new(workspace_dir).join("config.toml");

        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            let config: Config = toml::from_str(&content)?;
            Ok(config)
        } else {
            // Backward compatibility: try exe_dir config.toml
            if let Some(exe_dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())) {
                let old_config_path = exe_dir.join("config.toml");
                if old_config_path.exists() {
                    tracing::info!("Migrating config.toml from exe dir to workspace");
                    let _ = std::fs::copy(&old_config_path, &config_path);
                    let content = std::fs::read_to_string(&config_path)?;
                    // Parse with relaxed deserialization — ignore unknown fields from old format
                    let config: Config = toml::from_str(&content).unwrap_or_default();
                    return Ok(config);
                }
            }
            // No config anywhere — generate minimal default
            Self::generate_default(workspace_dir)?;
            Ok(Config::default())
        }
    }

    /// Generate a minimal config.toml in the workspace with essential fields only.
    fn generate_default(workspace_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
        let config_content = r#"# RustAgent Configuration
# Models are managed via models.json, MCP servers via mcp_servers.json.
# Settings can also be changed via the Web UI Settings page.

[server]
host = "127.0.0.1"
port = 7788

[agent]
workspace_dir = "%USERPROFILE%\\.RustAgent\\Workspace"
working_dir = "."
max_iterations = 100
rabbit_hole_threshold = 5
trim_redundant_tool_calls = true
context_window_threshold = 80
# Raise per-tool inline caps with the model's context window (default: true)
enable_context_scaling = true
# Absolute cap (chars) on how much of one tool result / web body is injected
# into context, even when scaling is on (default: 120000)
max_inline_chars = 120000
# Skill catalog listing strategy for the system prompt (query | names-only | discover-tool-only)
skill_listing_strategy = "query"
# Max chars of a single hot skill body inlined into the prompt (default: 6000)
skill_max_inline_chars = 6000
# Max number of cold skills listed (name:desc) in the catalog (default: 40)
skill_catalog_max = 40
# Top-K fuzzy-matched skills inlined (hot) per turn (default: 3)
skill_hot_top_k = 3
tool_timeout_secs = 300
max_tool_retries = 2
# Enable parallel execution for IR collection tools (ir_scan, ir_process, etc.)
# Set to false to force sequential execution for debugging or compatibility
parallel_ir_tools = true
# Enable Computer Use (GUI control) tools
computer_use = false
# Primary and fallback model names (set via Settings UI)
# primary_model = "gpt-4o"
# fallback_model = ""
# Timezone offset in hours (e.g., 8 = UTC+8)
timezone_offset = 8
# Tool permissions (category -> allowed/denied)
# [agent.tool_permissions]
# read = true
# write = true
# delete = false
# execute = true
"#;
        let config_path = std::path::Path::new(workspace_dir).join("config.toml");
        std::fs::write(&config_path, config_content)?;
        tracing::info!("Generated default config.toml in workspace: {}", config_path.display());
        Ok(())
    }

    /// Save the current config to config.toml in the workspace directory.
    /// This persists agent settings (max_iterations, rabbit_hole_threshold, etc.)
    /// so they survive restarts.
    pub fn save(&self, workspace_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
        let config_path = std::path::Path::new(workspace_dir).join("config.toml");
        let content = toml::to_string_pretty(self)?;
        std::fs::write(&config_path, content)?;
        tracing::info!("Saved config.toml to workspace: {}", config_path.display());
        Ok(())
    }

    /// Save only agent settings to config.toml, preserving existing server settings.
    /// Reads the current config, updates agent fields, and writes back.
    pub fn save_agent_settings(
        workspace_dir: &str,
        max_iterations: usize,
        rabbit_hole_threshold: usize,
        context_window_threshold: usize,
        tool_timeout_secs: usize,
        max_tool_retries: usize,
        trim_redundant_tool_calls: bool,
        enable_context_scaling: bool,
        max_inline_chars: usize,
        skill_listing_strategy: String,
        skill_max_inline_chars: usize,
        skill_catalog_max: usize,
        skill_hot_top_k: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Load existing config (or create default if none exists)
        let mut config = Self::load(workspace_dir).unwrap_or_default();

        // Update agent settings
        config.agent.max_iterations = max_iterations;
        config.agent.rabbit_hole_threshold = rabbit_hole_threshold;
        config.agent.context_window_threshold = context_window_threshold;
        config.agent.tool_timeout_secs = tool_timeout_secs;
        config.agent.max_tool_retries = max_tool_retries;
        config.agent.trim_redundant_tool_calls = trim_redundant_tool_calls;
        config.agent.enable_context_scaling = enable_context_scaling;
        config.agent.max_inline_chars = max_inline_chars;
        config.agent.skill_listing_strategy = skill_listing_strategy;
        config.agent.skill_max_inline_chars = skill_max_inline_chars;
        config.agent.skill_catalog_max = skill_catalog_max;
        config.agent.skill_hot_top_k = skill_hot_top_k;

        // Save back to file
        config.save(workspace_dir)
    }

    /// Save extended agent settings (model selection, timezone, permissions) to config.toml.
    pub fn save_extended_settings(
        workspace_dir: &str,
        primary_model: Option<String>,
        fallback_model: Option<String>,
        timezone_offset: i8,
        tool_permissions: HashMap<String, bool>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = Self::load(workspace_dir).unwrap_or_default();

        config.agent.primary_model = primary_model;
        config.agent.fallback_model = fallback_model;
        config.agent.timezone_offset = timezone_offset;
        config.agent.tool_permissions = tool_permissions;

        config.save(workspace_dir)
    }

    /// Save Expert mode settings to config.toml.
    pub fn save_expert_settings(
        workspace_dir: &str,
        expert_max_iterations: usize,
        expert_tool_timeout_secs: usize,
        expert_max_tool_retries: usize,
        expert_max_managed_rounds: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = Self::load(workspace_dir).unwrap_or_default();

        config.agent.expert_max_iterations = expert_max_iterations;
        config.agent.expert_tool_timeout_secs = expert_tool_timeout_secs;
        config.agent.expert_max_tool_retries = expert_max_tool_retries;
        config.agent.expert_max_managed_rounds = expert_max_managed_rounds;

        config.save(workspace_dir)
    }

    /// Save Expert-mode per-role model overrides (Manager/Auditor/Executor) to config.toml.
    pub fn save_role_models(
        workspace_dir: &str,
        role_models: &RoleModelsConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut config = Self::load(workspace_dir).unwrap_or_default();
        config.agent.expert_role_models = role_models.clone();
        config.save(workspace_dir)
    }
}