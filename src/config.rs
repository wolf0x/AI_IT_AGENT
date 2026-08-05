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
    /// Context window usage threshold percentage (default: 80 = trim at 80% of model context)
    #[serde(default = "default_context_window_threshold")]
    pub context_window_threshold: usize,
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
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ModelConfig {
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
                context_window_threshold: default_context_window_threshold(),
                tool_timeout_secs: default_tool_timeout_secs(),
                max_tool_retries: default_max_tool_retries(),
                parallel_ir_tools: default_parallel_ir_tools(),
                computer_use: false,
                primary_model: None,
                fallback_model: None,
                timezone_offset: default_timezone_offset(),
                tool_permissions: HashMap::new(),
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
fn default_context_window() -> usize { 128000 }
fn default_context_window_threshold() -> usize { 80 }
fn default_tool_timeout_secs() -> usize { 300 }
fn default_max_tool_retries() -> usize { 2 }
fn default_parallel_ir_tools() -> bool { true }
fn default_max_tokens() -> u32 { 16384 }
fn default_temperature() -> f64 { 0.7 }
fn default_timezone_offset() -> i8 { 8 }

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
context_window_threshold = 80
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Load existing config (or create default if none exists)
        let mut config = Self::load(workspace_dir).unwrap_or_default();

        // Update agent settings
        config.agent.max_iterations = max_iterations;
        config.agent.rabbit_hole_threshold = rabbit_hole_threshold;
        config.agent.context_window_threshold = context_window_threshold;
        config.agent.tool_timeout_secs = tool_timeout_secs;
        config.agent.max_tool_retries = max_tool_retries;

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
}
