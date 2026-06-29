use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub agent: AgentConfig,
    #[serde(default)]
    pub models: Vec<ModelConfig>,
    #[serde(default)]
    pub mcp_servers: Vec<McpServerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_password")]
    pub password: String,
    #[serde(default = "default_log_dir")]
    pub log_dir: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_working_dir")]
    pub working_dir: String,
    /// Agent workspace directory — the agent's "home" where AGENTS.md, SOUL.md, TOOLS.md live.
    /// Defaults to %USERPROFILE%\.RustAgent\workspace
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
                password: default_password(),
                log_dir: default_log_dir(),
            },
            agent: AgentConfig {
                working_dir: default_working_dir(),
                workspace_dir: default_workspace_dir(),
                max_iterations: default_max_iterations(),
                rabbit_hole_threshold: default_rabbit_hole_threshold(),
                context_window_threshold: default_context_window_threshold(),
                tool_timeout_secs: default_tool_timeout_secs(),
            },
            models: vec![],
            mcp_servers: vec![],
        }
    }
}

fn default_host() -> String { "0.0.0.0".to_string() }
fn default_port() -> u16 { 7788 }
fn default_password() -> String { "123".to_string() }
fn default_log_dir() -> String { "logs".to_string() }
fn default_working_dir() -> String { ".".to_string() }
fn default_workspace_dir() -> String {
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        format!("{}\\.RustAgent\\workspace", userprofile)
    } else {
        ".workspace".to_string()
    }
}
fn default_max_iterations() -> usize { 100 }
fn default_rabbit_hole_threshold() -> usize { 5 }
fn default_context_window() -> usize { 128000 }
fn default_context_window_threshold() -> usize { 80 }
fn default_tool_timeout_secs() -> usize { 300 }
fn default_max_tokens() -> u32 { 16384 }
fn default_temperature() -> f64 { 0.7 }

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let p = Path::new(path);
        if p.exists() {
            let content = std::fs::read_to_string(p)?;
            let config: Config = toml::from_str(&content)?;
            Ok(config)
        } else {
            tracing::warn!("Config file {} not found, using defaults", path);
            Ok(Config::default())
        }
    }
}
