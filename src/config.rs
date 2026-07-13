use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub agent: AgentConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
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
            },
        }
    }
}

fn default_host() -> String { "0.0.0.0".to_string() }
fn default_port() -> u16 { 7788 }
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
fn default_max_tool_retries() -> usize { 2 }
fn default_max_tokens() -> u32 { 16384 }
fn default_temperature() -> f64 { 0.7 }

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
        let config_content = r#"# RustAgent Configuration (minimal)
# Models are managed via models.json, MCP servers via mcp_servers.json.
# Settings can also be changed via the Web UI Settings page.

[server]
host = "0.0.0.0"
port = 7788

[agent]
workspace_dir = "."
working_dir = "."
max_iterations = 100
rabbit_hole_threshold = 5
context_window_threshold = 80
tool_timeout_secs = 300
max_tool_retries = 2
"#;
        let config_path = std::path::Path::new(workspace_dir).join("config.toml");
        std::fs::write(&config_path, config_content)?;
        tracing::info!("Generated default config.toml in workspace: {}", config_path.display());
        Ok(())
    }
}
