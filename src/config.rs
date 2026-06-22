use serde::Deserialize;
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
    #[serde(default = "default_max_iterations")]
    pub max_iterations: usize,
    #[serde(default = "default_rabbit_hole_threshold")]
    pub rabbit_hole_threshold: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModelConfig {
    pub name: String,
    pub api_base: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub api_key_env: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct McpServerConfig {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
}

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
                max_iterations: default_max_iterations(),
                rabbit_hole_threshold: default_rabbit_hole_threshold(),
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
fn default_max_iterations() -> usize { 100 }
fn default_rabbit_hole_threshold() -> usize { 5 }

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
