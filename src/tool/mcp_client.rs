use async_trait::async_trait;
use rmcp::model::CallToolRequestParams;
use rmcp::service::RunningService;
use rmcp::{RoleClient, ServiceExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::process::Command;
use tracing::{error, info, warn};

use super::Tool;
use crate::config::McpServerConfig;
use crate::context::ToolContext;
use crate::error::AgentResult;

// ============================================================
// Data types
// ============================================================

/// MCP server status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ServerStatus {
    Connected,
    Disconnected,
    Error(String),
}

/// Runtime MCP server handle — wraps an rmcp RunningService
pub struct McpServerHandle {
    pub config: McpServerConfig,
    pub status: ServerStatus,
    service: Option<Arc<RunningService<RoleClient, ()>>>,
    tools: Vec<McpToolInfo>,
}

#[derive(Debug, Clone)]
struct McpToolInfo {
    name: String,
    description: String,
    input_schema: Value,
    #[allow(dead_code)]
    server_name: String,
}

/// Manages multiple MCP server connections with persistence.
/// Uses the `rmcp` crate (ADK-Rust's MCP protocol layer) for all
/// JSON-RPC / protocol handling — no hand-rolled wire code.
pub struct McpClientManager {
    servers: Vec<McpServerHandle>,
    persist_path: PathBuf,
}

impl McpClientManager {
    pub fn new() -> Self {
        Self {
            servers: Vec::new(),
            persist_path: PathBuf::from("mcp_servers.json"),
        }
    }

    pub fn with_persist_path(path: PathBuf) -> Self {
        Self {
            servers: Vec::new(),
            persist_path: path,
        }
    }

    // ── Connection lifecycle ──────────────────────────────

    /// Connect to all servers from config.
    pub async fn connect(&mut self, configs: &[McpServerConfig]) {
        for config in configs {
            if !config.enabled {
                info!("MCP server '{}' is disabled, skipping", config.name);
                self.servers.push(McpServerHandle {
                    config: config.clone(),
                    status: ServerStatus::Disconnected,
                    service: None,
                    tools: Vec::new(),
                });
                continue;
            }
            self.connect_server(config).await;
        }
    }

    /// Connect a single server (dispatches to stdio or HTTP).
    pub async fn connect_server(&mut self, config: &McpServerConfig) {
        info!("Connecting to MCP server: {} ({})", config.name, config.transport);
        match config.transport.as_str() {
            "sse" => self.connect_http(config).await,
            _ => self.connect_stdio(config).await,
        }
    }

    /// Connect via stdio child process using rmcp's TokioChildProcess.
    async fn connect_stdio(&mut self, config: &McpServerConfig) {
        let command = match &config.command {
            Some(cmd) => cmd,
            None => {
                warn!("MCP server '{}' has no command, skipping", config.name);
                self.servers.push(McpServerHandle {
                    config: config.clone(),
                    status: ServerStatus::Error("No command specified".to_string()),
                    service: None,
                    tools: Vec::new(),
                });
                return;
            }
        };

        // Build the tokio::process::Command
        let mut cmd = Command::new(command);
        cmd.args(&config.args);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        // Hide console window on Windows
        #[cfg(target_os = "windows")]
        cmd.creation_flags(0x08000000);

        // rmcp: spawn child process + perform MCP handshake automatically
        match rmcp::transport::TokioChildProcess::new(cmd) {
            Ok(transport) => match ().serve(transport).await {
                Ok(service) => {
                    let service = Arc::new(service);
                    let mut tools = Self::discover_tools(&service).await;
                    for t in &mut tools {
                        t.server_name = config.name.clone();
                    }
                    info!(
                        "MCP server '{}' connected via stdio with {} tools",
                        config.name,
                        tools.len()
                    );
                    self.servers.push(McpServerHandle {
                        config: config.clone(),
                        status: ServerStatus::Connected,
                        service: Some(service),
                        tools,
                    });
                }
                Err(e) => {
                    let msg = format!("Initialize failed: {}", e);
                    warn!("MCP server '{}' {}", config.name, msg);
                    self.servers.push(McpServerHandle {
                        config: config.clone(),
                        status: ServerStatus::Error(msg),
                        service: None,
                        tools: Vec::new(),
                    });
                }
            },
            Err(e) => {
                let msg = format!("Spawn failed: {}", e);
                warn!("MCP server '{}' {}", config.name, msg);
                self.servers.push(McpServerHandle {
                    config: config.clone(),
                    status: ServerStatus::Error(msg),
                    service: None,
                    tools: Vec::new(),
                });
            }
        }
    }

    /// Connect via HTTP (Streamable HTTP / SSE) using rmcp's transport.
    async fn connect_http(&mut self, config: &McpServerConfig) {
        let url = match &config.url {
            Some(u) => u.trim_end_matches('/').to_string(),
            None => {
                warn!("MCP server '{}' has no URL, skipping", config.name);
                self.servers.push(McpServerHandle {
                    config: config.clone(),
                    status: ServerStatus::Error("No URL specified".to_string()),
                    service: None,
                    tools: Vec::new(),
                });
                return;
            }
        };

        // Build HTTP transport with optional auth via rmcp config
        let mut transport_config =
            rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig::with_uri(
                url.as_str(),
            );

        if let Some(ref token) = config.auth_token {
            if !token.is_empty() {
                transport_config = transport_config.auth_header(token.as_str());
            }
        }

        let transport =
            rmcp::transport::StreamableHttpClientTransport::<reqwest::Client>::from_config(transport_config);

        match ().serve(transport).await {
            Ok(service) => {
                let service = Arc::new(service);
                let mut tools = Self::discover_tools(&service).await;
                for t in &mut tools {
                    t.server_name = config.name.clone();
                }
                info!(
                    "MCP server '{}' connected via HTTP with {} tools",
                    config.name,
                    tools.len()
                );
                self.servers.push(McpServerHandle {
                    config: config.clone(),
                    status: ServerStatus::Connected,
                    service: Some(service),
                    tools,
                });
            }
            Err(e) => {
                let msg = format!("HTTP initialize failed: {}", e);
                warn!("MCP server '{}' {}", config.name, msg);
                self.servers.push(McpServerHandle {
                    config: config.clone(),
                    status: ServerStatus::Error(msg),
                    service: None,
                    tools: Vec::new(),
                });
            }
        }
    }

    /// Discover tools from a connected rmcp service.
    async fn discover_tools(service: &Arc<RunningService<RoleClient, ()>>) -> Vec<McpToolInfo> {
        match service.list_all_tools().await {
            Ok(tools) => tools
                .into_iter()
                .map(|t| {
                    let schema_val: Value =
                        serde_json::to_value(t.input_schema.as_ref()).unwrap_or(json!({}));
                    McpToolInfo {
                        name: t.name.to_string(),
                        description: t
                            .description
                            .map(|d| d.to_string())
                            .unwrap_or_default(),
                        input_schema: schema_val,
                        server_name: String::new(),
                    }
                })
                .collect(),
            Err(e) => {
                warn!("tools/list failed: {}", e);
                Vec::new()
            }
        }
    }

    // ── Server management ─────────────────────────────────

    /// Disconnect a server by name.
    pub async fn disconnect_server(&mut self, name: &str) -> bool {
        if let Some(handle) = self.servers.iter_mut().find(|s| s.config.name == name) {
            handle.tools.clear();
            handle.status = ServerStatus::Disconnected;
            // Drop the service — rmcp cancels the background task and
            // closes the transport (kills child process for stdio).
            handle.service.take();
            info!("MCP server '{}' disconnected", name);
            true
        } else {
            false
        }
    }

    /// Remove a server by name (disconnect + remove from list).
    pub async fn remove_server(&mut self, name: &str) -> bool {
        if let Some(pos) = self.servers.iter().position(|s| s.config.name == name) {
            self.servers.remove(pos);
            info!("MCP server '{}' removed", name);
            true
        } else {
            false
        }
    }

    /// Reconnect a server by name.
    pub async fn reconnect_server(&mut self, name: &str) -> bool {
        let config = self
            .servers
            .iter()
            .find(|s| s.config.name == name)
            .map(|s| s.config.clone());

        if let Some(config) = config {
            self.remove_server(name).await;
            self.connect_server(&config).await;
            true
        } else {
            false
        }
    }

    /// Add a new server config (does not connect yet).
    pub fn add_server_config(&mut self, config: McpServerConfig) {
        self.servers.push(McpServerHandle {
            config,
            status: ServerStatus::Disconnected,
            service: None,
            tools: Vec::new(),
        });
    }

    /// Toggle a server's enabled state and connect/disconnect accordingly.
    pub async fn toggle_server(&mut self, name: &str) -> Option<bool> {
        let (enabled, config) = {
            let handle = self.servers.iter_mut().find(|s| s.config.name == name)?;
            handle.config.enabled = !handle.config.enabled;
            (handle.config.enabled, handle.config.clone())
        };

        if enabled {
            self.remove_server(name).await;
            self.connect_server(&config).await;
        } else {
            self.disconnect_server(name).await;
        }
        Some(enabled)
    }

    // ── Tool access ───────────────────────────────────────

    /// Get all tools from all connected servers as Arc<dyn Tool>.
    pub fn get_tools(&self) -> Vec<Arc<dyn Tool>> {
        let mut tools: Vec<Arc<dyn Tool>> = Vec::new();
        for server in &self.servers {
            if server.status != ServerStatus::Connected {
                continue;
            }
            let service = match &server.service {
                Some(s) => s.clone(),
                None => continue,
            };
            for tool_info in &server.tools {
                tools.push(Arc::new(McpProxyTool {
                    info: tool_info.clone(),
                    service: service.clone(),
                }));
            }
        }
        tools
    }

    /// Server info for the API endpoint.
    pub fn server_info(&self) -> Vec<Value> {
        self.servers
            .iter()
            .map(|s| {
                json!({
                    "name": s.config.name,
                    "transport": s.config.transport,
                    "command": s.config.command,
                    "args": s.config.args,
                    "url": s.config.url,
                    "enabled": s.config.enabled,
                    "status": match &s.status {
                        ServerStatus::Connected => "connected".to_string(),
                        ServerStatus::Disconnected => "disconnected".to_string(),
                        ServerStatus::Error(e) => format!("error: {}", e),
                    },
                    "tools": s.tools.iter().map(|t| json!({
                        "name": t.name, "description": t.description,
                    })).collect::<Vec<_>>()
                })
            })
            .collect()
    }

    // ── Persistence ───────────────────────────────────────

    /// Persist current server configs to JSON file.
    pub fn save_configs(&self) {
        let configs: Vec<&McpServerConfig> = self.servers.iter().map(|s| &s.config).collect();
        match serde_json::to_string_pretty(&configs) {
            Ok(json_str) => {
                if let Err(e) = std::fs::write(&self.persist_path, json_str) {
                    error!("Failed to save MCP configs: {}", e);
                } else {
                    info!("MCP configs saved to {}", self.persist_path.display());
                }
            }
            Err(e) => error!("Failed to serialize MCP configs: {}", e),
        }
    }

    /// Load server configs from JSON file.
    pub fn load_configs(&mut self) -> Vec<McpServerConfig> {
        if !self.persist_path.exists() {
            return Vec::new();
        }
        match std::fs::read_to_string(&self.persist_path) {
            Ok(content) => match serde_json::from_str::<Vec<McpServerConfig>>(&content) {
                Ok(configs) => {
                    info!(
                        "Loaded {} MCP configs from {}",
                        configs.len(),
                        self.persist_path.display()
                    );
                    configs
                }
                Err(e) => {
                    warn!("Failed to parse MCP configs: {}", e);
                    Vec::new()
                }
            },
            Err(e) => {
                warn!("Failed to read MCP configs: {}", e);
                Vec::new()
            }
        }
    }

    /// Gracefully shut down all servers.
    pub async fn shutdown(&mut self) {
        for server in &mut self.servers {
            server.service.take(); // Drop -> rmcp cancels task + closes transport
        }
    }
}

// ============================================================
// McpProxyTool — implements our Tool trait via rmcp service
// ============================================================

/// Proxy tool that forwards execute() calls to an MCP server
/// through the rmcp RunningService.
struct McpProxyTool {
    info: McpToolInfo,
    service: Arc<RunningService<RoleClient, ()>>,
}

#[async_trait]
impl Tool for McpProxyTool {
    fn name(&self) -> &str {
        &self.info.name
    }
    fn description(&self) -> &str {
        &self.info.description
    }
    fn parameters_schema(&self) -> Value {
        self.info.input_schema.clone()
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        // Convert args to rmcp's JsonObject (Map<String, Value>)
        let arguments = match args {
            Value::Object(map) => map,
            _ => serde_json::Map::new(),
        };

        // Build rmcp call request
        let params = CallToolRequestParams::new(self.info.name.clone()).with_arguments(arguments);

        // Call tool via rmcp service (Deref -> Peer<RoleClient>)
        let result = self
            .service
            .call_tool(params)
            .await
            .map_err(|e| format!("MCP call failed: {}", e))?;

        // Check for error
        if result.is_error == Some(true) {
            let msg = result
                .content
                .iter()
                .filter_map(|c| c.as_text().map(|t| t.text.as_ref()))
                .collect::<Vec<_>>()
                .join("\n");
            return Err(format!("MCP tool error: {}", msg).into());
        }

        // Serialize content to JSON Value
        Ok(serde_json::to_value(&result.content).unwrap_or(Value::Null))
    }
}
