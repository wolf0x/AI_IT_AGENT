use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tracing::{info, warn, error};

use super::Tool;
use crate::config::McpServerConfig;
use crate::context::ToolContext;
use crate::error::AgentResult;

/// MCP server status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ServerStatus {
    Connected,
    Disconnected,
    Error(String),
}

/// Runtime MCP server handle
pub struct McpServerHandle {
    pub config: McpServerConfig,
    pub status: ServerStatus,
    transport: McpTransport,
    tools: Vec<McpToolInfo>,
    request_id: Arc<Mutex<u64>>,
}

enum McpTransport {
    Stdio {
        child: Option<Child>,
        writer: Arc<Mutex<Option<tokio::process::ChildStdin>>>,
        reader: Arc<Mutex<Option<BufReader<tokio::process::ChildStdout>>>>,
    },
    Sse {
        client: reqwest::Client,
        base_url: String,
    },
}

#[derive(Debug, Clone)]
struct McpToolInfo {
    name: String,
    description: String,
    input_schema: Value,
    server_name: String,
}

#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: u64,
    method: String,
    params: Value,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct JsonRpcResponse {
    id: Option<u64>,
    result: Option<Value>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    #[allow(dead_code)]
    code: i64,
    message: String,
}

/// Manages multiple MCP server connections with persistence.
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

    /// Connect to all servers from config.
    pub async fn connect(&mut self, configs: &[McpServerConfig]) {
        for config in configs {
            if !config.enabled {
                info!("MCP server '{}' is disabled, skipping", config.name);
                // Still add to list as disconnected
                self.servers.push(McpServerHandle {
                    config: config.clone(),
                    status: ServerStatus::Disconnected,
                    transport: McpTransport::Stdio {
                        child: None,
                        writer: Arc::new(Mutex::new(None)),
                        reader: Arc::new(Mutex::new(None)),
                    },
                    tools: Vec::new(),
                    request_id: Arc::new(Mutex::new(0)),
                });
                continue;
            }
            self.connect_server(config).await;
        }
    }

    /// Connect a single server.
    pub async fn connect_server(&mut self, config: &McpServerConfig) {
        info!("Connecting to MCP server: {} ({})", config.name, config.transport);
        match config.transport.as_str() {
            "sse" => self.connect_sse(config).await,
            _ => self.connect_stdio(config).await,
        }
    }

    async fn connect_stdio(&mut self, config: &McpServerConfig) {
        let command = match &config.command {
            Some(cmd) => cmd,
            None => {
                warn!("MCP server '{}' has no command, skipping", config.name);
                self.servers.push(McpServerHandle {
                    config: config.clone(),
                    status: ServerStatus::Error("No command specified".to_string()),
                    transport: McpTransport::Stdio {
                        child: None,
                        writer: Arc::new(Mutex::new(None)),
                        reader: Arc::new(Mutex::new(None)),
                    },
                    tools: Vec::new(),
                    request_id: Arc::new(Mutex::new(0)),
                });
                return;
            }
        };

        let mut cmd = Command::new(command);
        cmd.args(&config.args);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.creation_flags(0x08000000);

        match cmd.spawn() {
            Ok(mut child) => {
                let stdin = child.stdin.take();
                let stdout = child.stdout.take();

                let writer = Arc::new(Mutex::new(stdin));
                let reader = Arc::new(Mutex::new(stdout.map(BufReader::new)));
                let request_id = Arc::new(Mutex::new(0u64));

                let mut handle = McpServerHandle {
                    config: config.clone(),
                    status: ServerStatus::Connected,
                    transport: McpTransport::Stdio {
                        child: Some(child),
                        writer: writer.clone(),
                        reader: reader.clone(),
                    },
                    tools: Vec::new(),
                    request_id: request_id.clone(),
                };

                // MCP Initialize handshake
                let init_result = Self::stdio_send_request(&writer, &reader, &request_id, "initialize", json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": { "name": "rust-agent", "version": "0.1.0" }
                })).await;

                match init_result {
                    Ok(_) => {
                        let _ = Self::stdio_send_notification(&writer, &reader, "notifications/initialized", json!({})).await;

                        // Get tools list
                        match Self::stdio_send_request(&writer, &reader, &request_id, "tools/list", json!({})).await {
                            Ok(tools_result) => {
                                if let Some(tools_arr) = tools_result.get("tools").and_then(|v| v.as_array()) {
                                    for tool_val in tools_arr {
                                        let name = tool_val["name"].as_str().unwrap_or("").to_string();
                                        let desc = tool_val["description"].as_str().unwrap_or("").to_string();
                                        let schema = tool_val["inputSchema"].clone();
                                        handle.tools.push(McpToolInfo {
                                            name, description: desc, input_schema: schema,
                                            server_name: config.name.clone(),
                                        });
                                    }
                                }
                                info!("MCP server '{}' connected with {} tools", config.name, handle.tools.len());
                            }
                            Err(e) => {
                                warn!("MCP server '{}' tools/list failed: {}", config.name, e);
                                handle.status = ServerStatus::Error(e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("MCP server '{}' initialize failed: {}", config.name, e);
                        handle.status = ServerStatus::Error(e);
                    }
                }

                self.servers.push(handle);
            }
            Err(e) => {
                warn!("Failed to spawn MCP server '{}': {}", config.name, e);
                self.servers.push(McpServerHandle {
                    config: config.clone(),
                    status: ServerStatus::Error(format!("Spawn failed: {}", e)),
                    transport: McpTransport::Stdio {
                        child: None,
                        writer: Arc::new(Mutex::new(None)),
                        reader: Arc::new(Mutex::new(None)),
                    },
                    tools: Vec::new(),
                    request_id: Arc::new(Mutex::new(0)),
                });
            }
        }
    }

    async fn connect_sse(&mut self, config: &McpServerConfig) {
        let base_url = match &config.url {
            Some(url) => url.trim_end_matches('/').to_string(),
            None => {
                warn!("MCP server '{}' has no URL for SSE, skipping", config.name);
                self.servers.push(McpServerHandle {
                    config: config.clone(),
                    status: ServerStatus::Error("No URL specified".to_string()),
                    transport: McpTransport::Sse {
                        client: reqwest::Client::new(),
                        base_url: String::new(),
                    },
                    tools: Vec::new(),
                    request_id: Arc::new(Mutex::new(0)),
                });
                return;
            }
        };

        let client = reqwest::Client::new();
        let request_id = Arc::new(Mutex::new(0u64));

        let mut handle = McpServerHandle {
            config: config.clone(),
            status: ServerStatus::Connected,
            transport: McpTransport::Sse {
                client: client.clone(),
                base_url: base_url.clone(),
            },
            tools: Vec::new(),
            request_id: request_id.clone(),
        };

        // SSE MCP handshake via HTTP POST
        let init_result = Self::sse_send_request(&client, &base_url, &request_id, "initialize", json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "rust-agent", "version": "0.1.0" }
        })).await;

        match init_result {
            Ok(_) => {
                let _ = Self::sse_send_notification(&client, &base_url, "notifications/initialized", json!({})).await;

                match Self::sse_send_request(&client, &base_url, &request_id, "tools/list", json!({})).await {
                    Ok(tools_result) => {
                        if let Some(tools_arr) = tools_result.get("tools").and_then(|v| v.as_array()) {
                            for tool_val in tools_arr {
                                let name = tool_val["name"].as_str().unwrap_or("").to_string();
                                let desc = tool_val["description"].as_str().unwrap_or("").to_string();
                                let schema = tool_val["inputSchema"].clone();
                                handle.tools.push(McpToolInfo {
                                    name, description: desc, input_schema: schema,
                                    server_name: config.name.clone(),
                                });
                            }
                        }
                        info!("MCP SSE server '{}' connected with {} tools", config.name, handle.tools.len());
                    }
                    Err(e) => {
                        warn!("MCP SSE server '{}' tools/list failed: {}", config.name, e);
                        handle.status = ServerStatus::Error(e);
                    }
                }
            }
            Err(e) => {
                warn!("MCP SSE server '{}' initialize failed: {}", config.name, e);
                handle.status = ServerStatus::Error(e);
            }
        }

        self.servers.push(handle);
    }

    /// Disconnect a server by name.
    pub async fn disconnect_server(&mut self, name: &str) -> bool {
        if let Some(handle) = self.servers.iter_mut().find(|s| s.config.name == name) {
            handle.tools.clear();
            handle.status = ServerStatus::Disconnected;
            // Kill child process if stdio
            if let McpTransport::Stdio { ref mut child, ref mut writer, ref mut reader } = handle.transport {
                if let Some(ref mut c) = child {
                    let _ = c.kill().await;
                }
                *child = None;
                *writer.lock().await = None;
                *reader.lock().await = None;
            }
            info!("MCP server '{}' disconnected", name);
            true
        } else {
            false
        }
    }

    /// Remove a server by name (disconnect + remove from list).
    pub async fn remove_server(&mut self, name: &str) -> bool {
        let len_before = self.servers.len();
        if let Some(pos) = self.servers.iter().position(|s| s.config.name == name) {
            let handle = &mut self.servers[pos];
            if let McpTransport::Stdio { ref mut child, .. } = handle.transport {
                if let Some(ref mut c) = child {
                    let _ = c.kill().await;
                }
            }
            self.servers.remove(pos);
            info!("MCP server '{}' removed", name);
            true
        } else {
            false
        }
    }

    /// Reconnect a server by name.
    pub async fn reconnect_server(&mut self, name: &str) -> bool {
        // Find the config
        let config = self.servers.iter()
            .find(|s| s.config.name == name)
            .map(|s| s.config.clone());

        if let Some(config) = config {
            // Remove old handle
            self.remove_server(name).await;
            // Reconnect
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
            transport: McpTransport::Stdio {
                child: None,
                writer: Arc::new(Mutex::new(None)),
                reader: Arc::new(Mutex::new(None)),
            },
            tools: Vec::new(),
            request_id: Arc::new(Mutex::new(0)),
        });
    }

    /// Toggle a server's enabled state and connect/disconnect accordingly.
    pub async fn toggle_server(&mut self, name: &str) -> Option<bool> {
        let handle = self.servers.iter_mut().find(|s| s.config.name == name)?;
        handle.config.enabled = !handle.config.enabled;
        let enabled = handle.config.enabled;
        let name_owned = name.to_string();

        if enabled {
            // Need to reconnect - get config first
            let config = handle.config.clone();
            drop(handle);
            self.remove_server(&name_owned).await;
            self.connect_server(&config).await;
        } else {
            self.disconnect_server(&name_owned).await;
        }
        Some(enabled)
    }

    pub fn get_tools(&self) -> Vec<Arc<dyn Tool>> {
        let mut tools: Vec<Arc<dyn Tool>> = Vec::new();
        for server in &self.servers {
            if server.status != ServerStatus::Connected {
                continue;
            }
            for tool_info in &server.tools {
                tools.push(Arc::new(McpProxyTool {
                    info: tool_info.clone(),
                    transport_type: match &server.transport {
                        McpTransport::Stdio { .. } => "stdio",
                        McpTransport::Sse { .. } => "sse",
                    }.to_string(),
                    writer: match &server.transport {
                        McpTransport::Stdio { writer, .. } => Some(writer.clone()),
                        _ => None,
                    },
                    reader: match &server.transport {
                        McpTransport::Stdio { reader, .. } => Some(reader.clone()),
                        _ => None,
                    },
                    request_id: server.request_id.clone(),
                    sse_client: match &server.transport {
                        McpTransport::Sse { client, .. } => Some(client.clone()),
                        _ => None,
                    },
                    sse_base_url: match &server.transport {
                        McpTransport::Sse { base_url, .. } => Some(base_url.clone()),
                        _ => None,
                    },
                }));
            }
        }
        tools
    }

    pub fn server_info(&self) -> Vec<Value> {
        self.servers.iter().map(|s| {
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
        }).collect()
    }

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
            Ok(content) => {
                match serde_json::from_str::<Vec<McpServerConfig>>(&content) {
                    Ok(configs) => {
                        info!("Loaded {} MCP configs from {}", configs.len(), self.persist_path.display());
                        configs
                    }
                    Err(e) => {
                        warn!("Failed to parse MCP configs: {}", e);
                        Vec::new()
                    }
                }
            }
            Err(e) => {
                warn!("Failed to read MCP configs: {}", e);
                Vec::new()
            }
        }
    }

    #[allow(dead_code)]
    pub async fn shutdown(&mut self) {
        for server in &mut self.servers {
            if let McpTransport::Stdio { ref mut child, .. } = server.transport {
                if let Some(ref mut c) = child {
                    let _ = c.kill().await;
                }
            }
        }
    }

    // --- Static helpers for stdio ---

    pub(crate) async fn stdio_send_request(
        writer: &Arc<Mutex<Option<tokio::process::ChildStdin>>>,
        reader: &Arc<Mutex<Option<BufReader<tokio::process::ChildStdout>>>>,
        request_id: &Arc<Mutex<u64>>,
        method: &str,
        params: Value,
    ) -> Result<Value, String> {
        let mut id_guard = request_id.lock().await;
        *id_guard += 1;
        let id = *id_guard;
        drop(id_guard);

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(), id, method: method.to_string(), params,
        };
        let msg = serde_json::to_string(&req).map_err(|e| format!("Serialize error: {}", e))?;

        let mut writer_guard = writer.lock().await;
        let w = writer_guard.as_mut().ok_or("Writer closed")?;
        w.write_all(msg.as_bytes()).await.map_err(|e| format!("Write error: {}", e))?;
        w.write_all(b"\n").await.map_err(|e| format!("Write error: {}", e))?;
        w.flush().await.map_err(|e| format!("Flush error: {}", e))?;
        drop(writer_guard);

        let mut reader_guard = reader.lock().await;
        let r = reader_guard.as_mut().ok_or("Reader closed")?;

        // Read lines until we get the response matching our request id.
        // MCP servers may emit asynchronous notifications (messages with a
        // `method` field and no `id`) interleaved with responses; those must be
        // skipped so they are not mistaken for the response.
        loop {
            let mut line = String::new();
            let n = r.read_line(&mut line).await.map_err(|e| format!("Read error: {}", e))?;
            if n == 0 {
                return Err("MCP server closed the connection".to_string());
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let parsed: Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(e) => {
                    // Skip unparseable lines (e.g. server banner/logging) but keep going.
                    tracing::debug!("MCP: skipping unparseable line: {} | {}", e, trimmed);
                    continue;
                }
            };
            // Notifications have no `id` — ignore them and keep waiting.
            if parsed.get("id").is_none() {
                tracing::debug!("MCP: skipping notification: {:?}", parsed.get("method"));
                continue;
            }
            // Only consume the message that matches our request id.
            if parsed["id"].as_u64() != Some(id) {
                tracing::debug!("MCP: skipping response for foreign id {:?}", parsed["id"]);
                continue;
            }
            if let Some(err) = parsed.get("error") {
                let msg = err["message"].as_str().unwrap_or("Unknown error");
                return Err(format!("MCP error: {}", msg));
            }
            return Ok(parsed.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    async fn stdio_send_notification(
        writer: &Arc<Mutex<Option<tokio::process::ChildStdin>>>,
        _reader: &Arc<Mutex<Option<BufReader<tokio::process::ChildStdout>>>>,
        method: &str,
        params: Value,
    ) -> Result<(), String> {
        let msg = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        let msg_str = serde_json::to_string(&msg).map_err(|e| format!("Serialize error: {}", e))?;
        let mut writer_guard = writer.lock().await;
        let w = writer_guard.as_mut().ok_or("Writer closed")?;
        w.write_all(msg_str.as_bytes()).await.map_err(|e| format!("Write error: {}", e))?;
        w.write_all(b"\n").await.map_err(|e| format!("Write error: {}", e))?;
        w.flush().await.map_err(|e| format!("Flush error: {}", e))?;
        Ok(())
    }

    // --- Static helpers for SSE ---

    async fn sse_send_request(
        client: &reqwest::Client,
        base_url: &str,
        request_id: &Arc<Mutex<u64>>,
        method: &str,
        params: Value,
    ) -> Result<Value, String> {
        let mut id_guard = request_id.lock().await;
        *id_guard += 1;
        let id = *id_guard;
        drop(id_guard);

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(), id, method: method.to_string(), params,
        };

        let resp = client.post(format!("{}/message", base_url))
            .json(&req)
            .send()
            .await
            .map_err(|e| format!("SSE request failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("SSE HTTP error: {}", resp.status()));
        }

        let body: Value = resp.json().await
            .map_err(|e| format!("SSE parse error: {}", e))?;

        if let Some(err) = body.get("error") {
            let msg = err["message"].as_str().unwrap_or("Unknown error");
            return Err(format!("MCP error: {}", msg));
        }

        Ok(body.get("result").cloned().unwrap_or(Value::Null))
    }

    async fn sse_send_notification(
        client: &reqwest::Client,
        base_url: &str,
        method: &str,
        params: Value,
    ) -> Result<(), String> {
        let msg = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        let _ = client.post(format!("{}/message", base_url))
            .json(&msg)
            .send()
            .await
            .map_err(|e| format!("SSE notification failed: {}", e))?;
        Ok(())
    }
}

/// Proxy tool that forwards calls to an MCP server (stdio or SSE).
struct McpProxyTool {
    info: McpToolInfo,
    transport_type: String,
    writer: Option<Arc<Mutex<Option<tokio::process::ChildStdin>>>>,
    reader: Option<Arc<Mutex<Option<BufReader<tokio::process::ChildStdout>>>>>,
    request_id: Arc<Mutex<u64>>,
    sse_client: Option<reqwest::Client>,
    sse_base_url: Option<String>,
}

#[async_trait]
impl Tool for McpProxyTool {
    fn name(&self) -> &str { &self.info.name }
    fn description(&self) -> &str { &self.info.description }
    fn parameters_schema(&self) -> Value { self.info.input_schema.clone() }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        match self.transport_type.as_str() {
            "sse" => {
                let client = self.sse_client.as_ref().ok_or_else(|| "No SSE client".to_string())?;
                let base_url = self.sse_base_url.as_ref().ok_or_else(|| "No SSE URL".to_string())?;

                let mut id_guard = self.request_id.lock().await;
                *id_guard += 1;
                let id = *id_guard;
                drop(id_guard);

                let req = json!({
                    "jsonrpc": "2.0", "id": id, "method": "tools/call",
                    "params": { "name": self.info.name, "arguments": args }
                });

                let resp = client.post(format!("{}/message", base_url))
                    .json(&req)
                    .send()
                    .await
                    .map_err(|e| format!("SSE call failed: {}", e))?;

                let body: Value = resp.json().await
                    .map_err(|e| format!("SSE parse: {}", e))?;

                if let Some(err) = body.get("error") {
                    let msg = err["message"].as_str().unwrap_or("Unknown");
                    return Err(format!("MCP tool error: {}", msg).into());
                }

                Ok(body.get("result").cloned().unwrap_or(Value::Null))
            }
            _ => {
                // stdio — delegate to the shared request helper so it benefits
                // from proper request/response correlation (id matching and
                // notification skipping).
                let writer = self.writer.as_ref().ok_or_else(|| "Writer closed".to_string())?;
                let reader = self.reader.as_ref().ok_or_else(|| "Reader closed".to_string())?;

                let params = json!({ "name": self.info.name, "arguments": args });
                let result = McpClientManager::stdio_send_request(
                    writer, reader, &self.request_id, "tools/call", params,
                )
                    .await
                    .map_err(crate::error::AgentError::from)?;
                Ok(result)
            }
        }
    }
}
