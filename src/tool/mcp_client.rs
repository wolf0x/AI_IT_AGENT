use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tracing::{info, warn};

use super::Tool;
use crate::config::McpServerConfig;
use crate::context::ToolContext;
use crate::error::AgentResult;

/// Lightweight MCP (Model Context Protocol) client using JSON-RPC 2.0 over stdio.
pub struct McpClientManager {
    servers: Vec<McpServerHandle>,
}

struct McpServerHandle {
    config: McpServerConfig,
    child: Option<Child>,
    request_id: Arc<Mutex<u64>>,
    writer: Arc<Mutex<Option<tokio::process::ChildStdin>>>,
    reader: Arc<Mutex<Option<BufReader<tokio::process::ChildStdout>>>>,
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

#[derive(Debug, Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: u64,
    method: String,
    params: Value,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    #[allow(dead_code)]
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

impl McpClientManager {
    pub fn new() -> Self {
        Self { servers: Vec::new() }
    }

    pub async fn connect(&mut self, configs: &[McpServerConfig]) {
        for config in configs {
            info!("Connecting to MCP server: {}", config.name);
            match Self::spawn_server(config).await {
                Ok(handle) => {
                    info!("MCP server '{}' connected with {} tools", config.name, handle.tools.len());
                    self.servers.push(handle);
                }
                Err(e) => {
                    warn!("Failed to connect MCP server '{}': {}", config.name, e);
                }
            }
        }
    }

    async fn spawn_server(config: &McpServerConfig) -> Result<McpServerHandle, String> {
        let mut cmd = Command::new(&config.command);
        cmd.args(&config.args);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.creation_flags(0x08000000);

        let mut child = cmd.spawn().map_err(|e| format!("Failed to spawn: {}", e))?;
        let stdin = child.stdin.take().ok_or("No stdin")?;
        let stdout = child.stdout.take().ok_or("No stdout")?;

        let writer = Arc::new(Mutex::new(Some(stdin)));
        let reader = Arc::new(Mutex::new(Some(BufReader::new(stdout))));
        let request_id = Arc::new(Mutex::new(0u64));

        let mut handle = McpServerHandle {
            config: config.clone(),
            child: Some(child),
            request_id,
            writer,
            reader,
            tools: Vec::new(),
        };

        // MCP initialize handshake
        handle.send_request("initialize", json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "rust-agent", "version": "0.1.0" }
        })).await?;

        handle.send_notification("notifications/initialized", json!({})).await?;

        let tools_result = handle.send_request("tools/list", json!({})).await?;
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

        Ok(handle)
    }

    pub fn get_tools(&self) -> Vec<Arc<dyn Tool>> {
        let mut tools: Vec<Arc<dyn Tool>> = Vec::new();
        for server in &self.servers {
            for tool_info in &server.tools {
                tools.push(Arc::new(McpProxyTool {
                    info: tool_info.clone(),
                    writer: server.writer.clone(),
                    reader: server.reader.clone(),
                    request_id: server.request_id.clone(),
                }));
            }
        }
        tools
    }

    pub fn server_info(&self) -> Vec<Value> {
        self.servers.iter().map(|s| {
            json!({
                "name": s.config.name,
                "command": s.config.command,
                "tools": s.tools.iter().map(|t| json!({
                    "name": t.name, "description": t.description,
                })).collect::<Vec<_>>()
            })
        }).collect()
    }

    #[allow(dead_code)]
    pub async fn shutdown(&mut self) {
        for server in &mut self.servers {
            if let Some(ref mut child) = server.child {
                let _ = child.kill().await;
            }
        }
    }
}

impl McpServerHandle {
    async fn send_request(&self, method: &str, params: Value) -> Result<Value, String> {
        let mut id_guard = self.request_id.lock().await;
        *id_guard += 1;
        let id = *id_guard;
        drop(id_guard);

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(), id, method: method.to_string(), params,
        };
        let msg = serde_json::to_string(&req).map_err(|e| format!("Serialize error: {}", e))?;

        let mut writer_guard = self.writer.lock().await;
        let writer = writer_guard.as_mut().ok_or("Writer closed")?;
        writer.write_all(msg.as_bytes()).await.map_err(|e| format!("Write error: {}", e))?;
        writer.write_all(b"\n").await.map_err(|e| format!("Write error: {}", e))?;
        writer.flush().await.map_err(|e| format!("Flush error: {}", e))?;
        drop(writer_guard);

        let mut reader_guard = self.reader.lock().await;
        let reader = reader_guard.as_mut().ok_or("Reader closed")?;
        let mut line = String::new();
        reader.read_line(&mut line).await.map_err(|e| format!("Read error: {}", e))?;

        let resp: JsonRpcResponse = serde_json::from_str(&line)
            .map_err(|e| format!("Parse error: {} | line: {}", e, line))?;

        if let Some(err) = resp.error {
            return Err(format!("MCP error: {}", err.message));
        }
        Ok(resp.result.unwrap_or(Value::Null))
    }

    async fn send_notification(&self, method: &str, params: Value) -> Result<(), String> {
        let msg = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        let msg_str = serde_json::to_string(&msg).map_err(|e| format!("Serialize error: {}", e))?;
        let mut writer_guard = self.writer.lock().await;
        let writer = writer_guard.as_mut().ok_or("Writer closed")?;
        writer.write_all(msg_str.as_bytes()).await.map_err(|e| format!("Write error: {}", e))?;
        writer.write_all(b"\n").await.map_err(|e| format!("Write error: {}", e))?;
        writer.flush().await.map_err(|e| format!("Flush error: {}", e))?;
        Ok(())
    }
}

/// Proxy tool that forwards calls to an MCP server
struct McpProxyTool {
    info: McpToolInfo,
    writer: Arc<Mutex<Option<tokio::process::ChildStdin>>>,
    reader: Arc<Mutex<Option<BufReader<tokio::process::ChildStdout>>>>,
    request_id: Arc<Mutex<u64>>,
}

#[async_trait]
impl Tool for McpProxyTool {
    fn name(&self) -> &str { &self.info.name }
    fn description(&self) -> &str { &self.info.description }
    fn parameters_schema(&self) -> Value { self.info.input_schema.clone() }
    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let mut id_guard = self.request_id.lock().await;
        *id_guard += 1;
        let id = *id_guard;
        drop(id_guard);

        let req = json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": self.info.name, "arguments": args }
        });
        let msg = serde_json::to_string(&req).map_err(|e| format!("Serialize: {}", e))?;

        let mut writer_guard = self.writer.lock().await;
        let writer = writer_guard.as_mut().ok_or_else(|| "Writer closed".to_string())?;
        writer.write_all(msg.as_bytes()).await.map_err(|e| format!("Write: {}", e))?;
        writer.write_all(b"\n").await.map_err(|e| format!("Write: {}", e))?;
        writer.flush().await.map_err(|e| format!("Flush: {}", e))?;
        drop(writer_guard);

        let mut reader_guard = self.reader.lock().await;
        let reader = reader_guard.as_mut().ok_or_else(|| "Reader closed".to_string())?;
        let mut line = String::new();
        reader.read_line(&mut line).await.map_err(|e| format!("Read: {}", e))?;

        let resp: JsonRpcResponse = serde_json::from_str(&line)
            .map_err(|e| format!("Parse: {} | {}", e, line))?;

        if let Some(err) = resp.error {
            return Err(format!("MCP tool error: {}", err.message).into());
        }
        Ok(resp.result.unwrap_or(Value::Null))
    }
}

impl Drop for McpServerHandle {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.start_kill();
        }
    }
}
