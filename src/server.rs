use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    response::{IntoResponse, Response},
    routing::{get, post, put, delete},
    Json, Router,
};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;
use tracing::info;

use crate::agent::AgentEvent;
use crate::log::ConversationLogger;
use crate::memory::MemoryStore;
use crate::model::ChatMessage;
use crate::permission::{PermissionResolver, PendingMap};
use crate::runner::Runner;
use crate::runner::ResumeState;
use crate::scheduler::{Scheduler, CronTask};
use crate::skill::SkillManager;
use crate::config::McpServerConfig;
use crate::external_tools::ExternalToolsManager;
use crate::tool::mcp_client::McpClientManager;
use crate::tool::ToolRegistry;
use crate::web::StaticServer;

/// Type alias for the broadcast channel used to push notifications to all WS clients.
pub type NotifyTx = tokio::sync::broadcast::Sender<String>;
pub type NotifyRx = tokio::sync::broadcast::Receiver<String>;

pub struct AppState {
    pub runner: Arc<Runner>,
    pub skill_manager: Arc<SkillManager>,
    pub mcp_manager: Arc<Mutex<McpClientManager>>,
    /// Shared tool registry — wrapped in RwLock so MCP handlers can register/unregister tools dynamically
    pub tools: Arc<tokio::sync::RwLock<ToolRegistry>>,
    pub logger: Arc<ConversationLogger>,
    pub memory_store: Arc<MemoryStore>,
    pub external_tools: Arc<Mutex<ExternalToolsManager>>,
    pub password: String,
    /// Shared mutable model configs (shared with OpenAiProvider for runtime CRUD)
    pub model_configs: Arc<tokio::sync::RwLock<Vec<crate::config::ModelConfig>>>,
    /// Path to models.json persistence file
    pub model_store_path: String,
    pub max_iterations: usize,
    pub rabbit_hole_threshold: usize,
    pub context_window_threshold: usize,
    pub tool_timeout_secs: usize,
    /// Per-session conversation history for multi-turn context
    pub sessions: Mutex<std::collections::HashMap<String, Vec<ChatMessage>>>,
    /// Permission settings (category -> allowed), shared across connections
    pub permissions: Arc<Mutex<std::collections::HashMap<String, bool>>>,
    /// Resolver for pending permission requests
    pub permission_resolver: PermissionResolver,
    /// Shared pending map for permission requests
    pub permission_pending: PendingMap,
    /// CRON task scheduler
    pub scheduler: Arc<Mutex<Scheduler>>,
    /// Broadcast channel for push notifications (sys_remind, etc.)
    pub notify_tx: NotifyTx,
    /// Agent workspace directory (where AGENTS.md, SOUL.md, TOOLS.md live)
    pub workspace_dir: String,
}

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/static/{*path}", get(static_handler))
        .route("/ws", get(ws_handler))
        .route("/api/models", get(models_handler))
        .route("/api/providers", get(providers_handler))
        .route("/api/providers", post(providers_create_handler))
        .route("/api/providers/{name}", put(providers_update_handler))
        .route("/api/providers/{name}", delete(providers_delete_handler))
        .route("/api/health", get(health_handler))
        .route("/api/skills", get(skills_handler))
        .route("/api/skills", post(skills_create_handler))
        .route("/api/skills/reload", post(skills_reload_handler))
        .route("/api/skills/{name}", delete(skills_delete_handler))
        .route("/api/skills/{name}/toggle", post(skills_toggle_handler))
        .route("/api/mcp", get(mcp_handler))
        .route("/api/mcp", post(mcp_create_handler))
        .route("/api/mcp/{name}", delete(mcp_delete_handler))
        .route("/api/mcp/{name}/toggle", post(mcp_toggle_handler))
        .route("/api/mcp/{name}/restart", post(mcp_restart_handler))
        .route("/api/logs", get(logs_handler))
        .route("/api/logs/dates", get(log_dates_handler))
        .route("/api/cron", get(cron_list_handler))
        .route("/api/cron", post(cron_create_handler))
        .route("/api/cron/{id}", put(cron_update_handler))
        .route("/api/cron/{id}", delete(cron_delete_handler))
        .route("/api/cron/{id}/toggle", post(cron_toggle_handler))
        .route("/api/notify", post(notify_handler))
        .route("/api/memory/dates", get(memory_dates_handler))
        .route("/api/memory/summaries", get(memory_summaries_handler))
        .route("/api/memory", get(memory_entries_handler))
        .route("/api/memory/summarize", post(memory_summarize_handler))
        .route("/api/history", get(history_handler))
        .route("/api/tools", get(tools_handler))
        .route("/api/tools/{name}/toggle", post(tools_toggle_handler))
        .route("/api/tools/{name}/description", post(tools_desc_handler))
        .route("/api/config/files", get(config_files_handler))
        .route("/api/config/files/{name}", put(config_file_save_handler))
        .route("/api/checkpoints", get(checkpoints_list_handler))
        .route("/api/checkpoints/{id}", delete(checkpoints_delete_handler))
        .route("/workspace/{*path}", get(workspace_file_handler))
        .with_state(state)
}

async fn index_handler(State(state): State<Arc<AppState>>) -> Response {
    StaticServer::serve_index(&state.workspace_dir)
}

async fn static_handler(State(state): State<Arc<AppState>>, Path(path): Path<String>) -> Response {
    StaticServer::serve_file(&path, &state.workspace_dir)
}

/// Serve files from workspace directory (e.g., screenshots).
/// Includes path traversal protection — only serves files within workspace_dir.
async fn workspace_file_handler(State(state): State<Arc<AppState>>, Path(path): Path<String>) -> Response {
    use axum::http::{header, StatusCode};

    let workspace = std::path::Path::new(&state.workspace_dir);
    let file_path = workspace.join(&path);

    // Path traversal protection: ensure resolved path is within workspace
    let canonical = match file_path.canonicalize() {
        Ok(p) => p,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let ws_canonical = match workspace.canonicalize() {
        Ok(p) => p,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if !canonical.starts_with(&ws_canonical) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !canonical.is_file() {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Determine content type from extension
    let mime = mime_guess::from_path(&canonical)
        .first_or_octet_stream();

    match tokio::fs::read(&canonical).await {
        Ok(data) => {
            let mut response = axum::body::Body::from(data).into_response();
            response.headers_mut().insert(header::CONTENT_TYPE, mime.to_string().parse().unwrap());
            response
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn health_handler() -> Json<Value> {
    Json(json!({ "status": "ok", "version": "0.1.0" }))
}

async fn models_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let models = state.model_configs.read().await;
    let list: Vec<Value> = models.iter().map(|m| {
        json!({ "name": &m.name, "context_window": m.context_window, "supports_vision": m.supports_vision })
    }).collect();
    Json(json!({
        "models": list,
        "context_window_threshold": state.context_window_threshold,
        "max_iterations": state.max_iterations,
        "rabbit_hole_threshold": state.rabbit_hole_threshold,
        "tool_timeout_secs": state.tool_timeout_secs,
    }))
}

async fn providers_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let models = state.model_configs.read().await;
    let list: Vec<Value> = models.iter().map(|m| {
        let masked_key = m.api_key.as_ref().map(|k| {
            if k.len() > 8 { format!("{}...{}", &k[..4], &k[k.len()-4..]) }
            else if !k.is_empty() { "****".to_string() }
            else { String::new() }
        });
        json!({
            "name": m.name,
            "api_base": m.api_base,
            "api_key": masked_key,
            "api_key_env": m.api_key_env,
            "context_window": m.context_window,
            "max_tokens": m.max_tokens,
            "temperature": m.temperature,
        })
    }).collect();
    Json(json!({ "providers": list, "count": list.len() }))
}

async fn providers_create_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let name = body["name"].as_str().unwrap_or("").to_string();
    let api_base = body["api_base"].as_str().unwrap_or("").to_string();
    if name.is_empty() || api_base.is_empty() {
        return Json(json!({"error": "name and api_base are required"}));
    }
    let new_config = crate::config::ModelConfig {
        name: name.clone(),
        api_base,
        api_key: body["api_key"].as_str().map(|s| s.to_string()).filter(|s| !s.is_empty()),
        api_key_env: body["api_key_env"].as_str().map(|s| s.to_string()).filter(|s| !s.is_empty()),
        context_window: body["context_window"].as_u64().map(|v| v as usize).unwrap_or(128000),
        max_tokens: body["max_tokens"].as_u64().map(|v| v as u32).unwrap_or(16384),
        temperature: body["temperature"].as_f64().unwrap_or(0.7),
        supports_vision: body["supports_vision"].as_bool().unwrap_or(false),
    };
    let mut models = state.model_configs.write().await;
    if models.iter().any(|m| m.name == name) {
        return Json(json!({"error": format!("Model '{}' already exists", name)}));
    }
    models.push(new_config);
    crate::model_store::save_configs(&models, std::path::Path::new(&state.model_store_path));
    info!("Provider '{}' added via API", name);
    Json(json!({"ok": true, "name": name}))
}

async fn providers_update_handler(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let mut models = state.model_configs.write().await;
    let idx = match models.iter().position(|m| m.name == name) {
        Some(i) => i,
        None => return Json(json!({"error": format!("Model '{}' not found", name)})),
    };
    let existing = &models[idx];
    // Preserve existing api_key if the incoming one is empty or looks like a masked value
    let incoming_key = body["api_key"].as_str().unwrap_or("").to_string();
    let api_key = if incoming_key.is_empty() || incoming_key.contains("...") || incoming_key == "****" {
        existing.api_key.clone()
    } else {
        Some(incoming_key)
    };
    models[idx] = crate::config::ModelConfig {
        name: body["name"].as_str().map(|s| s.to_string()).unwrap_or(name.clone()),
        api_base: body["api_base"].as_str().map(|s| s.to_string()).unwrap_or_else(|| existing.api_base.clone()),
        api_key,
        api_key_env: body["api_key_env"].as_str().map(|s| s.to_string()).filter(|s| !s.is_empty())
            .or_else(|| existing.api_key_env.clone()),
        context_window: body["context_window"].as_u64().map(|v| v as usize).unwrap_or(existing.context_window),
        max_tokens: body["max_tokens"].as_u64().map(|v| v as u32).unwrap_or(existing.max_tokens),
        temperature: body["temperature"].as_f64().unwrap_or(existing.temperature),
        supports_vision: body["supports_vision"].as_bool().unwrap_or(existing.supports_vision),
    };
    crate::model_store::save_configs(&models, std::path::Path::new(&state.model_store_path));
    info!("Provider '{}' updated via API", name);
    Json(json!({"ok": true, "name": name}))
}

async fn providers_delete_handler(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Json<Value> {
    let mut models = state.model_configs.write().await;
    let len_before = models.len();
    models.retain(|m| m.name != name);
    if models.len() == len_before {
        return Json(json!({"error": format!("Model '{}' not found", name)}));
    }
    crate::model_store::save_configs(&models, std::path::Path::new(&state.model_store_path));
    info!("Provider '{}' deleted via API", name);
    Json(json!({"ok": true, "name": name}))
}

async fn skills_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let skills = state.skill_manager.list();
    Json(json!({ "skills": skills, "count": skills.len() }))
}

async fn skills_create_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let name = body["name"].as_str().unwrap_or("").to_string();
    let description = body["description"].as_str().unwrap_or("").to_string();
    let content = body["content"].as_str().unwrap_or("").to_string();
    let triggers: Vec<String> = body["triggers"].as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    if name.is_empty() || content.is_empty() {
        return Json(json!({ "success": false, "error": "Name and content are required" }));
    }
    match state.skill_manager.create_skill(&name, &description, &triggers, &content) {
        Ok(filename) => Json(json!({ "success": true, "filename": filename })),
        Err(e) => Json(json!({ "success": false, "error": e })),
    }
}

async fn skills_reload_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    state.skill_manager.reload();
    let skills = state.skill_manager.list();
    Json(json!({ "status": "reloaded", "count": skills.len() }))
}

async fn skills_delete_handler(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Json<Value> {
    match state.skill_manager.delete_skill(&name) {
        Ok(_) => Json(json!({ "success": true })),
        Err(e) => Json(json!({ "success": false, "error": e })),
    }
}

async fn skills_toggle_handler(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Json<Value> {
    match state.skill_manager.toggle_skill(&name) {
        Some(enabled) => Json(json!({ "success": true, "enabled": enabled })),
        None => Json(json!({ "success": false, "error": "Not found" })),
    }
}

async fn mcp_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let mgr = state.mcp_manager.lock().await;
    Json(json!({ "servers": mgr.server_info() }))
}

async fn mcp_create_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let name = body["name"].as_str().unwrap_or("").to_string();
    if name.is_empty() {
        return Json(json!({ "success": false, "error": "Missing name" }));
    }
    let transport = body["transport"].as_str().unwrap_or("stdio").to_string();
    let config = McpServerConfig {
        name: name.clone(),
        transport,
        command: body["command"].as_str().map(|s| s.to_string()),
        args: body["args"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        url: body["url"].as_str().map(|s| s.to_string()),
        auth_token: body["auth_token"].as_str().map(|s| s.to_string()),
        enabled: body["enabled"].as_bool().unwrap_or(true),
    };
    let mut mgr = state.mcp_manager.lock().await;
    // Snapshot old MCP tool names before connecting
    let old_names = mgr.tool_names();
    mgr.connect_server(&config).await;
    mgr.save_configs();
    // Sync registry: remove old, add new
    let new_names = mgr.tool_names();
    let mcp_tools = mgr.get_tools();
    drop(mgr);
    let mut registry = state.tools.write().await;
    registry.unregister_many(&old_names);
    for tool in &mcp_tools {
        registry.register(tool.clone());
    }
    info!("MCP registry synced: {} tools after create '{}'", new_names.len(), name);
    Json(json!({ "success": true, "name": name }))
}

async fn mcp_delete_handler(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Json<Value> {
    let mut mgr = state.mcp_manager.lock().await;
    let old_names = mgr.tool_names();
    let ok = mgr.remove_server(&name).await;
    if ok {
        mgr.save_configs();
        let new_names = mgr.tool_names();
        let mcp_tools = mgr.get_tools();
        drop(mgr);
        let mut registry = state.tools.write().await;
        registry.unregister_many(&old_names);
        for tool in &mcp_tools {
            registry.register(tool.clone());
        }
        info!("MCP registry synced: {} tools after delete '{}'", new_names.len(), name);
    }
    Json(json!({ "success": ok }))
}

async fn mcp_toggle_handler(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Json<Value> {
    let mut mgr = state.mcp_manager.lock().await;
    let old_names = mgr.tool_names();
    match mgr.toggle_server(&name).await {
        Some(enabled) => {
            mgr.save_configs();
            let mcp_tools = mgr.get_tools();
            drop(mgr);
            let mut registry = state.tools.write().await;
            registry.unregister_many(&old_names);
            for tool in &mcp_tools {
                registry.register(tool.clone());
            }
            Json(json!({ "success": true, "enabled": enabled }))
        }
        None => Json(json!({ "success": false, "error": "Not found" })),
    }
}

async fn mcp_restart_handler(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Json<Value> {
    let mut mgr = state.mcp_manager.lock().await;
    let old_names = mgr.tool_names();
    let ok = mgr.reconnect_server(&name).await;
    if ok {
        mgr.save_configs();
        let mcp_tools = mgr.get_tools();
        drop(mgr);
        let mut registry = state.tools.write().await;
        registry.unregister_many(&old_names);
        for tool in &mcp_tools {
            registry.register(tool.clone());
        }
    }
    Json(json!({ "success": ok }))
}

#[derive(Deserialize)]
struct LogsQuery {
    date: Option<String>,
}

async fn logs_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LogsQuery>,
) -> Json<Value> {
    let date = query
        .date
        .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());
    match state.logger.read_logs(&date) {
        Ok(entries) => Json(json!({ "date": date, "entries": entries, "count": entries.len() })),
        Err(e) => Json(json!({ "error": e })),
    }
}

async fn log_dates_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let dates = state.logger.available_dates();
    Json(json!({ "dates": dates }))
}

// ============================================================
// CRON Task Handlers
// ============================================================

async fn cron_list_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let scheduler = state.scheduler.lock().await;
    let tasks = scheduler.list();
    Json(json!({ "tasks": tasks, "count": tasks.len() }))
}

async fn cron_create_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let task = CronTask {
        id: String::new(),
        name: body["name"].as_str().unwrap_or("Unnamed").to_string(),
        schedule: body["schedule"].as_str().unwrap_or("every 1h").to_string(),
        message: body["message"].as_str().unwrap_or("").to_string(),
        model: body["model"].as_str().unwrap_or("").to_string(),
        enabled: body["enabled"].as_bool().unwrap_or(true),
        last_run: None,
        next_run: None,
        interval_secs: 0,
    };
    let mut scheduler = state.scheduler.lock().await;
    let created = scheduler.create(task);
    Json(json!({ "task": created }))
}

async fn cron_update_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let mut scheduler = state.scheduler.lock().await;
    let ok = scheduler.update(
        &id,
        body["name"].as_str().map(|s| s.to_string()),
        body["schedule"].as_str().map(|s| s.to_string()),
        body["message"].as_str().map(|s| s.to_string()),
        body["model"].as_str().map(|s| s.to_string()),
    );
    Json(json!({ "success": ok }))
}

async fn cron_delete_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Json<Value> {
    let mut scheduler = state.scheduler.lock().await;
    let ok = scheduler.delete(&id);
    Json(json!({ "success": ok }))
}

async fn cron_toggle_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Json<Value> {
    let mut scheduler = state.scheduler.lock().await;
    let ok = scheduler.toggle(&id);
    let enabled = if ok {
        scheduler.list().iter().find(|t| t.id == id).map(|t| t.enabled)
    } else {
        None
    };
    Json(json!({ "success": ok, "enabled": enabled }))
}

/// POST /api/notify — push a notification message to all connected WebSocket clients.
async fn notify_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let message = body["message"].as_str().unwrap_or("");
    if message.is_empty() {
        return Json(json!({ "success": false, "error": "Missing message" }));
    }
    // Build a WS-formatted notification JSON
    let ws_msg = json!({
        "type": "notification",
        "message": message,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }).to_string();
    match state.notify_tx.send(ws_msg) {
        Ok(n) => Json(json!({ "success": true, "delivered_to": n })),
        Err(_) => Json(json!({ "success": false, "delivered_to": 0 })),
    }
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>) -> Response {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(socket: WebSocket, state: Arc<AppState>) {
    use futures::SinkExt;

    let (mut ws_sink, mut ws_stream) = socket.split();
    info!("WebSocket client connected");

    // Phase 1: Authentication
    let authenticated = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        ws_stream.next(),
    )
    .await
    {
        Ok(Some(Ok(Message::Text(msg)))) => {
            let msg_str: String = msg.to_string();
            match serde_json::from_str::<Value>(&msg_str) {
                Ok(parsed) if parsed["type"] == "auth" => {
                    let pwd = parsed["password"].as_str().unwrap_or("");
                    if pwd == state.password {
                        let _ = ws_sink
                            .send(Message::Text(json!({"type":"auth_ok"}).to_string().into()))
                            .await;
                        true
                    } else {
                        let _ = ws_sink
                            .send(Message::Text(
                                json!({"type":"auth_fail","message":"Invalid password"})
                                    .to_string()
                                    .into(),
                            ))
                            .await;
                        false
                    }
                }
                _ => {
                    let _ = ws_sink
                        .send(Message::Text(
                            json!({"type":"auth_fail","message":"Send {type:'auth', password:'...'} first"})
                                .to_string().into(),
                        ))
                        .await;
                    false
                }
            }
        }
        _ => false,
    };

    if !authenticated {
        info!("Auth failed, closing connection");
        return;
    }
    info!("Client authenticated");

    // Phase 2: Chat loop with dedicated reader task
    let ws_sink = Arc::new(Mutex::new(ws_sink));
    let session_id = uuid::Uuid::new_v4().to_string();

    // Single dedicated reader task: owns ws_stream, forwards ALL messages via channel.
    // This eliminates the race condition where two tasks compete for the same stream.
    let (ws_tx, mut ws_rx) = tokio::sync::mpsc::channel::<Message>(50);
    tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_stream.next().await {
            if ws_tx.send(msg).await.is_err() {
                break;
            }
        }
        // Signal stream ended
        let _ = ws_tx.send(Message::Close(None)).await;
    });

    // Subscribe to broadcast notifications and forward to this client's sink
    let mut notify_rx = state.notify_tx.subscribe();
    let notify_sink = ws_sink.clone();
    tokio::spawn(async move {
        use futures::SinkExt;
        while let Ok(msg) = notify_rx.recv().await {
            let mut sink = notify_sink.lock().await;
            if sink.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    let cancelled = Arc::new(AtomicBool::new(false));

    loop {
        // Wait for next user message
        let user_msg = match ws_rx.recv().await {
            Some(msg) => msg,
            None => break,
        };

        match user_msg {
            Message::Text(text) => {
                let text_str: String = text.to_string();
                if let Ok(parsed) = serde_json::from_str::<Value>(&text_str) {
                    let msg_type = parsed["type"].as_str().unwrap_or("");

                    match msg_type {
                        "chat" => {
                            let content = parsed["content"].as_str().unwrap_or("").to_string();
                            let default_model = {
                                let mc = state.model_configs.read().await;
                                mc.first().map(|m| m.name.clone()).unwrap_or_else(|| "gpt-4o".to_string())
                            };
                            let model = parsed["model"]
                                .as_str()
                                .unwrap_or(&default_model)
                                .to_string();
                            let max_iter = parsed["max_iterations"]
                                .as_u64()
                                .map(|v| v as usize)
                                .unwrap_or(state.max_iterations);
                            let fallback_model = parsed["fallback_model"]
                                .as_str()
                                .filter(|s| !s.is_empty())
                                .map(|s| s.to_string());
                            let rabbit_hole = parsed["rabbit_hole_threshold"]
                                .as_u64()
                                .map(|v| v as usize)
                                .unwrap_or(state.rabbit_hole_threshold);
                            let ctx_window_threshold = parsed["context_window_threshold"]
                                .as_u64()
                                .map(|v| v as usize)
                                .unwrap_or(state.context_window_threshold);
                            let tool_timeout = parsed["tool_timeout_secs"]
                                .as_u64()
                                .map(|v| v as usize)
                                .unwrap_or(state.tool_timeout_secs);
                            let ctx_window = {
                                let mc = state.model_configs.read().await;
                                mc.iter().find(|m| m.name == model).map(|m| m.context_window).unwrap_or(128000)
                            };

                            // Parse optional images (base64 data URIs or URLs)
                            let images: Vec<String> = parsed["images"]
                                .as_array()
                                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                                .unwrap_or_default();

                            // If images are present, check that the model supports vision
                            if !images.is_empty() {
                                let supports_vision = {
                                    let mc = state.model_configs.read().await;
                                    mc.iter().find(|m| m.name == model).map(|m| m.supports_vision).unwrap_or(false)
                                };
                                if !supports_vision {
                                    let err_msg = format!("Model '{}' does not support image input. Please select a vision-capable model (e.g., gpt-4o).", model);
                                    let err_event = serde_json::json!({
                                        "type": "error",
                                        "message": err_msg
                                    });
                                    let mut sink = ws_sink.lock().await;
                                    let _ = sink.send(Message::Text(err_event.to_string().into())).await;
                                    continue;
                                }
                            }

                            if content.is_empty() && images.is_empty() {
                                continue;
                            }

                            // Reset cancellation for new chat
                            cancelled.store(false, Ordering::SeqCst);

                            // Get session history for multi-turn context
                            let mut history = {
                                let sessions = state.sessions.lock().await;
                                sessions.get(&session_id).cloned().unwrap_or_default()
                            };

                            // Inject memory context for new sessions (page refresh)
                            if history.is_empty() {
                                // Inject a memory context (daily summaries of past
                                // conversations) as a SYSTEM message so the LLM
                                // treats it as authoritative background, not chat.
                                if let Some(mem_ctx) = state.memory_store.build_context_string(7) {
                                    info!("Injecting memory context ({} chars)", mem_ctx.len());
                                    history.push(ChatMessage::system(&mem_ctx));
                                }
                                // Do NOT replay today's full raw chat history into the
                                // model context. The frontend already restores chat UI
                                // from localStorage / /api/history after refresh. Raw
                                // replay here makes the model continue old unfinished
                                // threads (e.g. keep investigating memory.db after a
                                // simple "hello"). The memory context above provides a
                                // concise summary instead.
                            }

                            // Mid-session recall: if the user is asking about earlier
                            // conversations during an ongoing session, query SQLite
                            // (keyword search + daily summaries) and inject the result
                            // as an ephemeral SYSTEM message at the start of history.
                            // This is NOT persisted — the server only stores the
                            // original user content + assistant reply below.
                            if !history.is_empty() && is_recall_query(&content) {
                                if let Some(recall) = state.memory_store.build_recall_context(&content, 14) {
                                    info!("Injecting recall context ({} chars) for query", recall.len());
                                    history.insert(0, ChatMessage::system(&recall));
                                }
                            }

                            // Run via Runner
                            match state.runner.run(
                                &content, &session_id, &model, max_iter, history,
                                state.permissions.clone(), state.permission_pending.clone(),
                                fallback_model, rabbit_hole,
                                ctx_window, ctx_window_threshold,
                                tool_timeout as u64,
                                images,
                                None, None,  // normal chat — no checkpoint resume
                            ).await {
                                Ok(mut event_stream) => {
                                    let mut assistant_text = String::new();
                                    loop {
                                        tokio::select! {
                                            // Agent event
                                            result = event_stream.next() => {
                                                match result {
                                                    Some(Ok(event)) => {
                                                        if let AgentEvent::TextDelta { content: c, .. } = &event {
                                                            assistant_text.push_str(c);
                                                        }
                                                        let msg_str = event.to_ws_message();
                                                        let mut sink = ws_sink.lock().await;
                                                        if sink.send(Message::Text(msg_str.into())).await.is_err() {
                                                            break;
                                                        }
                                                        if event.is_done() {
                                                            break;
                                                        }
                                                    }
                                                    Some(Err(e)) => {
                                                        let err_event = AgentEvent::error(&e.to_string(), &session_id, "system");
                                                        let msg_str = err_event.to_ws_message();
                                                        let mut sink = ws_sink.lock().await;
                                                        let _ = sink.send(Message::Text(msg_str.into())).await;
                                                        break;
                                                    }
                                                    None => break,
                                                }
                                            }
                                            // Incoming WS message during agent execution (stop/permissions)
                                            ws_msg = ws_rx.recv() => {
                                                match ws_msg {
                                                    Some(Message::Text(t)) => {
                                                        let s: String = t.to_string();
                                                        if let Ok(p) = serde_json::from_str::<Value>(&s) {
                                                            let mt = p["type"].as_str().unwrap_or("");
                                                            match mt {
                                                                "stop" => {
                                                                    info!("Stop signal received");
                                                                    cancelled.store(true, Ordering::SeqCst);
                                                                }
                                                                "permission_response" => {
                                                                    let req_id = p["request_id"].as_str().unwrap_or("");
                                                                    let allowed = p["allowed"].as_bool().unwrap_or(false);
                                                                    state.permission_resolver.resolve(req_id, allowed).await;
                                                                }
                                                                "permissions" => {
                                                                    // Update permission settings
                                                                    let mut perms = state.permissions.lock().await;
                                                                    for cat in &["read", "write", "delete", "modify", "execute"] {
                                                                        if let Some(v) = p[cat].as_bool() {
                                                                            perms.insert(cat.to_string(), v);
                                                                        }
                                                                    }
                                                                    info!("Permissions updated: {:?}", *perms);
                                                                }
                                                                _ => {}
                                                            }
                                                        }
                                                    }
                                                    Some(Message::Close(_)) | None => {
                                                        cancelled.store(true, Ordering::SeqCst);
                                                        break;
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                        // Check if user sent stop
                                        if cancelled.load(Ordering::SeqCst) {
                                            info!("Agent execution stopped by user");
                                            let stop_event = AgentEvent::text("\n\n*[Stopped by user]*", &session_id, "system");
                                            let msg_str = stop_event.to_ws_message();
                                            let mut sink = ws_sink.lock().await;
                                            let _ = sink.send(Message::Text(msg_str.into())).await;
                                            let done_event = AgentEvent::done(&session_id, "system");
                                            let msg_str = done_event.to_ws_message();
                                            let _ = sink.send(Message::Text(msg_str.into())).await;
                                            break;
                                        }
                                    }

                                    // Update session history
                                    if !assistant_text.is_empty() {
                                        let mut sessions = state.sessions.lock().await;
                                        let hist = sessions.entry(session_id.clone()).or_insert_with(Vec::new);
                                        hist.push(ChatMessage::user(&content));
                                        hist.push(ChatMessage::assistant(&assistant_text));
                                        if hist.len() > 50 {
                                            let drain = hist.len() - 50;
                                            hist.drain(..drain);
                                        }

                                        // Store in memory (SQLite)
                                        let _ = state.memory_store.store_entry(&session_id, "user", &content, None);
                                        let _ = state.memory_store.store_entry(&session_id, "assistant", &assistant_text, None);

                                        // Refresh today's auto-summary so future
                                        // sessions (and mid-session recall
                                        // queries) can reference this exchange.
                                        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
                                        let _ = state.memory_store.auto_summarize_date(&today);
                                    }
                                }
                                Err(e) => {
                                    let err_event = AgentEvent::error(&e.to_string(), &session_id, "system");
                                    let msg_str = err_event.to_ws_message();
                                    let mut sink = ws_sink.lock().await;
                                    let _ = sink.send(Message::Text(msg_str.into())).await;
                                }
                            }
                        }
                        "clear" => {
                            state.sessions.lock().await.remove(&session_id);
                            let mut sink = ws_sink.lock().await;
                            let _ = sink
                                .send(Message::Text(json!({"type":"cleared"}).to_string().into()))
                                .await;
                        }
                        "resume" => {
                            let cp_id = parsed["checkpoint_id"].as_str().unwrap_or("").to_string();
                            if cp_id.is_empty() { continue; }

                            // Load checkpoint from SQLite
                            let cp = match state.memory_store.get_checkpoint(&cp_id) {
                                Ok(Some(cp)) => cp,
                                Ok(None) => {
                                    let err = json!({"type":"error","message":"Checkpoint not found"}).to_string();
                                    let mut sink = ws_sink.lock().await;
                                    let _ = sink.send(Message::Text(err.into())).await;
                                    continue;
                                }
                                Err(e) => {
                                    let err = json!({"type":"error","message":format!("Failed to load checkpoint: {}", e)}).to_string();
                                    let mut sink = ws_sink.lock().await;
                                    let _ = sink.send(Message::Text(err.into())).await;
                                    continue;
                                }
                            };

                            // Deserialize history
                            let history: Vec<ChatMessage> = match serde_json::from_str(&cp.history_json) {
                                Ok(h) => h,
                                Err(e) => {
                                    let err = json!({"type":"error","message":format!("Failed to deserialize checkpoint history: {}", e)}).to_string();
                                    let mut sink = ws_sink.lock().await;
                                    let _ = sink.send(Message::Text(err.into())).await;
                                    continue;
                                }
                            };

                            let model = cp.model_name.clone();
                            let resume_state = ResumeState {
                                history,
                                start_iteration: cp.iteration,
                            };
                            let new_cp_id = uuid::Uuid::new_v4().to_string();

                            info!("Resuming checkpoint {} (session: {}, model: {}, iter: {})",
                                  cp_id, session_id, model, cp.iteration);

                            // Send a status message to the UI
                            let resume_event = serde_json::json!({
                                "type": "text",
                                "content": format!("\n\n*[Resuming interrupted task from iteration {}...]*\n\n", cp.iteration + 1),
                                "invocation_id": session_id,
                                "author": "system"
                            });
                            {
                                let mut sink = ws_sink.lock().await;
                                let _ = sink.send(Message::Text(resume_event.to_string().into())).await;
                            }

                            let ctx_window = {
                                let mc = state.model_configs.read().await;
                                mc.iter().find(|m| m.name == model).map(|m| m.context_window).unwrap_or(128000)
                            };

                            cancelled.store(false, Ordering::SeqCst);

                            match state.runner.run(
                                &cp.user_message, &session_id, &model, state.max_iterations,
                                vec![],  // empty base history — resume_state provides it
                                state.permissions.clone(), state.permission_pending.clone(),
                                None, state.rabbit_hole_threshold,
                                ctx_window, state.context_window_threshold,
                                state.tool_timeout_secs as u64,
                                vec![],  // no images
                                Some(new_cp_id),
                                Some(resume_state),
                            ).await {
                                Ok(mut event_stream) => {
                                    let mut assistant_text = String::new();
                                    loop {
                                        tokio::select! {
                                            result = event_stream.next() => {
                                                match result {
                                                    Some(Ok(event)) => {
                                                        if let AgentEvent::TextDelta { content: c, .. } = &event {
                                                            assistant_text.push_str(c);
                                                        }
                                                        let msg_str = event.to_ws_message();
                                                        let mut sink = ws_sink.lock().await;
                                                        if sink.send(Message::Text(msg_str.into())).await.is_err() {
                                                            break;
                                                        }
                                                        if event.is_done() {
                                                            break;
                                                        }
                                                    }
                                                    Some(Err(e)) => {
                                                        let err_event = AgentEvent::error(&e.to_string(), &session_id, "system");
                                                        let msg_str = err_event.to_ws_message();
                                                        let mut sink = ws_sink.lock().await;
                                                        let _ = sink.send(Message::Text(msg_str.into())).await;
                                                        break;
                                                    }
                                                    None => break,
                                                }
                                            }
                                            msg = ws_rx.recv() => {
                                                match msg {
                                                    Some(Message::Text(ref t)) => {
                                                        if let Ok(p) = serde_json::from_str::<Value>(t) {
                                                            if p["type"].as_str() == Some("stop") {
                                                                cancelled.store(true, Ordering::SeqCst);
                                                            }
                                                            if p["type"].as_str() == Some("permission_response") {
                                                                let req_id = p["request_id"].as_str().unwrap_or("");
                                                                let allowed = p["allowed"].as_bool().unwrap_or(false);
                                                                state.permission_resolver.resolve(req_id, allowed).await;
                                                            }
                                                        }
                                                    }
                                                    Some(Message::Close(_)) => {
                                                        cancelled.store(true, Ordering::SeqCst);
                                                        break;
                                                    }
                                                    None => break,
                                                    _ => {}
                                                }
                                            }
                                        }
                                        if cancelled.load(Ordering::SeqCst) {
                                            info!("Agent execution stopped by user (resume)");
                                            let stop_event = AgentEvent::text("\n\n*[Stopped by user]*", &session_id, "system");
                                            let msg_str = stop_event.to_ws_message();
                                            let mut sink = ws_sink.lock().await;
                                            let _ = sink.send(Message::Text(msg_str.into())).await;
                                            let done_event = AgentEvent::done(&session_id, "system");
                                            let msg_str = done_event.to_ws_message();
                                            let _ = sink.send(Message::Text(msg_str.into())).await;
                                            break;
                                        }
                                    }

                                    // Store in memory (SQLite)
                                    if !assistant_text.is_empty() {
                                        let _ = state.memory_store.store_entry(&session_id, "user", &cp.user_message, None);
                                        let _ = state.memory_store.store_entry(&session_id, "assistant", &assistant_text, None);
                                        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
                                        let _ = state.memory_store.auto_summarize_date(&today);
                                    }
                                }
                                Err(e) => {
                                    let err_event = AgentEvent::error(&e.to_string(), &session_id, "system");
                                    let msg_str = err_event.to_ws_message();
                                    let mut sink = ws_sink.lock().await;
                                    let _ = sink.send(Message::Text(msg_str.into())).await;
                                }
                            }
                        }
                        "permissions" => {
                            // Update permission settings (when not in agent execution)
                            let mut perms = state.permissions.lock().await;
                            for cat in &["read", "write", "delete", "modify", "execute"] {
                                if let Some(v) = parsed[cat].as_bool() {
                                    perms.insert(cat.to_string(), v);
                                }
                            }
                            info!("Permissions updated: {:?}", *perms);
                        }
                        "permission_response" => {
                            // Handle permission response when not in agent execution (edge case)
                            let req_id = parsed["request_id"].as_str().unwrap_or("");
                            let allowed = parsed["allowed"].as_bool().unwrap_or(false);
                            state.permission_resolver.resolve(req_id, allowed).await;
                        }
                        _ => {}
                    }
                }
            }
            Message::Close(_) => {
                info!("Client disconnected");
                break;
            }
            _ => {}
        }
    }
}

// ============================================================
// Memory Handlers
// ============================================================

async fn memory_dates_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    match state.memory_store.available_dates() {
        Ok(dates) => Json(json!({ "dates": dates, "count": dates.len() })),
        Err(e) => Json(json!({ "error": e })),
    }
}

async fn memory_summaries_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    match state.memory_store.get_all_summaries() {
        Ok(summaries) => Json(json!({ "summaries": summaries, "count": summaries.len() })),
        Err(e) => Json(json!({ "error": e })),
    }
}

#[derive(Deserialize)]
struct MemoryQuery {
    date: Option<String>,
}

async fn memory_entries_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<MemoryQuery>,
) -> Json<Value> {
    let date = query.date.unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());
    match state.memory_store.get_entries_by_date(&date) {
        Ok(entries) => Json(json!({ "date": date, "entries": entries, "count": entries.len() })),
        Err(e) => Json(json!({ "error": e })),
    }
}

#[derive(Deserialize)]
struct SummarizeRequest {
    date: Option<String>,
}

async fn memory_summarize_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SummarizeRequest>,
) -> Json<Value> {
    let date = body.date.unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());
    match state.memory_store.build_raw_context_for_date(&date) {
        Ok(raw) => {
            // Build a summary prompt
            let prompt = format!(
                "Please provide a concise summary of the following conversation log from {}. \
                 Focus on key topics discussed, actions taken, and outcomes. Keep it under 200 words.\n\n{}",
                date, raw
            );
            // For now, store a simple extractive summary (LLM-based summary would need provider access)
            let lines: Vec<&str> = raw.lines().collect();
            let user_msgs: Vec<&str> = lines.iter()
                .filter(|l| l.starts_with("User:"))
                .copied()
                .collect();
            let summary = if user_msgs.is_empty() {
                format!("{} conversation entries recorded ({} chars)", lines.len(), raw.len())
            } else {
                let topics: Vec<String> = user_msgs.iter().take(5)
                    .map(|m| {
                        let text = m.trim_start_matches("User:").trim();
                        let preview: String = text.chars().take(80).collect();
                        preview
                    })
                    .collect();
                format!("Topics: {}", topics.join("; "))
            };
            match state.memory_store.store_summary(&date, &summary) {
                Ok(_) => {
                    info!("Summary stored for {}: {} chars", date, summary.len());
                    Json(json!({ "success": true, "date": date, "summary": summary }))
                }
                Err(e) => Json(json!({ "success": false, "error": e })),
            }
        }
        Err(e) => Json(json!({ "success": false, "error": e })),
    }
}

// ============================================================
// History API - fetch recent conversation from memory store
// ============================================================

#[derive(Deserialize)]
struct HistoryQuery {
    #[serde(default = "default_history_days")]
    days: usize,
    #[serde(default = "default_history_limit")]
    limit: usize,
}

fn default_history_days() -> usize { 3 }
fn default_history_limit() -> usize { 50 }

async fn history_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HistoryQuery>,
) -> Json<Value> {
    let days = query.days.max(1).min(30);
    let limit = query.limit.max(1).min(200);
    match state.memory_store.get_recent_entries(days) {
        Ok(entries) => {
            // Filter to user/assistant roles and take the last N entries
            let filtered: Vec<_> = entries.into_iter()
                .filter(|e| e.role == "user" || e.role == "assistant")
                .collect();
            let chat: Vec<Value> = filtered.into_iter()
                .rev()
                .take(limit)
                .rev()
                .map(|e| json!({
                    "role": e.role,
                    "text": e.content,
                    "time": chrono::DateTime::parse_from_rfc3339(&e.timestamp)
                        .map(|dt| dt.format("%H:%M:%S").to_string())
                        .unwrap_or_default(),
                    "session_id": e.session_id,
                }))
                .collect();
            Json(json!({ "messages": chat, "count": chat.len() }))
        }
        Err(e) => Json(json!({ "messages": [], "count": 0, "error": e })),
    }
}

// ============================================================
// External Tools Handlers
// ============================================================

async fn tools_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let mut mgr = state.external_tools.lock().await;
    mgr.scan();
    let tools = mgr.list_tools();
    let tools_dir = mgr.tools_dir().to_string_lossy().to_string();
    Json(json!({ "tools": tools, "tools_dir": tools_dir, "count": tools.len() }))
}

async fn tools_toggle_handler(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Json<Value> {
    let mut mgr = state.external_tools.lock().await;
    match mgr.toggle_tool(&name) {
        Some(enabled) => {
            mgr.save_state();
            Json(json!({ "success": true, "enabled": enabled }))
        }
        None => Json(json!({ "success": false, "error": "Not found" })),
    }
}

async fn tools_desc_handler(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let description = body["description"].as_str().unwrap_or("").to_string();
    let mut mgr = state.external_tools.lock().await;
    if mgr.update_description(&name, &description) {
        mgr.save_state();
        Json(json!({ "success": true }))
    } else {
        Json(json!({ "success": false, "error": "Not found" }))
    }
}

// ============================================================
// Config Files (AGENTS.md, SOUL.md, TOOLS.md)
// ============================================================

async fn config_files_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let workspace = &state.workspace_dir;
    let files = ["AGENTS.md", "SOUL.md", "TOOLS.md", "MEMORY.md"];
    let mut result = serde_json::Map::new();

    for file_name in &files {
        let path = std::path::Path::new(workspace).join(file_name);
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        result.insert(file_name.to_string(), json!(content));
    }

    Json(json!({ "files": result, "workspace_dir": workspace }))
}

async fn config_file_save_handler(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let allowed = ["AGENTS.md", "SOUL.md", "TOOLS.md", "MEMORY.md"];
    if !allowed.contains(&name.as_str()) {
        return Json(json!({ "success": false, "error": "Invalid file name. Allowed: AGENTS.md, SOUL.md, TOOLS.md, MEMORY.md" }));
    }

    let content = body["content"].as_str().unwrap_or("");
    let path = std::path::Path::new(&state.workspace_dir).join(&name);

    if let Err(e) = std::fs::create_dir_all(&state.workspace_dir) {
        return Json(json!({ "success": false, "error": format!("Failed to create workspace: {}", e) }));
    }

    match std::fs::write(&path, content) {
        Ok(_) => {
            info!("Config file saved: {}", path.display());
            Json(json!({ "success": true, "file": name }))
        }
        Err(e) => Json(json!({ "success": false, "error": format!("Failed to save: {}", e) })),
    }
}

// ============================================================
// Checkpoint Handlers
// ============================================================

async fn checkpoints_list_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    match state.memory_store.list_checkpoints() {
        Ok(cps) => {
            // Return metadata only — do NOT send the full history_json to the client.
            let items: Vec<Value> = cps.iter().map(|cp| {
                json!({
                    "id": cp.id,
                    "session_id": cp.session_id,
                    "model_name": cp.model_name,
                    "user_message": cp.user_message.chars().take(200).collect::<String>(),
                    "iteration": cp.iteration,
                    "tool_summary": cp.tool_summary,
                    "created_at": cp.created_at,
                    "updated_at": cp.updated_at,
                })
            }).collect();
            Json(json!({ "checkpoints": items, "count": items.len() }))
        }
        Err(e) => Json(json!({ "error": e })),
    }
}

async fn checkpoints_delete_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Json<Value> {
    match state.memory_store.delete_checkpoint(&id) {
        Ok(_) => {
            info!("Checkpoint {} deleted via API", id);
            Json(json!({ "ok": true }))
        }
        Err(e) => Json(json!({ "error": e })),
    }
}

/// Detect whether the user's message is asking about earlier conversations.
/// Used to trigger mid-session injection of the memory context so the agent
/// can recall past topics instead of claiming it has no history.
fn is_recall_query(text: &str) -> bool {
    let lower = text.to_lowercase();
    const KEYWORDS: &[&str] = &[
        // Chinese
        "之前", "昨天", "前天", "上次", "历史", "过往", "以前",
        "记得", "回忆", "我们讨论", "我们聊", "我们说过", "你之前",
        "你说过", "之前的对话", "前几次",
        // English
        "previous", "yesterday", "last time", "earlier", "we discussed",
        "we talked", "do you remember", "chat history", "previous chat",
        "earlier conversation", "before we",
    ];
    KEYWORDS.iter().any(|k| lower.contains(k))
}
