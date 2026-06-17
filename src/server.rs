use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    response::Response,
    routing::{get, post},
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
use crate::model::ChatMessage;
use crate::permission::{PermissionResolver, PendingMap};
use crate::runner::Runner;
use crate::skill::SkillManager;
use crate::tool::mcp_client::McpClientManager;
use crate::web::StaticServer;

pub struct AppState {
    pub runner: Arc<Runner>,
    pub skill_manager: Arc<SkillManager>,
    pub mcp_manager: Arc<Mutex<McpClientManager>>,
    pub logger: Arc<ConversationLogger>,
    pub password: String,
    pub model_names: Vec<String>,
    pub max_iterations: usize,
    /// Per-session conversation history for multi-turn context
    pub sessions: Mutex<std::collections::HashMap<String, Vec<ChatMessage>>>,
    /// Permission settings (category -> allowed), shared across connections
    pub permissions: Arc<Mutex<std::collections::HashMap<String, bool>>>,
    /// Resolver for pending permission requests
    pub permission_resolver: PermissionResolver,
    /// Shared pending map for permission requests
    pub permission_pending: PendingMap,
}

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/static/{*path}", get(static_handler))
        .route("/ws", get(ws_handler))
        .route("/api/models", get(models_handler))
        .route("/api/health", get(health_handler))
        .route("/api/skills", get(skills_handler))
        .route("/api/skills/reload", post(skills_reload_handler))
        .route("/api/mcp", get(mcp_handler))
        .route("/api/logs", get(logs_handler))
        .route("/api/logs/dates", get(log_dates_handler))
        .with_state(state)
}

async fn index_handler() -> Response {
    StaticServer::serve_index()
}

async fn static_handler(Path(path): Path<String>) -> Response {
    StaticServer::serve_file(&path)
}

async fn health_handler() -> Json<Value> {
    Json(json!({ "status": "ok", "version": "0.1.0" }))
}

async fn models_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({ "models": state.model_names }))
}

async fn skills_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let skills = state.skill_manager.list();
    Json(json!({ "skills": skills, "count": skills.len() }))
}

async fn skills_reload_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    state.skill_manager.reload();
    let skills = state.skill_manager.list();
    Json(json!({ "status": "reloaded", "count": skills.len() }))
}

async fn mcp_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let mgr = state.mcp_manager.lock().await;
    Json(json!({ "servers": mgr.server_info() }))
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
                            let model = parsed["model"]
                                .as_str()
                                .unwrap_or(
                                    state.model_names.first()
                                        .map(|s| s.as_str())
                                        .unwrap_or("gpt-4o"),
                                )
                                .to_string();

                            if content.is_empty() {
                                continue;
                            }

                            // Reset cancellation for new chat
                            cancelled.store(false, Ordering::SeqCst);

                            // Get session history for multi-turn context
                            let history = {
                                let sessions = state.sessions.lock().await;
                                sessions.get(&session_id).cloned().unwrap_or_default()
                            };

                            // Run via Runner
                            match state.runner.run(
                                &content, &session_id, &model, state.max_iterations, history,
                                state.permissions.clone(), state.permission_pending.clone(),
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
