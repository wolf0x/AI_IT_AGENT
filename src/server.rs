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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::agent::AgentEvent;
use crate::log::ConversationLogger;
use crate::memory::MemoryStore;
use crate::model::ChatMessage;
use crate::permission::{PermissionResolver, PendingMap};
use crate::runner::Runner;
use crate::runner::ResumeState;
use crate::scheduler::{Scheduler, CronTask};
use crate::agent_store::AgentStore;
use crate::skill::SkillManager;
use crate::config::McpServerConfig;
use crate::external_tools::ExternalToolsManager;
use crate::tool::mcp_client::McpClientManager;
use crate::tool::subagent::SharedJobs;
use crate::tool::ToolRegistry;
use crate::web::StaticServer;
use crate::model::openai::OpenAiProvider;
use crate::distill;

/// Reduce the distilled handoff to a single concise line (<= 100 chars) for the
/// Expert continue prompt, instead of showing the full raw findings dump.
/// Picks the latest instruction, the original task, and the first descriptive
/// finding line, then flattens + truncates to one line.
/// Does the user message carry an actual task to run, or is it only a mode-switch /
/// filler command (e.g. "go", "continues", "hello")? Used to decide whether a
/// "Start new round" Expert choice should dispatch immediately or ask for the task.
fn is_concrete_task(input: &str) -> bool {
    let t = input.trim();
    if t.is_empty() {
        return false;
    }
    let lower = t.to_lowercase();
    let fillers = [
        "go", "hello", "hi", "hey", "ok", "okay", "yes", "yep", "retry", "again",
        "new", "start", "开", "新", "开始", "继续", "继续吧", "好的", "好", "嗯", "在",
    ];
    if fillers.iter().any(|f| lower == *f) {
        return false;
    }
    if lower.starts_with("continue") || lower.starts_with("continu") || lower.starts_with("接着") {
        return false;
    }
    // Too short to be a concrete instruction.
    if t.chars().count() < 6 {
        return false;
    }
    true
}
/// Build a compact per-round summary ("Round 1 - <summary>; Round 2 - <summary>…")
/// from an existing TaskContract JSON. Each line is capped at 50 chars (one sentence).
fn rounds_summary_from_contract(json: &str) -> String {
    let Ok(v) = serde_json::from_str::<Value>(json) else { return String::new(); };
    let Some(notes) = v.get("manager_notes").and_then(|n| n.as_array()) else { return String::new(); };
    let mut pairs: Vec<(u32, String)> = Vec::new();
    for note in notes {
        let s = note.as_str().unwrap_or("").trim();
        if let Some(rest) = s.strip_prefix("Round ") {
            if let Some(col) = rest.find(':') {
                if let Ok(n) = rest[..col].trim().parse::<u32>() {
                    let body = rest[col + 1..].trim();
                    if !body.is_empty() {
                        pairs.push((n, body.chars().take(50).collect::<String>()));
                    }
                }
            }
        }
    }
    // Keep only the most recent rounds.
    if pairs.len() > 10 {
        pairs = pairs[pairs.len() - 10..].to_vec();
    }
    pairs.iter().map(|(n, s)| format!("Round {} - {}", n, s)).collect::<Vec<_>>().join("; ")
}
fn compress_handoff_summary(handoff: &str) -> String {
    const MAX: usize = 100;
    let mut original = String::new();
    let mut latest = String::new();
    let mut gist = String::new();
    let mut in_findings = false;
    for line in handoff.lines() {
        let l = line.trim();
        if let Some(r) = l.strip_prefix("Original task:") {
            original = r.trim().to_string();
            continue;
        }
        if let Some(r) = l.strip_prefix("Latest instruction:") {
            latest = r.trim().to_string();
            continue;
        }
        if l.starts_with("Prior findings") || l.starts_with("Prior") {
            in_findings = true;
            continue;
        }
        if in_findings && gist.is_empty()
            && !l.is_empty() && !l.starts_with('#') && !l.starts_with('|')
            && !l.starts_with('-') && !l.starts_with('*') && !l.starts_with('`') && !l.starts_with("[") {
            gist = l.to_string();
        }
    }
    let mut parts: Vec<String> = Vec::new();
    if !latest.is_empty() && latest != original {
        parts.push(latest.clone());
    }
    if !original.is_empty() {
        parts.push(original.clone());
    }
    if !gist.is_empty() {
        parts.push(gist.clone());
    }
    let joined = parts.join(" | ");
    let flat: String = joined.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= MAX {
        return flat;
    }
    let cut: String = flat.chars().take(MAX.saturating_sub(1)).collect();
    format!("{}…", cut.trim_end())
}


/// Type alias for the broadcast channel used to push notifications to all WS clients.
pub type NotifyTx = tokio::sync::broadcast::Sender<String>;

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
    pub max_iterations: Arc<AtomicUsize>,
    pub rabbit_hole_threshold: Arc<AtomicUsize>,
    pub context_window_threshold: Arc<AtomicUsize>,
    pub tool_timeout_secs: Arc<AtomicUsize>,
    pub max_tool_retries: Arc<AtomicUsize>,
    /// Expert mode settings (used when managed=true) — AtomicUsize so settings
    /// can be hot-reloaded from the UI without restarting the process.
    pub expert_max_iterations: Arc<AtomicUsize>,
    pub expert_tool_timeout_secs: Arc<AtomicUsize>,
    pub expert_max_tool_retries: Arc<AtomicUsize>,
    pub expert_max_managed_rounds: Arc<AtomicUsize>,
    /// Per-session conversation history for multi-turn context
    pub sessions: Mutex<std::collections::HashMap<String, Vec<ChatMessage>>>,
    /// Permission settings (category -> allowed), shared across connections
    pub permissions: Arc<Mutex<std::collections::HashMap<String, bool>>>,
    /// Resolver for pending permission requests
    pub permission_resolver: PermissionResolver,
    /// Shared pending map for permission requests
    pub permission_pending: PendingMap,
    /// Per-session Expert-mode task cancellation flags (session_id -> flag).
    /// Each managed run gets its OWN flag so a subsequent chat message (which
    /// resets the connection-level `cancelled`) cannot un-cancel a task that is
    /// still winding down — preventing two managed loops on the same contract.
    pub expert_tasks: Arc<std::sync::Mutex<std::collections::HashMap<String, Arc<AtomicBool>>>>,
    /// Predefined sub-agent store
    pub agent_store: Arc<Mutex<AgentStore>>,
    /// Shared sub-agent job registry (run_agent / orchestrate / /agent WS).
    pub sub_jobs: SharedJobs,
    /// CRON task scheduler
    pub scheduler: Arc<Mutex<Scheduler>>,
    /// Broadcast channel for push notifications (sys_remind, etc.)
    pub notify_tx: NotifyTx,
    /// Agent workspace directory (where AGENTS.md, SOUL.md, TOOLS.md live)
    pub workspace_dir: String,
    /// LLM provider for end-of-session knowledge distillation
    pub provider: Arc<OpenAiProvider>,
    /// Whether Computer Use (GUI control) tools are enabled
    pub computer_use_enabled: Arc<AtomicBool>,
    /// Whether to use LLM to simulate human intervention when Expert mode is blocked
    pub human_intervention_enabled: Arc<AtomicBool>,
    /// Primary model name (from config.toml) — RwLock for hot-reload from UI
    pub primary_model: Arc<std::sync::RwLock<Option<String>>>,
    /// Fallback model name (from config.toml) — RwLock for hot-reload from UI
    pub fallback_model: Arc<std::sync::RwLock<Option<String>>>,
    /// Expert-mode per-role model overrides (Manager/Auditor/Executor) and their
    /// optional fallbacks. Hot-reloadable from Settings UI.
    pub expert_role_models: Arc<std::sync::RwLock<crate::config::RoleModelsConfig>>,
    /// Timezone offset in hours (from config.toml) — RwLock for hot-reload from UI
    pub timezone_offset: Arc<std::sync::RwLock<i8>>,
}

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/static/{*path}", get(static_handler))
        .route("/ws", get(ws_handler))
        .route("/api/models", get(models_handler))
        .route("/api/providers", get(providers_handler))
        .route("/api/providers", post(providers_create_handler))
        .route("/api/providers/{title}", put(providers_update_handler))
        .route("/api/providers/{title}", delete(providers_delete_handler))
        .route("/api/providers/{title}/test", post(providers_test_handler))
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
        .route("/api/managed/reset", post(managed_reset_handler))
        .route("/api/cron", get(cron_list_handler))
        .route("/api/cron", post(cron_create_handler))
        .route("/api/cron/{id}", put(cron_update_handler))
        .route("/api/cron/{id}", delete(cron_delete_handler))
        .route("/api/cron/{id}/toggle", post(cron_toggle_handler))
        .route("/api/cron/settings", get(cron_settings_handler))
        .route("/api/cron/settings", post(cron_settings_update_handler))
        .route("/api/agents", get(agents_list_handler))
        .route("/api/agents", post(agents_create_handler))
        .route("/api/agents/{id}", put(agents_update_handler))
        .route("/api/agents/{id}", delete(agents_delete_handler))
        .route("/api/agents/{id}/toggle", post(agents_toggle_handler))
        .route("/api/notify", post(notify_handler))
        .route("/api/memory/dates", get(memory_dates_handler))
        .route("/api/memory/summaries", get(memory_summaries_handler))
        .route("/api/memory", get(memory_entries_handler))
        .route("/api/memory/summarize", post(memory_summarize_handler))
        .route("/api/history", get(history_handler))
        .route("/api/usage", get(usage_handler))
        .route("/api/usage/today", get(usage_today_handler))
        .route("/api/tools", get(tools_handler))
        .route("/api/tools/{name}/toggle", post(tools_toggle_handler))
        .route("/api/tools/{name}/description", post(tools_desc_handler))
        .route("/api/config/files", get(config_files_handler))
        .route("/api/config/files/{name}", put(config_file_save_handler))
        .route("/api/checkpoints", get(checkpoints_list_handler))
        .route("/api/checkpoints/{id}", delete(checkpoints_delete_handler))
        .route("/api/settings/computer_use", post(computer_use_toggle_handler))
        .route("/api/settings/human_intervention", get(human_intervention_get_handler).post(human_intervention_toggle_handler))
        .route("/api/settings/agent", post(agent_settings_save_handler))
        .route("/api/settings/agent/extended", post(agent_settings_extended_save_handler))
        .route("/api/settings/agent/expert", post(agent_settings_expert_save_handler))
        .route("/api/output/list", get(output_list_handler))
        .route("/api/output/download/{filename}", get(output_download_handler))
        .route("/api/output/open", post(output_open_handler))
        .route("/api/managed/runs", get(managed_runs_handler))
        .route("/api/managed/status", get(managed_status_handler))
        .route("/api/todos", get(todos_handler))
        .route("/workspace/{*path}", get(workspace_file_handler))
        .with_state(state)
}


// 閸€Predefined Sub-Agents 閸€
async fn agents_list_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let store = state.agent_store.lock().await;
    Json(json!({ "agents": store.list(), "count": store.list().len() }))
}

async fn agents_create_handler(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> Json<Value> {
    let name = body["name"].as_str().unwrap_or("").to_string();
    let description = body["description"].as_str().unwrap_or("").to_string();
    let system_prompt = body["system_prompt"].as_str().unwrap_or("").to_string();
    let model = body["model"].as_str().unwrap_or("").to_string();
    let mut store = state.agent_store.lock().await;
    match store.create(&name, &description, &system_prompt, &model) {
        Ok(def) => Json(json!({ "success": true, "agent": def, "error": "" })),
        Err(e) => Json(json!({ "success": false, "agent": serde_json::Value::Null, "error": e })),
    }
}

async fn agents_update_handler(State(state): State<Arc<AppState>>, Path(id): Path<String>, Json(body): Json<Value>) -> Json<Value> {
    let mut store = state.agent_store.lock().await;
    match store.update(
        &id,
        body["name"].as_str().map(|s| s.to_string()),
        body["description"].as_str().map(|s| s.to_string()),
        body["system_prompt"].as_str().map(|s| s.to_string()),
        body["model"].as_str().map(|s| s.to_string()),
        body["enabled"].as_bool(),
    ) {
        Ok(def) => Json(json!({ "success": true, "agent": def })),
        Err(e) => Json(json!({ "success": false, "error": e })),
    }
}

async fn agents_delete_handler(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Json<Value> {
    let mut store = state.agent_store.lock().await;
    let ok = store.delete(&id);
    Json(json!({ "success": ok }))
}

async fn agents_toggle_handler(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Json<Value> {
    let mut store = state.agent_store.lock().await;
    let enabled = store.toggle(&id);
    Json(json!({ "success": enabled.is_some(), "enabled": enabled }))
}

async fn index_handler(State(state): State<Arc<AppState>>) -> Response {
    StaticServer::serve_index(&state.workspace_dir)
}

async fn static_handler(State(state): State<Arc<AppState>>, Path(path): Path<String>) -> Response {
    StaticServer::serve_file(&path, &state.workspace_dir)
}

/// Serve files from workspace directory (e.g., output files, screenshots).
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

/// List the most recent output artifacts in workspace/output/ (max 5).
/// GET /api/managed/runs — list Expert-mode run archives (F9 Dashboard).
/// Scans managed/<contract_id>/round_NN/ for plan / audit / state files
/// and returns a structured per-round view for the Runs dashboard.
async fn managed_runs_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let managed_dir = std::path::Path::new(&state.workspace_dir)
        .join("managed");

    let mut runs: Vec<(i64, Value)> = Vec::new();
    if let Ok(mut contracts) = tokio::fs::read_dir(&managed_dir).await {
        while let Ok(Some(entry)) = contracts.next_entry().await {
            let is_dir = entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false);
            if !is_dir {
                continue;
            }
            let contract_id = entry.file_name().to_string_lossy().to_string();
            let contract_dir = entry.path();
            // Get modification time for sorting (newest first)
            let mtime = contract_dir.metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);

            let mut rounds: Vec<Value> = Vec::new();
            let mut total_rounds = 0usize;
            if let Ok(mut round_entries) = tokio::fs::read_dir(&contract_dir).await {
                let mut round_dirs: Vec<(u32, std::path::PathBuf)> = Vec::new();
                while let Ok(Some(re)) = round_entries.next_entry().await {
                    let name = re.file_name().to_string_lossy().to_string();
                    if let Some(round_str) = name.strip_prefix("round_") {
                        if let Ok(n) = round_str.parse::<u32>() {
                            round_dirs.push((n, re.path()));
                        }
                    }
                }
                round_dirs.sort_by_key(|(n, _)| *n);
                total_rounds = round_dirs.len();
                // Only process the last 5 rounds for display (others available via pagination)
                let display_rounds: Vec<_> = round_dirs.into_iter().rev().take(5).rev().collect();
                for (n, dir) in display_rounds {
                    let plan = tokio::fs::read_to_string(dir.join("plan.md")).await
                        .unwrap_or_default()
                        .chars().take(600).collect::<String>();
                    let audit = tokio::fs::read_to_string(dir.join("audit.json")).await
                        .unwrap_or_else(|_| "[]".to_string());
                    // Tool-call trace: count calls per tool + total duration.
                    let mut tool_calls: Vec<Value> = Vec::new();
                    let mut total_ms: u128 = 0;
                    let mut call_count = 0usize;
                    if let Ok(trace_str) = tokio::fs::read_to_string(dir.join("tool_calls.jsonl")).await {
                        for line in trace_str.lines() {
                            if let Ok(entry) = serde_json::from_str::<Value>(line) {
                                if let Some(tool) = entry["tool"].as_str() {
                                    if let Some(d) = entry["duration_ms"].as_u64() {
                                        total_ms += d as u128;
                                    }
                                    call_count += 1;
                                    tool_calls.push(json!({
                                        "tool": tool,
                                        "duration_ms": entry["duration_ms"].as_u64().unwrap_or(0),
                                        "ok": entry["ok"].as_bool().unwrap_or(true),
                                    }));
                                }
                            }
                        }
                    }
                    // Parse state.json for phase + findings count (best-effort).
                    let mut phase = String::new();
                    let mut findings = 0usize;
                    if let Ok(state_str) = tokio::fs::read_to_string(dir.join("state.json")).await {
                        if let Ok(state) = serde_json::from_str::<Value>(&state_str) {
                            phase = state["phase"].as_str().unwrap_or("").to_string();
                            findings = state["verified_findings"]
                                .as_array().map(|a| a.len()).unwrap_or(0);
                        }
                    }
                    rounds.push(json!({
                        "round": n,
                        "plan": plan,
                        "audit": audit,
                        "phase": phase,
                        "findings_count": findings,
                        "tool_calls": tool_calls,
                        "tool_call_count": call_count,
                        "tool_total_ms": total_ms,
                    }));
                }
            }

            runs.push((mtime, json!({
                "contract_id": contract_id,
                "round_count": rounds.len(),
                "total_rounds": total_rounds,
                "rounds": rounds,
            })));
        }
    }
    // Sort by modification time, newest first
    runs.sort_by(|a, b| b.0.cmp(&a.0));
    let runs: Vec<Value> = runs.into_iter().map(|(_, v)| v).collect();
    Json(json!({ "runs": runs }))
}

/// GET /api/managed/status — return current active Expert-mode task contract.
/// Returns round progress, findings, actions, and last 3 verified findings.
async fn managed_status_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    match state.memory_store.get_latest_active_contract_global() {
        Ok(Some(json_str)) => {
            match serde_json::from_str::<Value>(&json_str) {
                Ok(c) => {
                    let findings = c["verified_findings"].as_array().cloned().unwrap_or_default();
                    let actions = c["verified_actions"].as_array().cloned().unwrap_or_default();
                    let open_leads = c["open_leads"].as_array().cloned().unwrap_or_default();
                    let remaining_work = c["remaining_work"].as_array().cloned().unwrap_or_default();
                    let last_3: Vec<Value> = findings.iter().rev().take(3).rev().cloned().collect();
                    Json(json!({
                        "active": true,
                        "task": c["original_task"].as_str().unwrap_or("").chars().take(80).collect::<String>(),
                        "phase": c["phase"].as_str().unwrap_or("unknown"),
                        "current_round": c["current_round"].as_u64().unwrap_or(0),
                        "max_rounds": c["max_rounds"].as_u64().unwrap_or(0),
                        "findings_count": findings.len(),
                        "actions_count": actions.len(),
                        "open_leads_count": open_leads.len(),
                        "remaining_work": remaining_work,
                        "last_findings": last_3,
                    }))
                }
                Err(_) => Json(json!({ "active": false })),
            }
        }
        _ => Json(json!({ "active": false })),
    }
}

async fn output_list_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let output_dir = std::path::Path::new(&state.workspace_dir).join("output");

    let mut files: Vec<Value> = Vec::new();
    if let Ok(mut entries) = tokio::fs::read_dir(&output_dir).await {
        let mut items: Vec<(String, u64, i64)> = Vec::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Ok(meta) = entry.metadata().await {
                if meta.is_file() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    let size = meta.len();
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    items.push((name, size, mtime));
                }
            }
        }
        // Sort by modification time, newest first
        items.sort_by(|a, b| b.2.cmp(&a.2));
        for (name, size, mtime) in items.into_iter().take(5) {
            files.push(json!({
                "name": name,
                "size": size,
                "modified": mtime,
                "url": format!("/workspace/output/{}", name),
                "download": format!("/api/output/download/{}", name),
            }));
        }
    }

    Json(json!({ "files": files, "dir": output_dir.to_string_lossy() }))
}

/// Download an output artifact with Content-Disposition: attachment.
async fn output_download_handler(
    State(state): State<Arc<AppState>>,
    Path(filename): Path<String>,
) -> Response {
    use axum::http::{header, StatusCode};

    // Prevent path traversal — only allow a plain file name
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let file_path = std::path::Path::new(&state.workspace_dir)
        .join("output")
        .join(&filename);

    match tokio::fs::read(&file_path).await {
        Ok(data) => {
            let mime = mime_guess::from_path(&file_path).first_or_octet_stream();
            let mut response = axum::body::Body::from(data).into_response();
            response.headers_mut().insert(header::CONTENT_TYPE, mime.to_string().parse().unwrap());
            let disposition = format!("attachment; filename=\"{}\"", filename);
            response.headers_mut().insert(
                header::CONTENT_DISPOSITION,
                disposition.parse().unwrap(),
            );
            response
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Open the workspace/output folder in the system file explorer.
async fn output_open_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let output_dir = std::path::Path::new(&state.workspace_dir).join("output");
    if let Err(e) = std::fs::create_dir_all(&output_dir) {
        return Json(json!({ "success": false, "error": format!("Failed to create output dir: {}", e) }));
    }

    #[cfg(target_os = "windows")]
    let result = std::process::Command::new("explorer.exe").arg(&output_dir).spawn();
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open").arg(&output_dir).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let result = std::process::Command::new("xdg-open").arg(&output_dir).spawn();

    match result {
        Ok(_) => Json(json!({ "success": true, "dir": output_dir.to_string_lossy() })),
        Err(e) => Json(json!({ "success": false, "error": format!("Failed to open folder: {}", e) })),
    }
}

/// GET /api/todos — return current TODO list from workspace/todos.json
async fn todos_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let todos_path = std::path::Path::new(&state.workspace_dir).join("todos.json");
    if !todos_path.exists() {
        return Json(json!({ "items": [], "count": 0 }));
    }
    match tokio::fs::read_to_string(&todos_path).await {
        Ok(content) => {
            match serde_json::from_str::<Value>(&content) {
                Ok(data) => {
                    // Return the items array and count
                    let items = data.get("items").cloned().unwrap_or(json!([]));
                    let count = items.as_array().map(|a| a.len()).unwrap_or(0);
                    Json(json!({ "items": items, "count": count }))
                }
                Err(e) => {
                    warn!("Failed to parse todos.json: {}", e);
                    Json(json!({ "items": [], "count": 0, "error": format!("Parse error: {}", e) }))
                }
            }
        }
        Err(e) => {
            warn!("Failed to read todos.json: {}", e);
            Json(json!({ "items": [], "count": 0, "error": format!("Read error: {}", e) }))
        }
    }
}

async fn health_handler() -> Json<Value> {
    Json(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

async fn models_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let models = state.model_configs.read().await;
    let list: Vec<Value> = models.iter().map(|m| {
        json!({ "name": &m.name, "context_window": m.context_window, "supports_vision": m.supports_vision })
    }).collect();

    // Load config to get persisted settings
    let config = crate::config::Config::load(&state.workspace_dir).ok();
    let tool_permissions = config.as_ref()
        .map(|c| serde_json::to_value(&c.agent.tool_permissions).unwrap_or(json!({})))
        .unwrap_or(json!({}));

    Json(json!({
        "models": list,
        "context_window_threshold": state.context_window_threshold.load(Ordering::SeqCst),
        "max_iterations": state.max_iterations.load(Ordering::SeqCst),
        "rabbit_hole_threshold": state.rabbit_hole_threshold.load(Ordering::SeqCst),
        "tool_timeout_secs": state.tool_timeout_secs.load(Ordering::SeqCst),
        "max_tool_retries": state.max_tool_retries.load(Ordering::SeqCst),
        "primary_model": state.primary_model.read().unwrap().clone(),
        "fallback_model": state.fallback_model.read().unwrap().clone(),
        "expert_role_models": serde_json::to_value(state.expert_role_models.read().unwrap().clone()).unwrap_or(json!({})),
        "timezone_offset": *state.timezone_offset.read().unwrap(),
        "tool_permissions": tool_permissions,
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
            "title": m.title,
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
    let title_raw = body["title"].as_str().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
        .unwrap_or_else(|| name.clone());
    let mut models = state.model_configs.write().await;
    if models.iter().any(|m| m.title == title_raw) {
        return Json(json!({"error": format!("Provider title '{}' already exists", title_raw)}));
    }
    let new_config = crate::config::ModelConfig {
        title: title_raw.clone(),
        name: name.clone(),
        api_base,
        api_key: body["api_key"].as_str().map(|s| s.to_string()).filter(|s| !s.is_empty()),
        api_key_env: body["api_key_env"].as_str().map(|s| s.to_string()).filter(|s| !s.is_empty()),
        context_window: body["context_window"].as_u64().map(|v| v as usize).unwrap_or(128000),
        max_tokens: body["max_tokens"].as_u64().map(|v| v as u32).unwrap_or(16384),
        temperature: body["temperature"].as_f64().unwrap_or(0.7),
        supports_vision: body["supports_vision"].as_bool().unwrap_or(false),
    };
    models.push(new_config);
    crate::model_store::save_configs(&models, std::path::Path::new(&state.model_store_path));
    info!("Provider '{}' (title {}) added via API", name, title_raw);
    Json(json!({"ok": true, "name": name, "title": title_raw}))
}

async fn providers_update_handler(
    State(state): State<Arc<AppState>>,
    Path(title): Path<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let mut models = state.model_configs.write().await;
    let idx = match models.iter().position(|m| m.title == title) {
        Some(i) => i,
        None => return Json(json!({"error": format!("Provider title '{}' not found", title)})),
    };
    let existing = &models[idx];
    // Preserve existing api_key if the incoming one is empty or looks like a masked value
    let incoming_key = body["api_key"].as_str().unwrap_or("").to_string();
    let api_key = if incoming_key.is_empty() || incoming_key.contains("...") || incoming_key == "****" {
        existing.api_key.clone()
    } else {
        Some(incoming_key)
    };
    let fallback_title = models[idx].title.clone();
    let new_title = body["title"].as_str().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or(fallback_title);
    if new_title != title && models.iter().position(|m| m.title == new_title).is_some() {
        return Json(json!({"error": format!("Provider title '{}' already exists", new_title)}));
    }
    let fallback_name = models[idx].name.clone();
    models[idx] = crate::config::ModelConfig {
        title: new_title.clone(),
        name: body["name"].as_str().map(|s| s.to_string()).unwrap_or(fallback_name),
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
    info!("Provider title '{}' updated via API", title);
    Json(json!({"ok": true, "name": models[idx].name.clone(), "title": new_title}))
}

async fn providers_delete_handler(
    State(state): State<Arc<AppState>>,
    Path(title): Path<String>,
) -> Json<Value> {
    let mut models = state.model_configs.write().await;
    let len_before = models.len();
    models.retain(|m| m.title != title);
    if models.len() == len_before {
        return Json(json!({"error": format!("Provider title '{}' not found", title)}));
    }
    crate::model_store::save_configs(&models, std::path::Path::new(&state.model_store_path));
    info!("Provider title '{}' deleted via API", title);
    Json(json!({"ok": true, "title": title}))
}

/// POST /api/providers/{title}/test - verify a provider/model is reachable and
/// correctly configured by sending a tiny chat request and reporting latency.
async fn providers_test_handler(
    State(state): State<Arc<AppState>>,
    Path(title): Path<String>,
) -> Json<Value> {
    let model = { let models = state.model_configs.read().await; models.iter().find(|m| m.title == title).cloned() };
    let Some(model) = model else { return Json(json!({"ok": false, "error": format!("Provider title '{}' not found", title)})); };
    match state.provider.test_connection_for(&model).await {
        Ok((latency_ms, reply)) => {
            info!("Provider '{}' (title {}) tested OK ({} ms)", model.name, title, latency_ms);
            Json(json!({"ok": true, "name": model.name, "title": title, "latency_ms": latency_ms, "reply": reply}))
        }
        Err(e) => {
            warn!("Provider '{}' (title {}) test failed: {}", model.name, title, e);
            Json(json!({"ok": false, "name": model.name, "title": title, "error": e}))
        }
    }
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

/// POST /api/managed/reset — Clear all active (non-completed) Expert mode task contracts.
/// This resets the Expert mode state so the next Expert task starts fresh.
async fn managed_reset_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    match state.memory_store.clear_active_contracts() {
        Ok(deleted) => {
            info!("Managed plans reset: {} active contract(s) cleared", deleted);
            Json(json!({ "success": true, "deleted": deleted }))
        }
        Err(e) => {
            error!("Failed to reset managed plans: {}", e);
            Json(json!({ "success": false, "error": e }))
        }
    }
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
        start_date: body["start_date"].as_str()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        end_date: body["end_date"].as_str()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        start_time: body["start_time"].as_str()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        end_time: body["end_time"].as_str()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
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
        body["start_date"].as_str().map(|s| s.to_string()),
        body["end_date"].as_str().map(|s| s.to_string()),
        body["start_time"].as_str().map(|s| s.to_string()),
        body["end_time"].as_str().map(|s| s.to_string()),
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

async fn cron_settings_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let scheduler = state.scheduler.lock().await;
    Json(json!({ "auto_approve": scheduler.auto_approve() }))
}

async fn cron_settings_update_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let on = body["auto_approve"].as_bool().unwrap_or(false);
    let mut scheduler = state.scheduler.lock().await;
    scheduler.set_auto_approve(on);
    Json(json!({ "success": true, "auto_approve": scheduler.auto_approve() }))
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
    let mut session_id = session_id; // mutable: may be replaced by the client's persistent session id

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
                            let mut content = parsed["content"].as_str().unwrap_or("").to_string();
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
                                .unwrap_or(state.max_iterations.load(Ordering::SeqCst));
                            let fallback_model = parsed["fallback_model"]
                                .as_str()
                                .filter(|s| !s.is_empty())
                                .map(|s| s.to_string());
                            let rabbit_hole = parsed["rabbit_hole_threshold"]
                                .as_u64()
                                .map(|v| v as usize)
                                .unwrap_or(state.rabbit_hole_threshold.load(Ordering::SeqCst));
                            let ctx_window_threshold = parsed["context_window_threshold"]
                                .as_u64()
                                .map(|v| v as usize)
                                .unwrap_or(state.context_window_threshold.load(Ordering::SeqCst));
                            let tool_timeout = parsed["tool_timeout_secs"]
                                .as_u64()
                                .map(|v| v as usize)
                                .unwrap_or(state.tool_timeout_secs.load(Ordering::SeqCst));
                            let max_retries = parsed["max_tool_retries"]
                                .as_u64()
                                .map(|v| v as usize)
                                .unwrap_or(state.max_tool_retries.load(Ordering::SeqCst));
                            let ctx_window = {
                                let mc = state.model_configs.read().await;
                                mc.iter().find(|m| m.name == model).map(|m| m.context_window).unwrap_or(128000)
                            };

                            // Parse optional images (base64 data URIs or URLs)
                            let images: Vec<String> = parsed["images"]
                                .as_array()
                                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                                .unwrap_or_default();

                            // Parse optional attachments (document files as base64 data URLs).
                            // Save each to workspace/output/attachments/ and prepend the path
                            // to the message so the Agent can file_read it.
                            if let Some(attachments) = parsed["attachments"].as_array() {
                                let att_dir = std::path::Path::new(&state.workspace_dir)
                                    .join("output").join("attachments");
                                let _ = std::fs::create_dir_all(&att_dir);
                                let mut entry = String::new();
                                for v in attachments {
                                    let name = match v["name"].as_str() {
                                        Some(n) if !n.contains("..") && !n.contains('/') && !n.contains('\\') => n,
                                        _ => continue,
                                    };
                                    let data_url = match v["data"].as_str() {
                                        Some(d) => d,
                                        None => continue,
                                    };
                                    // data URL: "data:[<mediatype>][;base64],<base64>"
                                    if let Some(base64_str) = data_url.split(',').nth(1) {
                                        use ::base64::Engine as _;
                                        let engine = ::base64::engine::general_purpose::STANDARD;
                                        if let Ok(bytes) = engine.decode(base64_str) {
                                            let file_path = att_dir.join(name);
                                            if let Err(e) = std::fs::write(&file_path, &bytes) {
                                                tracing::warn!("Failed to save attachment {}: {}", name, e);
                                            } else {
                                                entry.push_str(&format!(
                                                    "\n*附件已保存到: {}*\n",
                                                    file_path.to_string_lossy()
                                                ));
                                            }
                                        }
                                    }
                                }
                                if !entry.is_empty() {
                                    content = format!("{}\n\n---\n{}", entry, content);
                                }
                            }

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

                            // Adopt the client-provided persistent session id (if any).
                            // The frontend keeps a stable id across WebSocket reconnects,
                            // so Expert-mode TaskContract resume (keyed by session_id)
                            // keeps working instead of starting over at Round 1.
                            if let Some(client_sess) = parsed["session"].as_str() {
                                if !client_sess.is_empty() && client_sess != session_id {
                                    info!("Adopting client session_id {} (connection default was {})",
                                          client_sess, &session_id[..8.min(session_id.len())]);
                                    session_id = client_sess.to_string();
                                }
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

                            // Run via Runner (managed mode dispatches to ManagedRunner)
                            // Managed mode is activated PER-TASK via the 'managed' field —
                            // NOT a global setting. When true, the task runs through the
                            // Manager-Executor-Auditor loop for long-horizon IR tasks.
                            let managed = parsed["managed"].as_bool().unwrap_or(false);
                            let managed_scope = parsed["managed_scope"].as_str().unwrap_or("").to_string();

                            let run_result = if managed {
                                info!("Expert mode requested for session {}", session_id);
                                // -- Instant -> Expert: inherit same-session Instant progress --
                                // Build a DISTILLED, evidence-indexed handoff of the session's
                                // prior Instant work: original/latest instruction, a bounded capture
                                // of the assistant's actual findings/analysis, and the evidence files
                                // referenced. Tagged UNVERIFIED so the Manager treats it as leads to
                                // continue AND re-audit -- but the substance is kept so the Expert does
                                // not blindly redo collection that already happened.
                                let handoff: Option<String> = {
                                    let mut parts: Vec<String> = Vec::new();
                                    let mut original_task: Option<String> = None;
                                    let mut latest_user: Option<String> = None;
                                    let mut findings: Vec<String> = Vec::new();
                                    let mut finding_chars = 0usize;
                                    let mut evidence: Vec<String> = Vec::new();
                                    const SUFFIXES: [&str; 11] = [".json", ".csv", ".txt", ".md", ".log", ".xml", ".html", ".png", ".evtx", ".zip", ".pdf"];
                                    for m in history.iter() {
                                        if m.role == "system" { continue; }
                                        let Some(text) = m.content_as_text() else { continue };
                                        let text = text.trim();
                                        if text.is_empty() { continue; }
                                        if m.role == "user" {
                                            let head: String = text.chars().take(300).collect();
                                            if original_task.is_none() { original_task = Some(head.clone()); }
                                            latest_user = Some(head);
                                        } else {
                                            // Keep substantive assistant findings (bounded), skip chatter,
                                            // and harvest evidence file references.
                                            if text.len() >= 40 && finding_chars < 2400 {
                                                let seg: String = text.chars().take(700).collect();
                                                finding_chars += seg.len();
                                                findings.push(seg);
                                            }
                                            for tok in text.split_whitespace() {
                                                let tok = tok.trim().trim_matches(|c: char| !(c.is_alphanumeric() || c == '.' || c == '\\' || c == '/' || c == '_' || c == '-'));
                                                let low = tok.to_lowercase();
                                                if tok.len() >= 6 && (tok.contains('\\') || tok.contains('/'))
                                                    && SUFFIXES.iter().any(|s| low.ends_with(s))
                                                    && !evidence.iter().any(|e| e == tok)
                                                {
                                                    evidence.push(tok.to_string());
                                                    if evidence.len() >= 12 { break; }
                                                }
                                            }
                                        }
                                    }
                                    // Bound to the most recent findings.
                                    while findings.len() > 4 && finding_chars > 2000 {
                                        findings.remove(0);
                                    }
                                    if let Some(t) = original_task.as_deref() { parts.push(format!("Original task: {}", t)); }
                                    if let Some(t) = latest_user.as_deref() {
                                        if t != original_task.as_deref().unwrap_or("") { parts.push(format!("Latest instruction: {}", t)); }
                                    }
                                    if !findings.is_empty() {
                                        parts.push("Prior findings/analysis (UNVERIFIED - use as leads; verify before trusting; DO NOT blindly redo this work):".to_string());
                                        parts.extend(findings.iter().cloned());
                                    }
                                    if !evidence.is_empty() {
                                        parts.push("Evidence files referenced earlier (RE-AUDIT before trusting):".to_string());
                                        for e in evidence.iter().take(12) { parts.push(format!("- {}", e)); }
                                    }
                                    if parts.is_empty() { None } else { Some(parts.join("\n")) }
                                };

                                let active_contract =
                                    state.memory_store.get_latest_active_contract(&session_id)
                                        .ok().flatten();
                                let has_expert_residue = active_contract.is_some();
                                let rounds_summary = active_contract.as_ref()
                                    .map(|(_id, json)| rounds_summary_from_contract(json))
                                    .unwrap_or_default();
                                let has_instant = handoff
                                    .as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false);

                                // Ask once whether to CONTINUE prior work (resume the Expert
                                // contract if present, else take over the Instant progress) or
                                // start a NEW round. Wait up to 30s; on no reply, default CONTINUE.
                                let mut start_fresh = false;
                                let mut aborted = false;
                                let mut ask_for_task = false;
                                if has_expert_residue || has_instant {
                                    // Summarize prior rounds into a short (<=100 word) digest for the
                                    // continue prompt instead of showing char-truncated raw notes. Falls
                                    // back to the concise summaries if the LLM call fails.
                                    let prior_source = if !rounds_summary.is_empty() {
                                        rounds_summary.clone()
                                    } else {
                                        handoff.clone().unwrap_or_default()
                                    };
                                    let prior_preview = if prior_source.trim().is_empty() {
                                        String::new()
                                    } else {
                                        crate::managed::manager::summarize_prior(&state.provider, &model, &prior_source)
                                            .await
                                            .unwrap_or_else(|_| {
                                                if !rounds_summary.is_empty() {
                                                    rounds_summary.clone()
                                                } else {
                                                    compress_handoff_summary(&prior_source)
                                                }
                                            })
                                    };
                                let prompt_event = serde_json::json!({
                                        "type": "expert_prompt",
                                        "has_expert": has_expert_residue,
                                        "has_instant": has_instant,
                                        "prior": prior_preview,
                                        "session": session_id,
                                    });
                                    {
                                        let mut sink = ws_sink.lock().await;
                                        let _ = sink.send(Message::Text(prompt_event.to_string().into())).await;
                                    }
                                    let mut choice: Option<String> = None;
                                    let choice_timeout = std::time::Duration::from_secs(30);
                                    loop {
                                        let recv = ws_rx.recv();
                                        match tokio::time::timeout(choice_timeout, recv).await {
                                            Ok(Some(Message::Text(ref t))) => {
                                                if let Ok(p) = serde_json::from_str::<Value>(t) {
                                                    match p["type"].as_str() {
                                                        Some("expert_choice") => {
                                                            let c = p["choice"].as_str().unwrap_or("continue").to_string();
                                                            if c == "continue" || c == "new" { choice = Some(c); }
                                                        }
                                                        Some("stop") => {
                                                            cancelled.store(true, Ordering::SeqCst);
                                                            aborted = true;
                                                        }
                                                        _ => {}
                                                    }
                                                }
                                            }
                                            Ok(Some(Message::Close(_))) => {
                                                cancelled.store(true, Ordering::SeqCst);
                                                aborted = true;
                                            }
                                            Ok(None) => { aborted = true; }
                                            Err(_elapsed) => {
                                                info!("[managed:{}] Expert choice prompt timed out (30s) - defaulting to CONTINUE", session_id);
                                                choice = Some("continue".to_string());
                                            }
                                            _ => {}
                                        }
                                        if choice.is_some() || aborted { break; }
                                    }
                                    if !aborted && choice.as_deref() == Some("new") {
                                        if !is_concrete_task(&content) {
                                            info!("[managed:{}] User chose NEW but gave no concrete task - asking for task", session_id);
                                            ask_for_task = true;
                                        } else {
                                            info!("[managed:{}] User chose NEW Expert round - clearing residue", session_id);
                                            let _ = state.memory_store.clear_session_active_contracts(&session_id);
                                            start_fresh = true;
                                        }
                                    }
                                }

                                if aborted {
                                    info!("[managed:{}] Expert start cancelled (no choice)", session_id);
                                    let stopped_stream: crate::agent::EventStream = Box::pin(futures::stream::iter(vec![
                                        Ok(AgentEvent::text("\n\n*[Expert start cancelled - no choice received]*", &session_id, "system")),
                                        Ok(AgentEvent::done(&session_id, "system")),
                                    ]));
                                    Ok(stopped_stream)
                                } else if ask_for_task {
                                    info!("[managed:{}] Expert waiting for a concrete task (new round chosen)", session_id);
                                    let ask_stream: crate::agent::EventStream = Box::pin(futures::stream::iter(vec![
                                        Ok(AgentEvent::text("\n\n**你选择了「Start New Job（开新任务）」，但当前这条消息更像是模式切换（例如 continue / go），没有给出具体任务。** 请在 Expert 模式下描述你想解决的具体任务，例如：“try to solve this challenge: <URL>”。收到具体任务后，我会清空旧进度并开始新一轮。\n\n*[Expert 已暂停 —— 等待具体任务指令 / waiting for your task description]*", &session_id, "system")),
                                        Ok(AgentEvent::done(&session_id, "system")),
                                    ]));
                                    Ok(ask_stream)
                                } else {
                                    let task_cancel = Arc::new(AtomicBool::new(false));
                                    {
                                        let mut tasks = state.expert_tasks.lock().unwrap();
                                        if let Some(old) = tasks.get(&session_id) {
                                            old.store(true, Ordering::SeqCst);
                                        }
                                        tasks.insert(session_id.clone(), task_cancel.clone());
                                    }
                                    let managed_runner = crate::managed::ManagedRunner::new(
                                        state.runner.clone(),
                                        state.provider.clone(),
                                        model.clone(),
                                        state.expert_max_managed_rounds.load(Ordering::SeqCst),
                                        state.memory_store.clone(),
                                        state.tools.clone(),
                                        ".".to_string(),
                                        state.workspace_dir.clone(),
                                        state.expert_max_iterations.load(Ordering::SeqCst),
                                        state.rabbit_hole_threshold.load(Ordering::SeqCst),
                                        ctx_window,
                                        state.expert_tool_timeout_secs.load(Ordering::SeqCst) as u64,
                                        state.expert_max_tool_retries.load(Ordering::SeqCst),
                                        state.skill_manager.clone(),
                                        state.computer_use_enabled.clone(),
                                        
                                        state.fallback_model.read().unwrap().clone(),
                                        state.expert_role_models.read().unwrap().clone(),
                                        state.human_intervention_enabled.clone(),
                                    );
                                    let handoff = if start_fresh { None } else { handoff };
                                    // On CONTINUE: if there is an unfinished Expert contract for this
                                    // session, RESUME it (starts at its next round). Only force a fresh
                                    // run when the user chose NEW, or when taking over recent Instant
                                    // work with no Expert contract to resume. This matches the prompt
                                    // copy (resume the Expert contract if present, else take over Instant).
                                    let force_new_run = start_fresh || (has_instant && !has_expert_residue);
                                    managed_runner.run(
                                        &content, &session_id, &model, &managed_scope,
                                        state.permissions.clone(), state.permission_pending.clone(),
                                        task_cancel, handoff, force_new_run,
                                    ).await
                                }
                            } else {
                                state.runner.run(
                                    &content, &session_id, &model, max_iter, history.clone(),
                                    state.permissions.clone(), state.permission_pending.clone(),
                                    None, // no pre-authorization profile (normal chat)
                                    fallback_model, rabbit_hole,
                                    ctx_window, ctx_window_threshold,
                                    tool_timeout as u64,
                                    max_retries,
                                    images,
                                    None, None,  // normal chat — no checkpoint resume
                                    None,        // no per-round output override (Instant mode)
                                ).await
                            };
                            match run_result {
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
                                                        // Persist token usage to database
                                                        if let AgentEvent::Usage { model, prompt_tokens, completion_tokens, total_tokens, .. } = &event {
                                                            let _ = state.memory_store.record_usage(model, *prompt_tokens, *completion_tokens, *total_tokens, &session_id);
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
                                                                    // Also stop the Expert-mode spawned task via its
                                                                    // per-task flag (the connection flag is reset by
                                                                    // the next message and must not be its signal).
                                                                    if managed {
                                                                        let tasks = state.expert_tasks.lock().unwrap();
                                                                        if let Some(flag) = tasks.get(&session_id) {
                                                                            flag.store(true, Ordering::SeqCst);
                                                                        }
                                                                    }
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
                                                        if managed {
                                                            let tasks = state.expert_tasks.lock().unwrap();
                                                            if let Some(flag) = tasks.get(&session_id) {
                                                                flag.store(true, Ordering::SeqCst);
                                                            }
                                                        }
                                                        break;
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                        // Check if user sent stop
                                        if cancelled.load(Ordering::SeqCst) {
                                            info!("Agent execution stopped by user");
                                            // For Expert mode: mark the contract as user-stopped so the
                                            // resume query can find it. The spawned task will NOT persist
                                            // (to avoid overwriting this marker).
                                            if managed {
                                                state.memory_store.set_contract_stopped(&session_id);
                                                info!("[managed:{}] Set USER_STOPPED marker on TaskContract", session_id);
                                            }
                                            let stop_event = AgentEvent::text("\n\n*[Stopped by user]*", &session_id, "system");
                                            let msg_str = stop_event.to_ws_message();
                                            let mut sink = ws_sink.lock().await;
                                            let _ = sink.send(Message::Text(msg_str.into())).await;
                                            let done_event = AgentEvent::done(&session_id, "system");
                                            let msg_str = done_event.to_ws_message();
                                            let _ = sink.send(Message::Text(msg_str.into())).await;
                                            // Brief yield to let the spawned task detect cancellation
                                            // and exit cleanly before the user can send a new message.
                                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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
                                &cp.user_message, &session_id, &model, state.max_iterations.load(Ordering::SeqCst),
                                vec![],  // empty base history — resume_state provides it
                                state.permissions.clone(), state.permission_pending.clone(),
                                None, // no pre-authorization profile (checkpoint resume)
                                None, state.rabbit_hole_threshold.load(Ordering::SeqCst),
                                ctx_window, state.context_window_threshold.load(Ordering::SeqCst),
                                state.tool_timeout_secs.load(Ordering::SeqCst) as u64,
                                state.max_tool_retries.load(Ordering::SeqCst),
                                vec![],  // no images
                                Some(new_cp_id),
                                Some(resume_state),
                                None, // no per-round output override (checkpoint resume)
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
                                                        // Persist token usage to database
                                                        if let AgentEvent::Usage { model, prompt_tokens, completion_tokens, total_tokens, .. } = &event {
                                                            let _ = state.memory_store.record_usage(model, *prompt_tokens, *completion_tokens, *total_tokens, &session_id);
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
                        "agent_job" => {
                            // Launch a predefined sub-agent as a ONE-TIME background job.
                            // The main session is NOT blocked (no agentRunning, no LLM loop).
                            // A completion notification is broadcast when it finishes; the
                            // full report is retrievable via fetch_agent_result / report.md.
                            let agent_name = parsed["agent"].as_str().unwrap_or("").to_string();
                            let task = parsed["task"].as_str().unwrap_or("").to_string();
                            if agent_name.is_empty() || task.is_empty() {
                                let ev = AgentEvent::error("agent and task are required for /agent", &session_id, "system");
                                let mut sink = ws_sink.lock().await;
                                let _ = sink.send(Message::Text(ev.to_ws_message().into())).await;
                                continue;
                            }
                            let workdir = {
                                let st = state.agent_store.lock().await;
                                st.workdir_of(&agent_name).unwrap_or_default()
                            };
                            let default_model = {
                                let dm = state.primary_model.read().unwrap().clone();
                                if let Some(d) = dm { d } else {
                                    let mc = state.model_configs.read().await;
                                    mc.first().map(|m| m.name.clone()).unwrap_or_else(|| "gpt-4o".to_string())
                                }
                            };
                            let max_iter = state.max_iterations.load(Ordering::SeqCst);
                            let rh = state.rabbit_hole_threshold.load(Ordering::SeqCst);
                            let ctxthr = state.context_window_threshold.load(Ordering::SeqCst);
                            let to = state.tool_timeout_secs.load(Ordering::SeqCst);
                            let retr = state.max_tool_retries.load(Ordering::SeqCst);
                            let job = crate::tool::subagent::launch_sub_agent_job(
                                &state.agent_store, &state.runner, &state.sub_jobs, &state.notify_tx,
                                &state.permissions, &state.permission_pending,
                                max_iter, rh, 128000, ctxthr, to, retr,
                                &default_model, &agent_name, &task,
                            ).await;
                            let ev = match &job {
                                Ok(job_id) => {
                                    let wd = if workdir.is_empty() { "its working directory".to_string() } else { workdir.clone() };
                                    AgentEvent::text(&format!("**Sub-agent '{}' launched** — job `{}` running in the background.
The main session is not blocked. You'll be notified when it finishes; read the report via fetch_agent_result({}) or from {}.", agent_name, job_id, job_id, wd), &session_id, "system")
                                }
                                Err(e) => AgentEvent::error(&e, &session_id, "system"),
                            };
                            let mut sink = ws_sink.lock().await;
                            let _ = sink.send(Message::Text(ev.to_ws_message().into())).await;
                            if job.is_ok() {
                                let done = AgentEvent::done(&session_id, "system");
                                let _ = sink.send(Message::Text(done.to_ws_message().into())).await;
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

    // ── End-of-session knowledge distillation ──
    let history = state.sessions.lock().await.get(&session_id).cloned().unwrap_or_default();
    if history.len() >= 4 {
        let provider = state.provider.clone();
        let model_name = state.model_configs.read().await.first().map(|m| m.name.clone()).unwrap_or_default();
        let workspace_dir = state.workspace_dir.clone();
        let sid = session_id.clone();
        tokio::spawn(async move {
            match distill::distill_session(&sid, &history, provider, &model_name, &workspace_dir).await {
                Ok(n) => info!("Session {} distilled {} knowledge entries", &sid[..8.min(sid.len())], n),
                Err(e) => warn!("Session {} distillation failed: {}", &sid[..8.min(sid.len())], e),
            }
        });
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
            // Store a simple extractive summary (LLM-based summary would need provider access).
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
    #[serde(default = "default_tz_offset")]
    tz_offset: i32,
}

fn default_history_days() -> usize { 3 }
fn default_history_limit() -> usize { 50 }
fn default_tz_offset() -> i32 { 8 }

async fn history_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HistoryQuery>,
) -> Json<Value> {
    let days = query.days.max(1).min(30);
    let limit = query.limit.max(1).min(200);
    let tz_secs = query.tz_offset.clamp(-12, 14) * 3600;
    let tz = chrono::FixedOffset::east_opt(tz_secs).unwrap_or_else(|| chrono::FixedOffset::east_opt(8 * 3600).unwrap());
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
                        .map(|dt| dt.with_timezone(&tz).format("%H:%M:%S").to_string())
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
    let handles = mgr.get_tool_handles();
    let tools = mgr.list_tools();
    let tools_dir = mgr.tools_dir().to_string_lossy().to_string();
    drop(mgr);

    // Sync external tools into ToolRegistry (LLM-visible)
    let mut registry = state.tools.write().await;
    registry.sync_external_tools(&handles);
    let registered_count = handles.len();
    drop(registry);

    info!("External tools synced to registry: {} tool(s)", registered_count);
    Json(json!({ "tools": tools, "tools_dir": tools_dir, "count": tools.len(), "registered": registered_count }))
}

async fn tools_toggle_handler(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Json<Value> {
    let mut mgr = state.external_tools.lock().await;
    match mgr.toggle_tool(&name) {
        Some(enabled) => {
            mgr.save_state();
            let handles = mgr.get_tool_handles();
            drop(mgr);

            // Re-sync registry after toggle
            let mut registry = state.tools.write().await;
            registry.sync_external_tools(&handles);

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
// Computer Use toggle
// ============================================================

async fn computer_use_toggle_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let enabled = body.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    let prev = state.computer_use_enabled.swap(enabled, Ordering::SeqCst);

    if prev != enabled {
        let mut registry = state.tools.write().await;
        if enabled {
            crate::tool::computer_use::register_computer_use_tools(&mut registry);
            info!("Computer Use tools ENABLED ({} tools registered)", crate::tool::computer_use::CU_TOOL_NAMES.len());
        } else {
            crate::tool::computer_use::unregister_computer_use_tools(&mut registry);
            info!("Computer Use tools DISABLED");
        }
    }

    Json(json!({ "success": true, "enabled": enabled }))
}

// ============================================================

// Human Intervention Simulation toggle
// ============================================================

async fn human_intervention_get_handler(
    State(state): State<Arc<AppState>>,
) -> Json<Value> {
    let enabled = state.human_intervention_enabled.load(Ordering::SeqCst);
    Json(json!({ "success": true, "enabled": enabled }))
}

async fn human_intervention_toggle_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let enabled = body.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    let prev = state.human_intervention_enabled.swap(enabled, Ordering::SeqCst);
    
    if prev != enabled {
        info!("Human Intervention Simulation {}", if enabled { "ENABLED" } else { "DISABLED" });
    }
    
    Json(json!({ "success": true, "enabled": enabled }))
}

/// Save agent settings (max_iterations, rabbit_hole_threshold, etc.) to config.toml
/// and update the in-memory AppState.
async fn agent_settings_save_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let max_iterations = body.get("max_iterations")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(state.max_iterations.load(Ordering::SeqCst));
    let rabbit_hole_threshold = body.get("rabbit_hole_threshold")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(state.rabbit_hole_threshold.load(Ordering::SeqCst));
    let context_window_threshold = body.get("context_window_threshold")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(state.context_window_threshold.load(Ordering::SeqCst));
    let tool_timeout_secs = body.get("tool_timeout_secs")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(state.tool_timeout_secs.load(Ordering::SeqCst));
    let max_tool_retries = body.get("max_tool_retries")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(state.max_tool_retries.load(Ordering::SeqCst));

    // Save to config.toml
    let workspace_dir = &state.workspace_dir;
    match crate::config::Config::save_agent_settings(
        workspace_dir,
        max_iterations,
        rabbit_hole_threshold,
        context_window_threshold,
        tool_timeout_secs,
        max_tool_retries,
    ) {
        Ok(()) => {
            // Hot-reload in-memory values so the next run picks them up immediately
            state.max_iterations.store(max_iterations, Ordering::SeqCst);
            state.rabbit_hole_threshold.store(rabbit_hole_threshold, Ordering::SeqCst);
            state.context_window_threshold.store(context_window_threshold, Ordering::SeqCst);
            state.tool_timeout_secs.store(tool_timeout_secs, Ordering::SeqCst);
            state.max_tool_retries.store(max_tool_retries, Ordering::SeqCst);

            info!("Agent settings saved and hot-reloaded: max_iterations={}, rabbit_hole={}, ctx_threshold={}, tool_timeout={}, max_retries={}",
                max_iterations, rabbit_hole_threshold, context_window_threshold, tool_timeout_secs, max_tool_retries);
            Json(json!({
                "success": true,
                "max_iterations": max_iterations,
                "rabbit_hole_threshold": rabbit_hole_threshold,
                "context_window_threshold": context_window_threshold,
                "tool_timeout_secs": tool_timeout_secs,
                "max_tool_retries": max_tool_retries,
            }))
        }
        Err(e) => {
            error!("Failed to save agent settings: {}", e);
            Json(json!({ "success": false, "error": format!("Failed to save: {}", e) }))
        }
    }
}

/// Save extended agent settings (model selection, timezone, permissions) to config.toml.
async fn agent_settings_extended_save_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let primary_model = body.get("primary_model")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let fallback_model = body.get("fallback_model")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let timezone_offset = body.get("timezone_offset")
        .and_then(|v| v.as_i64())
        .map(|v| v as i8)
        .unwrap_or(8);

    // Parse tool_permissions from the request
    let tool_permissions: std::collections::HashMap<String, bool> = body.get("tool_permissions")
        .and_then(|v| v.as_object())
        .map(|obj| obj.iter().filter_map(|(k, v)| v.as_bool().map(|b| (k.clone(), b))).collect())
        .unwrap_or_default();

    let workspace_dir = &state.workspace_dir;
    match crate::config::Config::save_extended_settings(
        workspace_dir,
        primary_model.clone(),
        fallback_model.clone(),
        timezone_offset,
        tool_permissions.clone(),
    ) {
        Ok(()) => {
            // Hot-reload in-memory values
            if let Some(ref m) = primary_model {
                *state.primary_model.write().unwrap() = Some(m.clone());
            }
            if let Some(ref m) = fallback_model {
                *state.fallback_model.write().unwrap() = Some(m.clone());
            }
            *state.timezone_offset.write().unwrap() = timezone_offset;

            info!("Extended settings saved and hot-reloaded: primary_model={:?}, fallback_model={:?}, timezone={}, permissions={:?}",
                primary_model, fallback_model, timezone_offset, tool_permissions);
            Json(json!({
                "success": true,
                "primary_model": primary_model,
                "fallback_model": fallback_model,
                "timezone_offset": timezone_offset,
                "tool_permissions": tool_permissions,
            }))
        }
        Err(e) => {
            error!("Failed to save extended settings: {}", e);
            Json(json!({ "success": false, "error": format!("Failed to save: {}", e) }))
        }
    }
}

/// Save Expert mode settings to config.toml (iterations/timeout/retries/rounds)
/// plus per-role model overrides for Manager/Auditor/Executor and their fallbacks.
async fn agent_settings_expert_save_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let expert_max_iterations = body.get("expert_max_iterations")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(200);
    let expert_tool_timeout_secs = body.get("expert_tool_timeout_secs")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(600);
    let expert_max_tool_retries = body.get("expert_max_tool_retries")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(3);
    let expert_max_managed_rounds = body.get("expert_max_managed_rounds")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(50);

    // Per-role model overrides (optional). Empty/missing => role uses the primary model.
    let str_opt = |k: &str| body.get(k)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let role_models = crate::config::RoleModelsConfig {
        manager: str_opt("role_manager"),
        manager_fallback: str_opt("role_manager_fallback"),
        auditor: str_opt("role_auditor"),
        auditor_fallback: str_opt("role_auditor_fallback"),
        executor: str_opt("role_executor"),
        executor_fallback: str_opt("role_executor_fallback"),
    };

    let workspace_dir = &state.workspace_dir;
    let save_main = crate::config::Config::save_expert_settings(
        workspace_dir,
        expert_max_iterations,
        expert_tool_timeout_secs,
        expert_max_tool_retries,
        expert_max_managed_rounds,
    );
    let save_roles = crate::config::Config::save_role_models(workspace_dir, &role_models);
    if let Err(e) = &save_main {
        error!("Failed to save expert settings: {}", e);
        return Json(json!({ "success": false, "error": format!("Failed to save: {}", e) }));
    }
    if let Err(e) = &save_roles {
        error!("Failed to save role models: {}", e);
        return Json(json!({ "success": false, "error": format!("Failed to save role models: {}", e) }));
    }

    // Hot-reload in-memory values so the next Expert run picks them up
    state.expert_max_iterations.store(expert_max_iterations, Ordering::SeqCst);
    state.expert_tool_timeout_secs.store(expert_tool_timeout_secs, Ordering::SeqCst);
    state.expert_max_tool_retries.store(expert_max_tool_retries, Ordering::SeqCst);
    state.expert_max_managed_rounds.store(expert_max_managed_rounds, Ordering::SeqCst);
    *state.expert_role_models.write().unwrap() = role_models.clone();

    info!("Expert settings saved: max_iter={}, timeout={}, retries={}, rounds={}, role_models={:?}",
        expert_max_iterations, expert_tool_timeout_secs, expert_max_tool_retries, expert_max_managed_rounds, role_models);
    Json(json!({
        "success": true,
        "expert_max_iterations": expert_max_iterations,
        "expert_tool_timeout_secs": expert_tool_timeout_secs,
        "expert_max_tool_retries": expert_max_tool_retries,
        "expert_max_managed_rounds": expert_max_managed_rounds,
        "role_models": role_models,
    }))
}

// ============================================================
// Config Files (AGENTS.md, SOUL.md, TOOLS.md)
// ============================================================

async fn config_files_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let workspace = &state.workspace_dir;
    let files = ["AGENTS.md", "SOUL.md", "TOOLS.md", "MEMORY.md", "USER.md"];
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
    let allowed = ["AGENTS.md", "SOUL.md", "TOOLS.md", "MEMORY.md", "USER.md"];
    if !allowed.contains(&name.as_str()) {
        return Json(json!({ "success": false, "error": "Invalid file name. Allowed: AGENTS.md, SOUL.md, TOOLS.md, MEMORY.md, USER.md" }));
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

// ============================================================
// Token usage tracking API
// ============================================================

#[derive(Deserialize)]
struct UsageQuery {
    #[serde(default = "default_usage_days")]
    days: usize,
    #[serde(default)]
    tz: f64,
}

fn default_usage_days() -> usize { 7 }

async fn usage_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<UsageQuery>,
) -> Json<Value> {
    // days == 0 -> all-time cumulative; otherwise clamp to [1, 90]
    let days = if query.days == 0 { 0 } else { query.days.max(1).min(90) };
    // Clamp timezone offset to a sane range (UTC-12 .. UTC+14)
    let tz = query.tz.max(-12.0).min(14.0);
    match state.memory_store.get_usage_stats(days, tz) {
        Ok(data) => {
            // Compute summary totals from the data array
            let mut total_calls: i64 = 0;
            let mut total_prompt: i64 = 0;
            let mut total_completion: i64 = 0;
            let mut total_tokens: i64 = 0;
            if let Some(arr) = data.as_array() {
                for item in arr {
                    total_calls += item["calls"].as_i64().unwrap_or(0);
                    total_prompt += item["prompt_tokens"].as_i64().unwrap_or(0);
                    total_completion += item["completion_tokens"].as_i64().unwrap_or(0);
                    total_tokens += item["total_tokens"].as_i64().unwrap_or(0);
                }
            }
            Json(json!({
                "days": days,
                "data": data,
                "summary": {
                    "total_calls": total_calls,
                    "total_prompt_tokens": total_prompt,
                    "total_completion_tokens": total_completion,
                    "total_tokens": total_tokens,
                }
            }))
        },
        Err(e) => Json(json!({ "error": e })),
    }
}

async fn usage_today_handler(
    State(state): State<Arc<AppState>>,
) -> Json<Value> {
    match state.memory_store.get_today_usage() {
        Ok(data) => Json(data),
        Err(e) => Json(json!({ "error": e })),
    }
}
