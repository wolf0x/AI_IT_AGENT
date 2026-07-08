#[allow(dead_code)]
mod agent;
#[allow(dead_code)]
mod callbacks;
mod checkpoint;
mod config;
mod crypto;
#[allow(dead_code)]
mod context;
#[allow(dead_code)]
mod error;
mod external_tools;
mod heartbeat;
mod log;
mod memory;
mod model;
mod model_store;
mod permission;
#[allow(dead_code)]
mod runner;
mod scheduler;
mod server;
#[allow(dead_code)]
mod session;
mod skill;
#[allow(dead_code)]
mod tool;
mod web;

use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::agent::LlmAgent;
use crate::checkpoint::TaskCheckpointer;
use crate::config::Config;
use crate::external_tools::ExternalToolsManager;
use crate::log::ConversationLogger;
use crate::memory::MemoryStore;
use crate::model::openai::OpenAiProvider;
use crate::runner::Runner;
use crate::permission::{PermissionResolver, default_permissions};
use crate::scheduler::Scheduler;
use crate::heartbeat::Heartbeat;
use crate::server::AppState;
use crate::skill::SkillManager;
use crate::tool::mcp_client::McpClientManager;
use crate::tool::ToolRegistry;

/// Workspace template files embedded into the binary at build time.
/// Extracted to workspace on first run only — existing files are never overwritten.
const EMBEDDED_FILES: &[(&str, &str)] = include!(concat!(env!("OUT_DIR"), "/embedded_files.rs"));

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,chromiumoxide::handler=error")),
        )
        .init();

    info!("Starting RustAgent...");

    // Resolve exe directory for relative paths
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    info!("Executable directory: {}", exe_dir.display());

    // Load config from exe directory
    let config_path = exe_dir.join("config.toml");
    let mut config = Config::load(config_path.to_str().unwrap_or("config.toml"))?;
    info!(
        "Config loaded: {} models, {} MCP servers",
        config.models.len(),
        config.mcp_servers.len()
    );

    // Build tool registry (built-in tools)
    // The notification broadcast channel is created early so tools that need to
    // push messages to WebSocket clients (e.g. sys_remind) can hold a sender.
    let (notify_tx, _) = tokio::sync::broadcast::channel::<String>(100);

    // Resolve workspace directory (agent's "home")
    let workspace_dir = if config.agent.workspace_dir.is_empty() || config.agent.workspace_dir == "." {
        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            format!("{}\\.RustAgent\\workspace", userprofile)
        } else {
            exe_dir.join(".workspace").to_string_lossy().to_string()
        }
    } else {
        config.agent.workspace_dir.clone()
    };
    // Create workspace directory and all subdirectories
    if let Err(e) = std::fs::create_dir_all(&workspace_dir) {
        tracing::warn!("Failed to create workspace directory {}: {}", workspace_dir, e);
    } else {
        info!("Workspace directory: {}", workspace_dir);
    }
    let ws_subdirs = ["memory", "tools", "skills", "logs", "static", "screenshots"];
    for sub in &ws_subdirs {
        let p = std::path::Path::new(&workspace_dir).join(sub);
        let _ = std::fs::create_dir_all(&p);
    }

    // ── Random password (first-run) ──────────────────────────
    // Each installation gets its own random 6-digit password, persisted to .password.
    // Subsequent runs reuse the same password — no more default "123".
    {
        let pwd_file = std::path::Path::new(&workspace_dir).join(".password");
        if pwd_file.exists() {
            if let Ok(pwd) = std::fs::read_to_string(&pwd_file) {
                let pwd = pwd.trim().to_string();
                if !pwd.is_empty() {
                    config.server.password = pwd;
                }
            }
        } else {
            let mut bytes = [0u8; 3];
            getrandom::fill(&mut bytes).expect("getrandom");
            let num = ((bytes[0] as u32) << 16 | (bytes[1] as u32) << 8 | bytes[2] as u32) % 1000000;
            let password = format!("{:06}", num);
            if let Err(e) = std::fs::write(&pwd_file, &password) {
                tracing::warn!("Failed to save password: {}", e);
            }
            config.server.password = password;
        }
    }

    // ── Extract embedded workspace files (first-run only) ────
    // AGENTS.md, SOUL.md, TOOLS.md are compiled into the binary.
    // On first run they are written to workspace; existing files are never overwritten.
    for &(name, content) in EMBEDDED_FILES {
        let path = std::path::Path::new(&workspace_dir).join(name);
        if !path.exists() {
            if let Err(e) = std::fs::write(&path, content) {
                tracing::warn!("Failed to extract {}: {}", name, e);
            } else {
                info!("Extracted {} to workspace", name);
            }
        }
    }

    // Migrate existing config files from exe_dir → workspace (first-run upgrade)
    let migrations = [
        ("models.json", "models.json"),
        ("cron_tasks.json", "cron_tasks.json"),
        ("mcp_servers.json", "mcp_servers.json"),
        ("memory.db", "memory/memory.db"),
    ];
    for (src_name, dst_rel) in &migrations {
        let src = exe_dir.join(src_name);
        let dst = std::path::Path::new(&workspace_dir).join(dst_rel);
        if src.exists() && !dst.exists() {
            if let Err(e) = std::fs::copy(&src, &dst) {
                tracing::warn!("Failed to migrate {} → {}: {}", src.display(), dst.display(), e);
            } else {
                info!("Migrated {} → {}", src.display(), dst.display());
            }
        }
    }
    // Migrate Tools/ → tools/ (case change for consistency)
    {
        let old_tools = exe_dir.join("Tools");
        let new_tools = std::path::Path::new(&workspace_dir).join("tools");
        if old_tools.exists() && !new_tools.exists() {
            let _ = std::fs::rename(&old_tools, &new_tools);
        }
    }
    // Migrate skills/ → workspace/skills/
    {
        let old_skills = exe_dir.join("skills");
        let new_skills = std::path::Path::new(&workspace_dir).join("skills");
        if old_skills.exists() && !new_skills.exists() {
            let _ = std::fs::rename(&old_skills, &new_skills);
        }
    }
    // Migrate logs/ → workspace/logs/
    {
        let old_logs = exe_dir.join(&config.server.log_dir);
        let new_logs = std::path::Path::new(&workspace_dir).join("logs");
        if old_logs.exists() && !new_logs.exists() {
            let _ = std::fs::rename(&old_logs, &new_logs);
        }
    }
    // Migrate static/ → workspace/static/
    {
        let old_static = exe_dir.join("static");
        let new_static = std::path::Path::new(&workspace_dir).join("static");
        if old_static.exists() && !new_static.exists() {
            let _ = std::fs::rename(&old_static, &new_static);
        }
    }

    let working_dir = if config.agent.working_dir == "." {
        workspace_dir.clone()
    } else {
        config.agent.working_dir.clone()
    };
    let mut registry = ToolRegistry::build_default(&working_dir, Some(notify_tx.clone()));
    info!("Built-in tools: {:?}", registry.tool_names());

    // Connect MCP servers (persist to workspace)
    let mcp_persist_path = std::path::Path::new(&workspace_dir).join("mcp_servers.json");
    let mut mcp_manager = McpClientManager::with_persist_path(mcp_persist_path);

    // Load persisted MCP server configs (from mcp_servers.json, auth tokens auto-decrypted)
    let persisted = mcp_manager.load_configs();
    if !persisted.is_empty() {
        info!("Loaded {} persisted MCP server(s)", persisted.len());
        mcp_manager.connect(&persisted).await;
    }

    // Also connect servers from static config.yaml (if not already loaded from persist)
    if !config.mcp_servers.is_empty() {
        mcp_manager.connect(&config.mcp_servers).await;
    }

    // Register all MCP tools into the tool registry
    let mcp_tools = mcp_manager.get_tools();
    for tool in &mcp_tools {
        info!("MCP tool: {} ({})", tool.name(), tool.description());
        registry.register(tool.clone());
    }
    if !mcp_tools.is_empty() {
        info!("Registered {} MCP tool(s) total", mcp_tools.len());
    }

    // Load skills (resolve skills dir from workspace)
    let skills_dir = std::path::Path::new(&workspace_dir).join("skills");
    let skill_manager = Arc::new(SkillManager::new(skills_dir.to_str().unwrap_or("skills")));
    let skills = skill_manager.list();
    info!("Loaded {} skills", skills.len());

    // Add skill meta-tools
    let meta_tools = skill_manager.build_meta_tools();
    for mt in &meta_tools {
        registry.register(mt.clone());
    }

    // Build LLM provider (implements Llm trait)
    // Load persisted model configs (from models.json in workspace, api_keys auto-decrypted)
    let model_store_path = std::path::Path::new(&workspace_dir).join("models.json");
    let persisted_models = model_store::load_configs(&model_store_path);
    let initial_models = if !persisted_models.is_empty() {
        info!("Loaded {} persisted model config(s)", persisted_models.len());
        persisted_models
    } else if !config.models.is_empty() {
        // First run: seed models.json from config.toml
        info!("Seeding models.json from config.toml ({} models)", config.models.len());
        model_store::save_configs(&config.models, &model_store_path);
        config.models.clone()
    } else {
        vec![]
    };
    let model_names: Vec<String> = initial_models.iter().map(|m| m.name.clone()).collect();
    let shared_models = Arc::new(tokio::sync::RwLock::new(initial_models));
    let provider = Arc::new(OpenAiProvider::new_with_shared(shared_models.clone()));
    info!("Models available: {:?}", model_names);

    // Build logger (resolve log dir from workspace)
    let log_dir = std::path::Path::new(&workspace_dir).join("logs");
    let logger = Arc::new(ConversationLogger::new(log_dir.to_str().unwrap_or("logs")));

    // Build memory store (resolve DB path from workspace/memory/)
    let db_path = std::path::Path::new(&workspace_dir).join("memory").join("memory.db");
    let memory_store = Arc::new(
        MemoryStore::new(db_path.to_str().unwrap_or("memory.db"))
            .expect("Failed to initialize memory store")
    );
    info!("Memory store ready: {}", db_path.display());

    // Clean up stale checkpoints (older than 24 hours) on startup
    let _ = memory_store.cleanup_stale_checkpoints(24);

    // Build task checkpointer for crash recovery (断点续跑)
    let checkpointer = Arc::new(TaskCheckpointer::new(memory_store.clone()));

    // Build external tools manager (resolve tools dir from workspace)
    let tools_dir = std::path::Path::new(&workspace_dir).join("tools");
    let external_tools = Arc::new(Mutex::new(ExternalToolsManager::new(tools_dir.clone())));
    info!("External tools dir: {}", tools_dir.display());

    // Wrap registry in Arc<RwLock> for dynamic MCP tool registration
    let shared_tools = Arc::new(tokio::sync::RwLock::new(registry));

    // Build agent using builder pattern (ADK-RUST style)
    let agent = LlmAgent::builder()
        .name("rust-agent")
        .description("Local AI agent with Windows system tools")
        .provider(provider)
        .tools(shared_tools.clone())
        .skill_manager(skill_manager.clone())
        .max_iterations(config.agent.max_iterations)
        .working_dir(&working_dir)
        .workspace_dir(&workspace_dir)
        .model_configs(config.models.clone())
        .build()
        .map_err(|e| format!("Failed to build agent: {}", e))?;
    let agent: Arc<dyn agent::Agent> = Arc::new(agent);

    // Build runner using builder pattern (ADK-RUST style)
    let runner = Runner::builder()
        .agent(agent)
        .logger(logger.clone())
        .checkpointer(checkpointer)
        .app_name("rust-agent")
        .build()
        .map_err(|e| format!("Failed to build runner: {}", e))?;
    let runner = Arc::new(runner);

    // Build permission state
    let (permission_resolver, permission_pending) = PermissionResolver::new();
    let permissions = Arc::new(Mutex::new(default_permissions()));

    // Build scheduler (resolve cron path from workspace)
    let cron_path = std::path::Path::new(&workspace_dir).join("cron_tasks.json");
    let scheduler = Arc::new(Mutex::new(Scheduler::new(
        cron_path.to_str().unwrap_or("cron_tasks.json"),
        runner.clone(),
        shared_models.clone(),
        permissions.clone(),
        permission_pending.clone(),
        config.agent.max_iterations,
        config.agent.rabbit_hole_threshold,
        128000,  // default context window for CRON tasks
        config.agent.context_window_threshold,
        config.agent.tool_timeout_secs as u64,
        notify_tx.clone(),
    )));

    // Spawn scheduler background loop
    let scheduler_loop = scheduler.clone();
    tokio::spawn(async move {
        Scheduler::run_loop(scheduler_loop).await;
    });

    // Spawn heartbeat background loop
    let heartbeat = Heartbeat::new(
        runner.clone(),
        shared_models.clone(),
        permissions.clone(),
        permission_pending.clone(),
        config.agent.max_iterations,
        config.agent.rabbit_hole_threshold,
        128000,
        config.agent.context_window_threshold,
        config.agent.tool_timeout_secs as u64,
        notify_tx.clone(),
        workspace_dir.clone(),
    );
    tokio::spawn(async move {
        heartbeat.run_loop().await;
    });
    info!("Heartbeat background loop spawned");

    // Register CRON management tool (needs scheduler, which depends on runner)
    // Register memory_md tool (file-based daily logs + long-term memory)
    // Register todo_update tool (lightweight task planning/tracking)
    // Register browser_cdp tool (CDP browser automation via chromiumoxide)
    let browser_session = crate::tool::browser_cdp::BrowserSession::new(workspace_dir.clone());
    {
        let mut reg = shared_tools.write().await;
        reg.register(Arc::new(crate::tool::cron_manage::CronManageTool::new(scheduler.clone())));
        reg.register(Arc::new(crate::tool::memory_md::MemoryMdTool::new(workspace_dir.clone())));
        reg.register(Arc::new(crate::tool::todo_update::TodoUpdateTool::new(workspace_dir.clone())));
        reg.register(Arc::new(crate::tool::browser_cdp::BrowserCdpTool::new(browser_session)));
    }
    info!("Registered cron_manage + memory_md + todo_update + browser_cdp tools");

    // Build app state
    let state = Arc::new(AppState {
        runner: runner.clone(),
        skill_manager,
        mcp_manager: Arc::new(Mutex::new(mcp_manager)),
        tools: shared_tools,
        logger,
        memory_store,
        external_tools,
        password: config.server.password.clone(),
        model_configs: shared_models.clone(),
        model_store_path: model_store_path.to_str().unwrap_or("models.json").to_string(),
        max_iterations: config.agent.max_iterations,
        rabbit_hole_threshold: config.agent.rabbit_hole_threshold,
        context_window_threshold: config.agent.context_window_threshold,
        tool_timeout_secs: config.agent.tool_timeout_secs,
        sessions: Mutex::new(std::collections::HashMap::new()),
        permissions,
        permission_resolver,
        permission_pending,
        scheduler,
        notify_tx,
        workspace_dir,
    });

    // Create router and start server
    let app = server::create_router(state);
    let addr = format!("{}:{}", config.server.host, config.server.port);

    info!("=== RustAgent is running ===");
    info!("Local:   http://localhost:{}", config.server.port);
    info!("Network: http://{}:{}", get_local_ip(), config.server.port);
    info!("Password: {}", config.server.password);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn get_local_ip() -> String {
    use std::net::UdpSocket;
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect("8.8.8.8:80")?;
            socket.local_addr()
        })
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| "0.0.0.0".to_string())
}
