#[allow(dead_code)]
mod agent;
#[allow(dead_code)]
mod callbacks;
mod config;
mod crypto;
#[allow(dead_code)]
mod context;
#[allow(dead_code)]
mod error;
mod external_tools;
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
use crate::config::Config;
use crate::external_tools::ExternalToolsManager;
use crate::log::ConversationLogger;
use crate::memory::MemoryStore;
use crate::model::openai::OpenAiProvider;
use crate::runner::Runner;
use crate::permission::{PermissionResolver, default_permissions};
use crate::scheduler::Scheduler;
use crate::server::AppState;
use crate::skill::SkillManager;
use crate::tool::mcp_client::McpClientManager;
use crate::tool::ToolRegistry;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
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
    let config = Config::load(config_path.to_str().unwrap_or("config.toml"))?;
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
    // Create workspace directory if it doesn't exist
    if let Err(e) = std::fs::create_dir_all(&workspace_dir) {
        tracing::warn!("Failed to create workspace directory {}: {}", workspace_dir, e);
    } else {
        info!("Workspace directory: {}", workspace_dir);
    }

    let working_dir = if config.agent.working_dir == "." {
        workspace_dir.clone()
    } else {
        config.agent.working_dir.clone()
    };
    let mut registry = ToolRegistry::build_default(&working_dir, Some(notify_tx.clone()));
    info!("Built-in tools: {:?}", registry.tool_names());

    // Connect MCP servers
    let mut mcp_manager = McpClientManager::new();

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

    // Load skills (resolve skills dir relative to exe)
    let skills_dir = exe_dir.join("skills");
    let skill_manager = Arc::new(SkillManager::new(skills_dir.to_str().unwrap_or("skills")));
    let skills = skill_manager.list();
    info!("Loaded {} skills", skills.len());

    // Add skill meta-tools
    let meta_tools = skill_manager.build_meta_tools();
    for mt in &meta_tools {
        registry.register(mt.clone());
    }

    // Build LLM provider (implements Llm trait)
    // Load persisted model configs (from models.json, api_keys auto-decrypted)
    let model_store_path = exe_dir.join("models.json");
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

    // Build logger (resolve log dir relative to exe)
    let log_dir = exe_dir.join(&config.server.log_dir);
    let logger = Arc::new(ConversationLogger::new(log_dir.to_str().unwrap_or("logs")));

    // Build memory store (resolve DB path relative to exe)
    let db_path = exe_dir.join("memory.db");
    let memory_store = Arc::new(
        MemoryStore::new(db_path.to_str().unwrap_or("memory.db"))
            .expect("Failed to initialize memory store")
    );
    info!("Memory store ready: {}", db_path.display());

    // Build external tools manager (resolve Tools dir relative to exe)
    let tools_dir = exe_dir.join("Tools");
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
        .app_name("rust-agent")
        .build()
        .map_err(|e| format!("Failed to build runner: {}", e))?;
    let runner = Arc::new(runner);

    // Build permission state
    let (permission_resolver, permission_pending) = PermissionResolver::new();
    let permissions = Arc::new(Mutex::new(default_permissions()));

    // Build scheduler (resolve cron path relative to exe)
    let cron_path = exe_dir.join("cron_tasks.json");
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

    // Register CRON management tool (needs scheduler, which depends on runner)
    {
        let mut reg = shared_tools.write().await;
        reg.register(Arc::new(crate::tool::cron_manage::CronManageTool::new(scheduler.clone())));
    }
    info!("Registered cron_manage tool");

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
