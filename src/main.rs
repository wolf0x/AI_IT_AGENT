#[allow(dead_code)]
mod agent;
#[allow(dead_code)]
mod callbacks;
mod config;
#[allow(dead_code)]
mod context;
#[allow(dead_code)]
mod error;
mod log;
mod model;
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
use crate::log::ConversationLogger;
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

    // Load config
    let config = Config::load("config.toml")?;
    info!(
        "Config loaded: {} models, {} MCP servers",
        config.models.len(),
        config.mcp_servers.len()
    );

    // Build tool registry (12 built-in tools)
    let mut registry = ToolRegistry::build_default(&config.agent.working_dir);
    info!("Built-in tools: {:?}", registry.tool_names());

    // Connect MCP servers
    let mut mcp_manager = McpClientManager::new();
    if !config.mcp_servers.is_empty() {
        mcp_manager.connect(&config.mcp_servers).await;
        let mcp_tools = mcp_manager.get_tools();
        for tool in &mcp_tools {
            info!("MCP tool: {} ({})", tool.name(), tool.description());
            registry.register(tool.clone());
        }
    }

    // Load skills
    let skill_manager = Arc::new(SkillManager::new("skills"));
    let skills = skill_manager.list();
    info!("Loaded {} skills", skills.len());

    // Add skill meta-tools
    let meta_tools = skill_manager.build_meta_tools();
    for mt in &meta_tools {
        registry.register(mt.clone());
    }

    // Build LLM provider (implements Llm trait)
    let model_names: Vec<String> = config.models.iter().map(|m| m.name.clone()).collect();
    let provider = Arc::new(OpenAiProvider::new(config.models.clone()));
    info!("Models available: {:?}", model_names);

    // Build logger
    let logger = Arc::new(ConversationLogger::new(&config.server.log_dir));

    // Build agent using builder pattern (ADK-RUST style)
    let agent = LlmAgent::builder()
        .name("rust-agent")
        .description("Local AI agent with Windows system tools")
        .provider(provider)
        .tools(Arc::new(registry))
        .skill_manager(skill_manager.clone())
        .max_iterations(config.agent.max_iterations)
        .working_dir(&config.agent.working_dir)
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

    // Build scheduler
    let scheduler = Arc::new(Mutex::new(Scheduler::new(
        "cron_tasks.json",
        runner.clone(),
        model_names.clone(),
        permissions.clone(),
        permission_pending.clone(),
        config.agent.max_iterations,
        config.agent.rabbit_hole_threshold,
    )));

    // Spawn scheduler background loop
    let scheduler_loop = scheduler.clone();
    tokio::spawn(async move {
        Scheduler::run_loop(scheduler_loop).await;
    });

    // Build app state
    let state = Arc::new(AppState {
        runner: runner.clone(),
        skill_manager,
        mcp_manager: Arc::new(Mutex::new(mcp_manager)),
        logger,
        password: config.server.password.clone(),
        model_names,
        max_iterations: config.agent.max_iterations,
        rabbit_hole_threshold: config.agent.rabbit_hole_threshold,
        sessions: Mutex::new(std::collections::HashMap::new()),
        permissions,
        permission_resolver,
        permission_pending,
        scheduler,
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
