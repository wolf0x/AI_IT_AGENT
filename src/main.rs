#[allow(dead_code)]
mod agent;
#[allow(dead_code)]
#[allow(dead_code)]
mod callbacks;
mod checkpoint;
mod config;
mod crypto;
mod distill;
#[allow(dead_code)]
mod forensics;
#[allow(dead_code)]
mod context;
#[allow(dead_code)]
mod error;
mod event_log;
mod external_tools;
mod heartbeat;
mod knowledge;
mod interject;
mod log;
#[allow(dead_code)]
mod managed;
mod memory;
mod model;
mod model_store;
mod permission;
mod policy;
#[allow(dead_code)]
mod runner;
mod scheduler;
mod agent_store;
mod server;
#[allow(dead_code)]
mod session;
mod skill;
#[allow(dead_code)]
mod tool;
mod web;

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
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

/// Shared per-process log state: the workspace logs directory, file prefix, and
/// the currently open per-day file together with the day it belongs to.
/// Shared per-process log state: the workspace logs directory, file prefix, and
/// the currently open per-run file (one file per program launch,
/// `rustagent-YYYY-MM-DD.N.log`) plus a stable dated alias
/// (`rustagent-YYYY-MM-DD.log`) that always holds only the current run.
struct DailyLogShared {
    log_dir: std::path::PathBuf,
    prefix: String,
    state: std::sync::Mutex<DailyLogState>,
}
struct DailyLogState {
    day: String,
    file: Option<std::fs::File>,
    alias: Option<std::fs::File>,
    run: u32,
}
impl DailyLogShared {
    fn new(log_dir: std::path::PathBuf, prefix: String) -> Self {
        Self {
            log_dir,
            prefix,
            state: std::sync::Mutex::new(DailyLogState { day: String::new(), file: None, alias: None, run: 0 }),
        }
    }
    fn today() -> String {
        chrono::Local::now().format("%Y-%m-%d").to_string()
    }
    /// Highest existing run index for the day, plus one (i.e. the next per-run file number).
    fn next_run_index(dir: &std::path::Path, prefix: &str, day: &str) -> u32 {
        let stem = format!("{}-{}.", prefix, day);
        let mut max: u32 = 0;
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if let Some(rest) = name.strip_prefix(&stem) {
                    if let Some(num) = rest.strip_suffix(".log") {
                        if let Ok(n) = num.parse::<u32>() {
                            if n > max { max = n; }
                        }
                    }
                }
            }
        }
        max + 1
    }
    fn run_path(&self, day: &str, n: u32) -> std::path::PathBuf {
        self.log_dir.join(format!("{}-{}.{}.log", self.prefix, day, n))
    }
    fn alias_path(&self, day: &str) -> std::path::PathBuf {
        self.log_dir.join(format!("{}-{}.log", self.prefix, day))
    }
    /// Path of the current run's log file (valid once the first log line is flushed).
    fn current_run_path(&self, today: &str) -> std::path::PathBuf {
        let run = self.state.lock()
            .map(|g| g.run)
            .unwrap_or_else(|e| e.into_inner().run);
        self.run_path(today, run)
    }

    /// Open a fresh per-run file (and its stable dated alias) for the day. Each
    /// call picks the next run index, so a re-launched process never appends to
    /// an earlier run's file. The stable alias is truncated so it holds only the
    /// current run (helpers that read the dated name still see this run).
    fn rotate(&self, st: &mut DailyLogState, today: &str) {
        if st.day == today && st.file.is_some() {
            return;
        }
        let n = Self::next_run_index(&self.log_dir, &self.prefix, today);
        let run_file = std::fs::OpenOptions::new()
            .create(true).write(true).truncate(true)
            .open(self.run_path(today, n)).ok();
        let alias_file = std::fs::OpenOptions::new()
            .create(true).write(true).truncate(true)
            .open(self.alias_path(today)).ok();
        st.day = today.to_string();
        st.file = run_file;
        st.alias = alias_file;
        st.run = n;
    }
}

/// A tracing writer that mirrors every formatted line to stdout, a fresh per-run
/// file (`rustagent-YYYY-MM-DD.N.log`), and a stable dated alias. Keeps live
/// console output while persisting a copy under workspace/logs/, with one log
/// file per program launch.
struct TeeLogWriter {
    shared: std::sync::Arc<DailyLogShared>,
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for TeeLogWriter {
    type Writer = TeeLogSink;
    fn make_writer(&'a self) -> Self::Writer {
        TeeLogSink { shared: self.shared.clone() }
    }
}

struct TeeLogSink {
    shared: std::sync::Arc<DailyLogShared>,
}
impl std::io::Write for TeeLogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Recover from a poisoned lock instead of panicking.
        let mut st = match self.shared.state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let _ = std::io::Write::write_all(&mut std::io::stdout(), buf);
        let today = DailyLogShared::today();
        self.shared.rotate(&mut st, &today);
        if let Some(f) = st.file.as_mut() {
            let _ = std::io::Write::write_all(f, buf);
        }
        if let Some(a) = st.alias.as_mut() {
            let _ = std::io::Write::write_all(a, buf);
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let mut st = match self.shared.state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let Some(f) = st.file.as_mut() {
            let _ = std::io::Write::flush(f);
        }
        if let Some(a) = st.alias.as_mut() {
            let _ = std::io::Write::flush(a);
        }
        Ok(())
    }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ---- Resolve exe + workspace dir first so logging can target workspace/logs/ ----
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let workspace_dir = if let Ok(userprofile) = std::env::var("USERPROFILE") {
        format!("{}\\.RustAgent\\workspace", userprofile)
    } else {
        exe_dir.join(".workspace").to_string_lossy().to_string()
    };
    if let Err(e) = std::fs::create_dir_all(&workspace_dir) {
        tracing::warn!("Failed to create workspace directory {}: {}", workspace_dir, e);
    }

    // Initialize logging: mirror to console AND a per-day file under workspace/logs/.
    // A fresh rustagent-YYYY-MM-DD.log is created per day and rotated at midnight.
    let logs_dir = std::path::Path::new(&workspace_dir).join("logs");
    let _ = std::fs::create_dir_all(&logs_dir);
    let log_shared = std::sync::Arc::new(DailyLogShared::new(logs_dir.clone(), "rustagent".to_string()));
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,chromiumoxide::handler=error")),
        )
        .with_writer(TeeLogWriter { shared: log_shared.clone() })
        .with_ansi(false)
        .init();

    info!("Starting RustAgent (pid {})", std::process::id());
    info!("Executable directory: {}", exe_dir.display());
    info!("Workspace directory: {}", workspace_dir);
    info!(
        "Runtime log file: {}",
        log_shared.current_run_path(&DailyLogShared::today()).display()
    );
    let ws_subdirs = ["memory", "tools", "skills", "logs", "static", "output", "knowledge", "rules"];
    for sub in &ws_subdirs {
        let p = std::path::Path::new(&workspace_dir).join(sub);
        let _ = std::fs::create_dir_all(&p);
    }

    // Extract embedded YARA rules to workspace/rules/ on first run
    let rules_dir = std::path::Path::new(&workspace_dir).join("rules");
    if let Err(e) = tool::malware_analysis::ensure_rules(&rules_dir) {
        tracing::warn!("Failed to extract YARA rules: {}", e);
    }

    // Load config from workspace (generates default config.toml on first run)
    let config = Config::load(&workspace_dir)?;
    info!("Config loaded from workspace");

    // ── Detect user's Given Name from Windows ──
    // Detect on every startup using whoami crate (no persistence to config).
    let user_given_name = crate::config::detect_user_given_name();
    info!("Detected user_given_name: {}", user_given_name);

    // Build tool registry (built-in tools)
    // The notification broadcast channel is created early so tools that need to
    // push messages to WebSocket clients (e.g. sys_remind) can hold a sender.
    let (notify_tx, _) = tokio::sync::broadcast::channel::<String>(100);

    // ── Random password (regenerated on EVERY startup) ──────
    // A fresh random 6-digit password is generated each time the process
    // starts — it is never reused across runs. It is written to .password
    // (for reference) and logged so the user can find the current one.
    let password = {
        let mut bytes = [0u8; 3];
        getrandom::fill(&mut bytes).expect("getrandom");
        let num = ((bytes[0] as u32) << 16 | (bytes[1] as u32) << 8 | bytes[2] as u32) % 1000000;
        let password = format!("{:06}", num);
        let pwd_file = std::path::Path::new(&workspace_dir).join(".password");
        if let Err(e) = std::fs::write(&pwd_file, &password) {
            tracing::warn!("Failed to save password: {}", e);
        }
        password
    };

    // ── Extract embedded workspace files (first-run only) ────
    // AGENTS.md, SOUL.md, TOOLS.md, USER.md are compiled into the binary.
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
        ("agents.json", "agents.json"),
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
        let old_logs = exe_dir.join("logs");
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

    // Register all MCP tools into the tool registry
    let mcp_tools = mcp_manager.get_tools();
    for tool in &mcp_tools {
        let one_liner = tool
            .description()
            .lines()
            .next()
            .unwrap_or("")
            .chars()
            .take(80)
            .collect::<String>();
        info!("MCP tool: {} - {}", tool.name(), one_liner);
        registry.register(tool.clone());
    }
    if !mcp_tools.is_empty() {
        info!("Registered {} MCP tool(s) total", mcp_tools.len());
    }

    // Load skills (resolve skills dir from workspace)
    let skills_dir = std::path::Path::new(&workspace_dir).join("skills");
    let skill_manager = Arc::new(SkillManager::new_with_notify(
        skills_dir.to_str().unwrap_or("skills"),
        Some(notify_tx.clone()),
    ));
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
    let initial_models = model_store::load_configs(&model_store_path);
    if !initial_models.is_empty() {
        info!("Loaded {} model config(s) from models.json", initial_models.len());
    }
    let model_names: Vec<String> = initial_models.iter().map(|m| m.name.clone()).collect();
    let shared_models = Arc::new(tokio::sync::RwLock::new(initial_models));
    let provider = Arc::new(OpenAiProvider::new_with_shared(shared_models.clone()));
    let provider_for_state = provider.clone();
    info!("Models available: {:?}", model_names);
    let default_model = config.agent.primary_model.clone()
        .filter(|m| !m.is_empty())
        .or_else(|| model_names.first().cloned())
        .unwrap_or_else(|| "gpt-4o".to_string());


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

    // Register external tools into registry (LLM-visible at startup)
    {
        let mgr = external_tools.lock().await;
        let handles = mgr.get_tool_handles();
        if !handles.is_empty() {
            registry.sync_external_tools(&handles);
            info!("Registered {} external tool(s): {:?}",
                handles.len(),
                handles.iter().map(|(n, _, _, _)| n.as_str()).collect::<Vec<_>>()
            );
        }
    }

    // Wrap registry in Arc<RwLock> for dynamic MCP tool registration
    let shared_tools = Arc::new(tokio::sync::RwLock::new(registry));

    // Create browser session early so it can be shared between agent (cleanup) and tool (use)
    let browser_session = crate::tool::browser_cdp::BrowserSession::new(workspace_dir.clone());

    // Build agent using builder pattern (ADK-RUST style)
    let agent = LlmAgent::builder()
        .name("RustAgent")
        .description("Local AI agent with Windows system tools")
        .provider(provider)
        .tools(shared_tools.clone())
        .skill_manager(skill_manager.clone())
        .max_iterations(config.agent.max_iterations)
        .working_dir(&working_dir)
        .workspace_dir(&workspace_dir)
        .parallel_ir_tools(config.agent.parallel_ir_tools)
        .user_given_name(&user_given_name)
        .cleanup_session(browser_session.clone())
        .build()
        .map_err(|e| format!("Failed to build agent: {}", e))?;
    let agent: Arc<dyn agent::Agent> = Arc::new(agent);

    // Shared hot-reloadable switch: drop redundant trailing tool calls after a
    // final text answer. Shared between the Runner and AppState so the Settings
    // toggle takes effect at runtime without a restart.
    let trim_redundant_tool_calls = Arc::new(std::sync::atomic::AtomicBool::new(config.agent.trim_redundant_tool_calls));

    // Build runner using builder pattern (ADK-RUST style)
    let runner = Runner::builder()
        .agent(agent)
        .logger(logger.clone())
        .checkpointer(checkpointer)
        .app_name("RustAgent")
        .trim_redundant_tool_calls(trim_redundant_tool_calls.clone())
        .build()
        .map_err(|e| format!("Failed to build runner: {}", e))?;
    let runner = Arc::new(runner);

    // Build permission state
    let (permission_resolver, permission_pending) = PermissionResolver::new();
    let permissions = Arc::new(Mutex::new({
        // Seed from config so persisted tool_permissions survive restart and are
        // inherited by CRON tasks (which share this same permission map).
        let mut perms = default_permissions();
        for (k, v) in &config.agent.tool_permissions {
            perms.insert(k.clone(), *v);
        }
        perms
    }));

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

    // Predefined sub-agent store (agents.json + per-agent workdirs)
    let agent_store = Arc::new(Mutex::new(agent_store::AgentStore::open(&workspace_dir)));

    // Shared sub-agent job registry (run_agent tool + /agent WS path).
    let sub_jobs = crate::tool::subagent::SharedJobs::new();

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
    // Register browser_cdp tool (uses same session as agent cleanup)
    {
        let mut reg = shared_tools.write().await;
        reg.register(Arc::new(crate::tool::cron_manage::CronManageTool::new(scheduler.clone())));
        reg.register(Arc::new(crate::tool::memory_md::MemoryMdTool::new(workspace_dir.clone())));
        reg.register(Arc::new(crate::tool::todo_update::TodoUpdateTool::new(workspace_dir.clone())));
        reg.register(Arc::new(crate::tool::knowledge_search::KnowledgeSearchTool::new(workspace_dir.clone())));
        reg.register(Arc::new(crate::tool::knowledge_ingest::KnowledgeIngestTool::new(workspace_dir.clone())));
        reg.register(Arc::new(crate::tool::browser_cdp::BrowserCdpTool::new(browser_session)));
        // Sub-agent tools: launch predefined sub-agents as background jobs.
        // Shared sub-agent job registry (also exposed to AppState for the /agent WS path).
        {
            reg.register(Arc::new(crate::tool::subagent::RunAgentTool {
                agent_store: agent_store.clone(),
                runner: runner.clone(),
                notify_tx: notify_tx.clone(),
                permissions: permissions.clone(),
                permission_pending: permission_pending.clone(),
                jobs: sub_jobs.clone(),
                max_iterations: Arc::new(AtomicUsize::new(config.agent.max_iterations)),
                rabbit_hole_threshold: Arc::new(AtomicUsize::new(config.agent.rabbit_hole_threshold)),
                context_window: 128000,
                context_window_threshold: Arc::new(AtomicUsize::new(config.agent.context_window_threshold)),
                tool_timeout_secs: Arc::new(AtomicUsize::new(config.agent.tool_timeout_secs)),
                max_tool_retries: Arc::new(AtomicUsize::new(config.agent.max_tool_retries)),
                default_model: default_model.clone(),
            }));
            reg.register(Arc::new(crate::tool::subagent::FetchAgentResultTool { jobs: sub_jobs.clone() }));
            reg.register(Arc::new(crate::tool::subagent::WaitAgentsTool { jobs: sub_jobs.clone() }));

        }

    }
    info!("Registered cron_manage + memory_md + todo_update + browser_cdp tools");
    if let Err(e) = crate::knowledge::build_index(&workspace_dir) {
        tracing::warn!("Failed to build knowledge index: {}", e);
    }

    // Conditionally register Computer Use tools based on config
    let computer_use_enabled = Arc::new(std::sync::atomic::AtomicBool::new(config.agent.computer_use));
    if config.agent.computer_use {
        let mut reg = shared_tools.write().await;
        crate::tool::computer_use::register_computer_use_tools(&mut reg);
        info!("Computer Use tools registered (enabled in config)");
    }
    
    
    // Human intervention simulation switch (default: false)
    let human_intervention_enabled = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Build app state
    let state = Arc::new(AppState {
        runner: runner.clone(),
        skill_manager,
        mcp_manager: Arc::new(Mutex::new(mcp_manager)),
        tools: shared_tools,
        logger,
        memory_store,
        external_tools,
        password: password.clone(),
        model_configs: shared_models.clone(),
        model_store_path: model_store_path.to_str().unwrap_or("models.json").to_string(),
        max_iterations: Arc::new(AtomicUsize::new(config.agent.max_iterations)),
        rabbit_hole_threshold: Arc::new(AtomicUsize::new(config.agent.rabbit_hole_threshold)),
        context_window_threshold: Arc::new(AtomicUsize::new(config.agent.context_window_threshold)),
        tool_timeout_secs: Arc::new(AtomicUsize::new(config.agent.tool_timeout_secs)),
        max_tool_retries: Arc::new(AtomicUsize::new(config.agent.max_tool_retries)),
        trim_redundant_tool_calls: trim_redundant_tool_calls.clone(),
        expert_max_iterations: Arc::new(AtomicUsize::new(config.agent.expert_max_iterations)),
        expert_tool_timeout_secs: Arc::new(AtomicUsize::new(config.agent.expert_tool_timeout_secs)),
        expert_max_tool_retries: Arc::new(AtomicUsize::new(config.agent.expert_max_tool_retries)),
        expert_max_managed_rounds: Arc::new(AtomicUsize::new(config.agent.expert_max_managed_rounds)),
        sessions: Arc::new(Mutex::new(std::collections::HashMap::new())),
        permissions,
        permission_resolver,
        permission_pending,
        expert_tasks: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        agent_store: agent_store.clone(),
        sub_jobs: sub_jobs.clone(),
        scheduler,
        notify_tx,
        workspace_dir,
        provider: provider_for_state,
        computer_use_enabled,
        human_intervention_enabled,
        primary_model: Arc::new(std::sync::RwLock::new(config.agent.primary_model.clone())),
        fallback_model: Arc::new(std::sync::RwLock::new(config.agent.fallback_model.clone())),
        expert_role_models: Arc::new(std::sync::RwLock::new(config.agent.expert_role_models.clone())),
        timezone_offset: Arc::new(std::sync::RwLock::new(config.agent.timezone_offset)),
    });

    // Create router and start server
    let app = server::create_router(state);
    let addr = format!("{}:{}", config.server.host, config.server.port);

    info!("=== RustAgent is running ===");
    info!("Local:   http://localhost:{}", config.server.port);
    info!("Network: http://{}:{}", get_local_ip(), config.server.port);
    info!("Password: {}", password);

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
