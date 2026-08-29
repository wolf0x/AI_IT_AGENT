//! Sub-agent tools: launch a predefined sub-agent as an isolated background job
//! from the main session, then fetch its aggregated report.
//!
//! - `run_agent(agent, task)` resolves a predefined sub-agent, runs it in a clean
//!   session with its own system prompt + dedicated working directory, returns a
//!   job id immediately (main loop keeps running), and broadcasts a notification
//!   on completion.
//! - `fetch_agent_result(job_id)` retrieves the finished report.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;

use crate::agent::AgentEvent;
use crate::agent_store::AgentStore;
use crate::error::{AgentError, AgentResult};
use crate::model::ChatMessage;
use crate::permission::PendingMap;
use crate::runner::{Runner, SubAgentRunParams};
use crate::server::NotifyTx;
use crate::tool::{Tool, ToolContext};

/// In-memory registry of launched sub-agent jobs (job_id -> state).
#[derive(Clone)]
pub struct SharedJobs(pub Arc<Mutex<HashMap<String, SubJobState>>>);

impl SharedJobs {
    pub fn new() -> Self { SharedJobs(Arc::new(Mutex::new(HashMap::new()))) }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct SubJobState {
    pub job_id: String,
    pub agent: String,
    pub status: String, // running | done | error
    pub report: String,
    pub error: String,
}

/// Tool: run_agent — launch a predefined sub-agent in the background.
pub struct RunAgentTool {
    pub agent_store: Arc<Mutex<AgentStore>>,
    pub runner: Arc<Runner>,
    pub notify_tx: NotifyTx,
    pub permissions: Arc<Mutex<HashMap<String, bool>>>,
    pub permission_pending: PendingMap,
    pub jobs: SharedJobs,
    pub max_iterations: Arc<AtomicUsize>,
    pub rabbit_hole_threshold: Arc<AtomicUsize>,
    pub context_window: usize,
    pub context_window_threshold: Arc<AtomicUsize>,
    pub tool_timeout_secs: Arc<AtomicUsize>,
    pub max_tool_retries: Arc<AtomicUsize>,
    pub default_model: String,
}

#[async_trait]
impl Tool for RunAgentTool {
    fn name(&self) -> &str { "run_agent" }

    fn description(&self) -> &str {
        "Launch a predefined sub-agent in the background to work on a task. \
         Provide `agent` (the sub-agent's name) and `task` (what it should do). \
         Returns a job_id immediately so the main session can keep working; the \
         sub-agent runs in its own clean session with its own system prompt and \
         working directory. Use fetch_agent_result(job_id) to read the finished report."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "agent": { "type": "string", "description": "Name of a predefined sub-agent" },
                "task": { "type": "string", "description": "Task description handed to the sub-agent" }
            },
            "required": ["agent", "task"]
        })
    }

    fn is_builtin(&self) -> bool { true }

async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
    let agent_name = args["agent"].as_str().unwrap_or("").to_string();
    let task = args["task"].as_str().unwrap_or("").to_string();
    let job_id = launch_sub_agent_job(
        &self.agent_store, &self.runner, &self.jobs, &self.notify_tx,
        &self.permissions, &self.permission_pending,
        self.max_iterations.load(Ordering::SeqCst),
        self.rabbit_hole_threshold.load(Ordering::SeqCst),
        self.context_window,
        self.context_window_threshold.load(Ordering::SeqCst),
        self.tool_timeout_secs.load(Ordering::SeqCst),
        self.max_tool_retries.load(Ordering::SeqCst),
        &self.default_model,
        &agent_name, &task,
        None, None,
    ).await.map_err(|e| AgentError::tool("run_agent", e))?;
    Ok(json!({ "job_id": job_id, "status": "started", "agent": agent_name,
        "note": "Sub-agent runs in the background; use fetch_agent_result(job_id) for the report." }))
    }
}

/// Resolve a predefined sub-agent and launch it as an isolated background job.
/// Shared by the `run_agent` tool and the `/agent` WS command path.
/// Returns the job_id. The main session is not blocked; a completion
/// notification is broadcast when the sub-agent finishes.
pub async fn launch_sub_agent_job(
    store: &Arc<Mutex<AgentStore>>,
    runner: &Arc<Runner>,
    jobs: &SharedJobs,
    notify: &NotifyTx,
    permissions: &Arc<Mutex<HashMap<String, bool>>>,
    pending: &PendingMap,
    max_iter: usize, rh: usize, ctxwin: usize, ctxthr: usize, to: usize, retr: usize,
    default_model: &str,
    agent_name: &str,
    task: &str,
    // Optional main-session id + sessions store: inject the sub-agent's
    // outcome into the main session history so the main LLM sees it as
    // context on subsequent turns.
    main_session: Option<String>,
    sessions: Option<Arc<Mutex<std::collections::HashMap<String, Vec<ChatMessage>>>>>,
) -> Result<String, String> {
    let agent_name = agent_name.trim().trim_start_matches('@').to_string();
    let task = task.trim().to_string();
    if agent_name.is_empty() { return Err("agent is required".to_string()); }
    if task.is_empty() { return Err("task is required".to_string()); }

    let def = { let s = store.lock().await; s.find(&agent_name).cloned() }
        .ok_or_else(|| format!("No enabled agent named '{}'", agent_name))?;

    let model = if def.model.trim().is_empty() { default_model.to_string() } else { def.model.clone() };
    let job_id = format!("sub-{}", uuid::Uuid::new_v4());
    let agent_display = def.name.clone();
    let system_prompt = def.system_prompt.clone();
    let workdir = def.workdir.clone();
    {
        let mut j = jobs.0.lock().await;
        j.insert(job_id.clone(), SubJobState { job_id: job_id.clone(), agent: agent_display.clone(), status: "running".into(), report: String::new(), error: String::new() });
    }

    let runner = runner.clone();
    let perms = permissions.clone();
    let pend = pending.clone();
    let jobs2 = jobs.clone();
    let ntf = notify.clone();
    let c_job_id = job_id.clone();
    let c_agent = agent_display.clone();
    let c_workdir = workdir.clone();

    tokio::spawn(async move {
        let start = std::time::Instant::now();
        let params = SubAgentRunParams {
            message: task, session_id: c_job_id.clone(), model,
            system_prompt, output_dir: c_workdir.clone(),
            max_iterations: max_iter, rabbit_hole_threshold: rh,
            context_window: ctxwin, context_window_threshold: ctxthr,
            tool_timeout_secs: to as u64, max_tool_retries: retr,
        };
        let res = runner.run_sub_agent(params, perms, pend).await;
        let mut report = String::new();
        let mut err = String::new();
        match res {
            Ok(mut stream) => {
                use futures::StreamExt;
                while let Some(r) = stream.next().await {
                    if let Ok(e) = r {
                        if let AgentEvent::TextDelta { content, .. } = &e { report.push_str(content); }
                    }
                }
            }
            Err(e) => err = e.to_string(),
        }
        let status = if err.is_empty() { "done".to_string() } else { "error".to_string() };
        {
            let mut j = jobs2.0.lock().await;
            if let Some(s) = j.get_mut(&c_job_id) { s.status = status.clone(); s.report = report.clone(); s.error = err.clone(); }
        }
        let _ = std::fs::write(std::path::Path::new(&c_workdir).join("report.md"), format!("# Sub-agent: {}\n\n{}", c_agent, report));
        // Inject the sub-agent's outcome into the MAIN session history so the
        // main LLM sees it as context on subsequent turns.
        if let (Some(ms), Some(sessions)) = (main_session, sessions) {
            let mut store = sessions.lock().await;
            let entry = store.entry(ms).or_default();
            let heading = if err.is_empty() {
                format!("[Sub-agent '{}' completed - job {}]\n", c_agent, c_job_id)
            } else {
                format!("[Sub-agent '{}' FAILED - job {}]\nERROR: {}\n", c_agent, c_job_id, err)
            };
            let body = if report.trim().is_empty() { "(no text output)".to_string() } else { report.clone() };
            entry.push(ChatMessage::system(&format!("{}\n{}", heading, body)));
        }
        let elapsed = start.elapsed().as_secs();
        let body = if report.trim().is_empty() { err } else { report };
        let summary = format!("🤖 **Sub-agent '{}' finished** ({}s)\n\n{}", c_agent, elapsed, body);
        let msg = serde_json::json!({ "type": "notification", "message": summary, "timestamp": chrono::Utc::now().to_rfc3339() }).to_string();
        let _ = ntf.send(msg);
    });

    Ok(job_id)
}
/// Tool: fetch_agent_result — read a launched sub-agent's report.
pub struct FetchAgentResultTool { pub jobs: SharedJobs }

#[async_trait]
impl Tool for FetchAgentResultTool {
    fn name(&self) -> &str { "fetch_agent_result" }
    fn description(&self) -> &str {
        "Retrieve the report of a previously launched sub-agent by its job_id (from run_agent)."
    }
    fn parameters_schema(&self) -> Value {
        json!({ "type": "object", "properties": { "job_id": { "type": "string", "description": "job_id returned by run_agent" } }, "required": ["job_id"] })
    }
    fn is_builtin(&self) -> bool { true }
    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let job_id = args["job_id"].as_str().unwrap_or("").to_string();
        let j = self.jobs.0.lock().await;
        match j.get(&job_id) {
            Some(s) => Ok(json!({ "job_id": job_id, "status": s.status, "agent": s.agent, "report": s.report, "error": s.error })),
            None => Err(AgentError::tool("fetch_agent_result", format!("Unknown job: {}", job_id))),
        }
    }
}