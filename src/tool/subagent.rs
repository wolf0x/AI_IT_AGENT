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
use crate::tool::{TimeoutStage, Tool, ToolContext};

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

/// Derive a strict reply-language rule for a sub-agent from its task text (same
/// heuristic as the main prompt): CJK -> Chinese, otherwise English. Keeps the
/// sub-agent's reply language consistent with the main session.
fn subagent_language_rule(task: &str) -> String {
    let has_cjk = task.chars().any(|ch| ('\u{4E00}'..='\u{9FFF}').contains(&ch) || ('\u{3400}'..='\u{4DBF}').contains(&ch));
    let lower = task.to_lowercase();
    let explicit_cn = task.contains("中文") && !task.contains("英文");
    let explicit_en = task.contains("英文")
        || (lower.contains("english") && (lower.contains("reply") || lower.contains("respond") || lower.contains("use")));
    if explicit_cn || (has_cjk && !explicit_en) {
        "Write your ENTIRE reply in Chinese (headings, bullets, table cells, greetings and closings included). Do not switch to English or mix languages.".to_string()
    } else {
        "Write your ENTIRE reply in English (headings, bullets, table cells, greetings and closings included). Do not switch to Chinese or mix languages.".to_string()
    }
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
    let language_rule = subagent_language_rule(&task);
    let system_prompt = format!("{}\n\n## LANGUAGE RULE (STRICT)\n{}", def.system_prompt, language_rule);
    // Per-agent Auto-Approve: when enabled, this sub-agent may run ANY tool
    // (incl. shell_exec) without asking — mirrors the CRON auto-approve toggle.
    let preauth = if def.auto_approve {
        let mut profile = crate::managed::permission_profile::PermissionProfile::new(job_id.clone());
        profile.allow_all = true;
        Some(std::sync::Arc::new(profile))
    } else {
        None
    };
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
        let res = runner.run_sub_agent(params, perms, pend, preauth).await;
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
        // Persist the report: write a unique per-job artifact (immune to
        // concurrent overwrites) and also refresh report.md as the "latest".
        let wd_path = std::path::Path::new(&c_workdir);
        let _ = std::fs::create_dir_all(wd_path);
        let report_body = format!("# Sub-agent: {}\n\n{}", c_agent, report);
        let _ = std::fs::write(wd_path.join(format!("report-{}.md", c_job_id)), &report_body);
        let _ = std::fs::write(wd_path.join("report.md"), &report_body);
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
use std::time::{Duration, Instant};
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

/// Tool: wait_agents — block until the listed sub-agent job(s) reach a terminal
/// state, then return all their reports at once so the main loop can write a
/// consolidated final summary. The sub-agents already run concurrently; this
/// call simply waits for the slowest one and returns the aggregated results.
pub struct WaitAgentsTool {
    pub jobs: SharedJobs,
}

#[async_trait]
impl Tool for WaitAgentsTool {
    fn name(&self) -> &str { "wait_agents" }

    fn description(&self) -> &str {
        "Wait for previously launched sub-agent job(s) (job_ids from run_agent) to finish, then return all their reports at once. Call this AFTER dispatching run_agent so the main loop can collect results and write the final consolidated summary. Provide `job_ids` (array of the job_id strings returned by run_agent) and optionally `timeout_secs` (default 240). If the timeout passes before every job finishes, partial results are returned with all_complete=false."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "job_ids": { "type": "array", "items": { "type": "string" }, "description": "job_id(s) returned by run_agent" },
                "timeout_secs": { "type": "integer", "minimum": 1, "description": "Max seconds to wait before returning partial results (default 240)" }
            },
            "required": ["job_ids"]
        })
    }

    fn is_builtin(&self) -> bool { true }

    fn is_read_only(&self) -> bool { true }

    /// Background wait is long-running: no hard wall-clock (Watchdog governs) and
    /// we periodically send progress so the liveness watchdog never fires early.
    fn timeout_stage(&self) -> TimeoutStage { TimeoutStage::Watchdog }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value> {
        let job_ids: Vec<String> = args["job_ids"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        if job_ids.is_empty() {
            return Err(AgentError::tool("wait_agents", "job_ids is required (array of job_id strings from run_agent)"));
        }
        let timeout_secs = args["timeout_secs"].as_u64().unwrap_or(240).max(1);
        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        let progress = ctx.progress_tx();

        loop {
            let (all_done, has_unknown) = {
                let j = self.jobs.0.lock().await;
                let mut all_done = true;
                let mut has_unknown = false;
                for id in &job_ids {
                    match j.get(id) {
                        Some(st) => { if st.status != "done" && st.status != "error" { all_done = false; } }
                        None => { has_unknown = true; }
                    }
                }
                (all_done, has_unknown)
            };
            if all_done || has_unknown || Instant::now() >= deadline { break; }
            if let Some(tx) = &progress {
                let _ = tx.send(format!("Waiting for sub-agent job(s) to finish...")).await;
            }
            tokio::time::sleep(Duration::from_millis(2000)).await;
        }

        let mut results = Vec::new();
        let mut all_complete = true;
        {
            let j = self.jobs.0.lock().await;
            for id in &job_ids {
                match j.get(id) {
                    Some(st) => {
                        if st.status != "done" && st.status != "error" { all_complete = false; }
                        let report = st.report.clone();
                        let report = if report.chars().count() > 6000 {
                            let head: String = report.chars().take(6000).collect();
                            format!("{}
...[report truncated to 6000 chars, job_id={}]", head, id)
                        } else { report };
                        results.push(json!({
                            "job_id": id, "agent": st.agent, "status": st.status,
                            "report": report, "error": st.error
                        }));
                    }
                    None => {
                        all_complete = false;
                        results.push(json!({ "job_id": id, "status": "unknown", "report": "", "error": "unknown job_id (never launched in this process)" }));
                    }
                }
            }
        }
        Ok(json!({ "job_ids": job_ids, "all_complete": all_complete, "results": results }))
    }
}
