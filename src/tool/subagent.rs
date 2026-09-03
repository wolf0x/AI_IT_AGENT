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
/// Internal core: spawn a sub-agent job that is already fully resolved
/// (system prompt, workdir, model, preauth). Shared by `run_agent` (predefined
/// agent), `run_skill` (isolated skill), and the `/agent` WS path. The main
/// session is never blocked; a completion notification is broadcast and the
/// outcome is writable to the main session history when `main_session` is set.
struct FinishGuard(Option<Box<dyn Fn() + Send + Sync>>);
impl Drop for FinishGuard {
    fn drop(&mut self) { if let Some(f) = self.0.take() { f(); } }
}

#[allow(clippy::too_many_arguments)]
async fn launch_job(
    runner: &Arc<Runner>,
    jobs: &SharedJobs,
    notify: &NotifyTx,
    permissions: &Arc<Mutex<HashMap<String, bool>>>,
    pending: &PendingMap,
    max_iter: usize, rh: usize, ctxwin: usize, ctxthr: usize, to: usize, retr: usize,
    job_id: String,
    agent_display: String,
    task: String,
    system_prompt: String,
    workdir: String,
    model: String,
    preauth: Option<std::sync::Arc<crate::managed::permission_profile::PermissionProfile>>,
    // Optional main-session id + sessions store: inject the sub-agent's outcome
    // into the main session history so the main LLM sees it on subsequent turns.
    main_session: Option<String>,
    sessions: Option<Arc<Mutex<std::collections::HashMap<String, Vec<ChatMessage>>>>>,
    // Optional callback run when the job finishes (e.g. release a concurrency
    // slot). Runs on drop regardless of success/failure.
    on_finish: Option<Box<dyn Fn() + Send + Sync>>,
) {
    {
        let mut j = jobs.0.lock().await;
        j.insert(job_id.clone(), SubJobState { job_id: job_id.clone(), agent: agent_display.clone(), status: "running".into(), report: String::new(), error: String::new() });
    }
    let runner = runner.clone();
    let perms = permissions.clone();
    let pend = pending.clone();
    let jobs2 = jobs.clone();
    let ntf = notify.clone();
    let c_job_id = job_id;
    let c_agent = agent_display;
    let c_workdir = workdir;
    tokio::spawn(async move {
        let _guard = FinishGuard(on_finish);
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
}

/// Launch a predefined sub-agent as an isolated background job. Resolves the
/// agent definition (system prompt / workdir / model / auto-approve), then
/// delegates to [`launch_job`]. Returns the job_id; the main session is not
/// blocked. Shared by the `run_agent` tool and the `/agent` WS command path.
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
    // (incl. shell_exec) without asking -- mirrors the CRON auto-approve toggle.
    let preauth = if def.auto_approve {
        let mut profile = crate::managed::permission_profile::PermissionProfile::new(job_id.clone());
        profile.allow_all = true;
        Some(std::sync::Arc::new(profile))
    } else {
        None
    };
    let workdir = def.workdir.clone();
    launch_job(runner, jobs, notify, permissions, pending,
        max_iter, rh, ctxwin, ctxthr, to, retr,
        job_id.clone(), agent_display, task, system_prompt, workdir, model,
        preauth, main_session, sessions, None).await;
    Ok(job_id)
}

/// Launch an isolated skill as a sub-agent job: the skill's SKILL.md body
/// becomes the sub-agent's instructions plus a compact return contract, and
/// the sub-agent runs in its own clean session with a dedicated working
/// directory. This is the `isolated` job-skill pattern (thClaws blueprint) --
/// nested skills run to completion in their own context and only return a
/// compact result. Unlike `run_agent`, skill sub-agents are **not**
/// auto-approved: they inherit the main session's permission posture.
/// Concurrency is gated (and thereby recursion depth is bounded) by
/// `max_concurrent`.
/// Atomically acquire one concurrency slot for an isolated skill job.
/// Returns Err when the `max` concurrent slots are all held. Extracted as a
/// standalone function so the gate can be verified deterministically in tests.
fn try_acquire_skill_slot(active: &std::sync::atomic::AtomicUsize, max: usize) -> Result<(), String> {
    loop {
        let cur = active.load(Ordering::SeqCst);
        if cur >= max {
            return Err(format!(
                "run_skill concurrency limit ({}) reached; wait for a running skill job and retry.",
                max
            ));
        }
        if active
            .compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Ok(());
        }
    }
}

pub async fn launch_skill_job(
    runner: &Arc<Runner>,
    jobs: &SharedJobs,
    notify: &NotifyTx,
    permissions: &Arc<Mutex<HashMap<String, bool>>>,
    pending: &PendingMap,
    max_iter: usize, rh: usize, ctxwin: usize, ctxthr: usize, to: usize, retr: usize,
    default_model: &str,
    skill: crate::skill::types::Skill,
    task: &str,
    workdir_root: &std::path::Path,
    active_jobs: &Arc<AtomicUsize>,
    max_concurrent: usize,
) -> Result<String, String> {
    let task = task.trim().to_string();
    if task.is_empty() { return Err("task is required".to_string()); }
    let name = skill.metadata.name.clone();

    // Concurrency gate (also bounds nested recursion depth). Atomic CAS so
    // concurrent callers cannot overshoot the cap.
    try_acquire_skill_slot(active_jobs, max_concurrent)?;

    let job_id = format!("sub-{}", uuid::Uuid::new_v4());
    let language_rule = subagent_language_rule(&task);
    let body = skill.body().into_owned();
    let system_prompt = format!("{}{}\n\n## LANGUAGE RULE (STRICT)\n{}", body, ISOLATED_SKILL_RETURN_CONTRACT, language_rule);
    let workdir = workdir_root.join(sanitize_workdir(&name)).to_string_lossy().to_string();

    // Release the concurrency slot when the job finishes (ran on drop).
    let release = active_jobs.clone();
    let on_finish: Box<dyn Fn() + Send + Sync> = Box::new(move || { release.fetch_sub(1, Ordering::SeqCst); });
    launch_job(runner, jobs, notify, permissions, pending,
        max_iter, rh, ctxwin, ctxthr, to, retr,
        job_id.clone(), format!("skill:{}", name), task, system_prompt, workdir,
        default_model.to_string(), None, None, None, Some(on_finish)).await;
    Ok(job_id)
}

/// Compact-return contract appended to an isolated skill sub-agent so its
/// result stays small in the caller's context -- the whole point of running
/// isolated is that the main conversation gets the result, not every step.
const ISOLATED_SKILL_RETURN_CONTRACT: &str = "\n\n---\n# Isolated skill run -- return contract\nYou are running this skill as an isolated job in your own context; the caller sees ONLY your final message, not your intermediate steps. When done, reply with a COMPACT result: the path(s) of any files you produced, a one-line status, and any fields you could not fill. Do NOT echo file contents or paste large outputs -- keep the result small.";

/// Sanitize a skill name into a safe single-segment working-directory name.
fn sanitize_workdir(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }).collect()
}

use std::time::{Duration, Instant};
/// Tool: fetch_agent_result — read a launched sub-agent's report.
/// Tool: run_skill — launch an isolated skill as a background sub-agent job.
/// Mirrors the thClaws `isolated` job-skill pattern: the skill's SKILL.md body
/// becomes the sub-agent's instructions plus a compact return contract; the sub-
/// agent runs in its own clean session + dedicated working directory, and only
/// the compact final result returns to the caller (via `fetch_agent_result` /
/// `wait_agents`). Skill sub-agents are NOT auto-approved (inherit main posture).
pub struct RunSkillTool {
    pub skill_manager: Arc<crate::skill::SkillManager>,
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
    pub workdir_root: std::path::PathBuf,
    pub max_concurrent_jobs: usize,
    pub active_jobs: Arc<AtomicUsize>,
}

#[async_trait]
impl Tool for RunSkillTool {
    fn name(&self) -> &str { "run_skill" }

    fn description(&self) -> &str { "Launch an installed skill as an isolated sub-agent in the background. Provide 'skill' (name) and 'task' (what it should do / its inputs). The skill runs in its own clean session with a dedicated working directory; only a compact result returns. Use fetch_agent_result(job_id) or wait_agents() to read the finished result. Skill sub-agents inherit the main session's permission posture and are not auto-approved." }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "skill": { "type": "string", "description": "Name of the installed skill to run (e.g. 'ProcessAnalysis')" },
                "task": { "type": "string", "description": "Task for the skill, including inputs and desired output" }
            },
            "required": ["skill", "task"]
        })
    }

    fn is_builtin(&self) -> bool { true }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let name = args["skill"].as_str().unwrap_or("").trim();
        let task = args["task"].as_str().unwrap_or("").trim();
        if name.is_empty() { return Err(AgentError::tool("run_skill", "skill is required")); }
        if task.is_empty() { return Err(AgentError::tool("run_skill", "task is required")); }
        let skill = self.skill_manager.find_skill(name)
            .ok_or_else(|| AgentError::tool("run_skill", format!("Skill not found: {} (use list_skills to see available skills)", name)))?;
        let job_id = launch_skill_job(
            &self.runner, &self.jobs, &self.notify_tx,
            &self.permissions, &self.permission_pending,
            self.max_iterations.load(Ordering::SeqCst),
            self.rabbit_hole_threshold.load(Ordering::SeqCst),
            self.context_window,
            self.context_window_threshold.load(Ordering::SeqCst),
            self.tool_timeout_secs.load(Ordering::SeqCst),
            self.max_tool_retries.load(Ordering::SeqCst),
            &self.default_model,
            skill, task, &self.workdir_root,
            &self.active_jobs, self.max_concurrent_jobs,
        ).await.map_err(|e| AgentError::tool("run_skill", e))?;
        Ok(json!({
            "job_id": job_id,
            "status": "started",
            "skill": name,
            "note": "Skill runs as an isolated sub-agent in the background; use fetch_agent_result(job_id) or wait_agents() for the result."
        }))
    }
}

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
        let report_cap = ctx.inline_limit(15_000);
        {
            let j = self.jobs.0.lock().await;
            for id in &job_ids {
                match j.get(id) {
                    Some(st) => {
                        if st.status != "done" && st.status != "error" { all_complete = false; }
                        let report = st.report.clone();
                        let report = if report.chars().count() > report_cap {
                            let head: String = report.chars().take(report_cap).collect();
                            format!("{}
...[report truncated to {} chars, job_id={}]", head, report_cap, id)
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


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Deterministic verification of the run_skill concurrency gate: no more
    // than `max` slots are ever granted, and the 5th acquirer is rejected.
    #[test]
    fn skill_slot_acquire_respects_cap() {
        let active = AtomicUsize::new(0);
        for _ in 0..4 {
            assert!(try_acquire_skill_slot(&active, 4).is_ok(), "first 4 slots must be granted");
        }
        assert_eq!(active.load(Ordering::SeqCst), 4);
        let err = try_acquire_skill_slot(&active, 4).unwrap_err();
        assert!(err.contains("concurrency limit"), "5th acquire must be rejected, got: {}", err);
        assert_eq!(active.load(Ordering::SeqCst), 4, "rejected acquire must not bump the counter");
    }

    // Releasing one slot (what the FinishGuard drop does) makes a later
    // acquire succeed again -- the gate is not permanently welded shut.
    #[test]
    fn skill_slot_release_allows_reacquire() {
        let active = AtomicUsize::new(0);
        for _ in 0..4 {
            assert!(try_acquire_skill_slot(&active, 4).is_ok());
        }
        assert!(try_acquire_skill_slot(&active, 4).is_err());
        active.fetch_sub(1, Ordering::SeqCst); // simulate FinishGuard drop
        assert!(try_acquire_skill_slot(&active, 4).is_ok(), "slot released by job finish must be reusable");
        assert_eq!(active.load(Ordering::SeqCst), 4);
    }

    // CAS must not overshoot under many racing acquirers: exactly `max`
    // succeed and the rest fail, counter never exceeds `max`.
    #[test]
    fn skill_slot_race_never_overshoots() {
        let active = std::sync::Arc::new(AtomicUsize::new(0));
        let max = 4usize;
        let mut handles = Vec::new();
        for _ in 0..32 {
            let a = active.clone();
            handles.push(std::thread::spawn(move || try_acquire_skill_slot(&a, max)));
        }
        let mut ok = 0usize;
        for h in handles {
            if h.join().unwrap().is_ok() { ok += 1; }
        }
        assert_eq!(ok, max, "exactly max=4 acquirers must win regardless of race order");
        assert!(active.load(Ordering::SeqCst) <= max);
    }
}
