//! ManagedRunner — outer orchestration loop for long-horizon tasks.
//!
//! The ManagedRunner wraps the existing `Runner::run` and adds the Manager-Executor
//! pattern. Each round:
//! 1. Manager plans the next subtask (fresh context, only TaskContract)
//! 2. Executor runs the subtask (existing agent loop with condensed brief)
//! 3. [Phase 4] Auditor verifies results
//! 4. TaskContract is updated with verified state
//!
//! This module is the integration point between the managed architecture and
//! the existing agent infrastructure.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;
use tracing::{info, warn, error};

use super::auditor::Auditor;
use super::manager::{self, ManagerRoute};
use super::permission_profile::PermissionProfile;
use super::task_contract::{IrPhase, TaskContract, VerifiedFinding};
use crate::agent::{AgentEvent, EventStream};
use crate::blackboard::{Blackboard, BlackboardEntry};
use crate::error::AgentResult;
use crate::memory::MemoryStore;
use crate::model::openai::OpenAiProvider;
use crate::permission::PendingMap;
use crate::runner::Runner;
use crate::skill::SkillManager;
use crate::tool::ToolRegistry;

/// The ManagedRunner orchestrates long-horizon tasks using the Manager-Executor pattern.
pub struct ManagedRunner {
    /// The underlying runner for Executor rounds.
    inner: Arc<Runner>,
    /// LLM provider for Manager rounds.
    provider: Arc<OpenAiProvider>,
    /// Model to use for Manager planning.
    manager_model: String,
    /// Maximum Manager rounds.
    max_rounds: usize,
    /// Memory store for TaskContract persistence (crash recovery).
    memory_store: Arc<MemoryStore>,
    /// Shared tool registry for the Auditor (read-only verification).
    tools: Arc<tokio::sync::RwLock<ToolRegistry>>,
    /// Working directory for Auditor tool execution.
    working_dir: String,
    /// Workspace directory for Auditor artifact checks.
    workspace_dir: String,
    /// Max iterations per Executor subtask round.
    max_executor_iterations: usize,
    /// Rabbit-hole detection threshold for Executor rounds.
    rabbit_hole_threshold: usize,
    /// Model context window for Executor rounds.
    context_window: usize,
    /// Tool execution timeout for Executor rounds.
    tool_timeout_secs: u64,
    /// Max automatic tool retries for Executor rounds.
    max_tool_retries: usize,
    /// Skill manager for injecting matched skills into Executor briefs.
    skill_manager: Arc<SkillManager>,
    /// Computer Use availability flag (shared with server; used for GUI-channel
    /// auto-enable with a user opt-in window).
    computer_use_enabled: Arc<AtomicBool>,
    /// Whether to share Instant mode context with Expert mode via Blackboard.
    share_blackboard_enabled: Arc<AtomicBool>,
}

impl ManagedRunner {
    /// Create a new ManagedRunner.
    pub fn new(
        inner: Arc<Runner>,
        provider: Arc<OpenAiProvider>,
        manager_model: String,
        max_rounds: usize,
        memory_store: Arc<MemoryStore>,
        tools: Arc<tokio::sync::RwLock<ToolRegistry>>,
        working_dir: String,
        workspace_dir: String,
        max_executor_iterations: usize,
        rabbit_hole_threshold: usize,
        context_window: usize,
        tool_timeout_secs: u64,
        max_tool_retries: usize,
        skill_manager: Arc<SkillManager>,
        computer_use_enabled: Arc<AtomicBool>,
        share_blackboard_enabled: Arc<AtomicBool>,
    ) -> Self {
        Self {
            inner,
            provider,
            manager_model,
            max_rounds,
            memory_store,
            tools,
            working_dir,
            workspace_dir,
            max_executor_iterations,
            rabbit_hole_threshold,
            context_window,
            tool_timeout_secs,
            max_tool_retries,
            skill_manager,
            computer_use_enabled,
            share_blackboard_enabled,
        }
    }

    /// Run a managed task.
    ///
    /// This method implements the Manager-Executor loop:
    /// 1. Create initial TaskContract from user message
    /// 2. Loop:
    ///    a. Manager plans next subtask
    ///    b. Executor runs subtask with fresh context
    ///    c. [Phase 4] Auditor verifies artifacts
    ///    d. TaskContract updated with verified findings + manager notes
    /// 3. Return final results
    ///
    /// The ManagedRunner reads the Blackboard directly to seed the TaskContract
    /// with Instant-mode context (original task + work summary). This replaces
    /// the old seed_context parameter that required the caller to pre-process
    /// session history.
    pub async fn run(
        &self,
        user_message: &str,
        session_id: &str,
        model_name: &str,
        scope: &str,
        permissions: Arc<Mutex<std::collections::HashMap<String, bool>>>,
        permission_pending: PendingMap,
        cancelled: Arc<AtomicBool>,
    ) -> AgentResult<EventStream> {
        info!("[managed:{}] Starting managed task (max_rounds: {})", session_id, self.max_rounds);

        // ── Fix 1: Resume existing active TaskContract (if any) ──
        // When the user clicks STOP and sends a new message, we resume the
        // previous contract instead of creating a blank one. This preserves
        // verified_findings, manager_notes, open_leads, and the round counter.
        let (contract_id, mut contract, resumed) = match self.memory_store.get_latest_active_contract(session_id) {
            Ok(Some((id, json))) => {
                match TaskContract::from_json(&json) {
                    Ok(mut c) => {
                        let round = c.current_round;
                        info!("[managed:{}] Resuming existing TaskContract {} from round {}",
                              session_id, &id[..8.min(id.len())], round);
                        // Clear the USER_STOPPED marker so normal lifecycle resumes.
                        c.blocked_reason = None;
                        // Also clear the SQL column so future persists don't carry the marker.
                        self.memory_store.clear_contract_stopped(&id);
                        // Append user's new message as a manager note so the Manager
                        // sees the updated instruction (e.g., "一个一个的完成").
                        c.manager_notes.push(format!("[User Resume] {}", user_message));
                        // Cap manager notes
                        if c.manager_notes.len() > 20 {
                            let overflow = c.manager_notes.len() - 20;
                            c.manager_notes.drain(0..overflow);
                        }
                        (id, c, true)
                    }
                    Err(e) => {
                        warn!("[managed:{}] Failed to deserialize existing contract, creating new: {}", session_id, e);
                        let new_id = uuid::Uuid::new_v4().to_string();
                        (new_id.clone(), TaskContract::new(new_id, user_message.to_string(), scope.to_string(), self.max_rounds), false)
                    }
                }
            }
            _ => {
                // No active contract — create a new one
                let contract_id = uuid::Uuid::new_v4().to_string();
                let contract = TaskContract::new(
                    contract_id.clone(),
                    user_message.to_string(),
                    scope.to_string(),
                    self.max_rounds,
                );
                (contract_id, contract, false)
            }
        };

        // ── Seed TaskContract from Blackboard (Instant-mode context) ──
        // Only for NEW contracts — resumed contracts already have this context.
        // Note: We use the current user_message as original_task, NOT the Blackboard's
        // original_task (which may be stale from previous Instant mode conversations).
        // Blackboard context is added as manager_notes for additional context only.
        // Only inject if share_blackboard_enabled is true.
        if !resumed && self.share_blackboard_enabled.load(std::sync::atomic::Ordering::SeqCst) {
            if let Ok(Some(json)) = self.memory_store.load_blackboard(session_id) {
                if let Ok(bb) = crate::blackboard::Blackboard::from_json(&json) {
                    let entries = bb.get_entries_by_source("instant");
                    if !entries.is_empty() {
                        let context_summary = bb.to_context_string(Some("instant"));
                        if !context_summary.trim().is_empty() {
                            info!("[managed:{}] Seeded TaskContract from Blackboard ({} entries, {} chars)",
                                  session_id, entries.len(), context_summary.len());
                            // DO NOT overwrite original_task — keep the current user_message
                            // contract.original_task = original_task.to_string(); // REMOVED
                            // Add clear warning that this context may not be relevant
                            contract.manager_notes.push(format!(
                                "[Pre-Expert Mode Work History — WARNING: This is Instant mode history, may NOT be relevant to current task. Use your own judgment.]\n{}", 
                                context_summary
                            ));
                        }
                    }
                }
            }
        }

        // Create the event stream channel
        let (tx, rx) = tokio::sync::mpsc::channel::<AgentResult<AgentEvent>>(200);

        // ── Phase 6: Permission pre-authorization profile for this task ──
        // Uses the IR containment profile so unattended containment actions can
        // proceed without blocking on human approval. Destructive actions are
        // never pre-authorized (safety interlock preserved).
        let permission_profile = std::sync::Arc::new(PermissionProfile::ir_containment(contract_id.clone()));

        // ── Phase 4: Auditor for independent verification ──
        // F6: Enable LLM-based semantic verification (deterministic checks always
        // run first; semantic artifacts additionally get LLM interpretation).
        let auditor = Auditor::new(
            self.tools.clone(),
            self.working_dir.clone(),
            self.workspace_dir.clone(),
        )
        .with_llm(
            self.provider.clone(),
            model_name.to_string(),
            8000, // auditor_context_chars budget
        );

        // ── Persist initial TaskContract for crash recovery ──
        if let Ok(json) = contract.to_json() {
            let _ = self.memory_store.save_task_contract(
                &contract_id, session_id, &json,
                &format!("{:?}", contract.phase).to_lowercase(),
                contract.current_round,
            );
        }

        let provider = self.provider.clone();
        let manager_model = self.manager_model.clone();
        let inner = self.inner.clone();
        let model = model_name.to_string();
        let session = session_id.to_string();
        let permissions = permissions.clone();
        let permission_pending = permission_pending.clone();
        let memory_store = self.memory_store.clone();
        // Executor round configuration (from server settings — not hardcoded).
        let max_executor_iterations = self.max_executor_iterations;
        let rabbit_hole_threshold = self.rabbit_hole_threshold;
        let context_window = self.context_window;
        let tool_timeout_secs = self.tool_timeout_secs;
        let max_tool_retries = self.max_tool_retries;
        let skill_manager = self.skill_manager.clone();
        let workspace_dir = self.workspace_dir.clone();
        let computer_use_enabled = self.computer_use_enabled.clone();
        // Direct registry access for GUI-channel auto-enable (register cu_* tools).
        let tools = self.tools.clone();
        // Move auditor + permission profile into the spawned task for post-Executor
        // verification and pre-authorization consultation (Phase 6).

        // Spawn the managed loop
        // Fix 3: cancelled flag is checked at every round start so STOP
        // propagates from the WebSocket handler into the spawned task.
        let cancelled_flag = cancelled.clone();
        tokio::spawn(async move {
            let mut round = if resumed { contract.current_round } else { 0usize };
            // F10: human-gate tracking — consecutive rounds with no new verified
            // findings trigger an intervention notice instead of silent looping.
            let mut stale_rounds: usize = 0;
            let mut last_finding_count: usize = 0;
            // F5: per-round archive directory for audit trail.
            let archive_dir = std::path::Path::new(&workspace_dir)
                .join("output").join("managed").join(&contract_id);
            let _ = std::fs::create_dir_all(&archive_dir);

            loop {
                // ── Fix 3: Check cancellation before each round ──
                if cancelled_flag.load(Ordering::SeqCst) {
                    info!("[managed:{}] STOP detected at round {}, contract already persisted by server", session, round + 1);
                    let _ = tx.send(Ok(AgentEvent::text(
                        &format!("\n\n*[Expert mode stopped at round {} — progress saved, send a message to resume]*\n\n", round + 1),
                        &contract_id, "manager"
                    ))).await;
                    // Do NOT persist here — the server already set the USER_STOPPED
                    // marker and persisted the contract. Persisting here could
                    // overwrite the marker with the old blocked_reason.
                    break;
                }

                // ── F10: Human gate — repeated rounds with zero new findings ──
                if contract.verified_findings.len() == last_finding_count {
                    stale_rounds += 1;
                } else {
                    stale_rounds = 0;
                    last_finding_count = contract.verified_findings.len();
                }
                if stale_rounds >= 3 {
                    info!("[managed:{}] Human gate: {} consecutive rounds without new findings", session, stale_rounds);
                    let _ = tx.send(Ok(AgentEvent::text(
                        "\n\n⚠️ *[需要人工介入] 连续 3 轮未产生新的已验证发现。任务已标记 blocked——请检查当前策略或提供新指令。*\n\n",
                        &contract_id, "manager"
                    ))).await;
                    contract.block("No progress after 3 consecutive rounds without new verified findings".to_string());
                    persist_contract(&memory_store, &contract_id, &session, &contract);
                    break;
                }

                if round >= contract.max_rounds {
                    warn!("[managed:{}] Max rounds reached ({})", session, contract.max_rounds);
                    let _ = tx.send(Ok(AgentEvent::text(
                        &format!("\n\n*[Managed task reached maximum rounds ({})]*\n\n", contract.max_rounds),
                        &contract_id, "manager"
                    ))).await;
                    break;
                }

                info!("[managed:{}] Round {} starting", session, round + 1);

                // ── Manager Round ──
                // Plan A: pass skills catalog so Manager knows which skills exist
                let skills = skill_manager.list();
                let plan = match manager::plan_next(&provider, &manager_model, &contract, &skills).await {
                    Ok(plan) => plan,
                    Err(e) => {
                        error!("[managed:{}] Manager planning failed: {}", session, e);
                        let _ = tx.send(Ok(AgentEvent::text(
                            &format!("\n\n*[Manager planning failed: {}]*\n\n", e),
                            &contract_id, "manager"
                        ))).await;
                        break;
                    }
                };

                info!("[managed:{}] Manager plan: route={:?}, subtask={}", session, plan.route, 
                      plan.subtask.chars().take(100).collect::<String>());

                // Send Manager plan to UI
                let plan_event = format!(
                    "\n\n## 🧭 Manager Plan (Round {})\n**Subtask**: {}\n**Success Criteria**: {}\n**Route**: {:?}\n\n",
                    round + 1, plan.subtask, plan.success_criteria, plan.route
                );
                let _ = tx.send(Ok(AgentEvent::text(&plan_event, &contract_id, "manager"))).await;

                // Check route before executing
                match &plan.route {
                    ManagerRoute::Done => {
                        // F1: Done guard — the completion decision belongs to the
                        // Auditor, not the Manager. If zero findings have been
                        // verified, reject the Done claim and feed back a synthetic
                        // audit note so the Manager continues with concrete work.
                        if contract.verified_findings.is_empty() {
                            warn!("[managed:{}] Done guard: Manager claimed Done with zero verified findings — rejected", session);
                            let _ = tx.send(Ok(AgentEvent::text(
                                "\n\n*[Audit Guard] Manager 声称任务完成，但当前没有任何已验证发现。\
                                 完成申请被驳回——请继续安排具体的工具执行工作。*\n\n",
                                &contract_id, "manager"
                            ))).await;
                            contract.manager_notes.push(
                                "[Audit Guard] Manager claimed Done with zero verified findings. \
                                 Rejected — continue with concrete tool work.".to_string()
                            );
                            round += 1;
                            continue;
                        }
                        let _ = tx.send(Ok(AgentEvent::text(
                            "\n\n*[Manager: Task complete]*\n\n",
                            &contract_id, "manager"
                        ))).await;
                        contract.complete();
                        // Persist the final state but do NOT delete — the user may
                        // want to resume or review the contract later.
                        persist_contract(&memory_store, &contract_id, &session, &contract);
                        break;
                    }
                    ManagerRoute::Blocked(reason) => {
                        let _ = tx.send(Ok(AgentEvent::text(
                            &format!("\n\n*[Manager: Task blocked — {}]*\n\n", reason),
                            &contract_id, "manager"
                        ))).await;
                        contract.block(reason.clone());
                        // Persist the blocked state so it survives a restart for resume.
                        persist_contract(&memory_store, &contract_id, &session, &contract);
                        break;
                    }
                    ManagerRoute::Invalid(reason) => {
                        warn!("[managed:{}] Invalid manager plan: {}", session, reason);
                        round += 1;
                        continue;
                    }
                    ManagerRoute::Continue => { /* proceed to executor */ }
                }

                // ── Executor Round ──
                // Advance phase (forward-only) before the Executor runs so the
                // brief reflects the phase the subtask belongs to.
                if let Some(p) = plan.phase {
                    if phase_rank(p) > phase_rank(contract.phase) {
                        info!("[managed:{}] Advancing phase: {:?} -> {:?}", session, contract.phase, p);
                        contract.advance_phase(p);
                    }
                }

                // Build the condensed brief for the Executor
                let brief = contract.executor_brief(&plan.subtask, &plan.success_criteria);

                // Plan C: pre-match skills against brief + original task and inject
                // matched skill content directly into the brief so the Executor
                // has the skill workflow available without fuzzy matching.
                let brief = {
                    let matching_context = format!("{} {}", contract.original_task, plan.subtask);
                    let matched = skill_manager.find_matching(&matching_context);
                    if matched.is_empty() {
                        brief
                    } else {
                        let mut enriched = brief;
                        enriched.push_str("\n\n## Active Skills (pre-matched for this subtask)\n");
                        enriched.push_str(
                            "The following skill(s) matched this subtask. Follow their \
                             workflows directly — no need to load them via file_read.\n\n"
                        );
                        for (content, score) in &matched {
                            info!("[managed:{}] Injecting matched skill (score {:.3}) into Executor brief", session, score);
                            enriched.push_str(content);
                            enriched.push('\n');
                        }
                        enriched
                    }
                };

                // ── Channel routing: inject execution-channel guidance into the brief ──
                // F8: gui channel ensures computer_use is available (30s user window,
                // auto-enable on timeout); ask channel tells the Executor to request
                // human input instead of terminating the round.
                let brief = match plan.channel.as_str() {
                    "gui" => {
                        ensure_gui_channel(&tx, &contract_id, &session, &computer_use_enabled, &tools, &cancelled_flag).await;
                        let mut b = brief;
                        b.push_str(
                            "\n\n## Execution Channel: GUI\n\
                             本轮任务必须通过 GUI 工具完成——优先使用 browser_skill（用户真实浏览器）\
                             或 computer_use 工具（cu_screenshot / cu_mouse / cu_keyboard 等桌面控制）。\
                             不要尝试用 shell_exec 或 curl 代替 GUI 交互。\n"
                        );
                        b
                    }
                    "ask" => {
                        let mut b = brief;
                        b.push_str(
                            "\n\n## Execution Channel: ASK\n\
                             本轮需要用户输入才能继续。完成可做的准备工作后，\
                             明确说明需要用户提供什么，并调用 request_help 等待用户。\n"
                        );
                        b
                    }
                    _ => {
                        let mut b = brief;
                        b.push_str(
                            "\n\n## Execution Channel: CLI\n\
                             本轮优先使用命令行/工具执行（shell_exec、ir_*、file_* 等）。\n"
                        );
                        b
                    }
                };

                info!("[managed:{}] Executor starting with brief ({} chars)", session, brief.len());

                // Run the Executor with the brief as the user message
                // This uses the existing agent loop with fresh context
                let executor_result = inner.run(
                    &brief,
                    &format!("{}-exec-{}", session, round),
                    &model,
                    max_executor_iterations,
                    vec![], // fresh history for each Executor round
                    permissions.clone(),
                    permission_pending.clone(),
                    Some(permission_profile.clone()), // Phase 6 pre-authorization profile
                    None, // no fallback model
                    rabbit_hole_threshold,
                    context_window,
                    80,   // context window threshold
                    tool_timeout_secs,
                    max_tool_retries,
                    vec![], // no images
                    None, None, // no checkpoint resume
                ).await;

                let mut executor_output = String::new();
                // ── Tool-call trace (per-round): pair ToolCall/ToolResult events
                // by call_id and record name, args, duration, result preview.
                // Written to round_dir/tool_calls.jsonl by the F5 archive step.
                let mut tool_trace: Vec<String> = Vec::new();
                let mut pending_calls: std::collections::HashMap<String, (String, serde_json::Value, std::time::Instant)> =
                    std::collections::HashMap::new();
                match executor_result {
                    Ok(mut stream) => {
                        // Forward Executor events to the main stream and capture the
                        // assistant's final text for the TaskContract.
                        use futures::StreamExt;
                        while let Some(result) = stream.next().await {
                            // Do NOT forward the Executor's Done event — it would
                            // cause server.rs to break the event loop prematurely.
                            if matches!(&result, Ok(AgentEvent::Done { .. })) {
                                continue;
                            }
                            // Record tool-call start.
                            if let Ok(AgentEvent::ToolCall { name, call_id, args, .. }) = &result {
                                pending_calls.insert(call_id.clone(), (name.clone(), args.clone(), std::time::Instant::now()));
                            }
                            // Record tool-call completion (paired by call_id).
                            if let Ok(AgentEvent::ToolResult { name, call_id, result, .. }) = &result {
                                // Check if result contains an error field (JSON structure check)
                                let ok = result.get("error").is_none();
                                if let Some((start_name, args, start_ts)) = pending_calls.remove(call_id) {
                                    let duration_ms = start_ts.elapsed().as_millis();
                                    let args_str = serde_json::to_string(&args).unwrap_or_default();
                                    let result_str = serde_json::to_string(result).unwrap_or_default();
                                    let line = serde_json::json!({
                                        "ts": chrono::Utc::now().to_rfc3339(),
                                        "tool": start_name,
                                        "args": args_str.chars().take(200).collect::<String>(),
                                        "duration_ms": duration_ms,
                                        "result_preview": result_str.chars().take(300).collect::<String>(),
                                        "ok": ok,
                                    }).to_string();
                                    tool_trace.push(line);
                                } else {
                                    // Result without a recorded start (e.g. stream began mid-call).
                                    let result_str = serde_json::to_string(result).unwrap_or_default();
                                    let line = serde_json::json!({
                                        "ts": chrono::Utc::now().to_rfc3339(),
                                        "tool": name,
                                        "args": "",
                                        "duration_ms": 0,
                                        "result_preview": result_str.chars().take(300).collect::<String>(),
                                        "ok": ok,
                                    }).to_string();
                                    tool_trace.push(line);
                                }
                            }
                            if let Ok(AgentEvent::TextDelta { content, .. }) = &result {
                                executor_output.push_str(content);
                            }
                            let _ = tx.send(result).await;
                        }
                        info!("[managed:{}] Executor round {} completed", session, round + 1);
                    }
                    Err(e) => {
                        error!("[managed:{}] Executor round failed: {}", session, e);
                        let _ = tx.send(Ok(AgentEvent::text(
                            &format!("\n\n*[Executor failed: {}]*\n\n", e),
                            &contract_id, "manager"
                        ))).await;
                    }
                }

                // ── F7: Crash-pattern scan ──
                // Detect common agent/tool crash signatures in Executor output and
                // escalate to a human-gate instead of silently looping.
                {
                    let lower = executor_output.to_lowercase();
                    let crash_markers = ["traceback", "agent_exit", "connection error", "panic:", "segmentation fault"];
                    if crash_markers.iter().any(|m| lower.contains(m)) {
                        warn!("[managed:{}] Crash pattern detected in Executor output (round {})", session, round + 1);
                        let _ = tx.send(Ok(AgentEvent::text(
                            "\n\n⚠️ *[崩溃检测] Executor 输出包含崩溃特征（Traceback/Connection error 等）。\
                              任务已标记 blocked，建议人工介入或更换策略。*\n\n",
                            &contract_id, "manager"
                        ))).await;
                        contract.block(format!("Crash pattern detected in Executor output at round {}", round + 1));
                        persist_contract(&memory_store, &contract_id, &session, &contract);
                        break;
                    }
                }

                // ── Phase 4: Auditor verification + TaskContract update ──
                // Verify each expected evidence path; verified artifacts become
                // findings, failed ones become structured open leads + notes.
                let mut round_audits = Vec::new();
                if !plan.expected_evidence.trim().is_empty() {
                    for item in plan.expected_evidence.split(|c| c == ',' || c == '\n') {
                        let mut path = item.trim();
                        // Strip bullet markers if the Manager listed items with "- " / "* ".
                        if let Some(stripped) = path.strip_prefix("- ").or_else(|| path.strip_prefix("* ")) {
                            path = stripped.trim();
                        }
                        if path.is_empty() {
                            continue;
                        }
                        let audit = auditor.verify_artifact(path, None).await;
                        round_audits.push(serde_json::json!({
                            "path": path,
                            "verified": audit.verified,
                            "status": audit.status,
                            "integrity": audit.integrity,
                            "evidence": audit.evidence.chars().take(300).collect::<String>(),
                            "failure_reason": audit.failure_reason,
                        }));
                        if audit.verified {
                            contract.add_finding(VerifiedFinding {
                                id: uuid::Uuid::new_v4().to_string(),
                                title: format!("Evidence collected: {}", path),
                                severity: "info".to_string(),
                                status: audit.status.clone(),
                                integrity_status: audit.integrity.clone(),
                                evidence_summary: audit.evidence,
                                evidence_path: Some(path.to_string()),
                                mitre_technique: None,
                                verified_at: chrono::Utc::now(),
                                round_index: round,
                            });
                        } else {
                            let reason = audit.failure_reason
                                .unwrap_or_else(|| "verification failed".to_string());
                            // F3: failed evidence becomes a structured open lead (pending)
                            // so the Manager sees an actionable unresolved item.
                            contract.add_lead(
                                &format!("Evidence '{}' not verified", path),
                                &reason,
                            );
                            contract.manager_notes.push(format!(
                                "Round {}: evidence '{}' not verified: {}",
                                round + 1, path, reason
                            ));
                        }
                    }
                }

                // Record a bounded summary of the Executor's output as a manager note
                // so the next Manager round can see what happened.
                let summary: String = executor_output.chars().take(800).collect();
                if !summary.trim().is_empty() {
                    contract.manager_notes.push(format!("Round {}: {}", round + 1, summary.trim()));
                }
                // Cap manager notes to the 20 most recent to bound contract size.
                if contract.manager_notes.len() > 20 {
                    let overflow = contract.manager_notes.len() - 20;
                    contract.manager_notes.drain(0..overflow);
                }

                // Record the completed round so a resume after STOP starts at the
                // NEXT round instead of re-running the just-completed one. current_round
                // is a count of finished rounds (also drives the Manager/Executor
                // "Round N" display via current_round + 1).
                contract.current_round = round + 1;

                // ── F5: Per-round archive (audit trail, re-playable) ──
                // Each round writes plan / executor output / audit report / state
                // snapshot to output/managed/<contract>/round_N/. SQLite remains
                // the recovery source; this directory is the audit archive.
                {
                    let round_dir = archive_dir.join(format!("round_{:03}", round + 1));
                    let _ = std::fs::create_dir_all(&round_dir);
                    let _ = std::fs::write(
                        round_dir.join("plan.md"),
                        format!(
                            "# Manager Plan (Round {})\n\n**Subtask**: {}\n\n**Success Criteria**: {}\n\n**Expected Evidence**: {}\n\n**Route**: {:?}\n\n**Channel**: {}\n",
                            round + 1, plan.subtask, plan.success_criteria, plan.expected_evidence, plan.route, plan.channel
                        ),
                    );
                    // O3: preserve the Manager's raw output (original reasoning +
                    // structured plan) for audit replay — plan.md is parsed fields.
                    if !plan.raw_output.trim().is_empty() {
                        let _ = std::fs::write(round_dir.join("plan_raw.md"), &plan.raw_output);
                    }
                    let _ = std::fs::write(round_dir.join("executor_output.md"), &executor_output);
                    let _ = std::fs::write(
                        round_dir.join("tool_calls.jsonl"),
                        tool_trace.join("\n"),
                    );
                    let _ = std::fs::write(
                        round_dir.join("audit.json"),
                        serde_json::to_string_pretty(&round_audits).unwrap_or_else(|_| "[]".to_string()),
                    );
                    if let Ok(state_json) = contract.to_json() {
                        let _ = std::fs::write(round_dir.join("state.json"), &state_json);
                    }
                }

                // ── Persist TaskContract after each round (crash recovery) ──
                persist_contract(&memory_store, &contract_id, &session, &contract);

                // ── Write Expert mode findings to Blackboard ──
                // This allows Instant mode to see what Expert mode discovered.
                let mut blackboard = Blackboard::new(&session);
                // Load existing blackboard from SQLite (if any)
                if let Ok(Some(json)) = memory_store.load_blackboard(&session) {
                    if let Ok(existing) = Blackboard::from_json(&json) {
                        blackboard = existing;
                    }
                }
                // Write verified findings (include audit status + integrity for Instant visibility)
                for f in &contract.verified_findings {
                    let summary: String = f.title.chars().take(100).collect();
                    // Include status/integrity in detail so Instant users see audit verdict
                    let detail = format!(
                        "[status: {}, integrity: {}] {}",
                        f.status, f.integrity_status,
                        f.evidence_summary.chars().take(180).collect::<String>()
                    );
                    blackboard.add_entry(BlackboardEntry {
                        source: "expert".to_string(),
                        entry_type: "finding".to_string(),
                        summary,
                        detail: Some(detail),
                        phase: Some(format!("{:?}", contract.phase).to_lowercase()),
                        timestamp: chrono::Utc::now(),
                    });
                }
                // Write latest manager notes (up to 3) as summary entries
                // Filter out executor trajectory summaries ("Round N: ...") — same rule as F2
                let start = if contract.manager_notes.len() > 3 { contract.manager_notes.len() - 3 } else { 0 };
                for note in contract.manager_notes.iter().skip(start) {
                    // Skip executor trajectory notes (consistent with F2 Manager input isolation)
                    if note.starts_with("Round ") && !note.starts_with("[Audit Guard]")
                        && !note.starts_with("[User Resume]") && !note.starts_with("[Pre-Expert") {
                        continue;
                    }
                    let summary: String = note.chars().take(100).collect();
                    blackboard.add_entry(BlackboardEntry {
                        source: "expert".to_string(),
                        entry_type: "summary".to_string(),
                        summary,
                        detail: None,
                        phase: Some(format!("{:?}", contract.phase).to_lowercase()),
                        timestamp: chrono::Utc::now(),
                    });
                }
                // Write phase change if applicable
                if let Some(p) = plan.phase {
                    blackboard.add_entry(BlackboardEntry {
                        source: "expert".to_string(),
                        entry_type: "phase_change".to_string(),
                        summary: format!("Phase: {:?}", p),
                        detail: None,
                        phase: Some(format!("{:?}", p).to_lowercase()),
                        timestamp: chrono::Utc::now(),
                    });
                }
                // Write open leads (unresolved items) so Instant users see what Expert hasn't solved
                for lead in &contract.open_leads {
                    let summary: String = lead.description.chars().take(100).collect();
                    blackboard.add_entry(BlackboardEntry {
                        source: "expert".to_string(),
                        entry_type: "open_lead".to_string(),
                        summary,
                        detail: Some(format!("[{}] {}", lead.status, lead.context)),
                        phase: Some(format!("{:?}", contract.phase).to_lowercase()),
                        timestamp: chrono::Utc::now(),
                    });
                }
                // Persist blackboard
                if let Ok(json) = blackboard.to_json() {
                    let _ = memory_store.save_blackboard(&session, &json);
                }

                round += 1;
            }

            // Safety net: if the task completed, persist but do NOT delete.
            // The contract remains in the DB for reference or manual cleanup.
            if contract.phase == IrPhase::Completed {
                persist_contract(&memory_store, &contract_id, &session, &contract);
            }

            // Send done event
            let _ = tx.send(Ok(AgentEvent::done(&contract_id, "manager"))).await;
            info!("[managed:{}] Managed task completed after {} rounds", session, round);
        });

        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }
}

/// Ensure Computer Use tools are available for a GUI-channel round.
///
/// If the flag is already enabled, returns immediately. Otherwise announces a
/// 30-second user opt-in window (the user can enable via Settings > Computer
/// Use), and auto-enables on timeout — matching the shared flag used by the
/// server's toggle endpoint so both paths stay consistent.
///
/// Respects the cancelled flag: if the user sends STOP during the wait, the
/// function returns early without enabling tools.
async fn ensure_gui_channel(
    tx: &tokio::sync::mpsc::Sender<AgentResult<AgentEvent>>,
    contract_id: &str,
    session: &str,
    enabled: &Arc<AtomicBool>,
    tools: &Arc<tokio::sync::RwLock<ToolRegistry>>,
    cancelled: &Arc<AtomicBool>,
) {
    if enabled.load(Ordering::SeqCst) {
        return;
    }
    let _ = tx.send(Ok(AgentEvent::text(
        "\n\n*[GUI 通道] 本轮任务需要 GUI 交互，但 computer_use 工具未启用。\n\
         请在 30 秒内前往 **设置 > Computer Use** 手动开启；\n\
         或等待 30 秒后自动开启。*\n\n",
        contract_id, "manager"
    ))).await;
    // 30-second window: poll every 1s so a manual enable or STOP interrupts the wait.
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        // Check if user sent STOP — if so, abort the wait immediately.
        if cancelled.load(Ordering::SeqCst) {
            let _ = tx.send(Ok(AgentEvent::text(
                "*[GUI 通道] 用户已停止任务，取消等待。*\n\n",
                contract_id, "manager"
            ))).await;
            return;
        }
        if enabled.load(Ordering::SeqCst) {
            let _ = tx.send(Ok(AgentEvent::text(
                "*[GUI 通道] computer_use 已手动开启。*\n\n",
                contract_id, "manager"
            ))).await;
            return;
        }
    }
    // Auto-enable on timeout: flip the shared flag + register the tools.
    enabled.store(true, Ordering::SeqCst);
    {
        let mut registry = tools.write().await;
        crate::tool::computer_use::register_computer_use_tools(&mut registry);
    }
    info!("[managed:{}] computer_use auto-enabled after GUI-channel timeout", session);
    let _ = tx.send(Ok(AgentEvent::text(
        "*[GUI 通道] 30 秒内未手动开启，已自动启用 computer_use 工具。*\n\n",
        contract_id, "manager"
    ))).await;
}

/// Persist the TaskContract to SQLite (best-effort crash recovery).
fn persist_contract(memory_store: &MemoryStore, contract_id: &str, session: &str, contract: &TaskContract) {
    if let Ok(json) = contract.to_json() {
        if let Err(e) = memory_store.save_task_contract(
            contract_id, session, &json,
            &format!("{:?}", contract.phase).to_lowercase(),
            contract.current_round,
        ) {
            warn!("[managed:{}] Failed to persist TaskContract: {}", session, e);
        }
    }
}

/// Rank IR phases in canonical progression order (forward-only advancement).
fn phase_rank(p: IrPhase) -> usize {
    match p {
        IrPhase::Collection => 0,
        IrPhase::Analysis => 1,
        IrPhase::Attribution => 2,
        IrPhase::Containment => 3,
        IrPhase::Eradication => 4,
        IrPhase::Reporting => 5,
        IrPhase::Completed => 6,
        IrPhase::Blocked => 7,
    }
}
