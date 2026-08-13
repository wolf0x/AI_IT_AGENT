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
use super::manager::{self, ManagerPlan, ManagerRoute, PendingPlan};
use super::permission_profile::PermissionProfile;
use super::task_contract::{IrPhase, TaskContract, TaskRecord, VerifiedFinding};
use crate::agent::{AgentEvent, EventStream};
use crate::error::AgentResult;
use crate::memory::MemoryStore;
use crate::model::openai::OpenAiProvider;
use crate::permission::PendingMap;
use crate::runner::Runner;
use crate::skill::SkillManager;

use crate::tool::ToolRegistry;

/// Does the resumed message express ONLY "continue" intent (no new substantive
/// content)? Used to decide whether to reuse the persisted in-flight plan
/// verbatim (bare resume) vs re-plan anchored on it (new context / redirect).
/// Biases toward `false` so user instructions are never silently ignored.
fn is_bare_resume(msg: &str) -> bool {
    let raw = msg.trim();
    if raw.is_empty() {
        return true;
    }
    let mut rest: &str = raw;
    // Strip ONE leading resume/filler prefix (longest first so "继续任务" wins
    // over "继续").
    const PREFIXES: [&str; 16] = [
        "continue the task", "continues", "continue", "resume", "go", "okay", "ok",
        "yes", "yep", "retry", "again", "继续任务", "继续", "接着", "再来", "好的",
    ];
    let mut stripped = false;
    for prefix in PREFIXES {
        // Use str::get so a non-char-boundary slice returns None instead of panicking.
        let Some(head) = rest.get(..prefix.len()) else { continue };
        if head.eq_ignore_ascii_case(prefix) {
            rest = &rest[prefix.len()..];
            stripped = true;
            break;
        }
    }
    if stripped {
        rest = rest.trim_start_matches(
            |c: char| matches!(c, ',' | '.' | '!' | '?' | ' ' | '\t' | '\n' | '。' | '，' | '！' | '？' | '；'),
        );
        rest = rest.trim();
    }
    if rest.is_empty() {
        return true;
    }
    let meaningful: String = rest.chars().filter(|c| c.is_alphanumeric()).collect();
    if meaningful.is_empty() {
        return true;
    }
    let ack = ["please", "pls", "yes", "ok", "okay", "thetask", "task", "ahead", "thanks",
               "continue", "继续", "接着", "好的", "嗯", "吧", "ok", "going"];
    let m = meaningful.to_lowercase();
    if ack.iter().any(|a| *a == m.as_str()) {
        return true;
    }
    false
}

/// Deadlock guardrails for the F10 backtrack gate.
/// A single lead is abandoned after this many rounds even when progress is slow.
const PER_LEAD_ROUND_CAP: usize = 6;
/// Hard cap on total backtracks before escalating to a human instead of looping.
const MAX_GLOBAL_BACKTRACKS: usize = 10;

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
    /// Whether to use LLM to simulate human intervention when blocked.
    human_intervention_enabled: Arc<AtomicBool>,
}

/// Compact signature of the most recent verified/active content.
///
/// Robust to FIFO caps on findings/leads: list lengths can saturate, but the
/// round_index/id of the newest item still advances when real work happens.
fn progress_marker(c: &TaskContract) -> String {
    let find = c.verified_findings
        .last()
        .map(|f| format!("{}:{}", f.round_index, f.id))
        .unwrap_or_default();
    let act = c.verified_actions
        .last()
        .map(|a| format!("{}:{}", a.round_index, a.id))
        .unwrap_or_default();
    let lead = c.open_leads
        .last()
        .map(|l| format!("{}:{}", l.status, l.description))
        .unwrap_or_default();
    format!("{}/{}/{}", find, act, lead)
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
        human_intervention_enabled: Arc<AtomicBool>,
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
            human_intervention_enabled,
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
    /// with a distilled, evidence-indexed handoff of prior session work.
    pub async fn run(
        &self,
        user_message: &str,
        session_id: &str,
        model_name: &str,
        scope: &str,
        permissions: Arc<Mutex<std::collections::HashMap<String, bool>>>,
        permission_pending: PendingMap,
        cancelled: Arc<AtomicBool>,
        handoff: Option<String>,
        force_new: bool,
    ) -> AgentResult<EventStream> {
        info!("[managed:{}] Starting managed task (max_rounds: {})", session_id, self.max_rounds);

        // ── Fix 1: Resume existing active TaskContract (if any) ──
        // When the user clicks STOP and sends a new message, we resume the
        // previous contract instead of creating a blank one. This preserves
        // verified_findings, manager_notes, open_leads, and the round counter.
        let (contract_id, mut contract, resumed) = if force_new {
            // force_new -> skip any stale/unrelated Expert contract and always start a
            // fresh contract for the current task (new round, or take over recent Instant
            // progress instead of an older unrelated Expert contract).
            let new_id = uuid::Uuid::new_v4().to_string();
            (new_id.clone(), TaskContract::new(new_id, user_message.to_string(), scope.to_string(), self.max_rounds), false)
        } else {
            match self.memory_store.get_latest_active_contract(session_id) {
            Ok(Some((id, json))) => {
                match TaskContract::from_json(&json) {
                    Ok(mut c) => {
                        let round = c.current_round;
                        let was_blocked = c.phase == IrPhase::Blocked;
                        info!("[managed:{}] Resuming existing TaskContract {} from round {} (was_blocked: {})",
                              session_id, &id[..8.min(id.len())], round, was_blocked);
                        // Unblock the contract if it was blocked (clears blocked_reason and resets phase)
                        if was_blocked {
                            c.unblock();
                        }
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
            }
        };


        // ── Seed distilled prior-work handoff (Instant -> Expert) ──
        // The server passes a distilled, evidence-indexed handoff of the session's
        // earlier Instant work. It is seeded as UNTRUSTED records plus a labelled
        // manager note, so the Manager treats it as leads/hypotheses to re-audit,
        // never as verified facts. This is the only continuation bridge between modes.
        if let Some(h) = handoff {
            let added = contract.seed_untrusted_handoff(&h);
            if added > 0 {
                info!("[managed:{}] Seeded distilled Instant handoff ({} chars, untrusted)", session_id, h.len());
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
        let human_intervention_enabled = self.human_intervention_enabled.clone();
        let provider = self.provider.clone();
        let manager_model = self.manager_model.clone();
        // Direct registry access for GUI-channel auto-enable (register cu_* tools).
        let tools = self.tools.clone();
        // Move auditor + permission profile into the spawned task for post-Executor
        // verification and pre-authorization consultation (Phase 6).

        // Spawn the managed loop
        // Fix 3: cancelled flag is checked at every round start so STOP
        // propagates from the WebSocket handler into the spawned task.
        let cancelled_flag = cancelled.clone();
        let resume_msg = user_message.to_string();
        tokio::spawn(async move {
            let mut round = if resumed { contract.current_round } else { 0usize };
            // F10: human-gate tracking — consecutive rounds with no progress
            // (no new findings, actions, or lead changes) trigger intervention.
            let mut stale_rounds: usize = 0;
            // Signature of the most recent verified/active content. Robust to FIFO
            // caps on findings/leads (lengths saturate; identity still advances).
            let mut last_progress: String = progress_marker(&contract);
            // Track how many times LLM human intervention has been attempted
            let mut human_intervention_attempts: usize = 0;
            let mut focus_rounds: usize = 0;
            // F5: per-round archive directory for audit trail.
            let archive_dir = std::path::Path::new(&workspace_dir)
                .join("managed").join(&contract_id);
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

                // ── F10: Human gate — repeated rounds with zero progress ──
                // Check multiple progress indicators, not just verified_findings.
                // Some tasks (e.g., CTF solving, report generation) may not produce findings
                // but still make progress through actions or lead resolution.
                let marker = progress_marker(&contract);
                if marker == last_progress {
                    stale_rounds += 1;
                } else {
                    stale_rounds = 0;
                    last_progress = marker;
                }
                focus_rounds += 1;
                if stale_rounds >= 3 || (contract.current_focus.is_some() && focus_rounds >= PER_LEAD_ROUND_CAP) {
                    info!("[managed:{}] Human gate: {} consecutive rounds without progress (findings: {}, actions: {}, leads: {})", 
                          session, stale_rounds, 
                          contract.verified_findings.len(), 
                          contract.verified_actions.len(),
                          contract.open_leads.len());
                    
                    // ---- Backtrack: abandon the current dead-end lead and switch
                    //      to a still-active lead before escalating to a human.
                    if contract.backtracks < MAX_GLOBAL_BACKTRACKS {
                        if contract.try_backtrack(round) {
                            info!("[managed:{}] Backtracked to next lead (backtracks={})", session, contract.backtracks);
                            let _ = tx.send(Ok(AgentEvent::text(
                                &format!("\n\n*[Backtrack] no progress on current branch, switched to next pending lead (backtrack #{})*\n\n", contract.backtracks),
                                &contract_id, "manager"
                            ))).await;
                            persist_contract(&memory_store, &contract_id, &session, &contract);
                            stale_rounds = 0;
                            focus_rounds = 0;
                            last_progress.clear();
                            continue;
                        }
                    }
                    // Check if human intervention simulation is enabled and not exhausted
                    if human_intervention_enabled.load(std::sync::atomic::Ordering::SeqCst) 
                        && human_intervention_attempts < 2 {
                        info!("[managed:{}] Human intervention simulation enabled (attempt {}/2) - using LLM to generate guidance", session, human_intervention_attempts + 1);
                        let _ = tx.send(Ok(AgentEvent::text(
                            "\n\n🤖 *[人工介入模拟] 连续 3 轮未取得进展，正在使用 LLM 生成指导...*\n\n",
                            &contract_id, "manager"
                        ))).await;
                        
                        // Use LLM to generate guidance based on current contract state
                        match Self::generate_human_guidance_static(&provider, &manager_model, &contract, &session).await {
                            Ok(guidance) => {
                                info!("[managed:{}] LLM generated guidance: {}", session, guidance.chars().take(100).collect::<String>());
                                let _ = tx.send(Ok(AgentEvent::text(
                                    &format!("\n\n💡 *[模拟人工指导]*\n{}\n\n", guidance),
                                    &contract_id, "manager"
                                ))).await;
                                // Add guidance as a manager note and reset stale counter
                                contract.manager_notes.push(format!("[Simulated Human Guidance] {}", guidance));
                                if contract.manager_notes.len() > 20 {
                                    let overflow = contract.manager_notes.len() - 20;
                                    contract.manager_notes.drain(0..overflow);
                                }
                                human_intervention_attempts += 1;
                                stale_rounds = 0; // Reset counter to give it more rounds
                                continue; // Continue to next round instead of breaking
                            }
                            Err(e) => {
                                error!("[managed:{}] Failed to generate LLM guidance: {}", session, e);
                                let _ = tx.send(Ok(AgentEvent::text(
                                    &format!("\n\n❌ *[人工介入模拟失败] {}*\n\n", e),
                                    &contract_id, "manager"
                                ))).await;
                                // Fall through to normal blocking
                            }
                        }
                    }
                    
                    let _ = tx.send(Ok(AgentEvent::text(
                        "\n\n⚠️ *[需要人工介入] 连续 3 轮未取得进展（无新发现、无新操作、无线索变化）。任务已标记 blocked——请检查当前策略或提供新指令。*\n\n",
                        &contract_id, "manager"
                    ))).await;
                    contract.block("No progress after 3 consecutive rounds".to_string());
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
                let tool_defs = tools.read().await.definitions();
                // ── Resume gating (persisted in-flight plan) ──
                // If a round was STOP'd mid-execution its plan is persisted on the
                // contract. A bare "continue" reuses that EXACT plan (no re-plan, no
                // 6A->6B drift). If the user added NEW context/redirect on resume, we
                // re-plan but anchor the Manager on the pending subtask so the new plan
                // stays aligned and does not redo completed work.
                let pending_json = contract.pending_plan.clone();
                let pending_opt = pending_json
                    .as_deref()
                    .and_then(|j| PendingPlan::from_json(j).ok());
                let msg_is_bare = is_bare_resume(&resume_msg);
                let plan: ManagerPlan = if resumed && msg_is_bare && pending_opt.is_some() {
                    let p = pending_opt.clone().unwrap();
                    info!("[managed:{}] Resuming stopped round {} with exact pending plan", session, round + 1);
                    p.to_plan()
                } else {
                    let anchor = if resumed && pending_opt.is_some() {
                        Some(pending_opt.as_ref().unwrap().subtask.as_str())
                    } else {
                        None
                    };
                    match manager::plan_next(&provider, &manager_model, &contract, &skills, &tool_defs, anchor).await {
                        Ok(p) => p,
                        Err(e) => {
                            error!("[managed:{}] Manager planning failed: {}", session, e);
                            let _ = tx.send(Ok(AgentEvent::text(
                                &format!("\n\n*[Manager planning failed: {}]*\n\n", e),
                                &contract_id, "manager"
                            ))).await;
                            break;
                        }
                    }
                };

                // Persist the in-flight plan right away so a STOP later in this round
                // can resume the exact same subtask on the next "continue".
                contract.pending_plan = PendingPlan::from_plan(&plan).to_json().ok();
                persist_contract(&memory_store, &contract_id, &session, &contract);

                info!("[managed:{}] Manager plan: route={:?}, subtask={}", session, plan.route, 
                      plan.subtask.chars().take(100).collect::<String>());

                // Send Manager plan to UI, split into labeled sections for readability
                // (mirrors the Executor's Subtask Complete report structure).
                let mut plan_event = format!(
                    "\n\n## 🧭 Manager Plan (Round {})\n\n**Subtask**\n{}\n\n**Success Criteria**\n{}",
                    round + 1, plan.subtask, plan.success_criteria
                );
                if !plan.expected_evidence.trim().is_empty() {
                    plan_event.push_str(&format!(
                        "\n\n**Expected Evidence**\n{}",
                        plan.expected_evidence
                    ));
                }
                plan_event.push_str(&format!(
                    "\n\n**Route**: {:?} \u{00b7} **Channel**: {}\n\n",
                    plan.route, plan.channel
                ));
                let _ = tx.send(Ok(AgentEvent::text(&plan_event, &contract_id, "manager"))).await;
                // G2: the Manager forecasts Remaining Work AFTER this subtask. Keep it
                // local here; only commit it to the contract once the round is actually
                // audited & verified (see reconcile step below), so a failed/partial
                // round never drops unfinished items.
                let planned_remaining: Vec<String> = plan.remaining_work.clone();

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
                        contract.remaining_work = Vec::new();
                        contract.pending_plan = None;
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
                // Force the Executor's output language to follow the original task, so that
                // autogenerated technical guidance never overrides the user's language.
                let brief_lang = crate::agent::llm_agent::detect_user_language(&contract.original_task);
                let brief_lang_cn = brief_lang == "Chinese";
                let brief = if brief_lang_cn {
                    format!("[语言要求] 原始任务为中文：请用中文回复（标题、要点、表格、称呼、结尾全部用中文，不要混用英文）。\n\n{}", brief)
                } else {
                    format!("[Language] The original task is in English: reply in ENGLISH throughout (headings, bullets, table cells, greetings, and closings included). Do not switch to Chinese or mix languages.\n\n{}", brief)
                };


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
                        if brief_lang_cn {
                            b.push_str("\n\n## Execution Channel: GUI\n本轮任务必须通过 GUI 工具完成——优先使用浏览器/技能工具（用户真实浏览器）或 computer_use 工具（cu_screenshot / cu_mouse / cu_keyboard 等界面控制）。不要尝试用 shell_exec 或 curl 代替 GUI 交互。");
                        } else {
                            b.push_str("\n\n## Execution Channel: GUI\nThis round MUST be completed through GUI tools - prefer a browser/skill tool (real user browser) or computer_use tools (cu_screenshot / cu_mouse / cu_keyboard). Do not try shell_exec or curl to replace GUI interaction.");
                        }
                        b
                    }
                    "ask" => {
                        let mut b = brief;
                        if brief_lang_cn {
                            b.push_str("\n\n## Execution Channel: ASK\n本轮需要用户输入才能继续。完成可做的准备工作后，明确说明需要用户提供什么，并调用 request_help 等待用户。");
                        } else {
                            b.push_str("\n\n## Execution Channel: ASK\nThis round needs user input to continue. After completing any preparatory work you can, clearly state what information the user must provide and call request_help to wait for the user.");
                        }
                        b
                    }
                    _ => {
                        let mut b = brief;
                        if brief_lang_cn {
                            b.push_str("\n\n## Execution Channel: CLI\n本轮优先使用命令行工具执行（shell_exec、ir_*、file_* 等）。");
                        } else {
                            b.push_str("\n\n## Execution Channel: CLI\nThis round prioritizes command-line tools (shell_exec, ir_*, file_*, etc.).");
                        }
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
                            // STOP during an Executor round: abort so the underlying
                            // agent loop sees its consumer close and stops issuing
                            // tools (e.g. browser_cdp) instead of running on.
                            if cancelled_flag.load(Ordering::SeqCst) {
                                info!("[managed:{}] STOP during Executor round {} - aborting executor", session, round + 1);
                                break;
                            }
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
                // If the executor round aborted due to STOP, skip audit/archive and
                // leave the main loop; the round-start cancel check confirms it.
                if cancelled_flag.load(Ordering::SeqCst) {
                    info!("[managed:{}] Executor round {} aborted by STOP", session, round + 1);
                    break;
                }
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
                // ── Independent round audit (fresh context, read-only) ──
                // The Auditor certifies whether this round's work is complete & clean.
                // Only evidence under a COMPLETE + non-violation verdict may be promoted
                // into verified state; otherwise it is recorded as untrusted / a lead.
                let executor_summary_bounded: String = executor_output.chars().take(1500).collect();
                let round_report = auditor.audit_round(
                    &contract.original_task,
                    &plan.subtask,
                    &plan.success_criteria,
                    &plan.expected_evidence,
                    &executor_summary_bounded,
                    &format!("{:?}", contract.phase),
                ).await;
                let round_ok = round_report.as_ref()
                    .map(|r| r.completion == "complete" && r.integrity != "violation")
                    .unwrap_or(true); // no LLM auditor configured -> do not block
                if let Some(rp) = &round_report {
                    round_audits.push(serde_json::json!({
                        "type": "round_audit",
                        "completion": rp.completion,
                        "integrity": rp.integrity,
                        "note": rp.note,
                        "supported_facts": rp.supported_facts,
                        "gaps": rp.gaps,
                    }));
                    info!("[managed:{}] Independent round audit: completion={}, integrity={}", session, rp.completion, rp.integrity);
                }
                // G0: never let a round appear "independently verified" when the auditor
                // could not run. Warn the user and record it as an Audit Guard note so
                // evidence is kept as leads/pending rather than silently trusted.
                if let Some(rp) = &round_report {
                    if rp.note.contains("round audit call failed") {
                        warn!("[managed:{}] Independent auditor call failed; evidence NOT promoted to verified", session);
                        let _ = tx.send(Ok(AgentEvent::text(
                            "\n\n*[Audit warning] The independent Auditor check failed this round, so this round's work was NOT promoted to verified state.*\n\n",
                            &contract_id, "manager"
                        ))).await;
                        contract.manager_notes.push(format!(
                            "[Audit Guard] Round {}: independent auditor call failed - evidence kept as leads/pending",
                            round + 1
                        ));
                    }
                }
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
                        if audit.verified && round_ok {
                            contract.add_finding(VerifiedFinding {
                                id: uuid::Uuid::new_v4().to_string(),
                                title: format!("Evidence collected: {}", path),
                                severity: "info".to_string(),
                                status: audit.status.clone(),
                                integrity_status: audit.integrity.clone(),
                                evidence_summary: audit.evidence.clone(),
                                evidence_path: Some(path.to_string()),
                                mitre_technique: None,
                                verified_at: chrono::Utc::now(),
                                round_index: round,
                            });
                            contract.add_record(TaskRecord {
                                id: uuid::Uuid::new_v4().to_string(),
                                kind: "artifact".to_string(),
                                title: format!("Evidence collected: {}", path),
                                status: "completed".to_string(),
                                integrity: audit.integrity.clone(),
                                evidence_summary: audit.evidence.clone(),
                                evidence_path: Some(path.to_string()),
                                phase: Some(format!("{:?}", contract.phase).to_lowercase()),
                                round_index: round,
                                updated_at: Some(chrono::Utc::now()),
                            });
                        } else {
                            // Not promoted to verified state: keep as untrusted/pending record.
                            contract.add_record(TaskRecord {
                                id: uuid::Uuid::new_v4().to_string(),
                                kind: "artifact".to_string(),
                                title: format!("Evidence collected: {}", path),
                                status: if audit.verified { "untrusted".to_string() } else { "pending".to_string() },
                                integrity: audit.integrity.clone(),
                                evidence_summary: audit.evidence.clone(),
                                evidence_path: Some(path.to_string()),
                                phase: Some(format!("{:?}", contract.phase).to_lowercase()),
                                round_index: round,
                                updated_at: Some(chrono::Utc::now()),
                            });
                            let reason = if audit.verified {
                                "round not independently certified (auditor verdict not complete/clean)".to_string()
                            } else {
                                audit.failure_reason.unwrap_or_else(|| "verification failed".to_string())
                            };
                            contract.add_lead(
                                &format!("Evidence '{}' not verified", path),
                                &reason,
                            );
                            contract.manager_notes.push(format!(
                                "Round {}: evidence '{}' not verified: {}",
                                round + 1, path, reason
                            ));
                        }                    }
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
                // G2: reconcile Remaining Work - only advance it when this round was
                // audited & verified. On a failed/partial round, keep the prior to-do
                // list so unfinished items are not dropped.
                if round_ok {
                    contract.remaining_work = planned_remaining;
                    contract.pending_plan = None;
                }

                contract.current_round = round + 1;

                // ── F5: Per-round archive (audit trail, re-playable) ──
                // Each round writes plan / executor output / audit report / state
                // snapshot to managed/<contract>/round_N/. SQLite remains
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

                round += 1;
            }

            // Safety net: if the task completed, persist but do NOT delete.
            // The contract remains in the DB for reference or manual cleanup.
            if contract.phase == IrPhase::Completed {
                persist_contract(&memory_store, &contract_id, &session, &contract);
                // Generate HTML report for completed Expert tasks
                write_expert_report(&workspace_dir, &contract, &contract_id, &archive_dir);
            }

            // Send done event
            let _ = tx.send(Ok(AgentEvent::done(&contract_id, "manager"))).await;
            info!("[managed:{}] Managed task completed after {} rounds", session, round);
        });

        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    /// Generate human guidance using LLM when Expert mode is blocked.
    /// Analyzes the current contract state and provides actionable guidance.
    async fn generate_human_guidance_static(
        provider: &Arc<OpenAiProvider>,
        manager_model: &str,
        contract: &TaskContract,
        _session: &str,
    ) -> Result<String, String> {
        use crate::model::ChatMessage;
        
        let system_prompt = r#"You are a human expert providing guidance to an AI agent that is stuck.
The agent has been working on a task but has made no progress for several rounds.

Analyze the current state and provide clear, actionable guidance:
1. What might be causing the lack of progress?
2. What specific actions should the agent take next?
3. Are there alternative approaches to consider?

Be concise and specific. Focus on practical next steps."#;

        let user_prompt = format!(
            "Current Task: {}\n\nCurrent Phase: {:?}\n\nVerified Findings: {}\n\nVerified Actions: {}\n\nOpen Leads: {}\n\nManager Notes (recent):\n{}\n\nPlease provide guidance on how to proceed.",
            contract.original_task,
            contract.phase,
            contract.verified_findings.len(),
            contract.verified_actions.len(),
            contract.open_leads.len(),
            contract.manager_notes.iter().rev().take(5).cloned().collect::<Vec<_>>().join("\n")
        );

        let messages = vec![
            ChatMessage::system(system_prompt),
            ChatMessage::user(&user_prompt),
        ];

        // Use a dummy channel for the LLM call (we don't stream this)
        let (dummy_tx, mut dummy_rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            while dummy_rx.recv().await.is_some() {}
        });

        let (content, _reasoning, _tool_calls, _usage) = provider
            .chat_stream(manager_model, &messages, &[], dummy_tx, &contract.id, "human_guidance")
            .await
            .map_err(|e| format!("LLM call failed: {}", e))?;

        Ok(content)
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

/// Generate a self-contained HTML report for a completed Expert task.
/// Writes to workspace/Expert/<task_name>_<contract_id_short>.html.
fn write_expert_report(
    workspace_dir: &str,
    contract: &TaskContract,
    contract_id: &str,
    archive_dir: &std::path::Path,
) {
    use std::fmt::Write as FmtWrite;

    // Ensure Expert directory exists
    let expert_dir = std::path::Path::new(workspace_dir).join("Expert");
    if let Err(e) = std::fs::create_dir_all(&expert_dir) {
        warn!("[managed] Failed to create Expert directory: {}", e);
        return;
    }

    // Sanitize task name for filename
    let task_slug: String = contract.original_task.chars()
        .take(40)
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();
    let short_id = &contract_id[..8.min(contract_id.len())];
    let filename = format!("Expert_{}_{}.html", task_slug, short_id);
    let report_path = expert_dir.join(&filename);

    // Build HTML content
    let mut html = String::with_capacity(16384);
    let _ = writeln!(html, "<!DOCTYPE html>
<html lang=\"zh-CN\"><head><meta charset=\"UTF-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
<title>Expert Report: {}</title>
<style>
:root{{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#c9d1d9;--t2:#8b949e;--accent:#58a6ff;--accent2:#7ee787;--accent3:#ffa657;--accent4:#ff7b72}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:40px 20px}}
.container{{max-width:960px;margin:0 auto}}
h1{{font-size:28px;color:#f0f6fc;margin-bottom:8px}}
h2{{font-size:20px;color:#f0f6fc;margin:32px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--border)}}
h3{{font-size:16px;color:var(--accent);margin:20px 0 8px}}
.meta{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px 20px;margin:16px 0}}
.meta-row{{display:flex;gap:24px;flex-wrap:wrap;margin:4px 0}}
.meta-label{{color:var(--t2);font-size:12px;min-width:80px}}
.meta-val{{font-size:13px}}
.badge{{display:inline-block;padding:2px 10px;border-radius:10px;font-size:11px;font-weight:700}}
.badge-ok{{background:#1a3a2a;color:var(--accent2)}}
.badge-warn{{background:#3a2a0a;color:var(--accent3)}}
.badge-info{{background:#0a2a3a;color:var(--accent)}}
.finding{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px 16px;margin:8px 0}}
.finding-title{{font-weight:700;color:#f0f6fc;font-size:14px;margin-bottom:4px}}
.finding-meta{{font-size:11px;color:var(--t2)}}
.round{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px 20px;margin:12px 0}}
.round-hdr{{display:flex;align-items:center;gap:12px;margin-bottom:12px}}
.round-num{{font-size:18px;font-weight:700;color:var(--accent)}}
.section{{margin:8px 0}}
.section-title{{font-size:12px;color:var(--t2);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}}
.section-content{{font-size:13px;white-space:pre-wrap;word-break:break-word}}
.tool-list{{display:flex;flex-wrap:wrap;gap:6px}}
.tool-tag{{background:#1a2332;border:1px solid var(--border);border-radius:6px;padding:2px 8px;font-size:11px}}
.footer{{margin-top:40px;padding-top:16px;border-top:1px solid var(--border);color:var(--t2);font-size:12px;text-align:center}}
</style></head><body><div class=\"container\">",
        html_escape(&contract.original_task));

    // Header
    let phase_str = format!("{:?}", contract.phase);
    let status_class = if contract.phase == IrPhase::Completed { "badge-ok" } else if contract.phase == IrPhase::Blocked { "badge-warn" } else { "badge-info" };
    let _ = writeln!(html, "<h1>🛠 Expert Task Report</h1>
<div class=\"meta\">
<div class=\"meta-row\"><span class=\"meta-label\">Task</span><span class=\"meta-val\">{}</span></div>
<div class=\"meta-row\"><span class=\"meta-label\">Scope</span><span class=\"meta-val\">{}</span></div>
<div class=\"meta-row\"><span class=\"meta-label\">Status</span><span class=\"badge {}\">{}</span></div>
<div class=\"meta-row\"><span class=\"meta-label\">Rounds</span><span class=\"meta-val\">{}</span></div>
<div class=\"meta-row\"><span class=\"meta-label\">Contract</span><span class=\"meta-val\" style=\"font-family:monospace;font-size:11px\">{}</span></div>
</div>",
        html_escape(&contract.original_task),
        html_escape(&contract.scope),
        status_class, html_escape(&phase_str),
        contract.current_round,
        contract_id);

    // Verified Findings
    if !contract.verified_findings.is_empty() {
        let _ = writeln!(html, "<h2>🔍 Verified Findings ({})</h2>", contract.verified_findings.len());
        for f in &contract.verified_findings {
            let _ = writeln!(html, "<div class=\"finding\">
<div class=\"finding-title\">[{}] {}</div>
<div class=\"finding-meta\">Severity: {} | Status: {} | Integrity: {}</div>
<div class=\"section-content\">{}</div>
</div>",
                html_escape(&f.severity), html_escape(&f.title),
                html_escape(&f.severity), html_escape(&f.status), html_escape(&f.integrity_status),
                html_escape(&f.evidence_summary));
        }
    }

    // Verified Actions
    if !contract.verified_actions.is_empty() {
        let _ = writeln!(html, "<h2>✅ Verified Actions ({})</h2>", contract.verified_actions.len());
        for a in &contract.verified_actions {
            let _ = writeln!(html, "<div class=\"finding\">
<div class=\"finding-title\">{}</div>
<div class=\"section-content\">{}</div>
</div>",
                html_escape(&a.description), html_escape(&a.verification));
        }
    }

    // Per-round details from archive
    let _ = writeln!(html, "<h2>📋 Round-by-Round Details</h2>");
    let mut round_dirs: Vec<(u32, std::path::PathBuf)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(archive_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(round_str) = name.strip_prefix("round_") {
                if let Ok(n) = round_str.parse::<u32>() {
                    round_dirs.push((n, entry.path()));
                }
            }
        }
    }
    round_dirs.sort_by_key(|(n, _)| *n);
    for (n, dir) in &round_dirs {
            let _ = writeln!(html, "<div class=\"round\">");
            let _ = writeln!(html, "<div class=\"round-hdr\"><span class=\"round-num\">Round {}</span></div>", n);

            // Plan
            if let Ok(plan) = std::fs::read_to_string(dir.join("plan.md")) {
                let _ = writeln!(html, "<div class=\"section\"><div class=\"section-title\">Manager Plan</div>
<div class=\"section-content\">{}</div></div>", html_escape(&plan.chars().take(500).collect::<String>()));
            }

            // Executor output
            if let Ok(output) = std::fs::read_to_string(dir.join("executor_output.md")) {
                let _ = writeln!(html, "<div class=\"section\"><div class=\"section-title\">Executor Output</div>
<div class=\"section-content\">{}</div></div>", html_escape(&output.chars().take(800).collect::<String>()));
            }

            // Tool calls
            if let Ok(trace) = std::fs::read_to_string(dir.join("tool_calls.jsonl")) {
                let mut tools: Vec<String> = Vec::new();
                for line in trace.lines() {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                        if let Some(tool) = v["tool"].as_str() {
                            let ms = v["duration_ms"].as_u64().unwrap_or(0);
                            tools.push(format!("{} ({}ms)", tool, ms));
                        }
                    }
                }
                if !tools.is_empty() {
                    let _ = writeln!(html, "<div class=\"section\"><div class=\"section-title\">Tool Calls ({})</div><div class=\"tool-list\">",
                        tools.len());
                    for t in &tools {
                        let _ = writeln!(html, "<span class=\"tool-tag\">{}</span>", html_escape(t));
                    }
                    let _ = writeln!(html, "</div></div>");
                }
            }

            // Audit
            if let Ok(audit_str) = std::fs::read_to_string(dir.join("audit.json")) {
                if let Ok(audits) = serde_json::from_str::<Vec<serde_json::Value>>(&audit_str) {
                    if !audits.is_empty() {
                        let _ = writeln!(html, "<div class=\"section\"><div class=\"section-title\">Audit Results</div>");
                        for a in &audits {
                            let path = a["path"].as_str().unwrap_or("");
                            let verified = a["verified"].as_bool().unwrap_or(false);
                            let icon = if verified { "✅" } else { "❌" };
                            let _ = writeln!(html, "<div style=\"font-size:12px;margin:2px 0\">{} {} — {}</div>",
                                icon, html_escape(path),
                                html_escape(a["failure_reason"].as_str().unwrap_or("verified")));
                        }
                        let _ = writeln!(html, "</div>");
                    }
                }
            }

            let _ = writeln!(html, "</div>");
    }

    // Manager Notes
    if !contract.manager_notes.is_empty() {
        let _ = writeln!(html, "<h2>📝 Manager Notes</h2><div class=\"section-content\">");
        for note in &contract.manager_notes {
            let _ = writeln!(html, "<div style=\"margin:4px 0;padding:6px 10px;background:var(--surface);border-radius:6px;font-size:12px\">{}</div>",
                html_escape(&note.chars().take(200).collect::<String>()));
        }
        let _ = writeln!(html, "</div>");
    }

    // Footer
    let _ = writeln!(html, "<div class=\"footer\">Generated by RustAgent Expert Mode · {}</div>
</div></body></html>",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));

    // Write report
    if let Err(e) = std::fs::write(&report_path, &html) {
        warn!("[managed] Failed to write Expert report: {}", e);
    } else {
        info!("[managed] Expert report written: {}", report_path.display());
    }
}

/// Escape HTML special characters.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&#39;")
}
