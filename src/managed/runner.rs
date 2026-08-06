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
use tokio::sync::Mutex;
use tracing::{info, warn, error};

use super::auditor::Auditor;
use super::manager::{self, ManagerRoute};
use super::permission_profile::PermissionProfile;
use super::task_contract::TaskContract;
use crate::agent::{AgentEvent, EventStream};
use crate::error::AgentResult;
use crate::memory::MemoryStore;
use crate::model::openai::OpenAiProvider;
use crate::permission::PendingMap;
use crate::runner::Runner;
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
        }
    }

    /// Run a managed task.
    ///
    /// This method implements the Manager-Executor loop:
    /// 1. Create initial TaskContract from user message
    /// 2. Loop:
    ///    a. Manager plans next subtask
    ///    b. Executor runs subtask with fresh context
    ///    c. [Phase 4] Auditor verifies (not yet implemented)
    ///    d. Update TaskContract
    /// 3. Return final results
    pub async fn run(
        &self,
        user_message: &str,
        session_id: &str,
        model_name: &str,
        scope: &str,
        permissions: Arc<Mutex<std::collections::HashMap<String, bool>>>,
        permission_pending: PendingMap,
    ) -> AgentResult<EventStream> {
        info!("[managed:{}] Starting managed task (max_rounds: {})", session_id, self.max_rounds);

        // Create initial TaskContract
        let contract_id = uuid::Uuid::new_v4().to_string();
        let mut contract = TaskContract::new(
            contract_id.clone(),
            user_message.to_string(),
            scope.to_string(),
            self.max_rounds,
        );

        // Create the event stream channel
        let (tx, rx) = tokio::sync::mpsc::channel::<AgentResult<AgentEvent>>(200);

        // ── Phase 6: Permission pre-authorization profile for this task ──
        // Uses the IR containment profile so unattended containment actions can
        // proceed without blocking on human approval. Destructive actions are
        // never pre-authorized (safety interlock preserved).
        let permission_profile = PermissionProfile::ir_containment(contract_id.clone());

        // ── Phase 4: Auditor for independent verification ──
        let auditor = Auditor::new(
            self.tools.clone(),
            self.working_dir.clone(),
            self.workspace_dir.clone(),
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
        let _ = permission_profile; // profile consulted by permission layer (Phase 6 integration)
        // Move auditor into the spawned task for post-Executor verification.

        // Spawn the managed loop
        tokio::spawn(async move {
            let mut round = 0usize;

            loop {
                if round >= contract.max_rounds {
                    warn!("[managed:{}] Max rounds reached ({})", session, contract.max_rounds);
                    let _ = tx.send(Ok(AgentEvent::text(
                        &format!("\n\n*[Managed task reached maximum rounds ({})]*\n\n", contract.max_rounds),
                        &contract_id, "manager"
                    ))).await;
                    break;
                }

                contract.current_round = round;
                info!("[managed:{}] Round {} starting", session, round + 1);

                // ── Manager Round ──
                let plan = match manager::plan_next(&provider, &manager_model, &contract).await {
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
                        let _ = tx.send(Ok(AgentEvent::text(
                            "\n\n*[Manager: Task complete]*\n\n",
                            &contract_id, "manager"
                        ))).await;
                        contract.complete();
                        break;
                    }
                    ManagerRoute::Blocked(reason) => {
                        let _ = tx.send(Ok(AgentEvent::text(
                            &format!("\n\n*[Manager: Task blocked — {}]*\n\n", reason),
                            &contract_id, "manager"
                        ))).await;
                        contract.block(reason.clone());
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
                // Build the condensed brief for the Executor
                let brief = contract.executor_brief(&plan.subtask, &plan.success_criteria);

                info!("[managed:{}] Executor starting with brief ({} chars)", session, brief.len());

                // Run the Executor with the brief as the user message
                // This uses the existing agent loop with fresh context
                let executor_result = inner.run(
                    &brief,
                    &format!("{}-exec-{}", session, round),
                    &model,
                    20, // max iterations per subtask
                    vec![], // fresh history for each Executor round
                    permissions.clone(),
                    permission_pending.clone(),
                    None, // no fallback model
                    5,    // rabbit hole threshold
                    128000, // context window
                    80,   // context window threshold
                    300,  // tool timeout
                    2,    // max tool retries
                    vec![], // no images
                    None, None, // no checkpoint resume
                ).await;

                match executor_result {
                    Ok(mut stream) => {
                        // Forward Executor events to the main stream
                        use futures::StreamExt;
                        while let Some(result) = stream.next().await {
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

                // ── Phase 4: Auditor verification (artifact checks) ──
                // After each Executor round, verify any artifacts the Manager expected.
                // For now this is a lightweight pass — full action verification is wired
                // in when containment/eradication phases are enabled.
                if !plan.expected_evidence.is_empty() {
                    let _audit = auditor.verify_artifact(&plan.expected_evidence, None).await;
                    // Future: gate TaskContract.findings on audit.verified
                }

                // ── Persist TaskContract after each round (crash recovery) ──
                if let Ok(json) = contract.to_json() {
                    if let Err(e) = memory_store.save_task_contract(
                        &contract_id, &session, &json,
                        &format!("{:?}", contract.phase).to_lowercase(),
                        contract.current_round,
                    ) {
                        warn!("[managed:{}] Failed to persist TaskContract: {}", session, e);
                    }
                }

                round += 1;
            }

            // Send done event
            let _ = tx.send(Ok(AgentEvent::done(&contract_id, "manager"))).await;
            info!("[managed:{}] Managed task completed after {} rounds", session, round);
        });

        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }
}
