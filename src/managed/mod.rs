//! Managed execution mode for long-horizon tasks.
//!
//! This module implements the Manager-Executor pattern inspired by LongHorizon-Harness.
//! When `managed_mode` is enabled, tasks are executed through a three-role separation:
//!
//! - **Manager**: Maintains the original goal, verified progress, and decides the next subtask.
//!   Each Manager round starts with only the TaskContract (no growing history), preventing
//!   context drift over long tasks.
//!
//! - **Executor**: The existing agent loop (`LlmAgent::run`) runs each subtask with a fresh,
//!   condensed brief instead of accumulating history. Evidence is persisted to files; the
//!   brief references paths rather than embedding full content.
//!
//! - **Auditor** (Phase 4): Independently verifies actions and artifacts before they enter
//!   the TaskContract's verified state.
//!
//! # Activation
//!
//! Managed mode is activated **per-task** (not via a global settings toggle):
//! - Via skill metadata: a skill with `managed: true` in its SKILL.md
//! - Via API parameter: `/chat` endpoint accepts `managed: true`
//!
//! When disabled (the default), the existing `Runner::run` path is used unchanged.
//!
//! # TaskContract
//!
//! The [`TaskContract`] is the persistent state that survives across Executor rounds.
//! It contains:
//! - Original task description
//! - Current IR phase (Collection → Analysis → Containment → ...)
//! - Verified findings (only results confirmed by Auditor enter here)
//! - Verified actions (containment/eradication results confirmed by re-check)
//! - Open leads being investigated
//!
//! # Data Flow
//!
//! ```text
//! User request (managed=true)
//!     │
//!     ▼
//! ManagedRunner::run()
//!     │
//!     ├── Manager round:
//!     │     Input: TaskContract only (no history!)
//!     │     Output: next subtask + success criteria + expected evidence
//!     │
//!     ├── Executor round:
//!     │     Input: system_prompt + TaskContract brief + current subtask
//!     │     Runs: existing LlmAgent::run with fresh context
//!     │     Output: tool results, evidence files
//!     │
//!     ├── [Phase 4] Auditor round:
//!     │     Verify actions/artifacts
//!     │     Update TaskContract with verified findings
//!     │
//!     └── Loop until task complete or max rounds reached
//! ```

pub mod task_contract;
pub mod manager;
pub mod runner;
pub mod auditor;

pub use task_contract::TaskContract;
#[allow(unused_imports)]
pub use runner::ManagedRunner;
#[allow(unused_imports)]
pub use auditor::Auditor;
