//! TaskContract — persistent state for managed (long-horizon) task execution.
//!
//! The TaskContract is the single source of truth for a managed task's progress.
//! It survives across Executor rounds and is the only input to the Manager's
//! planning decisions. This prevents context drift by keeping verified state
//! separate from the Executor's growing (and eventually trimmed) history.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Incident Response phase lifecycle (NIST SP 800-61 aligned).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IrPhase {
    /// Initial data collection (ir_* tools, YARA scans, etc.)
    Collection,
    /// Analysis and correlation of collected evidence
    Analysis,
    /// Attribution and attack path reconstruction
    Attribution,
    /// Containment actions (kill processes, isolate hosts)
    Containment,
    /// Eradication (remove persistence, clean artifacts)
    Eradication,
    /// Report generation and delivery
    Reporting,
    /// Task completed successfully
    Completed,
    /// Task blocked (waiting for human input or external dependency)
    Blocked,
}

impl Default for IrPhase {
    fn default() -> Self {
        IrPhase::Collection
    }
}

/// A verified finding — evidence that has passed Auditor verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedFinding {
    /// Unique identifier for this finding.
    pub id: String,
    /// Short title (e.g., "XMRig mining process detected").
    pub title: String,
    /// Severity: critical, high, medium, low, info.
    pub severity: String,
    /// Audit status: complete / incomplete / blocked (default: complete).
    #[serde(default = "default_complete")]
    pub status: String,
    /// Evidence integrity: clean / suspect / violation (default: clean).
    #[serde(default = "default_clean")]
    pub integrity_status: String,
    /// Evidence summary (not full content — reference files for details).
    pub evidence_summary: String,
    /// Path to evidence file in workspace (if applicable).
    pub evidence_path: Option<String>,
    /// MITRE ATT&CK technique ID (if applicable).
    pub mitre_technique: Option<String>,
    /// When this finding was verified.
    pub verified_at: DateTime<Utc>,
    /// Which Manager round verified this.
    pub round_index: usize,
}

fn default_complete() -> String { "complete".to_string() }
fn default_clean() -> String { "clean".to_string() }

/// A verified action — containment/eradication step confirmed by Auditor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedAction {
    /// Unique identifier.
    pub id: String,
    /// What action was taken (e.g., "Killed process xmrig.exe PID 1234").
    pub description: String,
    /// Verification result (e.g., "Process no longer in process list").
    pub verification: String,
    /// When this action was verified.
    pub verified_at: DateTime<Utc>,
    /// Which Manager round verified this.
    pub round_index: usize,
}

/// An open lead being investigated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenLead {
    /// Short description of the lead.
    pub description: String,
    /// Current status: pending / investigating / resolved / abandoned.
    pub status: String,
    /// Evidence or context so far.
    pub context: String,
    /// Round index of the lead's last activity.
    #[serde(default)]
    pub round_index: usize,
    /// Why the lead was resolved or abandoned.
    #[serde(default)]
    pub reason: Option<String>,
}

/// The TaskContract — persistent state for a managed task.
///
/// This struct is serialized to JSON and stored in SQLite. It is the sole
/// input to the Manager's planning decisions, ensuring that verified progress
/// is never lost to context window trimming.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskContract {
    /// Unique identifier for this managed task.
    pub id: String,
    /// Original task description from the user.
    pub original_task: String,
    /// Current IR phase.
    pub phase: IrPhase,
    /// Target host(s) or scope (e.g., "10.0.0.5", "this machine").
    pub scope: String,
    /// Event hypothesis (what we think happened, updated as evidence accumulates).
    pub hypothesis: String,
    /// Verified findings — only results confirmed by Auditor.
    pub verified_findings: Vec<VerifiedFinding>,
    /// Verified actions — containment/eradication confirmed by re-check.
    pub verified_actions: Vec<VerifiedAction>,
    /// Open leads being investigated.
    pub open_leads: Vec<OpenLead>,
    /// Index into open_leads of the lead currently being pursued (DFS focus).
    #[serde(default)]
    pub current_focus: Option<usize>,
    /// Total number of times the runner backtracked off a dead-end lead.
    #[serde(default)]
    pub backtracks: usize,
    /// Current Manager round index (0-based).
    pub current_round: usize,
    /// Maximum rounds allowed.
    pub max_rounds: usize,
    /// When this task was created.
    pub created_at: DateTime<Utc>,
    /// When this task was last updated.
    pub updated_at: DateTime<Utc>,
    /// Free-form notes from the Manager (e.g., "Need to check lateral movement from host X").
    pub manager_notes: Vec<String>,
    /// Why the task is blocked (if phase == Blocked).
    pub blocked_reason: Option<String>,
    /// Original phase before blocking (used to restore on unblock).
    #[serde(default)]
    pub phase_before_block: Option<IrPhase>,
}

impl TaskContract {
    /// Create a new TaskContract for a managed task.
    pub fn new(id: String, original_task: String, scope: String, max_rounds: usize) -> Self {
        let now = Utc::now();
        Self {
            id,
            original_task,
            phase: IrPhase::default(),
            scope,
            hypothesis: String::new(),
            verified_findings: Vec::new(),
            verified_actions: Vec::new(),
            open_leads: Vec::new(),
            current_focus: None,
            backtracks: 0,
            current_round: 0,
            max_rounds,
            created_at: now,
            updated_at: now,
            manager_notes: Vec::new(),
            blocked_reason: None,
            phase_before_block: None,
        }
    }

    /// Generate a condensed brief for the Executor.
    ///
    /// This brief replaces the full conversation history in managed mode.
    /// It contains only verified state and the current subtask, keeping
    /// the Executor's context small and focused.
    pub fn executor_brief(&self, subtask: &str, success_criteria: &str) -> String {
        let mut brief = String::new();

        brief.push_str("# Task Brief\n\n");
        brief.push_str(&format!("**Original Task**: {}\n", self.original_task));
        brief.push_str(&format!("**Scope**: {}\n", self.scope));
        brief.push_str(&format!("**Current Phase**: {:?}\n", self.phase));
        brief.push_str(&format!("**Round**: {} / {}\n\n", self.current_round + 1, self.max_rounds));

        if !self.hypothesis.is_empty() {
            brief.push_str("## Hypothesis\n");
            brief.push_str(&self.hypothesis);
            brief.push_str("\n\n");
        }

        if !self.verified_findings.is_empty() {
            brief.push_str("## Verified Findings\n");
            // Show only the most recent 20 findings to prevent brief from growing too large
            let display_findings: Vec<_> = self.verified_findings.iter().rev().take(20).rev().collect();
            if display_findings.len() < self.verified_findings.len() {
                brief.push_str(&format!("(Showing most recent {} of {} findings)\n", display_findings.len(), self.verified_findings.len()));
            }
            for f in display_findings {
                brief.push_str(&format!("- [{}] {} ({})\n", f.severity.to_uppercase(), f.title, f.evidence_summary));
                if let Some(ref path) = f.evidence_path {
                    brief.push_str(&format!("  Evidence file: `{}`\n", path));
                }
            }
            brief.push('\n');
        }

        if !self.verified_actions.is_empty() {
            brief.push_str("## Verified Actions Taken\n");
            // Show only the most recent 10 actions to prevent brief from growing too large
            let display_actions: Vec<_> = self.verified_actions.iter().rev().take(10).rev().collect();
            if display_actions.len() < self.verified_actions.len() {
                brief.push_str(&format!("(Showing most recent {} of {} actions)\n", display_actions.len(), self.verified_actions.len()));
            }
            for a in display_actions {
                brief.push_str(&format!("- {} → {}\n", a.description, a.verification));
            }
            brief.push('\n');
        }

        if !self.open_leads.is_empty() {
            brief.push_str("## Open Leads\n");
            // Show only the most recent 10 leads to prevent brief from growing too large
            let display_leads: Vec<_> = self.open_leads.iter().rev().take(10).rev().collect();
            if display_leads.len() < self.open_leads.len() {
                brief.push_str(&format!("(Showing most recent {} of {} leads)\n", display_leads.len(), self.open_leads.len()));
            }
            for l in display_leads {
                brief.push_str(&format!("- [{}] {}: {}\n", l.status, l.description, l.context));
            }
            brief.push('\n');
        }

        if !self.manager_notes.is_empty() {
            brief.push_str("## Manager Notes\n");
            for note in &self.manager_notes {
                brief.push_str(&format!("- {}\n", note));
            }
            brief.push('\n');
        }

        brief.push_str("## Current Subtask\n");
        brief.push_str(subtask);
        brief.push_str("\n\n");

        brief.push_str("## Success Criteria\n");
        brief.push_str(success_criteria);
        brief.push_str("\n\n");

        brief.push_str("## Instructions\n");
        brief.push_str("- Execute this subtask using available tools.\n");
        brief.push_str("- **MANDATORY**: Save ALL artifacts, evidence files, reports, and outputs to `workspace/output/` directory. NEVER save files to C:\\, D:\\, or any location outside workspace/output/.\n");
        brief.push_str("- Reference the saved file paths in your response (e.g., 'Saved to output/scan_result.json').\n");
        brief.push_str("- Focus ONLY on this subtask. Do not repeat work from verified findings.\n");
        brief.push_str("- If you encounter a timeout, use partial results and narrow scope.\n");

        brief
    }

    /// Add a verified finding.
    /// **Limit**: Max 50 findings (FIFO eviction) to prevent executor_brief from growing too large.
    pub fn add_finding(&mut self, finding: VerifiedFinding) {
        self.verified_findings.push(finding);
        // Enforce limit: remove oldest if over 50
        if self.verified_findings.len() > 50 {
            self.verified_findings.remove(0);
        }
        self.updated_at = Utc::now();
    }

    /// Add an open lead (unresolved item awaiting investigation).
    /// If a lead with the same description exists, update its context (failure reason).
    /// **Limit**: Max 20 leads (FIFO eviction) to prevent executor_brief from growing too large.
    pub fn add_lead(&mut self, description: &str, context: &str) {
        if let Some(existing) = self.open_leads.iter_mut().find(|l| l.description == description) {
            // Update context with latest failure reason
            existing.context = context.to_string();
            existing.status = "pending".to_string(); // Reset to pending for re-investigation
            existing.round_index = self.current_round;
            self.updated_at = Utc::now();
        } else {
            self.open_leads.push(OpenLead {
                description: description.to_string(),
                status: "pending".to_string(),
                context: context.to_string(),
                round_index: self.current_round,
                reason: None,
            });
            // Enforce limit: remove oldest if over 20
            if self.open_leads.len() > 20 {
                self.open_leads.remove(0);
            }
            self.updated_at = Utc::now();
        }
    }

    /// Abandon the current focus lead and switch to the next still-active lead
    /// (backtracking). Returns true if a lead remains to pursue, false if the
    /// frontier is exhausted (all leads resolved/abandoned). Bounded: each call
    /// abandons at most one lead; callers cap the total via MAX_GLOBAL_BACKTRACKS.
    pub fn try_backtrack(&mut self, round: usize) -> bool {
        // Abandon the current focus (it made no progress).
        if let Some(idx) = self.current_focus {
            if let Some(l) = self.open_leads.get_mut(idx) {
                if l.status == "pending" || l.status == "investigating" {
                    l.status = "abandoned".to_string();
                    l.reason = Some("no progress after consecutive rounds".to_string());
                    l.round_index = round;
                    self.backtracks += 1;
                }
            }
            self.current_focus = None;
        }
        // Pick the next still-active lead, or none if the frontier is exhausted.
        if let Some(idx) = self.open_leads.iter().position(|l| l.status == "pending" || l.status == "investigating") {
            self.current_focus = Some(idx);
            self.open_leads[idx].status = "investigating".to_string();
            self.open_leads[idx].round_index = round;
            true
        } else {
            false
        }
    }

    /// Add a verified action.
    pub fn add_action(&mut self, action: VerifiedAction) {
        self.verified_actions.push(action);
        self.updated_at = Utc::now();
    }

    /// Advance to the next phase.
    pub fn advance_phase(&mut self, phase: IrPhase) {
        self.phase = phase;
        self.updated_at = Utc::now();
    }

    /// Mark task as completed.
    pub fn complete(&mut self) {
        self.phase = IrPhase::Completed;
        // Clear stale resume metadata so a completed contract is not resumable.
        self.phase_before_block = None;
        self.updated_at = Utc::now();
    }

    /// Mark task as blocked.
    pub fn block(&mut self, reason: String) {
        // Save the current phase before blocking so it can be restored on unblock
        // Guard against double-blocking overwriting a previously saved phase.
        if self.phase != IrPhase::Blocked {
            self.phase_before_block = Some(self.phase);
        }
        self.phase = IrPhase::Blocked;
        self.blocked_reason = Some(reason);
        self.updated_at = Utc::now();
    }

    /// Unblock a previously blocked task, restoring the original phase.
    /// This is called when resuming a blocked contract with new user instructions.
    pub fn unblock(&mut self) {
        // Restore the original phase (or default to Collection if not saved)
        self.phase = self.phase_before_block.unwrap_or(IrPhase::Collection);
        self.phase_before_block = None;
        self.blocked_reason = None;
        self.updated_at = Utc::now();
    }

    /// Serialize to JSON for storage.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("Failed to serialize TaskContract: {}", e))
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("Failed to deserialize TaskContract: {}", e))
    }
}
