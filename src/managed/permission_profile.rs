//! Permission pre-authorization profiles for managed (long-horizon) tasks.
//!
//! In managed mode, tasks may run for hours without human intervention.
//! The permission system would normally pause for approval on containment
//! actions (kill process, disable service, remove persistence). This module
//! provides pre-authorization profiles that allow specific action classes
//! to proceed without waiting for human approval.
//!
//! # Safety Model
//!
//! Pre-authorization is scoped by action class:
//! - **Read-only**: Always pre-authorized (no risk)
//! - **Containment**: Can be pre-authorized (kill process, isolate host)
//! - **Eradication**: Can be pre-authorized with restrictions (delete known malware)
//! - **Destructive**: NEVER pre-authorized (format disk, delete system files)
//!
//! Pre-authorization profiles are stored per-task and expire when the task completes.
//! The Auditor verifies all pre-authorized actions post-hoc.
//!
//! # Integration
//!
//! The ManagedRunner checks the pre-authorization profile before each Executor round.
//! If an action is pre-authorized, it bypasses the normal permission gate.
//! If not pre-authorized, the task blocks until human approval (Phase 6 human gate).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Pre-authorization profile for a managed task.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PermissionProfile {
    /// Task ID this profile applies to.
    pub task_id: String,
    /// Action classes that are pre-authorized.
    pub preauthorized: HashSet<PreauthorizedAction>,
    /// When this profile was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When this profile expires (optional — defaults to task completion).
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Action classes that can be pre-authorized.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreauthorizedAction {
    /// Kill any process (by name or PID).
    KillProcess,
    /// Kill a specific process (by name).
    KillProcessNamed(String),
    /// Stop/disable a service.
    StopService,
    /// Remove persistence (registry, scheduled task, etc.).
    RemovePersistence,
    /// Isolate host (block network).
    IsolateHost,
    /// Delete files in specific directories (e.g., temp, malware drops).
    DeleteFilesInPath(String),
    /// Disable user account.
    DisableAccount,
}

impl PermissionProfile {
    /// Create a new permission profile for a task.
    pub fn new(task_id: String) -> Self {
        Self {
            task_id,
            preauthorized: HashSet::new(),
            created_at: chrono::Utc::now(),
            expires_at: None,
        }
    }

    /// Create a profile with standard IR containment pre-authorizations.
    pub fn ir_containment(task_id: String) -> Self {
        let mut profile = Self::new(task_id);
        profile.preauthorized.insert(PreauthorizedAction::KillProcess);
        profile.preauthorized.insert(PreauthorizedAction::StopService);
        profile.preauthorized.insert(PreauthorizedAction::RemovePersistence);
        profile
    }

    /// Create a profile with full IR pre-authorizations (including eradication).
    pub fn ir_full(task_id: String) -> Self {
        let mut profile = Self::ir_containment(task_id);
        profile.preauthorized.insert(PreauthorizedAction::IsolateHost);
        profile.preauthorized.insert(PreauthorizedAction::DisableAccount);
        profile
    }

    /// Check if an action is pre-authorized.
    pub fn is_preauthorized(&self, action: &PreauthorizedAction) -> bool {
        // Check exact match
        if self.preauthorized.contains(action) {
            return true;
        }

        // Check wildcard match (e.g., KillProcess matches KillProcessNamed)
        match action {
            PreauthorizedAction::KillProcessNamed(_) => {
                self.preauthorized.contains(&PreauthorizedAction::KillProcess)
            }
            PreauthorizedAction::DeleteFilesInPath(path) => {
                self.preauthorized.iter().any(|a| {
                    matches!(a, PreauthorizedAction::DeleteFilesInPath(p) if path.starts_with(p))
                })
            }
            _ => false,
        }
    }

    /// Add a pre-authorized action.
    pub fn authorize(&mut self, action: PreauthorizedAction) {
        self.preauthorized.insert(action);
    }

    /// Remove a pre-authorized action.
    pub fn revoke(&mut self, action: &PreauthorizedAction) {
        self.preauthorized.remove(action);
    }

    /// Check if the profile has expired.
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => chrono::Utc::now() > exp,
            None => false, // No expiration — valid until task completes
        }
    }
}

/// Check if a tool call is pre-authorized by the permission profile.
///
/// This is called by the ManagedRunner before each Executor round.
/// Returns true if the action can proceed without human approval.
pub fn check_preauthorization(
    profile: &PermissionProfile,
    tool_name: &str,
    args: &serde_json::Value,
) -> bool {
    if profile.is_expired() {
        return false;
    }

    // Map tool calls to pre-authorized actions
    match tool_name {
        "shell_exec" => {
            let cmd = args["command"].as_str().unwrap_or("");
            let lower = cmd.to_lowercase();

            // Process kill commands
            if lower.contains("stop-process") || lower.contains("taskkill") {
                return profile.is_preauthorized(&PreauthorizedAction::KillProcess);
            }

            // Service stop commands
            if lower.contains("stop-service") || lower.contains("sc stop") {
                return profile.is_preauthorized(&PreauthorizedAction::StopService);
            }

            false
        }

        "ir_persistence" => {
            let action = args["action"].as_str().unwrap_or("");
            if action == "remove" || action == "delete" {
                return profile.is_preauthorized(&PreauthorizedAction::RemovePersistence);
            }
            false
        }

        "sys_process" => {
            let action = args["action"].as_str().unwrap_or("");
            if action == "kill" {
                return profile.is_preauthorized(&PreauthorizedAction::KillProcess);
            }
            false
        }

        _ => false,
    }
}
