//! Command Intent Policy — safety interlock layer for shell_exec and linux_ssh.
//!
//! This module provides intent-based command analysis that operates independently
//! of the Permission system. While Permission answers "is this tool allowed?",
//! IntentPolicy answers "is this specific command catastrophically dangerous?"
//!
//! Design principles:
//! - Absolute Block: irreversible operations with NO legitimate IR use case (fuse)
//! - Audit: high-risk but legitimate operations — logged, not blocked
//! - Pass: normal operations — silent
//!
//! The policy is stateless and thread-safe. It does NOT depend on permission state.
//!
//! Two separate policies exist:
//! - IntentPolicy: for Windows commands (PowerShell/CMD)
//! - LinuxIntentPolicy: for Linux commands (bash/sh via SSH)

pub mod parse;
pub mod rules;
pub mod linux_parse;
pub mod linux_rules;

use rules::{BlockRule, AuditRule};
use linux_rules::{LinuxBlockRule, LinuxAuditRule};

/// Verdict from the intent policy evaluation.
#[derive(Debug, Clone)]
pub enum IntentVerdict {
    /// Normal operation — proceed silently.
    Pass,
    /// High-risk but legitimate — log audit entry, do NOT block.
    /// When Permission is already granted, this is transparent to the user.
    Audit { reason: String },
    /// Catastrophic irreversible operation — hard block regardless of permissions.
    Block { reason: String },
}

/// Stateless command intent policy engine.
///
/// Evaluates shell commands against block rules (absolute interlock)
/// and audit rules (logging for high-risk but legitimate operations).
pub struct IntentPolicy {
    block_rules: Vec<BlockRule>,
    audit_rules: Vec<AuditRule>,
}

impl IntentPolicy {
    /// Create a policy with default rules.
    pub fn new() -> Self {
        Self {
            block_rules: rules::default_block_rules(),
            audit_rules: rules::default_audit_rules(),
        }
    }

    /// Evaluate a command string. Returns a verdict independent of permission state.
    ///
    /// - `command`: the raw command string from shell_exec
    /// - `shell`: "powershell" or "cmd"
    pub fn evaluate(&self, command: &str, shell: &str) -> IntentVerdict {
        let intent = parse::parse_intent(command, shell);

        // Phase 1: Absolute block check (narrow, cannot be overridden)
        for rule in &self.block_rules {
            if rule.matches(&intent) {
                return IntentVerdict::Block {
                    reason: rule.explain(&intent),
                };
            }
        }

        // Phase 2: Audit-level check (high-risk but legitimate)
        for rule in &self.audit_rules {
            if rule.matches(&intent) {
                return IntentVerdict::Audit {
                    reason: rule.explain(&intent),
                };
            }
        }

        // Phase 3: Normal
        IntentVerdict::Pass
    }
}

impl Default for IntentPolicy {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// Linux Intent Policy — for SSH commands
// ============================================================

/// Verdict from Linux intent policy evaluation.
#[derive(Debug, Clone)]
pub enum LinuxIntentVerdict {
    /// Normal operation — proceed silently.
    Pass,
    /// High-risk but legitimate — log audit entry, do NOT block.
    Audit { reason: String },
    /// Catastrophic irreversible operation — hard block regardless of permissions.
    Block { reason: String },
}

/// Stateless Linux command intent policy engine.
///
/// Evaluates Linux/bash commands against block rules (absolute interlock)
/// and audit rules (logging for high-risk but legitimate operations).
pub struct LinuxIntentPolicy {
    block_rules: Vec<LinuxBlockRule>,
    audit_rules: Vec<LinuxAuditRule>,
}

impl LinuxIntentPolicy {
    /// Create a policy with default rules.
    pub fn new() -> Self {
        Self {
            block_rules: linux_rules::default_linux_block_rules(),
            audit_rules: linux_rules::default_linux_audit_rules(),
        }
    }

    /// Evaluate a Linux command string.
    ///
    /// - `command`: the raw bash/sh command string from linux_ssh
    pub fn evaluate(&self, command: &str) -> LinuxIntentVerdict {
        let intent = linux_parse::parse_linux_intent(command);

        // Phase 1: Absolute block check (narrow, cannot be overridden)
        for rule in &self.block_rules {
            if rule.matches(&intent) {
                return LinuxIntentVerdict::Block {
                    reason: rule.explain(&intent),
                };
            }
        }

        // Phase 2: Audit-level check (high-risk but legitimate)
        for rule in &self.audit_rules {
            if rule.matches(&intent) {
                return LinuxIntentVerdict::Audit {
                    reason: rule.explain(&intent),
                };
            }
        }

        // Phase 3: Normal
        LinuxIntentVerdict::Pass
    }
}

impl Default for LinuxIntentPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_commands_pass() {
        let policy = IntentPolicy::new();
        assert!(matches!(policy.evaluate("Get-Process", "powershell"), IntentVerdict::Pass));
        assert!(matches!(policy.evaluate("Get-ChildItem C:\\Temp", "powershell"), IntentVerdict::Pass));
        assert!(matches!(policy.evaluate("ipconfig /all", "cmd"), IntentVerdict::Pass));
        assert!(matches!(policy.evaluate("netstat -ano", "cmd"), IntentVerdict::Pass));
    }

    #[test]
    fn test_destructive_commands_audit() {
        let policy = IntentPolicy::new();
        assert!(matches!(
            policy.evaluate("Remove-Item 'C:\\Users\\Public\\miner.exe' -Force", "powershell"),
            IntentVerdict::Audit { .. }
        ));
        assert!(matches!(
            policy.evaluate("Stop-Service -Name 'MalSvc' -Force", "powershell"),
            IntentVerdict::Audit { .. }
        ));
        assert!(matches!(
            policy.evaluate("taskkill /F /PID 1234", "cmd"),
            IntentVerdict::Audit { .. }
        ));
    }

    #[test]
    fn test_catastrophic_commands_block() {
        let policy = IntentPolicy::new();
        assert!(matches!(
            policy.evaluate("Format-Volume -DriveLetter C -FileSystem NTFS", "powershell"),
            IntentVerdict::Block { .. }
        ));
        assert!(matches!(
            policy.evaluate("Clear-Disk -Number 0 -RemoveData", "powershell"),
            IntentVerdict::Block { .. }
        ));
        assert!(matches!(
            policy.evaluate("format C: /fs:ntfs /q", "cmd"),
            IntentVerdict::Block { .. }
        ));
        assert!(matches!(
            policy.evaluate("wevtutil cl Security", "cmd"),
            IntentVerdict::Block { .. }
        ));
        assert!(matches!(
            policy.evaluate("Clear-EventLog -LogName Security", "powershell"),
            IntentVerdict::Block { .. }
        ));
    }

    #[test]
    fn test_encoded_command_block() {
        let policy = IntentPolicy::new();
        // Encoded commands are blocked (cannot verify intent)
        assert!(matches!(
            policy.evaluate("powershell -EncodedCommand RwBlAHQA", "powershell"),
            IntentVerdict::Block { .. }
        ));
        assert!(matches!(
            policy.evaluate("powershell -enc RwBlAHQA", "powershell"),
            IntentVerdict::Block { .. }
        ));
    }
}
