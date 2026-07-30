//! Linux safety policy rules — BlockRule and AuditRule for SSH commands.
//!
//! BlockRule: catastrophic irreversible operations on Linux.
//! AuditRule: high-risk but legitimate operations (logged, not blocked).

use super::linux_parse::{LinuxParsedIntent, LinuxVerb};

// ============================================================
// Linux BlockRule — absolute interlock
// ============================================================

/// A rule that triggers absolute blocking when matched.
pub struct LinuxBlockRule {
    /// Human-readable rule name.
    pub name: &'static str,
    /// Matcher function.
    matcher: Box<dyn Fn(&LinuxParsedIntent) -> bool + Send + Sync>,
    /// Explanation for the block.
    explanation: &'static str,
}

impl LinuxBlockRule {
    /// Create a block rule from a pattern match on lowercased command.
    pub fn pattern(name: &'static str, pattern: &'static str, explanation: &'static str) -> Self {
        let pat = pattern.to_lowercase();
        Self {
            name,
            matcher: Box::new(move |intent: &LinuxParsedIntent| {
                intent.raw_lower.contains(&pat)
            }),
            explanation,
        }
    }

    /// Create a block rule from a custom matcher.
    pub fn custom<F>(name: &'static str, explanation: &'static str, f: F) -> Self
    where
        F: Fn(&LinuxParsedIntent) -> bool + Send + Sync + 'static,
    {
        Self {
            name,
            matcher: Box::new(f),
            explanation,
        }
    }

    /// Check if this rule matches.
    pub fn matches(&self, intent: &LinuxParsedIntent) -> bool {
        (self.matcher)(intent)
    }

    /// Generate explanation.
    pub fn explain(&self, _intent: &LinuxParsedIntent) -> String {
        format!("[{}] {}", self.name, self.explanation)
    }
}

// ============================================================
// Linux AuditRule — high-risk logging
// ============================================================

/// A rule that triggers audit logging when matched.
pub struct LinuxAuditRule {
    /// Category name.
    pub category: &'static str,
    /// Matcher function.
    matcher: Box<dyn Fn(&LinuxParsedIntent) -> bool + Send + Sync>,
}

impl LinuxAuditRule {
    /// Create an audit rule that matches by verb.
    pub fn by_verb(category: &'static str, verb: LinuxVerb) -> Self {
        Self {
            category,
            matcher: Box::new(move |intent: &LinuxParsedIntent| intent.verb == verb),
        }
    }

    /// Create an audit rule from a custom matcher.
    pub fn custom<F>(category: &'static str, f: F) -> Self
    where
        F: Fn(&LinuxParsedIntent) -> bool + Send + Sync + 'static,
    {
        Self {
            category,
            matcher: Box::new(f),
        }
    }

    /// Check if this rule matches.
    pub fn matches(&self, intent: &LinuxParsedIntent) -> bool {
        (self.matcher)(intent)
    }

    /// Generate audit explanation.
    pub fn explain(&self, intent: &LinuxParsedIntent) -> String {
        let targets_str = if intent.targets.is_empty() {
            "no specific target".to_string()
        } else {
            intent.targets.join(", ")
        };
        format!(
            "[audit:{}] verb={:?} targets=[{}] confidence={:.2}",
            self.category, intent.verb, targets_str, intent.confidence
        )
    }
}

// ============================================================
// Default rule sets
// ============================================================

/// Build the default Linux block rules.
///
/// These are catastrophic, irreversible operations that have NO
/// legitimate use case through an AI agent in IR scenarios.
pub fn default_linux_block_rules() -> Vec<LinuxBlockRule> {
    vec![
        // ═══ Root filesystem destruction ═══
        LinuxBlockRule::custom(
            "rm_rf_root",
            "root filesystem destruction (rm -rf /)",
            |intent: &LinuxParsedIntent| {
                intent.raw_lower.contains("rm ") && 
                (intent.raw_lower.contains(" -rf /") || 
                 intent.raw_lower.contains(" -rf /*") ||
                 intent.raw_lower.contains(" -r /") ||
                 intent.raw_lower.contains(" --recursive /"))
            },
        ),

        // ═══ Direct device write (dd to disk) ═══
        LinuxBlockRule::custom(
            "dd_to_disk",
            "direct write to disk device (irreversible data destruction)",
            |intent: &LinuxParsedIntent| {
                intent.verb == LinuxVerb::DeviceWrite
            },
        ),

        // ═══ Disk format operations ═══
        LinuxBlockRule::custom(
            "format_disk",
            "disk/partition format operation (irreversible)",
            |intent: &LinuxParsedIntent| {
                intent.verb == LinuxVerb::Format
            },
        ),

        // ═══ Security log destruction ═══
        LinuxBlockRule::custom(
            "destroy_security_logs",
            "security audit log destruction (attacker technique)",
            |intent: &LinuxParsedIntent| {
                let lower = &intent.raw_lower;
                // rm/truncate/echo > on auth.log, secure, audit.log
                (lower.contains("/var/log/auth") || lower.contains("/var/log/secure") 
                 || lower.contains("/var/log/audit"))
                && (lower.contains("rm ") || lower.contains("truncate") 
                    || lower.contains("echo >") || lower.contains("echo>")
                    || lower.contains(": >") || lower.contains("> /var/log"))
            },
        ),

        // ═══ Bootloader destruction ═══
        LinuxBlockRule::pattern(
            "grub_destroy",
            "grub",
            "bootloader modification/destruction",
        ),

        // ═══ Kernel panic / reboot triggers ═══
        LinuxBlockRule::pattern(
            "kernel_panic",
            "echo c > /proc/sysrq-trigger",
            "kernel panic trigger",
        ),
        LinuxBlockRule::pattern(
            "force_reboot",
            "echo b > /proc/sysrq-trigger",
            "force reboot trigger",
        ),

        // ═══ Fork bomb detection ═══
        LinuxBlockRule::custom(
            "fork_bomb",
            "fork bomb detected (system DoS)",
            |intent: &LinuxParsedIntent| {
                let lower = &intent.raw_lower;
                // :(){ :|:& };: pattern or similar
                (lower.contains(":(){") || lower.contains(": () {"))
                    && lower.contains(":|:")
            },
        ),

        // ═══ /dev/null redirect to critical device ═══
        LinuxBlockRule::custom(
            "null_to_disk",
            "overwrite disk with /dev/null (data destruction)",
            |intent: &LinuxParsedIntent| {
                intent.raw_lower.contains("dd if=/dev/null of=/dev/")
            },
        ),
    ]
}

/// Build the default Linux audit rules.
/// These log high-risk operations but never block them.
pub fn default_linux_audit_rules() -> Vec<LinuxAuditRule> {
    vec![
        // File/directory deletion
        LinuxAuditRule::by_verb("file_deletion", LinuxVerb::Delete),
        // Process/service termination
        LinuxAuditRule::by_verb("process_stop", LinuxVerb::Stop),
        // Service/firewall disable
        LinuxAuditRule::by_verb("disable_operation", LinuxVerb::Disable),
        // System config write
        LinuxAuditRule::by_verb("config_write", LinuxVerb::Write),
        // Log clearing (non-security)
        LinuxAuditRule::by_verb("log_clear", LinuxVerb::ClearLog),
        // Mount/unmount operations
        LinuxAuditRule::by_verb("mount_operation", LinuxVerb::Mount),
        // Low-confidence / unparseable commands
        LinuxAuditRule::custom("unparseable_command", |intent: &LinuxParsedIntent| {
            intent.confidence < 0.5 && intent.verb == LinuxVerb::Unknown
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::linux_parse::parse_linux_intent;

    #[test]
    fn test_block_rm_rf_root() {
        let rules = default_linux_block_rules();
        let intent = parse_linux_intent("rm -rf /");
        assert!(rules.iter().any(|r| r.matches(&intent)));
    }

    #[test]
    fn test_block_dd_to_disk() {
        let rules = default_linux_block_rules();
        let intent = parse_linux_intent("dd if=/dev/zero of=/dev/sda bs=4M");
        assert!(rules.iter().any(|r| r.matches(&intent)));
    }

    #[test]
    fn test_block_mkfs() {
        let rules = default_linux_block_rules();
        let intent = parse_linux_intent("mkfs.ext4 /dev/sda1");
        assert!(rules.iter().any(|r| r.matches(&intent)));
    }

    #[test]
    fn test_no_block_rm_file() {
        // Normal file deletion should NOT be blocked (audit-level only)
        let rules = default_linux_block_rules();
        let intent = parse_linux_intent("rm /tmp/malware.sh");
        assert!(!rules.iter().any(|r| r.matches(&intent)));
    }

    #[test]
    fn test_audit_rm_file() {
        let rules = default_linux_audit_rules();
        let intent = parse_linux_intent("rm /tmp/malware.sh");
        assert!(rules.iter().any(|r| r.matches(&intent)));
    }

    #[test]
    fn test_no_audit_read() {
        // Read operations should NOT trigger audit
        let rules = default_linux_audit_rules();
        let intent = parse_linux_intent("ps aux | grep sshd");
        assert!(!rules.iter().any(|r| r.matches(&intent)));
    }
}
