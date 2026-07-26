//! Policy rules — BlockRule (absolute interlock) and AuditRule (logging).
//!
//! BlockRule: matches catastrophic irreversible operations. Cannot be overridden
//! by any permission state. The list must be EXTREMELY narrow — only operations
//! that have NO legitimate IR/admin use case.
//!
//! AuditRule: matches high-risk but legitimate operations. Logged for traceability
//! but never blocked. When Permission is already granted, these are transparent.

use super::parse::{ParsedIntent, Verb};

// ============================================================
// BlockRule — absolute interlock (the "fuse")
// ============================================================

/// A rule that triggers absolute blocking when matched.
/// These operations are irreversible and have no legitimate use case through an AI agent.
pub struct BlockRule {
    /// Human-readable rule name for logging.
    pub name: &'static str,
    /// Matcher function: returns true if the intent matches this block rule.
    matcher: Box<dyn Fn(&ParsedIntent) -> bool + Send + Sync>,
    /// Explanation template for the block reason.
    explanation: &'static str,
}

impl BlockRule {
    /// Create a block rule that matches a specific cmdlet name (case-insensitive).
    pub fn cmdlet(name: &'static str, cmdlet: &'static str) -> Self {
        let cmdlet_lower = cmdlet.to_lowercase();
        Self {
            name,
            matcher: Box::new(move |intent: &ParsedIntent| {
                intent.raw_lower.contains(&cmdlet_lower)
            }),
            explanation: "irreversible disk/volume operation with no legitimate agent use case",
        }
    }

    /// Create a block rule that matches a cmdlet with specific arguments.
    pub fn cmdlet_with_arg(name: &'static str, cmdlet: &'static str, arg_pattern: &'static str) -> Self {
        let cmdlet_lower = cmdlet.to_lowercase();
        let arg_lower = arg_pattern.to_lowercase();
        Self {
            name,
            matcher: Box::new(move |intent: &ParsedIntent| {
                intent.raw_lower.contains(&cmdlet_lower) && intent.raw_lower.contains(&arg_lower)
            }),
            explanation: "destruction of security audit trail",
        }
    }

    /// Create a block rule from a raw pattern (substring match on lowercased command).
    pub fn pattern(name: &'static str, pattern: &'static str, explanation: &'static str) -> Self {
        let pat = pattern.to_lowercase();
        Self {
            name,
            matcher: Box::new(move |intent: &ParsedIntent| {
                intent.raw_lower.contains(&pat)
            }),
            explanation,
        }
    }

    /// Create a block rule for encoded/obfuscated commands.
    pub fn encoded_commands() -> Self {
        Self {
            name: "encoded_command",
            matcher: Box::new(|intent: &ParsedIntent| intent.is_encoded),
            explanation: "encoded/obfuscated commands cannot be verified for safety",
        }
    }

    /// Check if this rule matches the given intent.
    pub fn matches(&self, intent: &ParsedIntent) -> bool {
        (self.matcher)(intent)
    }

    /// Generate a human-readable explanation for the block.
    pub fn explain(&self, _intent: &ParsedIntent) -> String {
        format!(
            "[{}] {}: command contains irreversible operation",
            self.name, self.explanation
        )
    }
}

// ============================================================
// AuditRule — high-risk logging (transparent to user)
// ============================================================

/// A rule that triggers audit logging when matched.
/// These operations are high-risk but legitimate — they are logged, never blocked.
pub struct AuditRule {
    /// Human-readable category name.
    pub category: &'static str,
    /// Matcher function.
    matcher: Box<dyn Fn(&ParsedIntent) -> bool + Send + Sync>,
}

impl AuditRule {
    /// Create an audit rule that matches by verb.
    pub fn by_verb(category: &'static str, verb: Verb) -> Self {
        Self {
            category,
            matcher: Box::new(move |intent: &ParsedIntent| intent.verb == verb),
        }
    }

    /// Create an audit rule for unparseable/low-confidence commands.
    pub fn low_confidence(category: &'static str, threshold: f64) -> Self {
        Self {
            category,
            matcher: Box::new(move |intent: &ParsedIntent| {
                intent.confidence < threshold && intent.verb == Verb::Unknown
            }),
        }
    }

    /// Create an audit rule from a custom matcher.
    pub fn custom<F>(category: &'static str, f: F) -> Self
    where
        F: Fn(&ParsedIntent) -> bool + Send + Sync + 'static,
    {
        Self {
            category,
            matcher: Box::new(f),
        }
    }

    /// Check if this rule matches the given intent.
    pub fn matches(&self, intent: &ParsedIntent) -> bool {
        (self.matcher)(intent)
    }

    /// Generate audit explanation.
    pub fn explain(&self, intent: &ParsedIntent) -> String {
        let targets_str = if intent.targets.is_empty() {
            "unknown target".to_string()
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

/// Build the default absolute block rules.
///
/// Admission criteria for block rules:
/// 1. IRREVERSIBLE — cannot be undone after execution
/// 2. NO legitimate IR/admin use case through an AI agent
/// 3. Near-zero false positive probability
pub fn default_block_rules() -> Vec<BlockRule> {
    vec![
        // ═══ Disk/Volume destruction (irreversible) ═══
        BlockRule::cmdlet("format_volume", "Format-Volume"),
        BlockRule::cmdlet("clear_disk", "Clear-Disk"),
        BlockRule::cmdlet("initialize_disk", "Initialize-Disk"),
        BlockRule::pattern(
            "cmd_format",
            "format ",
            "disk format operation",
        ),
        BlockRule::pattern(
            "diskpart_clean",
            "clean all",
            "diskpart full disk wipe",
        ),
        // ═══ Security log destruction (attacker-only operation) ═══
        BlockRule::cmdlet_with_arg(
            "clear_security_log",
            "Clear-EventLog",
            "security",
        ),
        BlockRule::pattern(
            "wevtutil_clear_security",
            "wevtutil cl security",
            "security event log destruction",
        ),
        BlockRule::pattern(
            "wevtutil_clear_security2",
            "wevtutil clear-log security",
            "security event log destruction",
        ),
        // ═══ Boot/MBR destruction ═══
        BlockRule::pattern(
            "bcdedit_delete",
            "bcdedit /delete",
            "boot configuration destruction",
        ),
        BlockRule::pattern(
            "bootrec_wipe",
            "bootrec /wipe",
            "boot record destruction",
        ),
        // ═══ Physical device direct access ═══
        BlockRule::pattern(
            "physical_drive",
            "\\\\?\\physicaldrive",
            "direct physical disk access",
        ),
        BlockRule::pattern(
            "harddisk_device",
            "\\device\\harddisk",
            "direct disk device access",
        ),
        // ═══ Encoded/obfuscated commands (cannot verify safety) ═══
        BlockRule::encoded_commands(),
    ]
}

/// Build the default audit rules.
/// These log high-risk operations but never block them.
pub fn default_audit_rules() -> Vec<AuditRule> {
    vec![
        // File/directory deletion
        AuditRule::by_verb("file_deletion", Verb::Delete),
        // Process/service termination
        AuditRule::by_verb("process_service_stop", Verb::Stop),
        // Network/system feature disable
        AuditRule::by_verb("disable_operation", Verb::Disable),
        // Registry/file write operations
        AuditRule::by_verb("write_operation", Verb::Write),
        // Event log clearing (non-security)
        AuditRule::by_verb("log_clear", Verb::ClearLog),
        // Low-confidence / unparseable commands
        AuditRule::low_confidence("unparseable_command", 0.5),
        // Nested shell invocations (potential indirection)
        AuditRule::custom("nested_shell", |intent: &ParsedIntent| {
            intent.has_nested_shell
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::parse::parse_intent;

    #[test]
    fn test_block_format_volume() {
        let rules = default_block_rules();
        let intent = parse_intent("Format-Volume -DriveLetter C -FileSystem NTFS -Force", "powershell");
        assert!(rules.iter().any(|r| r.matches(&intent)));
    }

    #[test]
    fn test_block_clear_security_log() {
        let rules = default_block_rules();
        let intent = parse_intent("Clear-EventLog -LogName Security", "powershell");
        assert!(rules.iter().any(|r| r.matches(&intent)));
    }

    #[test]
    fn test_no_block_clear_system_log() {
        // Clearing System log is NOT blocked (only Security is)
        let rules = default_block_rules();
        let intent = parse_intent("Clear-EventLog -LogName System", "powershell");
        assert!(!rules.iter().any(|r| r.matches(&intent)));
    }

    #[test]
    fn test_no_block_remove_item() {
        // Remove-Item should NOT be blocked (it's audit-level)
        let rules = default_block_rules();
        let intent = parse_intent("Remove-Item 'C:\\Users\\Public\\malware.exe' -Force", "powershell");
        assert!(!rules.iter().any(|r| r.matches(&intent)));
    }

    #[test]
    fn test_audit_delete() {
        let rules = default_audit_rules();
        let intent = parse_intent("Remove-Item 'C:\\Temp\\junk.tmp'", "powershell");
        assert!(rules.iter().any(|r| r.matches(&intent)));
    }

    #[test]
    fn test_no_audit_read() {
        let rules = default_audit_rules();
        let intent = parse_intent("Get-Process | Select-Object Name, CPU", "powershell");
        assert!(!rules.iter().any(|r| r.matches(&intent)));
    }

    #[test]
    fn test_block_encoded() {
        let rules = default_block_rules();
        let intent = parse_intent("powershell -EncodedCommand RwBlAHQALgAuAC4A", "powershell");
        assert!(rules.iter().any(|r| r.matches(&intent)));
    }
}
