//! Lightweight command intent parser.
//!
//! Parses PowerShell and CMD commands into structured intent (verb + targets)
//! without requiring a full PowerShell AST parser. Uses heuristic tokenization
//! to identify the primary action and its targets.
//!
//! Design: conservative — when parsing confidence is low, the command is marked
//! as "uncertain" so rules can choose to escalate rather than pass silently.

/// The parsed semantic intent of a command.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ParsedIntent {
    /// Primary action verb detected in the command.
    pub verb: Verb,
    /// Target paths/names extracted from the command.
    pub targets: Vec<String>,
    /// The original raw command string (lowercased for matching).
    pub raw_lower: String,
    /// Original command (preserved case).
    pub raw: String,
    /// Shell type: "powershell" or "cmd".
    pub shell: String,
    /// Parsing confidence: 0.0 (pure guess) to 1.0 (clear cmdlet match).
    pub confidence: f64,
    /// Whether the command contains encoded/obfuscated content.
    pub is_encoded: bool,
    /// Whether the command uses nested shell invocation.
    pub has_nested_shell: bool,
}

/// Semantic verb categories for command classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Verb {
    /// Delete/remove files, directories, registry keys
    Delete,
    /// Format/clear disk or volume
    Format,
    /// Stop/kill process or service
    Stop,
    /// Disable adapter, feature, service
    Disable,
    /// Write/modify content
    Write,
    /// Read/query information
    Read,
    /// Execute/run a program
    Execute,
    /// Clear event logs
    ClearLog,
    /// Could not determine
    Unknown,
}

/// Parse a command string into structured intent.
pub fn parse_intent(command: &str, shell: &str) -> ParsedIntent {
    let raw_lower = command.to_lowercase();
    let is_encoded = detect_encoded(&raw_lower);
    let has_nested_shell = detect_nested_shell(&raw_lower);

    let (verb, confidence) = if shell == "cmd" {
        parse_cmd_verb(&raw_lower)
    } else {
        parse_ps_verb(&raw_lower)
    };

    let targets = extract_targets(command, shell);

    ParsedIntent {
        verb,
        targets,
        raw_lower,
        raw: command.to_string(),
        shell: shell.to_string(),
        confidence,
        is_encoded,
        has_nested_shell,
    }
}

/// Detect encoded/obfuscated command content.
fn detect_encoded(cmd_lower: &str) -> bool {
    cmd_lower.contains("-encodedcommand")
        || cmd_lower.contains("-enc ")
        || cmd_lower.contains("-e ")  // short form, but risky for false positives
        || cmd_lower.contains("frombase64string")
        || cmd_lower.contains("invoke-expression")
        || cmd_lower.contains("iex ")
        || cmd_lower.contains("iex(")
}

/// Detect nested shell invocation (cmd within ps, or ps within cmd).
fn detect_nested_shell(cmd_lower: &str) -> bool {
    cmd_lower.contains("cmd /c")
        || cmd_lower.contains("cmd.exe /c")
        || cmd_lower.contains("powershell -command")
        || cmd_lower.contains("powershell -c ")
}

/// Parse PowerShell command verb using cmdlet name matching.
fn parse_ps_verb(cmd_lower: &str) -> (Verb, f64) {
    // Check for catastrophic verbs first (highest priority)
    if contains_word(cmd_lower, "format-volume")
        || contains_word(cmd_lower, "clear-disk")
        || contains_word(cmd_lower, "initialize-disk")
    {
        return (Verb::Format, 0.95);
    }

    // Clear event log
    if contains_word(cmd_lower, "clear-eventlog")
        || contains_word(cmd_lower, "clear-windowseventlog")
    {
        return (Verb::ClearLog, 0.95);
    }

    // Delete/Remove
    if contains_word(cmd_lower, "remove-item")
        || contains_word(cmd_lower, "remove-itemproperty")
        || contains_word(cmd_lower, "del ")
        || contains_word(cmd_lower, "rm ")
        || contains_word(cmd_lower, "ri ")
        || contains_word(cmd_lower, "erase ")
        || contains_word(cmd_lower, "rmdir ")
        || contains_word(cmd_lower, "rd ")
    {
        return (Verb::Delete, 0.9);
    }

    // .NET deletion methods
    if cmd_lower.contains("[system.io.file]::delete")
        || cmd_lower.contains("[system.io.directory]::delete")
        || cmd_lower.contains("[io.file]::delete")
        || cmd_lower.contains("[io.directory]::delete")
        || cmd_lower.contains(".delete(")
    {
        return (Verb::Delete, 0.85);
    }

    // Stop/Kill
    if contains_word(cmd_lower, "stop-process")
        || contains_word(cmd_lower, "stop-service")
        || contains_word(cmd_lower, "stop-computer")
        || contains_word(cmd_lower, "kill ")
        || contains_word(cmd_lower, "spps ")
    {
        return (Verb::Stop, 0.9);
    }

    // Disable
    if contains_word(cmd_lower, "disable-netadapter")
        || contains_word(cmd_lower, "disable-windowsoptionalfeature")
        || contains_word(cmd_lower, "disable-scheduledtask")
        || contains_word(cmd_lower, "disable-localuser")
    {
        return (Verb::Disable, 0.9);
    }

    // Write/Modify
    if contains_word(cmd_lower, "set-content")
        || contains_word(cmd_lower, "set-itemproperty")
        || contains_word(cmd_lower, "add-content")
        || contains_word(cmd_lower, "out-file")
        || contains_word(cmd_lower, "new-item")
        || contains_word(cmd_lower, "copy-item")
        || contains_word(cmd_lower, "move-item")
        || contains_word(cmd_lower, "rename-item")
    {
        return (Verb::Write, 0.85);
    }

    // Read/Query (most common, lowest risk)
    // Use prefix matching for wildcard cmdlet families (Get-*, Select-*, etc.)
    if contains_cmdlet_prefix(cmd_lower, "get-")
        || contains_cmdlet_prefix(cmd_lower, "select-")
        || contains_cmdlet_prefix(cmd_lower, "where-")
        || contains_cmdlet_prefix(cmd_lower, "measure-")
        || contains_cmdlet_prefix(cmd_lower, "test-")
        || contains_cmdlet_prefix(cmd_lower, "find-")
        || contains_cmdlet_prefix(cmd_lower, "search-")
        || contains_cmdlet_prefix(cmd_lower, "show-")
        || contains_cmdlet_prefix(cmd_lower, "export-")
        || contains_cmdlet_prefix(cmd_lower, "convertto-")
        || contains_cmdlet_prefix(cmd_lower, "format-table")
        || contains_cmdlet_prefix(cmd_lower, "format-list")
        || contains_cmdlet_prefix(cmd_lower, "sort-object")
    {
        return (Verb::Read, 0.9);
    }

    // Format (CMD-style within PS)
    if contains_word(cmd_lower, "format ") && cmd_lower.contains(":\\") {
        return (Verb::Format, 0.8);
    }

    (Verb::Unknown, 0.3)
}

/// Parse CMD command verb.
fn parse_cmd_verb(cmd_lower: &str) -> (Verb, f64) {
    let trimmed = cmd_lower.trim();

    // Format command
    if trimmed.starts_with("format ") || trimmed.contains(" format ") {
        return (Verb::Format, 0.9);
    }

    // DiskPart
    if trimmed.contains("diskpart") && trimmed.contains("clean") {
        return (Verb::Format, 0.9);
    }

    // Event log clearing
    if trimmed.contains("wevtutil") && (trimmed.contains(" cl ") || trimmed.contains(" clear-log")) {
        return (Verb::ClearLog, 0.9);
    }

    // Delete operations
    if trimmed.starts_with("del ")
        || trimmed.starts_with("erase ")
        || trimmed.starts_with("rd ")
        || trimmed.starts_with("rmdir ")
        || trimmed.contains(" del ")
        || trimmed.contains(" erase ")
        || trimmed.contains(" rd ")
        || trimmed.contains(" rmdir ")
    {
        return (Verb::Delete, 0.9);
    }

    // Kill
    if trimmed.starts_with("taskkill") || trimmed.contains(" taskkill") {
        return (Verb::Stop, 0.9);
    }

    // Service control
    if trimmed.starts_with("sc ") || trimmed.contains(" sc ") {
        if trimmed.contains(" stop ") || trimmed.contains(" delete ") || trimmed.contains(" config ") {
            return (Verb::Stop, 0.85);
        }
    }

    // Net stop
    if trimmed.contains("net stop") || trimmed.contains("net1 stop") {
        return (Verb::Stop, 0.9);
    }

    // Registry
    if trimmed.starts_with("reg ") || trimmed.contains(" reg ") {
        if trimmed.contains(" delete ") || trimmed.contains(" add ") {
            return (Verb::Write, 0.85);
        }
        return (Verb::Read, 0.8);
    }

    // Read-only commands
    let read_cmds = ["dir", "type", "find", "findstr", "netstat", "ipconfig", "whoami",
                     "systeminfo", "tasklist", "sc query", "wmic", "certutil -urlcache"];
    for rc in &read_cmds {
        if trimmed.starts_with(rc) || trimmed.contains(&format!(" {} ", rc)) {
            return (Verb::Read, 0.85);
        }
    }

    (Verb::Unknown, 0.3)
}

/// Extract target paths/names from the command (best-effort).
fn extract_targets(command: &str, shell: &str) -> Vec<String> {
    let mut targets = Vec::new();

    // Extract quoted strings (likely paths)
    let mut in_quote = false;
    let mut quote_char = ' ';
    let mut current = String::new();
    for ch in command.chars() {
        if !in_quote && (ch == '\'' || ch == '"') {
            in_quote = true;
            quote_char = ch;
            current.clear();
        } else if in_quote && ch == quote_char {
            in_quote = false;
            if !current.is_empty() {
                targets.push(current.clone());
            }
        } else if in_quote {
            current.push(ch);
        }
    }

    // Extract drive-letter paths (e.g., C:\something)
    let lower = command.to_lowercase();
    for segment in lower.split_whitespace() {
        let seg = segment.trim_matches(|c| c == '\'' || c == '"' || c == ',' || c == ';');
        if seg.len() >= 3 && seg.as_bytes()[1] == b':' && seg.as_bytes()[2] == b'\\' {
            if !targets.iter().any(|t| t.to_lowercase() == seg) {
                targets.push(seg.to_string());
            }
        }
    }

    // For CMD: extract paths after command keywords
    if shell == "cmd" {
        let parts: Vec<&str> = command.split_whitespace().collect();
        for (i, part) in parts.iter().enumerate() {
            let p = part.to_lowercase();
            if (p == "del" || p == "erase" || p == "rd" || p == "rmdir" || p == "format") && i + 1 < parts.len() {
                let target = parts[i + 1].trim_matches('"');
                if !target.starts_with('/') && !targets.iter().any(|t| t == target) {
                    targets.push(target.to_string());
                }
            }
        }
    }

    targets
}

/// Check if a command string contains a word/cmdlet (with boundary awareness).
/// Matches if the pattern appears preceded by start-of-string, whitespace, or pipe,
/// and followed by whitespace, end-of-string, or typical PS delimiters.
fn contains_word(cmd_lower: &str, pattern: &str) -> bool {
    // Simple but effective: check if pattern exists with word boundaries
    if let Some(pos) = cmd_lower.find(pattern) {
        let before_ok = pos == 0
            || cmd_lower.as_bytes()[pos - 1] == b' '
            || cmd_lower.as_bytes()[pos - 1] == b'|'
            || cmd_lower.as_bytes()[pos - 1] == b';'
            || cmd_lower.as_bytes()[pos - 1] == b'&'
            || cmd_lower.as_bytes()[pos - 1] == b'{'
            || cmd_lower.as_bytes()[pos - 1] == b'(';
        let end_pos = pos + pattern.len();
        let after_ok = end_pos >= cmd_lower.len()
            || cmd_lower.as_bytes()[end_pos] == b' '
            || cmd_lower.as_bytes()[end_pos] == b'\t'
            || cmd_lower.as_bytes()[end_pos] == b'\r'
            || cmd_lower.as_bytes()[end_pos] == b'\n'
            || cmd_lower.as_bytes()[end_pos] == b';'
            || cmd_lower.as_bytes()[end_pos] == b'|'
            || cmd_lower.as_bytes()[end_pos] == b')'
            || cmd_lower.as_bytes()[end_pos] == b'}';
        before_ok && after_ok
    } else {
        false
    }
}

/// Check if a command contains a cmdlet prefix (e.g., "get-" matches "get-process").
/// Only requires a word boundary BEFORE the prefix, not after (since the prefix
/// is followed by the cmdlet noun: get-<Noun>, select-<Noun>, etc.).
fn contains_cmdlet_prefix(cmd_lower: &str, prefix: &str) -> bool {
    let mut search_from = 0;
    while let Some(pos) = cmd_lower[search_from..].find(prefix) {
        let abs_pos = search_from + pos;
        let before_ok = abs_pos == 0
            || cmd_lower.as_bytes()[abs_pos - 1] == b' '
            || cmd_lower.as_bytes()[abs_pos - 1] == b'|'
            || cmd_lower.as_bytes()[abs_pos - 1] == b';'
            || cmd_lower.as_bytes()[abs_pos - 1] == b'&'
            || cmd_lower.as_bytes()[abs_pos - 1] == b'{'
            || cmd_lower.as_bytes()[abs_pos - 1] == b'('
            || cmd_lower.as_bytes()[abs_pos - 1] == b'\n'
            || cmd_lower.as_bytes()[abs_pos - 1] == b'\r';
        if before_ok {
            return true;
        }
        search_from = abs_pos + 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ps_delete() {
        let intent = parse_intent("Remove-Item 'C:\\Temp\\junk.tmp' -Force", "powershell");
        assert_eq!(intent.verb, Verb::Delete);
        assert!(intent.confidence > 0.8);
        assert!(intent.targets.iter().any(|t| t.contains("junk.tmp")));
    }

    #[test]
    fn test_parse_ps_read() {
        let intent = parse_intent("Get-Process | Sort-Object CPU -Descending", "powershell");
        assert_eq!(intent.verb, Verb::Read);
    }

    #[test]
    fn test_parse_cmd_format() {
        let intent = parse_intent("format C: /fs:ntfs /q", "cmd");
        assert_eq!(intent.verb, Verb::Format);
    }

    #[test]
    fn test_parse_encoded() {
        let intent = parse_intent("powershell -EncodedCommand RwBlAHQA", "powershell");
        assert!(intent.is_encoded);
    }

    #[test]
    fn test_parse_cmd_delete() {
        let intent = parse_intent("del /f /q C:\\Temp\\*.tmp", "cmd");
        assert_eq!(intent.verb, Verb::Delete);
    }

    #[test]
    fn test_parse_stop_service() {
        let intent = parse_intent("Stop-Service -Name 'W3SVC' -Force", "powershell");
        assert_eq!(intent.verb, Verb::Stop);
    }
}
