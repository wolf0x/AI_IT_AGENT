//! Linux command intent parser for SSH safety policy.
//!
//! Parses bash/sh commands into structured intent for safety evaluation.
//! Designed for IR scenarios where legitimate admin operations must be
//! distinguished from catastrophic destructive commands.

/// Parsed Linux command intent.
#[derive(Debug, Clone)]
pub struct LinuxParsedIntent {
    /// Primary action verb detected.
    pub verb: LinuxVerb,
    /// Target paths/devices extracted.
    pub targets: Vec<String>,
    /// Original command (lowercased).
    pub raw_lower: String,
    /// Original command (preserved case).
    pub raw: String,
    /// Parsing confidence: 0.0 to 1.0.
    pub confidence: f64,
    /// Whether command contains pipe chains (potential for complex operations).
    pub has_pipe_chain: bool,
    /// Whether command redirects to a device.
    pub has_device_redirect: bool,
}

/// Linux command verb categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVerb {
    /// Delete/remove files (rm, unlink)
    Delete,
    /// Format disk/partition (mkfs, mkext4, etc.)
    Format,
    /// Write directly to device (dd to /dev/sd*, etc.)
    DeviceWrite,
    /// Stop/kill process (kill, pkill, systemctl stop)
    Stop,
    /// Disable service/firewall (systemctl disable, ufw disable)
    Disable,
    /// Modify system config (echo > /etc/*, sed -i, etc.)
    Write,
    /// Read/query information (ls, cat, ps, netstat, etc.)
    Read,
    /// Execute/run a program
    Execute,
    /// Clear/truncate logs (truncate, echo > /var/log/*)
    ClearLog,
    /// Mount/unmount filesystems
    Mount,
    /// Could not determine
    Unknown,
}

/// Parse a Linux/bash command into structured intent.
pub fn parse_linux_intent(command: &str) -> LinuxParsedIntent {
    let raw_lower = command.to_lowercase();
    let has_pipe_chain = raw_lower.contains('|');
    let has_device_redirect = raw_lower.contains(">/dev/") || raw_lower.contains("> /dev/");

    let (verb, confidence) = parse_linux_verb(&raw_lower);
    let targets = extract_linux_targets(command);

    LinuxParsedIntent {
        verb,
        targets,
        raw_lower,
        raw: command.to_string(),
        confidence,
        has_pipe_chain,
        has_device_redirect,
    }
}

/// Parse Linux command verb.
fn parse_linux_verb(cmd: &str) -> (LinuxVerb, f64) {
    let cmd = cmd.trim();

    // ═══ CATASTROPHIC: Direct device destruction ═══
    // dd writing to disk devices
    if cmd.contains("dd ") && (cmd.contains("of=/dev/sd") || cmd.contains("of=/dev/hd") 
        || cmd.contains("of=/dev/nvme") || cmd.contains("of=/dev/xvd"))
    {
        return (LinuxVerb::DeviceWrite, 0.98);
    }

    // ═══ CATASTROPHIC: Format operations ═══
    let format_cmds = [
        "mkfs.", "mkfs ", "mke2fs", "mkext4", "mkxfs", "mkswap",
        "fdisk ", "parted ", "gdisk ",
    ];
    for fc in &format_cmds {
        if cmd.contains(fc) {
            return (LinuxVerb::Format, 0.95);
        }
    }

    // ═══ CATASTROPHIC: Wipe/shred entire disk ═══
    if (cmd.contains("shred ") || cmd.contains("wipe ")) 
        && (cmd.contains("/dev/sd") || cmd.contains("/dev/hd") || cmd.contains("/dev/nvme"))
    {
        return (LinuxVerb::DeviceWrite, 0.95);
    }

    // ═══ Security log destruction ═══
    if cmd.contains("/var/log/") && (cmd.contains("rm ") || cmd.contains("truncate") 
        || cmd.contains("echo >") || cmd.contains("echo>") || cmd.contains(": >"))
    {
        return (LinuxVerb::ClearLog, 0.9);
    }

    // ═══ DELETE operations ═══
    // rm -rf / (root filesystem destruction)
    if cmd.contains("rm ") && (cmd.contains(" -rf /") || cmd.contains(" -rf /*") 
        || cmd.contains(" -r /") || cmd.contains(" --recursive /"))
    {
        return (LinuxVerb::Delete, 0.98);
    }
    // Normal rm
    if cmd.starts_with("rm ") || cmd.contains(" rm ") || cmd.contains(" rm\t")
        || cmd.starts_with("unlink ") || cmd.contains(" unlink ")
    {
        return (LinuxVerb::Delete, 0.85);
    }

    // ═══ MOUNT/UNMOUNT ═══
    if cmd.starts_with("mount ") || cmd.contains(" mount ") 
        || cmd.starts_with("umount ") || cmd.contains(" umount ")
    {
        return (LinuxVerb::Mount, 0.85);
    }

    // ═══ STOP/KILL operations ═══
    let stop_patterns = [
        "kill ", "killall ", "pkill ", 
        "systemctl stop", "systemctl kill",
        "service ", "stop ",
    ];
    for sp in &stop_patterns {
        if cmd.contains(sp) {
            // Check if it's actually systemctl start/enable (not stop)
            if cmd.contains("systemctl start") || cmd.contains("systemctl enable") {
                return (LinuxVerb::Execute, 0.8);
            }
            return (LinuxVerb::Stop, 0.85);
        }
    }

    // ═══ DISABLE operations ═══
    if cmd.contains("systemctl disable") || cmd.contains("systemctl mask")
        || cmd.contains("ufw disable") || cmd.contains("iptables -f")
    {
        return (LinuxVerb::Disable, 0.9);
    }

    // ═══ WRITE operations (modify system config) ═══
    if cmd.contains("echo ") && cmd.contains(">/etc/") || cmd.contains("echo > /etc/")
        || cmd.contains("sed -i") || cmd.contains("tee /etc/")
    {
        return (LinuxVerb::Write, 0.85);
    }

    // ═══ READ operations (most common, lowest risk) ═══
    let read_cmds = [
        "ls", "cat ", "head ", "tail ", "less ", "more ",
        "ps ", "top", "htop", "netstat ", "ss ", "ip ",
        "whoami", "id", "uname", "hostname", "uptime",
        "find ", "grep ", "awk ", "sed ", "cut ",
        "df ", "du ", "free ", "vmstat", "iostat",
        "journalctl", "dmesg", "last ", "lastlog",
        "wget ", "curl ",  // downloading for analysis
    ];
    for rc in &read_cmds {
        if cmd.starts_with(rc) || cmd.contains(&format!(" {} ", rc)) || cmd.contains(&format!(" {}|", rc)) {
            return (LinuxVerb::Read, 0.85);
        }
    }

    // ═══ EXECUTE operations ═══
    let exec_cmds = [
        "systemctl start", "systemctl enable", "systemctl restart",
        "service start", "./", "bash ", "sh ", "python", "perl",
        "apt ", "apt-get ", "yum ", "dnf ", "pacman ",
        "chmod ", "chown ",
    ];
    for ec in &exec_cmds {
        if cmd.contains(ec) {
            return (LinuxVerb::Execute, 0.8);
        }
    }

    (LinuxVerb::Unknown, 0.3)
}

/// Extract target paths/devices from command.
fn extract_linux_targets(command: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let lower = command.to_lowercase();

    // Extract /dev/* paths
    for word in lower.split_whitespace() {
        let trimmed = word.trim_matches(|c: char| c == '\'' || c == '"' || c == ';' || c == '|');
        if trimmed.starts_with("/dev/") {
            if !targets.iter().any(|t| t == trimmed) {
                targets.push(trimmed.to_string());
            }
        }
    }

    // Extract /etc/* paths (config modifications)
    for word in lower.split_whitespace() {
        let trimmed = word.trim_matches(|c: char| c == '\'' || c == '"' || c == ';' || c == '|');
        if trimmed.starts_with("/etc/") && !targets.iter().any(|t| t == trimmed) {
            targets.push(trimmed.to_string());
        }
    }

    // Extract /var/log/* paths (log operations)
    for word in lower.split_whitespace() {
        let trimmed = word.trim_matches(|c: char| c == '\'' || c == '"' || c == ';' || c == '|');
        if trimmed.starts_with("/var/log/") && !targets.iter().any(|t| t == trimmed) {
            targets.push(trimmed.to_string());
        }
    }

    // Extract absolute paths that look like targets
    for word in command.split_whitespace() {
        let trimmed = word.trim_matches(|c: char| c == '\'' || c == '"' || c == ';' || c == '|');
        if trimmed.starts_with('/') && trimmed.len() > 4 
            && !trimmed.starts_with("/dev/") && !trimmed.starts_with("/etc/")
            && !trimmed.starts_with("/var/log/") && !trimmed.starts_with("/usr/")
            && !trimmed.starts_with("/bin/") && !trimmed.starts_with("/sbin/")
            && !targets.iter().any(|t| t == trimmed)
        {
            targets.push(trimmed.to_string());
        }
    }

    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rm_file() {
        let intent = parse_linux_intent("rm /tmp/malware.sh");
        assert_eq!(intent.verb, LinuxVerb::Delete);
        assert!(intent.confidence > 0.8);
    }

    #[test]
    fn test_parse_rm_rf_root() {
        let intent = parse_linux_intent("rm -rf /");
        assert_eq!(intent.verb, LinuxVerb::Delete);
        assert!(intent.confidence > 0.95);
    }

    #[test]
    fn test_parse_dd_to_device() {
        let intent = parse_linux_intent("dd if=/dev/zero of=/dev/sda bs=4M");
        assert_eq!(intent.verb, LinuxVerb::DeviceWrite);
        assert!(intent.confidence > 0.95);
    }

    #[test]
    fn test_parse_mkfs() {
        let intent = parse_linux_intent("mkfs.ext4 /dev/sda1");
        assert_eq!(intent.verb, LinuxVerb::Format);
        assert!(intent.confidence > 0.9);
    }

    #[test]
    fn test_parse_log_destruction() {
        let intent = parse_linux_intent("rm /var/log/auth.log");
        assert_eq!(intent.verb, LinuxVerb::ClearLog);
    }

    #[test]
    fn test_parse_read_command() {
        let intent = parse_linux_intent("ps aux | grep sshd");
        assert_eq!(intent.verb, LinuxVerb::Read);
    }

    #[test]
    fn test_parse_kill_process() {
        let intent = parse_linux_intent("kill -9 1234");
        assert_eq!(intent.verb, LinuxVerb::Stop);
    }
}
