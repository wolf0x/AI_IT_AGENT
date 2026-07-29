//! Linux IR — Auth Analysis (M12, M17)
//! Detects privilege escalation artifacts, suspicious accounts.

use super::linux_ir_common::*;

pub struct AuthCategory;

static MODULES: &[ModuleDef] = &[
    ModuleDef {
        id: 12,
        name: "auth_privilege",
        description: "Check for privilege escalation artifacts",
        commands: &[
            "cat /etc/sudoers 2>/dev/null; ls -la /etc/sudoers.d/ 2>/dev/null",
            "find / -perm -4000 -type f 2>/dev/null | xargs ls -la 2>/dev/null | head -30",
            "getcap -r / 2>/dev/null | head -20",
        ],
    },
    ModuleDef {
        id: 17,
        name: "auth_accounts",
        description: "Check for suspicious accounts",
        commands: &[
            "cat /etc/passwd | grep -E '(bash|sh)$' | grep -vE '^(root|sync|shutdown|halt)'",
            "awk -F: '$3==0 {print $1}' /etc/passwd",
            "cat /etc/shadow 2>/dev/null | grep -vE '(!|\\*)' | cut -d: -f1",
        ],
    },
];

impl LinuxIrCategory for AuthCategory {
    fn category(&self) -> &'static str { "auth" }
    fn modules(&self) -> &'static [ModuleDef] { MODULES }

    fn parse(&self, module_id: u32, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        match module_id {
            12 => {
                // Dangerous capabilities
                let dangerous_caps = ["cap_setuid", "cap_setgid", "cap_sys_admin"];
                for cap in &dangerous_caps {
                    if output.to_lowercase().contains(cap) {
                        findings.push(
                            Finding::new(12, "auth_privilege", Severity::High,
                                &format!("Dangerous capability: {}", cap))
                                .with_evidence(&extract_line(output, cap))
                        );
                    }
                }
            }
            17 => {
                // UID 0 accounts other than root
                for line in output.lines() {
                    if line.contains(":0:") && !line.starts_with("root:") {
                        findings.push(
                            Finding::new(17, "auth_accounts", Severity::Critical,
                                "Non-root UID 0 account detected")
                                .with_evidence(line)
                        );
                    }
                }
                // Accounts with password hashes
                for line in output.lines() {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 2 && !parts[1].starts_with('!') && !parts[1].starts_with('*') && parts[1].len() > 10 {
                        // Has a real password hash - might be suspicious for service accounts
                    }
                }
            }
            _ => {}
        }
        findings
    }
}
