//! Linux IR — Lateral Movement (M10, M43, M44, M45)
//! Detects SSH keys, lateral tools, shell history, login aggregation.

use super::linux_ir_common::*;

pub struct LateralCategory;

static MODULES: &[ModuleDef] = &[
    ModuleDef {
        id: 10,
        name: "lateral_ssh_keys",
        description: "Check SSH keys and authorized_keys for lateral movement",
        commands: &[
            "find / -name 'authorized_keys' -exec ls -la {} \\; -exec cat {} \\; 2>/dev/null",
            "find / -name 'id_rsa*' -o -name 'id_ed25519*' -o -name '*.ppk' 2>/dev/null | head -20",
            "cat /root/.ssh/known_hosts 2>/dev/null | wc -l; cat /root/.ssh/known_hosts 2>/dev/null | head -20",
        ],
    },
    ModuleDef {
        id: 43,
        name: "lateral_tools",
        description: "Detect lateral movement tools",
        commands: &[
            "find / -type f \\( -name 'masscan*' -o -name 'nmap*' -o -name 'fscan*' -o -name 'psexec*' \\) 2>/dev/null | head -20",
            "history | grep -iE '(ssh|scp|rsync|nc|ncat)' | tail -30",
        ],
    },
    ModuleDef {
        id: 44,
        name: "lateral_history",
        description: "Analyze shell history for lateral movement",
        commands: &[
            "cat /root/.bash_history /home/*/.bash_history 2>/dev/null | grep -iE '(ssh|scp|rsync|nc|nmap|masscan)' | tail -50",
        ],
    },
    ModuleDef {
        id: 45,
        name: "lateral_login",
        description: "Aggregate login records for lateral movement analysis",
        commands: &[
            "last -n 50 2>/dev/null",
            "lastb -n 50 2>/dev/null",
            "grep 'Accepted' /var/log/auth.log /var/log/secure 2>/dev/null | tail -50",
        ],
    },
];

const LATERAL_TOOLS: &[&str] = &["masscan", "nmap", "fscan", "psexec", "wmiexec", "hydra", "medusa"];

impl LinuxIrCategory for LateralCategory {
    fn category(&self) -> &'static str { "lateral" }
    fn modules(&self) -> &'static [ModuleDef] { MODULES }

    fn parse(&self, module_id: u32, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let output_lower = output.to_lowercase();

        match module_id {
            10 => {
                // Count authorized_keys entries
                let key_count = output.lines()
                    .filter(|l| l.contains("ssh-rsa") || l.contains("ssh-ed25519"))
                    .count();
                if key_count > 3 {
                    findings.push(
                        Finding::new(10, "lateral_ssh_keys", Severity::Medium,
                            &format!("Multiple SSH keys in authorized_keys ({})", key_count))
                            .with_description("High number of authorized keys may indicate lateral movement")
                    );
                }
                // Known hosts count
                if let Some(line) = output.lines().find(|l| l.trim().parse::<usize>().is_ok()) {
                    if let Ok(count) = line.trim().parse::<usize>() {
                        if count > 20 {
                            findings.push(
                                Finding::new(10, "lateral_ssh_keys", Severity::Medium,
                                    &format!("Large known_hosts file ({}) entries", count))
                            );
                        }
                    }
                }
            }
            43 => {
                for tool in LATERAL_TOOLS {
                    if output_lower.contains(tool) {
                        findings.push(
                            Finding::new(43, "lateral_tools", Severity::High,
                                &format!("Lateral movement tool found: {}", tool))
                                .with_evidence(&extract_line(output, tool))
                        );
                    }
                }
            }
            44 => {
                // SSH commands in history
                let ssh_count = output.lines()
                    .filter(|l| l.to_lowercase().contains("ssh "))
                    .count();
                if ssh_count > 5 {
                    findings.push(
                        Finding::new(44, "lateral_history", Severity::Medium,
                            &format!("Multiple SSH commands in history ({})", ssh_count))
                    );
                }
            }
            45 => {
                // Count unique source IPs
                let mut ips: Vec<&str> = output.lines()
                    .filter_map(|l| l.split_whitespace().nth(2))
                    .filter(|s| s.contains('.'))
                    .collect();
                ips.sort();
                ips.dedup();
                if ips.len() > 10 {
                    findings.push(
                        Finding::new(45, "lateral_login", Severity::Medium,
                            &format!("Multiple login sources ({})", ips.len()))
                    );
                }
            }
            _ => {}
        }
        findings
    }
}
