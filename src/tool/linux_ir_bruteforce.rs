//! Linux IR — Brute Force Detection (M36, M37)
//! Detects SSH/MySQL/FTP/Redis brute force attacks.

use super::linux_ir_common::*;

pub struct BruteForceCategory;

static MODULES: &[ModuleDef] = &[
    ModuleDef {
        id: 36,
        name: "brute_ssh",
        description: "Detect SSH brute force attacks",
        commands: &[
            "grep 'Failed password' /var/log/auth.log /var/log/secure 2>/dev/null | tail -100",
            "grep 'Failed password' /var/log/auth.log /var/log/secure 2>/dev/null | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20",
        ],
    },
    ModuleDef {
        id: 37,
        name: "brute_service",
        description: "Detect MySQL/FTP/Redis brute force",
        commands: &[
            "grep -iE '(failed|denied|error)' /var/log/mysql/error.log /var/log/vsftpd.log /var/log/redis/redis.log 2>/dev/null | tail -50",
        ],
    },
];

impl LinuxIrCategory for BruteForceCategory {
    fn category(&self) -> &'static str { "bruteforce" }
    fn modules(&self) -> &'static [ModuleDef] { MODULES }

    fn parse(&self, module_id: u32, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        match module_id {
            36 => {
                let failed_count = output.matches("Failed password").count();
                if failed_count > 100 {
                    findings.push(
                        Finding::new(36, "brute_ssh", Severity::Critical,
                            &format!("Active SSH brute force ({} failed attempts)", failed_count))
                    );
                } else if failed_count > 50 {
                    findings.push(
                        Finding::new(36, "brute_ssh", Severity::High,
                            &format!("SSH brute force detected ({} failed attempts)", failed_count))
                    );
                } else if failed_count > 10 {
                    findings.push(
                        Finding::new(36, "brute_ssh", Severity::Medium,
                            &format!("Multiple SSH failures ({})", failed_count))
                    );
                }
                // Top attacking IPs
                for line in output.lines() {
                    if let Some(count) = line.trim().split_whitespace().next() {
                        if let Ok(n) = count.parse::<usize>() {
                            if n > 50 {
                                findings.push(
                                    Finding::new(36, "brute_ssh", Severity::High,
                                        "High-volume SSH attacker")
                                        .with_evidence(line)
                                );
                            }
                        }
                    }
                }
            }
            37 => {
                let output_lower = output.to_lowercase();
                if output_lower.contains("access denied") || output_lower.contains("authentication failed") {
                    findings.push(
                        Finding::new(37, "brute_service", Severity::Medium,
                            "Service authentication failures detected")
                            .with_evidence(&truncate(output, 300))
                    );
                }
            }
            _ => {}
        }
        findings
    }
}
