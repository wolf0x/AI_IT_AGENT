//! Linux IR — Persistence Detection (M03, M19, M21, M22, M23, M26)
//! Detects cron, init, systemd, udev, ld.so, startup persistence.

use super::linux_ir_common::*;

pub struct PersistenceCategory;

static MODULES: &[ModuleDef] = &[
    ModuleDef {
        id: 3,
        name: "persistence_cron",
        description: "Check crontab and cron directories for persistence",
        commands: &[
            "for u in $(cut -f1 -d: /etc/passwd); do echo \"=== $u ===\"; crontab -l -u $u 2>/dev/null; done",
            "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null; cat /etc/cron.d/* 2>/dev/null",
            "ls -la /var/spool/cron/ /var/spool/cron/crontabs/ 2>/dev/null",
        ],
    },
    ModuleDef {
        id: 19,
        name: "persistence_init",
        description: "Check init scripts and rc.local",
        commands: &[
            "ls -la /etc/init.d/ 2>/dev/null | head -30",
            "cat /etc/rc.local 2>/dev/null; cat /etc/rc.d/rc.local 2>/dev/null",
        ],
    },
    ModuleDef {
        id: 21,
        name: "persistence_systemd",
        description: "Check systemd services for persistence",
        commands: &[
            "systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -50",
            "ls -la /etc/systemd/system/*.service 2>/dev/null | head -30",
        ],
    },
    ModuleDef {
        id: 22,
        name: "persistence_udev",
        description: "Check udev rules for persistence",
        commands: &[
            "ls -la /etc/udev/rules.d/ 2>/dev/null",
            "grep -r 'RUN+=' /etc/udev/rules.d/ 2>/dev/null",
        ],
    },
    ModuleDef {
        id: 23,
        name: "persistence_ld",
        description: "Check ld.so.preload and LD_PRELOAD persistence",
        commands: &[
            "cat /etc/ld.so.preload 2>/dev/null",
            "echo $LD_PRELOAD; env | grep -i preload",
        ],
    },
    ModuleDef {
        id: 26,
        name: "persistence_startup",
        description: "Check startup scripts and profile.d",
        commands: &[
            "ls -la /etc/profile.d/ 2>/dev/null",
            "cat /etc/profile /etc/bash.bashrc /root/.bashrc 2>/dev/null | grep -E '(wget|curl|base64|eval|exec)' | head -20",
        ],
    },
];

const SUSPICIOUS_CRON: &[&str] = &["wget", "curl", "base64", "/tmp/", "/dev/shm", "python", "nc ", "ncat", "bash -i"];

impl LinuxIrCategory for PersistenceCategory {
    fn category(&self) -> &'static str { "persistence" }
    fn modules(&self) -> &'static [ModuleDef] { MODULES }

    fn parse(&self, module_id: u32, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let output_lower = output.to_lowercase();

        match module_id {
            3 => {
                for line in output.lines() {
                    let line_lower = line.to_lowercase();
                    if line.starts_with('#') || line.starts_with("===") { continue; }
                    for pattern in SUSPICIOUS_CRON {
                        if line_lower.contains(pattern) {
                            findings.push(
                                Finding::new(3, "persistence_cron", Severity::High,
                                    "Suspicious cron entry")
                                    .with_description(&format!("Found '{}' in cron", pattern))
                                    .with_evidence(line)
                            );
                            break;
                        }
                    }
                }
            }
            19 => {
                // Suspicious init/rc.local entries
                for line in output.lines() {
                    let line_lower = line.to_lowercase();
                    for kw in &["wget", "curl", "base64", "/tmp/", "/dev/shm", "nc ", "bash -i"] {
                        if line_lower.contains(kw) {
                            findings.push(
                                Finding::new(19, "persistence_init", Severity::High,
                                    "Suspicious init/rc.local entry")
                                    .with_evidence(line)
                            );
                            break;
                        }
                    }
                }
            }
            21 => {
                // Suspicious systemd services
                for line in output.lines() {
                    let line_lower = line.to_lowercase();
                    if line_lower.contains("/tmp/") || line_lower.contains("/dev/shm") {
                        findings.push(
                            Finding::new(21, "persistence_systemd", Severity::High,
                                "Suspicious systemd service")
                                .with_evidence(line)
                        );
                    }
                }
            }
            22 => {
                if output_lower.contains("run+=") {
                    findings.push(
                        Finding::new(22, "persistence_udev", Severity::Medium,
                            "Udev rule with RUN directive")
                            .with_evidence(&extract_line(output, "RUN+="))
                    );
                }
            }
            23 => {
                if !output.trim().is_empty() && !output.contains("No such file") {
                    for line in output.lines() {
                        if line.contains(".so") && !line.starts_with('#') {
                            findings.push(
                                Finding::new(23, "persistence_ld", Severity::Critical,
                                    "LD_PRELOAD persistence detected")
                                    .with_evidence(line)
                            );
                        }
                    }
                }
            }
            26 => {
                for line in output.lines() {
                    let line_lower = line.to_lowercase();
                    for kw in &["wget", "curl", "base64", "eval"] {
                        if line_lower.contains(kw) {
                            findings.push(
                                Finding::new(26, "persistence_startup", Severity::Medium,
                                    "Suspicious startup script")
                                    .with_evidence(line)
                            );
                            break;
                        }
                    }
                }
            }
            _ => {}
        }
        findings
    }
}
