//! Linux IR — Configuration Analysis (M13, M27, M33, M34, M41)
//! Checks container environment, ptrace, DNS, environment, firewall.

use super::linux_ir_common::*;

pub struct ConfigCategory;

static MODULES: &[ModuleDef] = &[
    ModuleDef {
        id: 13,
        name: "config_container",
        description: "Detect container environment",
        commands: &[
            "cat /proc/1/cgroup 2>/dev/null | head -10",
            "ls -la /.dockerenv /run/.containerenv 2>/dev/null",
            "systemd-detect-virt 2>/dev/null",
        ],
    },
    ModuleDef {
        id: 27,
        name: "config_ptrace",
        description: "Check ptrace scope and debugging config",
        commands: &[
            "cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null",
            "sysctl kernel.yama.ptrace_scope 2>/dev/null",
        ],
    },
    ModuleDef {
        id: 33,
        name: "config_dns",
        description: "Check DNS configuration for hijacking",
        commands: &[
            "cat /etc/resolv.conf 2>/dev/null",
            "cat /etc/hosts 2>/dev/null | grep -vE '^#|^$'",
        ],
    },
    ModuleDef {
        id: 34,
        name: "config_env",
        description: "Check environment variables for anomalies",
        commands: &[
            "env | grep -iE '(proxy|http|ld_|path)' | head -20",
            "cat /etc/environment 2>/dev/null",
        ],
    },
    ModuleDef {
        id: 41,
        name: "config_firewall",
        description: "Check firewall rules",
        commands: &[
            "iptables -L -n 2>/dev/null | head -30",
            "firewall-cmd --list-all 2>/dev/null || ufw status 2>/dev/null",
        ],
    },
];

const SUSPICIOUS_DNS: &[&str] = &["8.8.8.8", "1.1.1.1"]; // Unusual for internal servers

impl LinuxIrCategory for ConfigCategory {
    fn category(&self) -> &'static str { "config" }
    fn modules(&self) -> &'static [ModuleDef] { MODULES }

    fn parse(&self, module_id: u32, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let output_lower = output.to_lowercase();

        match module_id {
            13 => {
                // Container detection (informational)
                if output_lower.contains("docker") || output_lower.contains(".dockerenv") {
                    findings.push(
                        Finding::new(13, "config_container", Severity::Info,
                            "Running inside Docker container")
                            .with_description("IR scope may be limited to container filesystem")
                    );
                } else if output_lower.contains("kubepods") || output_lower.contains("containerd") {
                    findings.push(
                        Finding::new(13, "config_container", Severity::Info,
                            "Running inside Kubernetes pod")
                            .with_description("IR scope may be limited to container filesystem")
                    );
                } else if output_lower.contains("lxc") || output_lower.contains("containerenv") {
                    findings.push(
                        Finding::new(13, "config_container", Severity::Info,
                            "Running inside LXC/container")
                    );
                }
            }
            27 => {
                // ptrace_scope 0 = unrestricted (dangerous)
                if output.trim() == "0" || output.contains("= 0") {
                    findings.push(
                        Finding::new(27, "config_ptrace", Severity::Medium,
                            "Unrestricted ptrace scope (0)")
                            .with_description("Any process can ptrace any other process")
                    );
                }
            }
            33 => {
                // DNS hijacking indicators
                for dns in SUSPICIOUS_DNS {
                    if output.contains(dns) {
                        findings.push(
                            Finding::new(33, "config_dns", Severity::Low,
                                &format!("Public DNS server: {}", dns))
                                .with_description("Unusual for internal servers, verify legitimacy")
                        );
                    }
                }
                // Suspicious hosts entries
                for line in output.lines() {
                    let line_lower = line.to_lowercase();
                    if line_lower.contains("update") || line_lower.contains("download") {
                        findings.push(
                            Finding::new(33, "config_dns", Severity::High,
                                "Suspicious /etc/hosts entry")
                                .with_evidence(line)
                        );
                    }
                }
            }
            34 => {
                // Suspicious environment variables
                if output_lower.contains("ld_preload") {
                    findings.push(
                        Finding::new(34, "config_env", Severity::Critical,
                            "LD_PRELOAD set in environment")
                            .with_evidence(&extract_line(output, "ld_preload"))
                    );
                }
                if output_lower.contains("ld_library_path") {
                    findings.push(
                        Finding::new(34, "config_env", Severity::High,
                            "LD_LIBRARY_PATH modified")
                            .with_evidence(&extract_line(output, "ld_library_path"))
                    );
                }
            }
            41 => {
                // Firewall status
                if output_lower.contains("inactive") || output_lower.contains("not running") {
                    findings.push(
                        Finding::new(41, "config_firewall", Severity::Medium,
                            "Firewall is inactive")
                            .with_description("No firewall protection on this host")
                    );
                }
                // ACCEPT all policy
                if output_lower.contains("policy accept") && output_lower.contains("0.0.0.0/0") {
                    findings.push(
                        Finding::new(41, "config_firewall", Severity::Low,
                            "Permissive firewall policy (ACCEPT all)")
                    );
                }
            }
            _ => {}
        }
        findings
    }
}
