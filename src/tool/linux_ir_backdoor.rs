//! Linux IR — Backdoor Detection (M14, M15, M16, M20, M24, M25)
//! Detects LD_PRELOAD, alias, PAM, SSH, Python, kernel backdoors.

use super::linux_ir_common::*;

pub struct BackdoorCategory;

static MODULES: &[ModuleDef] = &[
    ModuleDef {
        id: 14,
        name: "backdoor_ld",
        description: "Detect LD_PRELOAD backdoors",
        commands: &[
            "cat /etc/ld.so.preload 2>/dev/null",
            "env | grep -i ld_",
            "ls -la /lib/x86_64-linux-gnu/lib*.so* 2>/dev/null | grep -vE '\\->' | head -20",
        ],
    },
    ModuleDef {
        id: 15,
        name: "backdoor_alias",
        description: "Detect malicious shell aliases and functions",
        commands: &[
            "alias 2>/dev/null",
            "cat /root/.bashrc /root/.bash_aliases /etc/bash.bashrc 2>/dev/null | grep -E '(alias|function)' | head -30",
        ],
    },
    ModuleDef {
        id: 16,
        name: "backdoor_pam",
        description: "Check PAM modules for backdoors",
        commands: &[
            "ls -la /lib/security/ /lib/x86_64-linux-gnu/security/ 2>/dev/null",
            "grep -r 'pam_' /etc/pam.d/ 2>/dev/null | grep -vE '(pam_unix|pam_env|pam_selinux|pam_limits)' | head -20",
        ],
    },
    ModuleDef {
        id: 20,
        name: "backdoor_ssh",
        description: "Detect SSH backdoors (sshd_config, wrapper)",
        commands: &[
            "cat /etc/ssh/sshd_config 2>/dev/null | grep -vE '^#' | grep -vE '^$'",
            "which sshd; ls -la $(which sshd) 2>/dev/null; md5sum $(which sshd) 2>/dev/null",
        ],
    },
    ModuleDef {
        id: 24,
        name: "backdoor_python",
        description: "Detect Python-based backdoors",
        commands: &[
            "find / -name 'sitecustomize.py' -o -name 'usercustomize.py' 2>/dev/null",
            "pip list 2>/dev/null | grep -iE '(reverse|shell|backdoor)'",
        ],
    },
    ModuleDef {
        id: 25,
        name: "backdoor_kernel",
        description: "Check kernel modules for backdoors",
        commands: &[
            "lsmod | grep -vE '^(Module|ip_|nf_|xt_|br_|bridge|stp|llc|ebtable|iptable|nf_)'",
        ],
    },
];

impl LinuxIrCategory for BackdoorCategory {
    fn category(&self) -> &'static str { "backdoor" }
    fn modules(&self) -> &'static [ModuleDef] { MODULES }

    fn parse(&self, module_id: u32, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let output_lower = output.to_lowercase();

        match module_id {
            14 => {
                if !output.trim().is_empty() && !output.contains("No such file") {
                    for line in output.lines() {
                        if line.contains(".so") && !line.starts_with('#') {
                            findings.push(
                                Finding::new(14, "backdoor_ld", Severity::Critical,
                                    "LD_PRELOAD backdoor suspected")
                                    .with_evidence(line)
                            );
                        }
                    }
                }
            }
            15 => {
                // Malicious shell aliases/functions
                let suspicious = ["wget", "curl", "base64", "nc ", "/dev/tcp", "bash -i", "python -c"];
                for line in output.lines() {
                    let ll = line.to_lowercase();
                    if ll.contains("alias") || ll.contains("function") {
                        for kw in &suspicious {
                            if ll.contains(kw) {
                                findings.push(
                                    Finding::new(15, "backdoor_alias", Severity::High,
                                        "Suspicious shell alias/function")
                                        .with_evidence(line)
                                );
                                break;
                            }
                        }
                    }
                }
            }
            16 => {
                // Unusual PAM modules
                for line in output.lines() {
                    let line_lower = line.to_lowercase();
                    if line_lower.contains("pam_") && !line_lower.contains("pam_unix")
                        && !line_lower.contains("pam_env") && !line_lower.contains("pam_limits")
                        && !line_lower.contains("pam_systemd") && !line_lower.contains("pam_loginuid")
                    {
                        findings.push(
                            Finding::new(16, "backdoor_pam", Severity::High,
                                "Unusual PAM module")
                                .with_evidence(line)
                        );
                    }
                }
            }
            20 => {
                // Weak SSH config
                let weak_configs = ["permitrootlogin yes", "passwordauthentication yes", "permitemptypasswords yes"];
                for cfg in &weak_configs {
                    if output_lower.contains(cfg) {
                        findings.push(
                            Finding::new(20, "backdoor_ssh", Severity::Medium,
                                &format!("Weak SSH config: {}", cfg))
                        );
                    }
                }
            }
            24 => {
                if output_lower.contains("sitecustomize.py") || output_lower.contains("usercustomize.py") {
                    findings.push(
                        Finding::new(24, "backdoor_python", Severity::High,
                            "Python customization file found (potential backdoor)")
                            .with_evidence(&extract_line(output, "customize.py"))
                    );
                }
            }
            25 => {
                // Unknown kernel modules
                for line in output.lines() {
                    if !line.starts_with("Module") && !line.trim().is_empty() {
                        let module_name = line.split_whitespace().next().unwrap_or("");
                        if !module_name.is_empty() {
                            findings.push(
                                Finding::new(25, "backdoor_kernel", Severity::Medium,
                                    &format!("Non-standard kernel module: {}", module_name))
                                    .with_evidence(line)
                            );
                        }
                    }
                }
            }
            _ => {}
        }
        findings
    }
}
