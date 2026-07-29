//! Linux IR — File Analysis (M05, M06, M09, M42)
//! Detects suspicious SUID/SGID, recent changes, suspicious names, temp files.

use super::linux_ir_common::*;

pub struct FileCategory;

static MODULES: &[ModuleDef] = &[
    ModuleDef {
        id: 5,
        name: "file_suid",
        description: "Find suspicious SUID/SGID files",
        commands: &[
            "find / -type f \\( -perm -4000 -o -perm -2000 \\) -exec ls -la {} \\; 2>/dev/null | head -50",
        ],
    },
    ModuleDef {
        id: 6,
        name: "file_changes",
        description: "Find recently modified files in sensitive directories",
        commands: &[
            "find /etc /usr/bin /usr/sbin -mtime -7 -type f 2>/dev/null | head -50",
            "find /tmp /var/tmp /dev/shm -type f -mtime -3 2>/dev/null | head -50",
        ],
    },
    ModuleDef {
        id: 9,
        name: "file_suspicious",
        description: "Find files with suspicious names/patterns",
        commands: &[
            "find / -type f \\( -name '.*' -o -name '*miner*' -o -name '*xmrig*' -o -name '*kworker*' \\) 2>/dev/null | grep -vE '/(proc|sys|usr/share)/' | head -50",
        ],
    },
    ModuleDef {
        id: 42,
        name: "file_temp",
        description: "Check temp directories for malicious files",
        commands: &[
            "ls -la /tmp /var/tmp /dev/shm 2>/dev/null",
            "find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null | head -30",
        ],
    },
];

const SUSPICIOUS_NAMES: &[&str] = &[
    "miner", "xmrig", "kworker", "kinsing", "kdevtmpfsi", ".hidden", ".x",
];

impl LinuxIrCategory for FileCategory {
    fn category(&self) -> &'static str { "file" }
    fn modules(&self) -> &'static [ModuleDef] { MODULES }

    fn parse(&self, module_id: u32, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let output_lower = output.to_lowercase();

        match module_id {
            5 => {
                // SUID in unusual locations
                for line in output.lines() {
                    let line_lower = line.to_lowercase();
                    if (line_lower.contains("/tmp/") || line_lower.contains("/home/") || line_lower.contains("/var/"))
                        && (line_lower.contains("-rws") || line_lower.contains("-rwxr-s"))
                    {
                        findings.push(
                            Finding::new(5, "file_suid", Severity::High,
                                "SUID/SGID file in unusual location")
                                .with_evidence(line)
                        );
                    }
                }
            }
            6 => {
                // Recently modified files in sensitive dirs
                let sensitive = ["/etc/", "/usr/bin/", "/usr/sbin/"];
                let mut count = 0;
                for line in output.lines() {
                    if !line.trim().is_empty() {
                        count += 1;
                        for s in &sensitive {
                            if line.contains(s) {
                                findings.push(
                                    Finding::new(6, "file_changes", Severity::Medium,
                                        "Recently modified sensitive file")
                                        .with_evidence(line)
                                );
                                break;
                            }
                        }
                    }
                }
                if count > 30 {
                    findings.push(
                        Finding::new(6, "file_changes", Severity::Medium,
                            &format!("High volume of recent file changes ({})", count))
                    );
                }
            }
            9 => {
                for name in SUSPICIOUS_NAMES {
                    if output_lower.contains(name) {
                        findings.push(
                            Finding::new(9, "file_suspicious", Severity::High,
                                &format!("Suspicious file name: {}", name))
                                .with_evidence(&extract_line(output, name))
                        );
                    }
                }
            }
            42 => {
                // Executables in temp dirs
                for line in output.lines() {
                    if line.contains("-rwx") && (line.contains("/tmp/") || line.contains("/dev/shm")) {
                        findings.push(
                            Finding::new(42, "file_temp", Severity::Medium,
                                "Executable in temp directory")
                                .with_evidence(line)
                        );
                    }
                }
            }
            _ => {}
        }
        findings
    }
}
