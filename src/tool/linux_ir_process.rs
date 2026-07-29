//! Linux IR — Process Analysis (M01, M31, M32)
//! Detects mining processes, hidden processes, deleted binaries.

use super::linux_ir_common::*;

pub struct ProcessCategory;

static MODULES: &[ModuleDef] = &[
    ModuleDef {
        id: 1,
        name: "process_mining",
        description: "Detect mining and RCE processes via ps and /proc analysis",
        commands: &[
            "ps auxwwf 2>/dev/null || ps aux",
            "ls -la /proc/*/exe 2>/dev/null | grep -E '(deleted|/tmp/|/dev/shm/)'",
        ],
    },
    ModuleDef {
        id: 31,
        name: "process_hidden",
        description: "Detect hidden processes via /proc vs ps comparison",
        commands: &[
            "ps -eo pid --no-headers | sort -n > /tmp/.ps_pids; ls /proc | grep -E '^[0-9]+$' | sort -n > /tmp/.proc_pids; comm -13 /tmp/.ps_pids /tmp/.proc_pids; rm -f /tmp/.ps_pids /tmp/.proc_pids",
        ],
    },
    ModuleDef {
        id: 32,
        name: "process_deleted",
        description: "Find processes running from deleted binaries",
        commands: &[
            "ls -la /proc/*/exe 2>/dev/null | grep deleted",
        ],
    },
];

const MINING_KEYWORDS: &[&str] = &[
    "xmrig", "minerd", "cpuminer", "minergate", "kworkerds", "kdevtmpfsi",
    "kinsing", "kthreaddi", "cryptonight", "stratum", "nicehash", "minexmr",
    "nanopool", "dwarfpool", "supportxmr", "hashvault", "monero", "coinhive",
];

impl LinuxIrCategory for ProcessCategory {
    fn category(&self) -> &'static str { "process" }
    fn modules(&self) -> &'static [ModuleDef] { MODULES }

    fn parse(&self, module_id: u32, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let output_lower = output.to_lowercase();

        match module_id {
            1 => {
                // Mining process detection
                for keyword in MINING_KEYWORDS {
                    if output_lower.contains(keyword) {
                        findings.push(
                            Finding::new(1, "process_mining", Severity::Critical,
                                &format!("Mining process detected: {}", keyword))
                                .with_evidence(&extract_line(output, keyword))
                        );
                    }
                }
                // High CPU processes
                for line in output.lines() {
                    if let Some(cpu) = extract_cpu(line) {
                        if cpu > 80.0 {
                            findings.push(
                                Finding::new(1, "process_mining", Severity::High,
                                    "High CPU process detected")
                                    .with_description(&format!("Process using {:.1}% CPU", cpu))
                                    .with_evidence(line)
                            );
                        }
                    }
                }
            }
            31 => {
                // Hidden processes
                let hidden: Vec<&str> = output.lines()
                    .filter(|l| !l.trim().is_empty())
                    .collect();
                if !hidden.is_empty() {
                    findings.push(
                        Finding::new(31, "process_hidden", Severity::Critical,
                            &format!("Hidden processes detected ({})", hidden.len()))
                            .with_description("PIDs in /proc but not in ps — possible rootkit")
                            .with_evidence(&truncate(output, 500))
                    );
                }
            }
            32 => {
                // Deleted binaries
                for line in output.lines() {
                    if line.contains("(deleted)") {
                        findings.push(
                            Finding::new(32, "process_deleted", Severity::High,
                                "Process running from deleted binary")
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

fn extract_cpu(line: &str) -> Option<f64> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() > 2 {
        parts[2].parse::<f64>().ok()
    } else {
        None
    }
}
