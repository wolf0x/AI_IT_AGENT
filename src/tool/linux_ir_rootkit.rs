//! Linux IR — Rootkit Detection (M04, M29)
//! Detects LKM rootkits, preload-based rootkits.

use super::linux_ir_common::*;

pub struct RootkitCategory;

static MODULES: &[ModuleDef] = &[
    ModuleDef {
        id: 4,
        name: "rootkit_lkm",
        description: "Detect LKM rootkits via lsmod and kallsyms",
        commands: &[
            "lsmod 2>/dev/null",
            "cat /proc/kallsyms 2>/dev/null | grep -iE '(hide|stealth|rootkit|hook)' | head -20",
            "dmesg 2>/dev/null | grep -iE '(module.*loaded|disagrees about version)' | tail -20",
        ],
    },
    ModuleDef {
        id: 29,
        name: "rootkit_preload",
        description: "Check for preload-based rootkits",
        commands: &[
            "cat /etc/ld.so.preload 2>/dev/null",
            "lsof 2>/dev/null | grep -E '\\.so' | grep -vE '/(usr|lib)/' | head -20",
        ],
    },
];

const ROOTKIT_KEYWORDS: &[&str] = &[
    "hide", "stealth", "rootkit", "hook", "diamorphine", "reptile",
    "adore", "suterusu", "jynx", "beurk", "azazel", "ld_linux",
];

impl LinuxIrCategory for RootkitCategory {
    fn category(&self) -> &'static str { "rootkit" }
    fn modules(&self) -> &'static [ModuleDef] { MODULES }

    fn parse(&self, module_id: u32, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let output_lower = output.to_lowercase();

        match module_id {
            4 => {
                for kw in ROOTKIT_KEYWORDS {
                    if output_lower.contains(kw) {
                        findings.push(
                            Finding::new(4, "rootkit_lkm", Severity::Critical,
                                &format!("Possible rootkit indicator: {}", kw))
                                .with_evidence(&extract_line(output, kw))
                        );
                    }
                }
            }
            29 => {
                if !output.trim().is_empty() && !output.contains("No such file") {
                    for line in output.lines() {
                        if line.contains(".so") && !line.starts_with('#') {
                            findings.push(
                                Finding::new(29, "rootkit_preload", Severity::Critical,
                                    "Preload-based rootkit suspected")
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
