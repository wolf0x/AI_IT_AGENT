//! Linux IR — Rootkit Detection (M04, M29)
//! Detects LKM rootkits, preload-based rootkits.

use super::linux_ir_common::*;

pub struct RootkitCategory;

static MODULES: &[ModuleDef] = &[
    ModuleDef {
        id: 4,
        name: "rootkit_lkm",
        description: "Detect LKM rootkits via lsmod and known-bad module names",
        commands: &[
            "lsmod 2>/dev/null",
            "dmesg 2>/dev/null | grep -iE '(module.*loaded|disagrees about version)' | tail -20",
        ],
    },
    ModuleDef {
        id: 29,
        name: "rootkit_preload",
        description: "Check for preload-based rootkits via /etc/ld.so.preload",
        commands: &[
            "cat /etc/ld.so.preload 2>/dev/null",
        ],
    },
];

/// Known-bad kernel module names (rootkit signatures).
/// Only match specific known rootkits, not generic terms like 'hook'.
const KNOWN_BAD_MODULES: &[&str] = &[
    "diamorphine", "reptile", "adore", "suterusu", "jynx", "beurk",
    "azazel", "ld_preload_hide", "nrootkit", "brootkit", "flk",
    "knark", "t0rn", "adore-ng", "reptile-ng", "suterusu2",
];

impl LinuxIrCategory for RootkitCategory {
    fn category(&self) -> &'static str { "rootkit" }
    fn modules(&self) -> &'static [ModuleDef] { MODULES }

    fn parse(&self, module_id: u32, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        match module_id {
            4 => {
                // Check lsmod output for known-bad module names
                for line in output.lines() {
                    let module_name = line.split_whitespace().next().unwrap_or("");
                    for bad in KNOWN_BAD_MODULES {
                        if module_name.eq_ignore_ascii_case(bad) {
                            findings.push(
                                Finding::new(4, "rootkit_lkm", Severity::Critical,
                                    &format!("Known rootkit module detected: {}", module_name))
                                    .with_evidence(line)
                            );
                        }
                    }
                }
            }
            29 => {
                // Check /etc/ld.so.preload content directly
                let trimmed = output.trim();
                if !trimmed.is_empty() && !trimmed.contains("No such file") {
                    for line in trimmed.lines() {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        findings.push(
                            Finding::new(29, "rootkit_preload", Severity::Critical,
                                "Preload library found in /etc/ld.so.preload")
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
