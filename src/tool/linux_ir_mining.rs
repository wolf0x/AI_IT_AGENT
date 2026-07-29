//! Linux IR — Mining Detection (M08)
//! Detects mining configuration files and pool connections.

use super::linux_ir_common::*;

pub struct MiningCategory;

static MODULES: &[ModuleDef] = &[
    ModuleDef {
        id: 8,
        name: "mining_config",
        description: "Detect mining configuration files and pool connections",
        commands: &[
            "find / -type f \\( -name 'config.json' -o -name '*.conf' \\) -exec grep -lE '(pool|stratum|mining|xmrig)' {} \\; 2>/dev/null | head -20",
            "ss -antp | grep -E ':(3333|4444|5555|7777|8888|9999|14444|14433)'",
        ],
    },
];

const MINING_PORTS: &[&str] = &["3333", "4444", "5555", "7777", "8888", "9999", "14444", "14433"];

impl LinuxIrCategory for MiningCategory {
    fn category(&self) -> &'static str { "mining" }
    fn modules(&self) -> &'static [ModuleDef] { MODULES }

    fn parse(&self, module_id: u32, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        match module_id {
            8 => {
                // Mining config files
                for line in output.lines() {
                    let line_lower = line.to_lowercase();
                    if line_lower.contains("config.json") || line_lower.contains(".conf") {
                        if line_lower.contains("pool") || line_lower.contains("stratum") || line_lower.contains("xmrig") {
                            findings.push(
                                Finding::new(8, "mining_config", Severity::Critical,
                                    "Mining configuration file found")
                                    .with_file(line.trim())
                            );
                        }
                    }
                }
                // Mining pool connections
                for port in MINING_PORTS {
                    if output.contains(&format!(":{}", port)) {
                        findings.push(
                            Finding::new(8, "mining_config", Severity::Critical,
                                &format!("Mining pool port {} connection", port))
                                .with_evidence(&extract_line(output, port))
                        );
                    }
                }
            }
            _ => {}
        }
        findings
    }
}
