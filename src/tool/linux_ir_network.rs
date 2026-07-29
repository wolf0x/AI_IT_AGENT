//! Linux IR — Network Analysis (M02, M35)
//! Detects C2 connections, suspicious ports, SSH/DNS/ICMP tunnels.

use super::linux_ir_common::*;

pub struct NetworkCategory;

static MODULES: &[ModuleDef] = &[
    ModuleDef {
        id: 2,
        name: "network_c2",
        description: "Detect C2 connections and suspicious ports",
        commands: &[
            "ss -antp 2>/dev/null || netstat -antp",
            "ss -untp 2>/dev/null || netstat -untp",
        ],
    },
    ModuleDef {
        id: 35,
        name: "network_tunnel",
        description: "Detect SSH/DNS/ICMP tunnels",
        commands: &[
            "ps aux | grep -E '(ssh.*-[LRD]|dns2tcp|iodine|ptunnel|icmptunnel)' | grep -v grep",
            "ss -antp | grep -E ':(53|443|80|22)\\s' | head -50",
        ],
    },
];

const C2_PORTS: &[&str] = &["4444", "5555", "6666", "7777", "8888", "9999", "14444", "14433", "3333", "4443"];
const MINING_POOLS: &[&str] = &["pool.", "minexmr", "nanopool", "supportxmr", "hashvault", "nicehash", "moneroocean"];

impl LinuxIrCategory for NetworkCategory {
    fn category(&self) -> &'static str { "network" }
    fn modules(&self) -> &'static [ModuleDef] { MODULES }

    fn parse(&self, module_id: u32, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let output_lower = output.to_lowercase();

        match module_id {
            2 => {
                // C2 port detection
                for port in C2_PORTS {
                    if output.contains(&format!(":{}", port)) {
                        findings.push(
                            Finding::new(2, "network_c2", Severity::High,
                                &format!("Suspicious port {} connection", port))
                                .with_evidence(&extract_line(output, port))
                        );
                    }
                }
                // Mining pool connections
                for pool in MINING_POOLS {
                    if output_lower.contains(pool) {
                        findings.push(
                            Finding::new(2, "network_c2", Severity::Critical,
                                &format!("Mining pool connection: {}", pool))
                                .with_evidence(&extract_line(output, pool))
                        );
                    }
                }
            }
            35 => {
                // Tunnel detection
                let tunnel_keywords = ["ssh", "dns2tcp", "iodine", "ptunnel", "icmptunnel"];
                for kw in &tunnel_keywords {
                    if output_lower.contains(kw) {
                        findings.push(
                            Finding::new(35, "network_tunnel", Severity::High,
                                &format!("Possible tunnel: {}", kw))
                                .with_evidence(&extract_line(output, kw))
                        );
                    }
                }
            }
            _ => {}
        }
        findings
    }
}
