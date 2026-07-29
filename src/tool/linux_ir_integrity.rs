//! Linux IR — Integrity Checks (M28, M30)
//! Verifies RPM/DEB package integrity, GPG keys.

use super::linux_ir_common::*;

pub struct IntegrityCategory;

static MODULES: &[ModuleDef] = &[
    ModuleDef {
        id: 28,
        name: "integrity_rpm",
        description: "Verify RPM/DEB package integrity",
        commands: &[
            "rpm -Va 2>/dev/null | head -50 || debsums -c 2>/dev/null | head -50",
        ],
    },
    ModuleDef {
        id: 30,
        name: "integrity_gpg",
        description: "Check GPG keys and package signing",
        commands: &[
            "rpm -qa gpg-pubkey 2>/dev/null; apt-key list 2>/dev/null | head -20",
        ],
    },
];

impl LinuxIrCategory for IntegrityCategory {
    fn category(&self) -> &'static str { "integrity" }
    fn modules(&self) -> &'static [ModuleDef] { MODULES }

    fn parse(&self, module_id: u32, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        match module_id {
            28 => {
                // rpm -Va output: lines starting with S.5....T. indicate modified files
                let modified_count = output.lines()
                    .filter(|l| l.contains("5") || l.contains("M") || l.contains("c"))
                    .count();
                if modified_count > 20 {
                    findings.push(
                        Finding::new(28, "integrity_rpm", Severity::High,
                            &format!("Many modified system files ({})", modified_count))
                            .with_description("Package integrity check failed for multiple files")
                    );
                } else if modified_count > 0 {
                    findings.push(
                        Finding::new(28, "integrity_rpm", Severity::Medium,
                            &format!("Modified system files ({})", modified_count))
                    );
                }
                // Check for modified binaries
                for line in output.lines() {
                    if line.contains("/usr/bin/") || line.contains("/usr/sbin/") {
                        if line.contains("5") {
                            findings.push(
                                Finding::new(28, "integrity_rpm", Severity::Critical,
                                    "Modified system binary detected")
                                    .with_evidence(line)
                            );
                        }
                    }
                }
            }
            30 => {
                // No GPG keys installed
                let output_lower = output.to_lowercase();
                if output.trim().is_empty() {
                    findings.push(
                        Finding::new(30, "integrity_gpg", Severity::Low,
                            "No GPG keys found — package signing not verifiable")
                    );
                }
                // Expired or revoked keys
                if output_lower.contains("expired") || output_lower.contains("revoked") {
                    findings.push(
                        Finding::new(30, "integrity_gpg", Severity::Medium,
                            "Expired or revoked GPG key detected")
                            .with_evidence(&extract_line(output, "expired"))
                    );
                }
            }
            _ => {}
        }
        findings
    }
}
