//! Linux IR Tool — Orchestrator for remote incident response.
//! Coordinates all linux_ir_* category modules via SSH.

use async_trait::async_trait;
use serde_json::{json, Value};
use std::time::Instant;
use tracing::info;

use super::linux_ir_common::{Finding, LinuxIrCategory, Severity};
use super::linux_ssh::{parse_target, SshAuth, SshClient, SshConfig};
use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

// Import all category modules
use super::linux_ir_auth::AuthCategory;
use super::linux_ir_backdoor::BackdoorCategory;
use super::linux_ir_bruteforce::BruteForceCategory;
use super::linux_ir_config::ConfigCategory;
use super::linux_ir_file::FileCategory;
use super::linux_ir_integrity::IntegrityCategory;
use super::linux_ir_lateral::LateralCategory;
use super::linux_ir_mining::MiningCategory;
use super::linux_ir_network::NetworkCategory;
use super::linux_ir_persistence::PersistenceCategory;
use super::linux_ir_process::ProcessCategory;
use super::linux_ir_rootkit::RootkitCategory;
use super::linux_ir_web::WebCategory;

/// Linux IR Tool — 45 detection modules for remote Linux incident response
pub struct IrLinuxTool;

/// Get all category handlers
fn all_categories() -> Vec<Box<dyn LinuxIrCategory>> {
    vec![
        Box::new(ProcessCategory),
        Box::new(NetworkCategory),
        Box::new(PersistenceCategory),
        Box::new(RootkitCategory),
        Box::new(FileCategory),
        Box::new(WebCategory),
        Box::new(MiningCategory),
        Box::new(LateralCategory),
        Box::new(AuthCategory),
        Box::new(BackdoorCategory),
        Box::new(BruteForceCategory),
        Box::new(IntegrityCategory),
        Box::new(ConfigCategory),
    ]
}

/// Parse module list from string (e.g., "1,2,10" or "all")
fn parse_module_list(input: &str) -> Option<Vec<u32>> {
    if input.trim().eq_ignore_ascii_case("all") {
        return None; // None means all modules
    }
    Some(
        input
            .split(',')
            .filter_map(|s| s.trim().parse::<u32>().ok())
            .collect()
    )
}

#[async_trait]
impl Tool for IrLinuxTool {
    fn name(&self) -> &str {
        "ir_linux"
    }

    fn description(&self) -> &str {
        "Linux incident response scanner. Connects to remote Linux hosts via SSH and executes 45 detection modules across 13 categories: process, network, persistence, rootkit, file, web, mining, lateral movement, auth, backdoor, brute force, integrity, config. Returns structured findings with risk scoring.\n\nIMPORTANT USAGE GUIDANCE:\n1. When listing capabilities (e.g., 'what can you do?'), INCLUDE Linux IR as a core capability alongside Windows IR.\n2. When asked about Linux IR capability, answer YES and describe the 45 detection modules across 13 categories.\n3. Only EXECUTE this tool when the user provides a REAL Linux target to investigate (e.g., 'scan 192.168.1.100', 'investigate root@server.example.com').\n4. Do NOT execute this tool to:\n   - Demonstrate capability without a real target\n   - Scan fake/example hosts like 'user@host', 'user@demo-host', 'root@example.com'"
    }

    fn is_builtin(&self) -> bool {
        true
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn is_long_running(&self) -> bool {
        true
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "SSH target in format user@host or user@host:port. MUST be a real, reachable Linux host (IP address or valid hostname). Examples: 'root@192.168.1.100', 'admin@server.example.com:22'. Do NOT use placeholder/example hosts."
                },
                "modules": {
                    "type": "string",
                    "description": "Module IDs: '1,2,10' or 'all' (default: all)"
                },
                "auth_method": {
                    "type": "string",
                    "enum": ["password", "key"],
                    "description": "Authentication method (default: key)"
                },
                "password": {
                    "type": "string",
                    "description": "SSH password (if auth_method=password)"
                },
                "key_path": {
                    "type": "string",
                    "description": "SSH private key path (default: ~/.ssh/id_rsa)"
                },
                "key_passphrase": {
                    "type": "string",
                    "description": "Passphrase for encrypted key"
                },
                "timeout_secs": {
                    "type": "integer",
                    "description": "Per-command timeout (default: 30)"
                },
                "severity_filter": {
                    "type": "string",
                    "enum": ["all", "critical", "high", "medium", "low"],
                    "description": "Minimum severity filter (default: all)"
                }
            },
            "required": ["target"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let target = args["target"]
            .as_str()
            .ok_or("Missing required parameter: target")?;

        let modules_str = args["modules"].as_str().unwrap_or("all");
        let auth_method = args["auth_method"].as_str().unwrap_or("key");
        let password = args["password"].as_str();
        let key_path = args["key_path"].as_str();
        let key_passphrase = args["key_passphrase"].as_str();
        let timeout_secs = args["timeout_secs"].as_u64().unwrap_or(30);
        let severity_filter = args["severity_filter"].as_str().unwrap_or("all");

        // Parse target
        let (username, host, port) = parse_target(target)
            .map_err(|e| format!("Invalid target '{}': {}", target, e))?;

        // Quick DNS resolution check to fail fast for invalid hostnames
        // (avoids waiting for TCP timeout on unreachable hosts)
        if let Err(e) = tokio::net::lookup_host(format!("{}:{}", host, port)).await {
            return Err(format!(
                "DNS resolution failed for '{}': {}. Please provide a valid hostname or IP address.",
                host, e
            )
            .into());
        }

        // Build SSH config
        let auth = match auth_method {
            "password" => {
                let pwd = password.ok_or("Password required for password auth")?;
                SshAuth::Password(pwd.to_string())
            }
            _ => {
                let default_key = dirs_next::home_dir()
                    .map(|h| h.join(".ssh/id_rsa").to_string_lossy().to_string())
                    .unwrap_or_else(|| "~/.ssh/id_rsa".to_string());
                SshAuth::KeyFile {
                    path: key_path.unwrap_or(&default_key).to_string(),
                    passphrase: key_passphrase.map(|s| s.to_string()),
                }
            }
        };

        let config = SshConfig {
            host: host.clone(),
            port,
            username: username.clone(),
            auth,
            timeout_secs,
        };

        // Parse module filter
        let module_filter = parse_module_list(modules_str);

        info!(
            "[ir_linux] Starting scan: {}@{}:{}, modules: {}",
            username, host, port, modules_str
        );

        let start_time = Instant::now();

        // Connect via SSH
        let mut client = SshClient::new(config);
        client
            .connect()
            .await
            .map_err(|e| format!("SSH connection failed: {}", e))?;

        info!("[ir_linux] SSH connected, executing modules");

        // Execute all categories
        let categories = all_categories();
        let mut all_findings: Vec<Finding> = Vec::new();
        let mut module_results: Vec<Value> = Vec::new();
        let mut modules_executed = 0;

        for category in &categories {
            for module in category.modules() {
                // Check module filter
                if let Some(ref filter) = module_filter {
                    if !filter.contains(&module.id) {
                        continue;
                    }
                }

                let module_start = Instant::now();
                let mut module_findings: Vec<Finding> = Vec::new();
                let mut command_outputs: Vec<Value> = Vec::new();

                // Execute all commands for this module
                for cmd in module.commands {
                    match client.exec(cmd).await {
                        Ok(output) => {
                            command_outputs.push(json!({
                                "command": cmd,
                                "exit_code": output.exit_code,
                                "stdout_preview": super::linux_ir_common::truncate(&output.stdout, 2000),
                            }));

                            // Parse output using category's parser
                            let findings = category.parse(module.id, &output.stdout);
                            module_findings.extend(findings);
                        }
                        Err(e) => {
                            command_outputs.push(json!({
                                "command": cmd,
                                "error": e.to_string(),
                            }));
                        }
                    }
                }

                modules_executed += 1;
                module_results.push(json!({
                    "module_id": module.id,
                    "module_name": module.name,
                    "category": category.category(),
                    "findings_count": module_findings.len(),
                    "duration_ms": module_start.elapsed().as_millis(),
                }));

                all_findings.extend(module_findings);
            }
        }

        // Disconnect
        client.disconnect().await;

        let total_duration = start_time.elapsed();

        // Calculate risk score
        let risk_score: u32 = all_findings.iter().map(|f| f.score).sum();
        let risk_level = match risk_score {
            s if s >= 50 => "CRITICAL",
            s if s >= 30 => "HIGH",
            s if s >= 15 => "MEDIUM",
            s if s >= 5 => "LOW",
            _ => "INFO",
        };

        // Lateral movement analysis
        let lateral_findings: Vec<_> = all_findings
            .iter()
            .filter(|f| [10, 43, 44, 45].contains(&f.module_id))
            .collect();
        let lateral_judgment = match lateral_findings.len() {
            0 => "NO_EVIDENCE",
            1..=2 => "SUSPICIOUS",
            3..=5 => "LIKELY",
            _ => "ACTIVE_PIVOT",
        };

        // Filter by severity
        let filtered: Vec<Value> = all_findings
            .iter()
            .filter(|f| severity_matches(&f.severity, severity_filter))
            .map(|f| {
                json!({
                    "module_id": f.module_id,
                    "module": f.module_name,
                    "severity": f.severity.as_str(),
                    "title": f.title,
                    "evidence": f.evidence,
                    "score": f.score,
                })
            })
            .collect();

        // Summary counts
        let critical = all_findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = all_findings.iter().filter(|f| f.severity == Severity::High).count();
        let medium = all_findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let low = all_findings.iter().filter(|f| f.severity == Severity::Low).count();

        info!(
            "[ir_linux] Scan complete: {} findings, risk={}, duration={}s",
            all_findings.len(),
            risk_level,
            total_duration.as_secs()
        );

        Ok(json!({
            "status": "ok",
            "target": format!("{}@{}:{}", username, host, port),
            "scan_duration_secs": total_duration.as_secs(),
            "modules_executed": modules_executed,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "summary": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "total": all_findings.len(),
            },
            "lateral_movement": {
                "evidence_count": lateral_findings.len(),
                "judgment": lateral_judgment,
            },
            "findings": filtered,
            "module_details": module_results,
        }))
    }
}

fn severity_matches(severity: &Severity, filter: &str) -> bool {
    match filter {
        "critical" => *severity == Severity::Critical,
        "high" => matches!(severity, Severity::Critical | Severity::High),
        "medium" => matches!(severity, Severity::Critical | Severity::High | Severity::Medium),
        "low" => *severity != Severity::Info,
        _ => true,
    }
}
