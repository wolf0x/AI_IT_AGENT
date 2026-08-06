//! Auditor — independent verification for managed task execution.
//!
//! The Auditor verifies actions and artifacts before they enter the TaskContract's
//! verified state. It operates independently from the Executor, using read-only
//! tools to confirm that claimed results actually hold in the environment.
//!
//! # Verification Scope
//!
//! The Auditor verifies:
//! - **Actions**: Containment/eradication steps (e.g., "killed process X" → verify process gone)
//! - **Artifacts**: Report files (e.g., "generated report" → verify file exists, non-empty, valid)
//! - **Collection completeness**: All required IR tools ran successfully
//!
//! The Auditor does NOT verify:
//! - **Analysis judgments**: "This process is suspicious" is subjective
//! - **Attribution conclusions**: "This is APT29" requires human expertise
//!
//! # Implementation
//!
//! Verification uses two approaches:
//! 1. **Programmatic checks**: File existence, process list queries, service status
//! 2. **LLM-based checks**: Evidence chain completeness, finding consistency
//!
//! Programmatic checks are preferred for speed and determinism. LLM checks are used
//! when the verification requires interpretation of complex evidence.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

use super::task_contract::{TaskContract, VerifiedAction, VerifiedFinding};
use crate::tool::ToolRegistry;
use crate::context::ToolContext;

/// Result of an audit verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResult {
    /// Whether the verification passed.
    pub verified: bool,
    /// Description of what was verified.
    pub description: String,
    /// Evidence from the verification (e.g., process list output).
    pub evidence: String,
    /// If verification failed, why it failed.
    pub failure_reason: Option<String>,
}

/// Auditor for managed task execution.
pub struct Auditor {
    tools: std::sync::Arc<tokio::sync::RwLock<ToolRegistry>>,
    working_dir: String,
    workspace_dir: String,
}

impl Auditor {
    /// Create a new Auditor.
    pub fn new(
        tools: std::sync::Arc<tokio::sync::RwLock<ToolRegistry>>,
        working_dir: String,
        workspace_dir: String,
    ) -> Self {
        Self {
            tools,
            working_dir,
            workspace_dir,
        }
    }

    /// Verify a containment/eradication action.
    ///
    /// For example, if the Executor claims "killed process xmrig.exe", the Auditor
    /// re-runs ir_process to verify the process is no longer present.
    pub async fn verify_action(&self, action_desc: &str) -> AuditResult {
        info!("[auditor] Verifying action: {}", action_desc);

        // Parse the action description to determine what to verify
        let lower = action_desc.to_lowercase();

        // Process kill verification
        if lower.contains("kill") || lower.contains("terminated") || lower.contains("stopped") {
            return self.verify_process_gone(action_desc).await;
        }

        // Service stop verification
        if lower.contains("service") && (lower.contains("stop") || lower.contains("disable")) {
            return self.verify_service_stopped(action_desc).await;
        }

        // Persistence removal verification
        if lower.contains("remov") || lower.contains("delet") || lower.contains("clean") {
            return self.verify_persistence_removed(action_desc).await;
        }

        // Default: cannot verify automatically
        AuditResult {
            verified: false,
            description: action_desc.to_string(),
            evidence: String::new(),
            failure_reason: Some("No automatic verification method for this action type".to_string()),
        }
    }

    /// Verify an artifact (file) exists and is valid.
    pub async fn verify_artifact(&self, path: &str, expected_content: Option<&str>) -> AuditResult {
        info!("[auditor] Verifying artifact: {}", path);

        let full_path = if std::path::Path::new(path).is_absolute() {
            path.to_string()
        } else {
            format!("{}/{}", self.workspace_dir, path)
        };

        // Check file exists
        let metadata = match tokio::fs::metadata(&full_path).await {
            Ok(m) => m,
            Err(e) => {
                return AuditResult {
                    verified: false,
                    description: format!("Artifact verification: {}", path),
                    evidence: String::new(),
                    failure_reason: Some(format!("File not found: {}", e)),
                };
            }
        };

        // Check non-empty
        if metadata.len() == 0 {
            return AuditResult {
                verified: false,
                description: format!("Artifact verification: {}", path),
                evidence: String::new(),
                failure_reason: Some("File is empty".to_string()),
            };
        }

        // Check content if expected
        if let Some(expected) = expected_content {
            match tokio::fs::read_to_string(&full_path).await {
                Ok(content) => {
                    if !content.contains(expected) {
                        return AuditResult {
                            verified: false,
                            description: format!("Artifact verification: {}", path),
                            evidence: format!("File size: {} bytes", metadata.len()),
                            failure_reason: Some(format!("Expected content '{}' not found", expected)),
                        };
                    }
                }
                Err(e) => {
                    return AuditResult {
                        verified: false,
                        description: format!("Artifact verification: {}", path),
                        evidence: String::new(),
                        failure_reason: Some(format!("Cannot read file: {}", e)),
                    };
                }
            }
        }

        AuditResult {
            verified: true,
            description: format!("Artifact verified: {}", path),
            evidence: format!("File exists, {} bytes", metadata.len()),
            failure_reason: None,
        }
    }

    /// Verify a process is no longer running.
    async fn verify_process_gone(&self, action_desc: &str) -> AuditResult {
        // Extract process name from action description
        // This is a simplified extraction — real implementation would parse more carefully
        let process_name = extract_process_name(action_desc);

        if process_name.is_empty() {
            return AuditResult {
                verified: false,
                description: action_desc.to_string(),
                evidence: String::new(),
                failure_reason: Some("Could not extract process name from action description".to_string()),
            };
        }

        // Run ir_process to check if process is still running
        let registry = self.tools.read().await;
        if let Some(tool) = registry.get("ir_process") {
            let ctx = ToolContext::simple(self.working_dir.clone(), self.workspace_dir.clone());
            let args = serde_json::json!({
                "action": "list",
                "filter": process_name
            });

            match tool.execute(args, &ctx).await {
                Ok(result) => {
                    let result_str = result.to_string();
                    // Check if process is still in the list
                    if result_str.to_lowercase().contains(&process_name.to_lowercase()) {
                        AuditResult {
                            verified: false,
                            description: action_desc.to_string(),
                            evidence: result_str.chars().take(500).collect(),
                            failure_reason: Some(format!("Process '{}' still running", process_name)),
                        }
                    } else {
                        AuditResult {
                            verified: true,
                            description: action_desc.to_string(),
                            evidence: format!("Process '{}' not found in process list", process_name),
                            failure_reason: None,
                        }
                    }
                }
                Err(e) => {
                    AuditResult {
                        verified: false,
                        description: action_desc.to_string(),
                        evidence: String::new(),
                        failure_reason: Some(format!("ir_process failed: {}", e)),
                    }
                }
            }
        } else {
            AuditResult {
                verified: false,
                description: action_desc.to_string(),
                evidence: String::new(),
                failure_reason: Some("ir_process tool not available".to_string()),
            }
        }
    }

    /// Verify a service is stopped.
    async fn verify_service_stopped(&self, action_desc: &str) -> AuditResult {
        // Simplified — would need to extract service name and check status
        AuditResult {
            verified: false,
            description: action_desc.to_string(),
            evidence: String::new(),
            failure_reason: Some("Service verification not yet implemented".to_string()),
        }
    }

    /// Verify persistence was removed.
    async fn verify_persistence_removed(&self, action_desc: &str) -> AuditResult {
        // Simplified — would need to re-run ir_persistence and check
        AuditResult {
            verified: false,
            description: action_desc.to_string(),
            evidence: String::new(),
            failure_reason: Some("Persistence verification not yet implemented".to_string()),
        }
    }
}

/// Extract a process name from an action description.
/// This is a simplified heuristic — real implementation would be more robust.
fn extract_process_name(action_desc: &str) -> String {
    let lower = action_desc.to_lowercase();

    // Look for common patterns
    let patterns = [
        "killed process ",
        "terminated process ",
        "stopped process ",
        "process ",
    ];

    for pattern in &patterns {
        if let Some(idx) = lower.find(pattern) {
            let rest = &action_desc[idx + pattern.len()..];
            // Take until whitespace or punctuation
            let name: String = rest.chars()
                .take_while(|c| c.is_alphanumeric() || *c == '.' || *c == '_' || *c == '-')
                .collect();
            if !name.is_empty() {
                return name;
            }
        }
    }

    String::new()
}
