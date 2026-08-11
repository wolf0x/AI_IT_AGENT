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
use tracing::info;

use crate::model::openai::OpenAiProvider;
use crate::tool::ToolRegistry;
use crate::context::ToolContext;

/// Result of an audit verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResult {
    /// Whether the verification passed (complete == verified true).
    pub verified: bool,
    /// Audit status: complete / incomplete / blocked.
    pub status: String,
    /// Evidence integrity: clean / suspect / violation.
    pub integrity: String,
    /// Description of what was verified.
    pub description: String,
    /// Evidence from the verification (e.g., process list output).
    pub evidence: String,
    /// If verification failed, why it failed.
    pub failure_reason: Option<String>,
}

impl AuditResult {
    pub fn ok(description: &str, evidence: String) -> Self {
        Self {
            verified: true,
            status: "complete".to_string(),
            integrity: "clean".to_string(),
            description: description.to_string(),
            evidence,
            failure_reason: None,
        }
    }

    pub fn fail(description: &str, evidence: String, reason: &str) -> Self {
        Self {
            verified: false,
            status: "incomplete".to_string(),
            integrity: "suspect".to_string(),
            description: description.to_string(),
            evidence,
            failure_reason: Some(reason.to_string()),
        }
    }

    pub fn blocked(description: &str, evidence: String, reason: &str) -> Self {
        Self {
            verified: false,
            status: "blocked".to_string(),
            integrity: "violation".to_string(),
            description: description.to_string(),
            evidence,
            failure_reason: Some(reason.to_string()),
        }
    }
}

/// Auditor for managed task execution.
///
/// Hybrid design:
/// - Deterministic layer (code, zero token): file existence, process checks.
/// - Semantic layer (LLM, optional): log interpretation, test results, evidence chains.
pub struct Auditor {
    tools: std::sync::Arc<tokio::sync::RwLock<ToolRegistry>>,
    working_dir: String,
    workspace_dir: String,
    /// LLM provider for semantic verification (None = code-only mode).
    provider: Option<std::sync::Arc<OpenAiProvider>>,
    /// Model used for semantic verification.
    auditor_model: String,
    /// Max characters of evidence fed to the LLM (budget control).
    auditor_context_chars: usize,
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
            provider: None,
            auditor_model: String::new(),
            auditor_context_chars: 8000,
        }
    }

    /// Enable LLM-based semantic verification.
    pub fn with_llm(mut self, provider: std::sync::Arc<OpenAiProvider>, model: String, context_chars: usize) -> Self {
        self.provider = Some(provider);
        self.auditor_model = model;
        self.auditor_context_chars = context_chars.max(1000);
        self
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
        AuditResult::fail(action_desc, String::new(), "No automatic verification method for this action type")
    }

    /// Verify an artifact (file) exists and is valid.
    /// If the file is a log/test-output artifact and an LLM is configured,
    /// additionally run semantic verification against the expected criteria.
    /// 
    /// **MANDATORY**: All artifacts MUST be saved under workspace/output/. 
    /// Paths outside workspace/output/ will be rejected.
    pub async fn verify_artifact(&self, path: &str, expected_content: Option<&str>) -> AuditResult {
        info!("[auditor] Verifying artifact: {}", path);

        // **MANDATORY CHECK**: Ensure path is under workspace/output/
        let normalized_path = path.replace('\\', "/").to_lowercase();
        let workspace_output = format!("{}/output/", self.workspace_dir.replace('\\', "/")).to_lowercase();
        
        // Check if path is relative (starts with "output/" or "workspace/output/")
        // or absolute and under workspace_dir/output/
        let is_valid_path = if std::path::Path::new(path).is_absolute() {
            // Absolute path: must be under workspace_dir/output/
            normalized_path.starts_with(&workspace_output)
        } else {
            // Relative path: must start with "output/" or be just a filename (will be prefixed with workspace_dir)
            normalized_path.starts_with("output/") || normalized_path.starts_with("workspace/output/") || !normalized_path.contains('/')
        };
        
        if !is_valid_path {
            return AuditResult::fail(
                path,
                String::new(),
                &format!("VIOLATION: Artifact path '{}' is NOT under workspace/output/. ALL artifacts MUST be saved under workspace/output/ directory. NEVER save to C:\\, D:\\, or other locations.", path)
            );
        }

        let full_path = if std::path::Path::new(path).is_absolute() {
            path.to_string()
        } else {
            format!("{}/{}", self.workspace_dir, path)
        };

        // Check file exists
        let metadata = match tokio::fs::metadata(&full_path).await {
            Ok(m) => m,
            Err(e) => {
                return AuditResult::fail(
                    &format!("Artifact verification: {}", path),
                    String::new(),
                    &format!("File not found: {}", e),
                );
            }
        };

        // Check non-empty
        if metadata.len() == 0 {
            return AuditResult::fail(
                &format!("Artifact verification: {}", path),
                String::new(),
                "File is empty",
            );
        }

        // Check content if expected
        if let Some(expected) = expected_content {
            match tokio::fs::read_to_string(&full_path).await {
                Ok(content) => {
                    if !content.contains(expected) {
                        return AuditResult::fail(
                            &format!("Artifact verification: {}", path),
                            format!("File size: {} bytes", metadata.len()),
                            &format!("Expected content '{}' not found", expected),
                        );
                    }
                }
                Err(e) => {
                    return AuditResult::fail(
                        &format!("Artifact verification: {}", path),
                        String::new(),
                        &format!("Cannot read file: {}", e),
                    );
                }
            }
        }

        // Deterministic layer passed. Now try semantic verification if an LLM is
        // configured AND the artifact looks like a semantic artifact (log/test/
        // analysis output larger than a bare marker file).
        let is_semantic = matches!(
            path.to_lowercase().rsplit('.').next().unwrap_or(""),
            "log" | "txt" | "md" | "json" | "csv" | "out"
        );
        if is_semantic && self.provider.is_some() {
            if let Ok(content) = tokio::fs::read_to_string(&full_path).await {
                let criteria = expected_content.unwrap_or("the artifact is valid and complete");
                return self.verify_semantic(path, &content, criteria).await;
            }
        }

        AuditResult::ok(&format!("Artifact verified: {}", path), format!("File exists, {} bytes", metadata.len()))
    }

    /// LLM-based semantic verification: interprets real file content against
    /// the Manager's success criteria. Never fabricates evidence — it only
    /// receives actual file content and must state insufficiency explicitly.
    pub async fn verify_semantic(&self, path: &str, content: &str, criteria: &str) -> AuditResult {
        let Some(provider) = &self.provider else {
            return AuditResult::fail(path, String::new(), "LLM verification not configured");
        };

        // Budget control: truncate evidence to auditor_context_chars.
        let truncated: String = content.chars().take(self.auditor_context_chars).collect();
        let truncated_note = if truncated.len() < content.len() {
            format!("\n[truncated from {} chars]", content.len())
        } else {
            String::new()
        };

        let mut system = String::from("You are the Auditor role in a long-horizon incident response task.\n\
            ROLE: READ-ONLY verification. You never modify anything.\n\
            HARD RULES:\n\
            1. You receive ONLY real file content — never accept agent claims.\n\
            2. Verify the evidence against the success criteria.\n\
            3. Output EXACTLY this format, nothing else:\n\
               status: complete|incomplete|blocked\n\
               integrity: clean|suspect|violation\n\
               reason: <one sentence>\n\
            4. NEVER fabricate evidence. If the provided data is insufficient, say so explicitly.\n\
            5. If evidence contradicts the claim, integrity = violation.");
        let lang = crate::agent::llm_agent::detect_user_language(criteria);
        system.push_str(&format!("\nLANGUAGE: The success criteria are in {lang}. Write the reason line in {lang}; keep status/integrity tokens exactly as specified."));
        let user = format!(
            "Evidence file: {}\n\nSuccess criteria: {}\n\nEvidence content (truncated to {} chars):\n{}{}\n\nOutput the verdict in the required format.",
            path, criteria, self.auditor_context_chars, truncated, truncated_note
        );

        let messages = vec![
            crate::model::ChatMessage::system(&system),
            crate::model::ChatMessage::user(&user),
        ];

        let output = match provider.chat_simple(&self.auditor_model, &messages).await {
            Ok(o) => o,
            Err(e) => {
                return AuditResult::blocked(
                    &format!("Semantic verification: {}", path),
                    String::new(),
                    &format!("LLM verification failed: {}", e),
                );
            }
        };

        // Parse fixed format: status / integrity / reason lines.
        let lower = output.to_lowercase();
        let status = if lower.contains("status: complete") || lower.contains("status:complete") {
            "complete"
        } else if lower.contains("status: blocked") || lower.contains("status:blocked") {
            "blocked"
        } else {
            "incomplete"
        };
        let integrity = if lower.contains("integrity: clean") || lower.contains("integrity:clean") {
            "clean"
        } else if lower.contains("integrity: violation") || lower.contains("integrity:violation") {
            "violation"
        } else {
            "suspect"
        };
        let reason = output.lines()
            .find(|l| l.trim_start().starts_with("reason:"))
            .map(|l| l.trim_start().trim_start_matches("reason:").trim().to_string())
            .unwrap_or_else(|| "No reason provided".to_string());

        let verified = status == "complete" && integrity != "violation";
        AuditResult {
            verified,
            status: status.to_string(),
            integrity: integrity.to_string(),
            description: format!("Semantic verification: {}", path),
            evidence: truncated.chars().take(500).collect(),
            failure_reason: if verified { None } else { Some(reason) },
        }
    }

    /// Verify a process is no longer running.
    async fn verify_process_gone(&self, action_desc: &str) -> AuditResult {
        // Extract process name from action description
        // This is a simplified extraction — real implementation would parse more carefully
        let process_name = extract_process_name(action_desc);

        if process_name.is_empty() {
            return AuditResult::fail(action_desc, String::new(), "Could not extract process name from action description");
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
                        AuditResult::fail(
                            action_desc,
                            result_str.chars().take(500).collect(),
                            &format!("Process '{}' still running", process_name),
                        )
                    } else {
                        AuditResult::ok(
                            action_desc,
                            format!("Process '{}' not found in process list", process_name),
                        )
                    }
                }
                Err(e) => {
                    AuditResult::fail(action_desc, String::new(), &format!("ir_process failed: {}", e))
                }
            }
        } else {
            AuditResult::fail(action_desc, String::new(), "ir_process tool not available")
        }
    }

    /// Verify a service is stopped.
    async fn verify_service_stopped(&self, action_desc: &str) -> AuditResult {
        // Simplified — would need to extract service name and check status
        AuditResult::fail(action_desc, String::new(), "Service verification not yet implemented")
    }

    /// Verify persistence was removed.
    async fn verify_persistence_removed(&self, action_desc: &str) -> AuditResult {
        // Simplified — would need to re-run ir_persistence and check
        AuditResult::fail(action_desc, String::new(), "Persistence verification not yet implemented")
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
