//! Common types for Linux IR tool chain.
//! Shared across all linux_ir_* modules.

use serde::{Deserialize, Serialize};

/// Severity level for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn score(&self) -> u32 {
        match self {
            Severity::Critical => 10,
            Severity::High => 7,
            Severity::Medium => 4,
            Severity::Low => 2,
            Severity::Info => 0,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

/// A single detection finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub module_id: u32,
    pub module_name: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence: Option<String>,
    pub file_path: Option<String>,
    pub score: u32,
}

impl Finding {
    pub fn new(module_id: u32, module_name: &str, severity: Severity, title: &str) -> Self {
        Self {
            module_id,
            module_name: module_name.to_string(),
            severity,
            title: title.to_string(),
            description: String::new(),
            evidence: None,
            file_path: None,
            score: severity.score(),
        }
    }

    pub fn with_evidence(mut self, evidence: &str) -> Self {
        self.evidence = Some(evidence.to_string());
        self
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn with_file(mut self, path: &str) -> Self {
        self.file_path = Some(path.to_string());
        self
    }
}

/// Module definition — each linux_ir_* file exports these
#[derive(Clone)]
pub struct ModuleDef {
    pub id: u32,
    pub name: &'static str,
    pub description: &'static str,
    pub commands: &'static [&'static str],
}

/// Trait for Linux IR module categories
pub trait LinuxIrCategory: Send + Sync {
    /// Category name
    fn category(&self) -> &'static str;

    /// All modules in this category
    fn modules(&self) -> &'static [ModuleDef];

    /// Parse command output for a specific module
    fn parse(&self, module_id: u32, output: &str) -> Vec<Finding>;
}

/// Helper: extract line containing keyword
pub fn extract_line(output: &str, keyword: &str) -> String {
    output
        .lines()
        .find(|l| l.to_lowercase().contains(&keyword.to_lowercase()))
        .map(|l| truncate(l, 200))
        .unwrap_or_default()
}

/// Helper: truncate string
pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}
