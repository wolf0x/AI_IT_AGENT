//! Partial result protocol for long-running tools.
//!
//! When a tool times out, instead of returning an error and losing all accumulated work,
//! it can return a partial result with status="partial". This allows the agent to:
//! 1. Use the partial results for analysis
//! 2. Decide whether to retry with a narrower scope
//! 3. Avoid wasting work already done
//!
//! # Protocol
//!
//! Tools that support partial results return a JSON object with:
//! - `status`: "partial" (instead of success/error)
//! - `findings` or `results`: accumulated data so far
//! - `progress`: human-readable progress indicator (e.g., "62%", "3 of 8 drives")
//! - `hint`: guidance for the agent on how to proceed (e.g., "narrow scope to C:\\Windows")
//!
//! # Implementation Pattern
//!
//! Tools should:
//! 1. Track progress internally (e.g., which files/drives have been scanned)
//! 2. Accumulate results in a shared structure
//! 3. Periodically check elapsed time
//! 4. If approaching timeout, return partial results with status="partial"
//!
//! # Example
//!
//! ```json
//! {
//!   "status": "partial",
//!   "findings": [...],
//!   "progress": "3 of 8 drives scanned",
//!   "hint": "Scan timed out. Consider narrowing scope to specific directories."
//! }
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Status of a tool execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionStatus {
    /// Tool completed successfully with full results.
    Success,
    /// Tool timed out but has partial results.
    Partial,
    /// Tool failed with an error.
    Error,
}

/// Partial result wrapper for long-running tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialResult {
    /// Always "partial" for this struct.
    pub status: ExecutionStatus,
    /// Accumulated findings/results so far.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub findings: Option<Value>,
    /// Human-readable progress indicator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<String>,
    /// Guidance for the agent on how to proceed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Elapsed time in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_secs: Option<u64>,
}

impl PartialResult {
    /// Create a new partial result with the given findings.
    pub fn new(findings: Value) -> Self {
        Self {
            status: ExecutionStatus::Partial,
            findings: Some(findings),
            progress: None,
            hint: None,
            elapsed_secs: None,
        }
    }

    /// Add a progress indicator.
    pub fn with_progress(mut self, progress: impl Into<String>) -> Self {
        self.progress = Some(progress.into());
        self
    }

    /// Add a hint for the agent.
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Add elapsed time.
    pub fn with_elapsed(mut self, secs: u64) -> Self {
        self.elapsed_secs = Some(secs);
        self
    }

    /// Convert to JSON Value for tool return.
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}
