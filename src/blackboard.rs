//! Blackboard — shared information exchange hub between Instant and Expert modes.
//!
//! The Blackboard replaces the one-way seed_context mechanism with a bidirectional
//! information store. Both modes write their findings and read the other's findings,
//! enabling seamless mode switching without context loss.
//!
//! # Data Flow
//!
//! ```text
//! Instant mode completes → writes summary to Blackboard
//!     ↓
//! Expert mode starts → reads Blackboard for Instant-mode context
//!     ↓
//! Expert mode completes a round → writes findings to Blackboard
//!     ↓
//! Instant mode starts → reads Blackboard for Expert-mode findings
//! ```
//!
//! Each entry is lightweight (summary ≤ 100 chars, optional detail ≤ 200 chars)
//! to keep context injection efficient. Max 20 entries per session (FIFO eviction).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single structured entry on the Blackboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlackboardEntry {
    /// Source mode: "instant" or "expert"
    pub source: String,
    /// Entry type: "finding", "action", "phase_change", "summary", "original_task"
    pub entry_type: String,
    /// One-line summary, max 100 characters
    pub summary: String,
    /// Optional detail, max 200 characters
    pub detail: Option<String>,
    /// IR phase this entry belongs to (Expert mode only)
    pub phase: Option<String>,
    /// When this entry was created
    pub timestamp: DateTime<Utc>,
}

/// Session-scoped Blackboard.
///
/// Persisted to SQLite after each write. Max 20 entries — oldest are evicted
/// first when the limit is reached.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blackboard {
    /// Session ID this blackboard belongs to
    pub session_id: String,
    /// Ordered entries (newest last)
    pub entries: Vec<BlackboardEntry>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

impl Blackboard {
    /// Create a new empty Blackboard for a session.
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: session_id.to_string(),
            entries: Vec::new(),
            updated_at: Utc::now(),
        }
    }

    /// Add an entry. Evicts oldest if over 20 entries.
    ///
    /// P3: Deduplication — if an entry with the same source + entry_type + summary
    /// already exists, its timestamp and detail are updated in-place instead of
    /// adding a duplicate.
    pub fn add_entry(&mut self, entry: BlackboardEntry) {
        // Dedup: same source + entry_type + summary → update in-place
        if let Some(existing) = self.entries.iter_mut().rev().find(|e| {
            e.source == entry.source
                && e.entry_type == entry.entry_type
                && e.summary == entry.summary
        }) {
            existing.timestamp = entry.timestamp;
            if entry.detail.is_some() {
                existing.detail = entry.detail;
            }
            return;
        }
        self.entries.push(entry);
        if self.entries.len() > 20 {
            self.entries.remove(0);
        }
        self.updated_at = Utc::now();
    }

    /// Get all entries from a specific source mode.
    pub fn get_entries_by_source(&self, source: &str) -> Vec<&BlackboardEntry> {
        self.entries.iter().filter(|e| e.source == source).collect()
    }

    /// Get the most recent original_task entry, if any.
    pub fn get_original_task(&self) -> Option<&str> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.entry_type == "original_task")
            .map(|e| e.summary.as_str())
    }

    /// Format entries into a concise context string for LLM injection.
    ///
    /// P5: Entries are grouped by phase (when available) for better readability.
    /// Entries without a phase are listed under "General".
    /// This is used by Instant mode to see Expert mode's findings.
    pub fn to_context_string(&self, source_filter: Option<&str>) -> String {
        let mut s = String::from("[Blackboard Context]\n");
        let entries: Vec<&BlackboardEntry> = match source_filter {
            Some(filter) => self.get_entries_by_source(filter),
            None => self.entries.iter().collect(),
        };
        if entries.is_empty() {
            s.push_str("(no entries)\n");
            return s;
        }

        // Group entries by phase (None → "General")
        let mut phased: std::collections::BTreeMap<Option<&str>, Vec<&BlackboardEntry>> =
            std::collections::BTreeMap::new();
        for entry in &entries {
            let phase_key: Option<&str> = entry.phase.as_deref();
            phased.entry(phase_key).or_default().push(entry);
        }

        for (phase_key, group_entries) in &phased {
            let phase_label = match phase_key {
                Some(p) => format!("=== {} ===", p),
                None => "=== General ===".to_string(),
            };
            s.push_str(&format!("{} ({} entries)\n", phase_label, group_entries.len()));
            for entry in group_entries {
                let summary: String = entry.summary.chars().take(100).collect();
                s.push_str(&format!(
                    "- [{}] {}: {}\n",
                    entry.source.to_uppercase(),
                    entry.entry_type,
                    summary
                ));
                if let Some(ref detail) = entry.detail {
                    let detail_trimmed: String = detail.chars().take(200).collect();
                    s.push_str(&format!("  {}\n", detail_trimmed));
                }
            }
        }
        s
    }

    /// Serialize to JSON for storage.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize Blackboard: {}", e))
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("Failed to deserialize Blackboard: {}", e))
    }
}