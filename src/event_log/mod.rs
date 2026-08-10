//! Append-only JSONL event log for agent run state persistence.
//!
//! This module provides crash-safe state persistence for agent runs.
//! All state changes are written to a JSONL file before being applied to memory.
//! The file serves as the single source of truth for a run's execution history.
//!
//! # Design Principles
//!
//! - **Append-only**: Events are only appended, never modified or deleted
//! - **Crash-safe**: Critical events trigger fsync to ensure durability
//! - **No database**: JSONL is sufficient for sequential event streams
//! - **Replayable**: The log can be replayed to reconstruct run state
//!
//! # Event Types
//!
//! - `RunStarted`: Agent begins processing a task
//! - `TurnStarted`: Agent begins a new reasoning turn
//! - `Thinking`: LLM thinking/reasoning output
//! - `TextOutput`: LLM text output to user
//! - `ToolCallStarted`: Tool call initiated (before execution)
//! - `ToolCallCompleted`: Tool call finished with result
//! - `Checkpoint`: Periodic state snapshot for resume
//! - `RunCompleted`: Task finished successfully
//! - `RunFailed`: Task failed with error
//! - `Usage`: Token usage statistics

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

/// Unique identifier for a run session.
pub type RunId = String;

/// A single event in the JSONL event log.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum LogEvent {
    /// Agent begins processing a task.
    #[serde(rename = "run_started")]
    RunStarted {
        run_id: RunId,
        timestamp: DateTime<Utc>,
        instruction: String,
        model: String,
        session_id: String,
    },

    /// Agent begins a new reasoning turn.
    #[serde(rename = "turn_started")]
    TurnStarted {
        run_id: RunId,
        timestamp: DateTime<Utc>,
        turn_number: u32,
    },

    /// LLM thinking/reasoning output.
    #[serde(rename = "thinking")]
    Thinking {
        run_id: RunId,
        timestamp: DateTime<Utc>,
        turn_number: u32,
        content: String,
    },

    /// LLM text output to user.
    #[serde(rename = "text_output")]
    TextOutput {
        run_id: RunId,
        timestamp: DateTime<Utc>,
        turn_number: u32,
        content: String,
    },

    /// Tool call initiated (before execution).
    #[serde(rename = "tool_call_started")]
    ToolCallStarted {
        run_id: RunId,
        timestamp: DateTime<Utc>,
        turn_number: u32,
        call_id: String,
        tool_name: String,
        args: Value,
    },

    /// Tool call finished with result.
    #[serde(rename = "tool_call_completed")]
    ToolCallCompleted {
        run_id: RunId,
        timestamp: DateTime<Utc>,
        turn_number: u32,
        call_id: String,
        tool_name: String,
        result: Value,
        success: bool,
        duration_ms: u64,
    },

    /// Periodic state snapshot for resume.
    #[serde(rename = "checkpoint")]
    Checkpoint {
        run_id: RunId,
        timestamp: DateTime<Utc>,
        turn_number: u32,
        tokens_used: u64,
        conversation_summary: Option<String>,
        state: Value,
    },

    /// Task finished successfully.
    #[serde(rename = "run_completed")]
    RunCompleted {
        run_id: RunId,
        timestamp: DateTime<Utc>,
        total_turns: u32,
        total_tokens: u64,
        duration_ms: u64,
    },

    /// Task failed with error.
    #[serde(rename = "run_failed")]
    RunFailed {
        run_id: RunId,
        timestamp: DateTime<Utc>,
        total_turns: u32,
        error: String,
    },

    /// Token usage statistics.
    #[serde(rename = "usage")]
    Usage {
        run_id: RunId,
        timestamp: DateTime<Utc>,
        turn_number: u32,
        model: String,
        prompt_tokens: u64,
        completion_tokens: u64,
        total_tokens: u64,
    },
}

impl LogEvent {
    /// Check if this event should trigger fsync.
    pub fn requires_sync(&self) -> bool {
        matches!(
            self,
            Self::Checkpoint { .. }
                | Self::RunCompleted { .. }
                | Self::RunFailed { .. }
                | Self::ToolCallCompleted { .. }
        )
    }
}

/// Append-only JSONL event log writer.
///
/// Writes events to a file in JSONL format (one JSON object per line).
/// Critical events trigger fsync to ensure durability.
pub struct EventLog {
    file: File,
    events_written: u64,
}

impl EventLog {
    /// Create a new event log, appending to existing file if present.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        // Count existing events
        let events_written = Self::count_events(&path).unwrap_or(0);

        Ok(Self {
            file,
            events_written,
        })
    }

    /// Append an event to the log.
    pub fn append(&mut self, event: &LogEvent) -> std::io::Result<()> {
        let json = serde_json::to_string(event)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        writeln!(self.file, "{}", json)?;
        self.events_written += 1;

        // Fsync for critical events
        if event.requires_sync() {
            self.file.sync_data()?;
        }

        Ok(())
    }

    /// Count events in an existing log file.
    fn count_events(path: &Path) -> std::io::Result<u64> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(reader.lines().count() as u64)
    }
}

/// Read events from a JSONL log file.
#[allow(dead_code)] // replay API — reserved for crash-resume feature
pub fn read_events(path: impl AsRef<Path>) -> std::io::Result<Vec<LogEvent>> {
    let file = File::open(path.as_ref())?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<LogEvent>(&line) {
            Ok(event) => events.push(event),
            Err(e) => {
                tracing::warn!("Failed to parse event log line: {}", e);
            }
        }
    }

    Ok(events)
}

/// Find the last checkpoint in an event log.
#[allow(dead_code)] // replay API — reserved for crash-resume feature
pub fn find_last_checkpoint(events: &[LogEvent]) -> Option<&LogEvent> {
    events.iter().rev().find(|e| matches!(e, LogEvent::Checkpoint { .. }))
}

/// Get the run_id from a log file (from the first RunStarted event).
#[allow(dead_code)] // replay API — reserved for crash-resume feature
pub fn get_run_id(events: &[LogEvent]) -> Option<&str> {
    events.iter().find_map(|e| match e {
        LogEvent::RunStarted { run_id, .. } => Some(run_id.as_str()),
        _ => None,
    })
}

/// Replay statistics for a run.
#[allow(dead_code)] // replay API — reserved for crash-resume feature
#[derive(Debug, Default)]
pub struct ReplayStats {
    pub total_events: usize,
    pub total_turns: u32,
    pub total_tokens: u64,
    pub tool_calls: u32,
    pub successful_tool_calls: u32,
    pub failed_tool_calls: u32,
    pub completed: bool,
    pub failed: bool,
    pub error: Option<String>,
}

/// Compute replay statistics from events.
#[allow(dead_code)] // replay API — reserved for crash-resume feature
pub fn compute_replay_stats(events: &[LogEvent]) -> ReplayStats {
    let mut stats = ReplayStats {
        total_events: events.len(),
        ..Default::default()
    };

    for event in events {
        match event {
            LogEvent::TurnStarted { turn_number, .. } => {
                stats.total_turns = stats.total_turns.max(*turn_number);
            }
            LogEvent::ToolCallCompleted { success, .. } => {
                stats.tool_calls += 1;
                if *success {
                    stats.successful_tool_calls += 1;
                } else {
                    stats.failed_tool_calls += 1;
                }
            }
            LogEvent::RunCompleted { total_tokens, .. } => {
                stats.completed = true;
                stats.total_tokens = *total_tokens;
            }
            LogEvent::RunFailed { error, .. } => {
                stats.failed = true;
                stats.error = Some(error.clone());
            }
            LogEvent::Usage { total_tokens, .. } => {
                stats.total_tokens = stats.total_tokens.max(*total_tokens);
            }
            _ => {}
        }
    }

    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_event_log_write_and_read() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.jsonl");

        // Write events
        let mut log = EventLog::create_new(&path).unwrap();

        let event1 = LogEvent::RunStarted {
            run_id: "test-run-1".to_string(),
            timestamp: Utc::now(),
            instruction: "Test task".to_string(),
            model: "gpt-4".to_string(),
            session_id: "session-1".to_string(),
        };
        log.append(&event1).unwrap();

        let event2 = LogEvent::TurnStarted {
            run_id: "test-run-1".to_string(),
            timestamp: Utc::now(),
            turn_number: 1,
        };
        log.append(&event2).unwrap();

        log.sync().unwrap();
        drop(log);

        // Read events back
        let events = read_events(&path).unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], LogEvent::RunStarted { .. }));
        assert!(matches!(events[1], LogEvent::TurnStarted { .. }));
    }

    #[test]
    fn test_checkpoint_detection() {
        let events = vec![
            LogEvent::RunStarted {
                run_id: "run-1".to_string(),
                timestamp: Utc::now(),
                instruction: "Task".to_string(),
                model: "gpt-4".to_string(),
                session_id: "s1".to_string(),
            },
            LogEvent::TurnStarted {
                run_id: "run-1".to_string(),
                timestamp: Utc::now(),
                turn_number: 1,
            },
            LogEvent::Checkpoint {
                run_id: "run-1".to_string(),
                timestamp: Utc::now(),
                turn_number: 1,
                tokens_used: 1000,
                conversation_summary: None,
                state: Value::Null,
            },
            LogEvent::TurnStarted {
                run_id: "run-1".to_string(),
                timestamp: Utc::now(),
                turn_number: 2,
            },
        ];

        let checkpoint = find_last_checkpoint(&events);
        assert!(checkpoint.is_some());
        if let Some(LogEvent::Checkpoint { turn_number, .. }) = checkpoint {
            assert_eq!(*turn_number, 1);
        }
    }

    #[test]
    fn test_replay_stats() {
        let events = vec![
            LogEvent::RunStarted {
                run_id: "run-1".to_string(),
                timestamp: Utc::now(),
                instruction: "Task".to_string(),
                model: "gpt-4".to_string(),
                session_id: "s1".to_string(),
            },
            LogEvent::ToolCallCompleted {
                run_id: "run-1".to_string(),
                timestamp: Utc::now(),
                turn_number: 1,
                call_id: "c1".to_string(),
                tool_name: "shell_exec".to_string(),
                result: Value::String("ok".to_string()),
                success: true,
                duration_ms: 100,
            },
            LogEvent::RunCompleted {
                run_id: "run-1".to_string(),
                timestamp: Utc::now(),
                total_turns: 1,
                total_tokens: 500,
                duration_ms: 1000,
            },
        ];

        let stats = compute_replay_stats(&events);
        assert_eq!(stats.total_events, 3);
        assert_eq!(stats.tool_calls, 1);
        assert_eq!(stats.successful_tool_calls, 1);
        assert!(stats.completed);
        assert!(!stats.failed);
    }
}
