//! CRON Task Scheduler — periodic task execution via chat-style prompts.
//!
//! Tasks are stored in cron_tasks.json and checked every 30 seconds.
//! Supports simple interval syntax: "every 5m", "every 1h", "every 30s"
//! and basic 5-field cron expressions: "*/5 * * * *"

use chrono::Timelike;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn, error};

use crate::agent::AgentEvent;
use crate::permission::PendingMap;
use crate::runner::Runner;
use crate::server::NotifyTx;

use std::collections::HashMap;

/// A scheduled task definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronTask {
    pub id: String,
    pub name: String,
    /// Schedule expression: "every 5m", "every 1h", or 5-field cron "*/5 * * * *"
    pub schedule: String,
    /// The chat message to send when triggered
    pub message: String,
    /// Model to use (empty = default)
    #[serde(default)]
    pub model: String,
    /// Whether the task is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Last execution time (ISO 8601)
    #[serde(default)]
    pub last_run: Option<String>,
    /// Next scheduled run (ISO 8601)
    #[serde(default)]
    pub next_run: Option<String>,
    /// Interval in seconds (computed from schedule)
    #[serde(default)]
    pub interval_secs: u64,
}

fn default_true() -> bool { true }

/// The scheduler manages periodic tasks.
pub struct Scheduler {
    tasks: Vec<CronTask>,
    storage_path: String,
    runner: Arc<Runner>,
    model_configs: Arc<tokio::sync::RwLock<Vec<crate::config::ModelConfig>>>,
    permissions: Arc<Mutex<HashMap<String, bool>>>,
    permission_pending: PendingMap,
    max_iterations: usize,
    rabbit_hole_threshold: usize,
    context_window: usize,
    context_window_threshold: usize,
    tool_timeout_secs: u64,
    notify_tx: NotifyTx,
}

impl Scheduler {
    pub fn new(
        storage_path: &str,
        runner: Arc<Runner>,
        model_configs: Arc<tokio::sync::RwLock<Vec<crate::config::ModelConfig>>>,
        permissions: Arc<Mutex<HashMap<String, bool>>>,
        permission_pending: PendingMap,
        max_iterations: usize,
        rabbit_hole_threshold: usize,
        context_window: usize,
        context_window_threshold: usize,
        tool_timeout_secs: u64,
        notify_tx: NotifyTx,
    ) -> Self {
        let mut scheduler = Self {
            tasks: Vec::new(),
            storage_path: storage_path.to_string(),
            runner,
            model_configs,
            permissions,
            permission_pending,
            max_iterations,
            rabbit_hole_threshold,
            context_window,
            context_window_threshold,
            tool_timeout_secs,
            notify_tx,
        };
        scheduler.load();
        scheduler
    }

    /// Load tasks from JSON file.
    fn load(&mut self) {
        let path = Path::new(&self.storage_path);
        if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    match serde_json::from_str::<Vec<CronTask>>(&content) {
                        Ok(tasks) => {
                            info!("Loaded {} cron tasks", tasks.len());
                            self.tasks = tasks;
                        }
                        Err(e) => warn!("Failed to parse cron tasks: {}", e),
                    }
                }
                Err(e) => warn!("Failed to read cron tasks file: {}", e),
            }
        }
    }

    /// Save tasks to JSON file.
    fn save(&self) {
        match serde_json::to_string_pretty(&self.tasks) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.storage_path, json) {
                    error!("Failed to save cron tasks: {}", e);
                }
            }
            Err(e) => error!("Failed to serialize cron tasks: {}", e),
        }
    }

    /// Parse schedule expression into interval seconds.
    /// Supports: "every 10m", "every 10 min", "every 10 mins", "every 10 minutes",
    /// "every 1h", "every 1 hour", "every 2 hours", "every 30s", "every 30 sec", etc.
    pub fn parse_interval(schedule: &str) -> u64 {
        let s = schedule.trim().to_lowercase();

        // "every N..." syntax
        if let Some(rest) = s.strip_prefix("every ") {
            let rest = rest.trim();
            // Extract the number and the unit
            let (num_str, unit) = rest.split_at(
                rest.find(|c: char| c.is_alphabetic()).unwrap_or(rest.len())
            );
            let num_str = num_str.trim();
            let unit = unit.trim();

            if let Ok(n) = num_str.parse::<u64>() {
                // Match unit: seconds, minutes, hours (and abbreviations)
                if unit.is_empty() || unit == "s" || unit.starts_with("sec") {
                    return n;
                } else if unit == "m" || unit.starts_with("min") {
                    return n * 60;
                } else if unit == "h" || unit.starts_with("hour") || unit.starts_with("hr") {
                    return n * 3600;
                } else if unit == "d" || unit.starts_with("day") {
                    return n * 86400;
                }
            }
            // Try parsing as plain number (seconds)
            if let Ok(n) = rest.parse::<u64>() {
                return n;
            }
        }

        // Basic 5-field cron: compute the interval to the next matching time
        if s.contains('*') || s.split_whitespace().count() == 5 {
            // For cron expressions, return the interval to the next match
            let fields: Vec<&str> = s.split_whitespace().collect();
            if fields.len() == 5 {
                let now = chrono::Utc::now();
                if let Some(next) = Self::next_cron_time(&fields, now) {
                    let interval = (next - now).num_seconds().max(60) as u64;
                    return interval;
                }
            }
            return 3600; // Fallback: 1 hour if cron parse fails
        }

        60 // Default fallback
    }

    /// Check if a single cron field matches a value.
    /// Supports: * (any), N (exact), N-M (range), */N (step), N,M,... (list).
    fn cron_field_matches(field: &str, value: u32) -> bool {
        for part in field.split(',') {
            let part = part.trim();
            if part == "*" {
                return true;
            }
            // Step: */N or N-M/S
            if let Some((range, step_str)) = part.split_once('/') {
                if let Ok(step) = step_str.parse::<u32>() {
                    if step == 0 { continue; }
                    let (start, end) = if range == "*" {
                        (0, u32::MAX)
                    } else if let Some((s, e)) = range.split_once('-') {
                        (s.parse().unwrap_or(0), e.parse().unwrap_or(0))
                    } else {
                        (range.parse().unwrap_or(0), u32::MAX)
                    };
                    if value >= start && value <= end && (value - start) % step == 0 {
                        return true;
                    }
                }
                continue;
            }
            // Range: N-M
            if let Some((s, e)) = part.split_once('-') {
                if let (Ok(start), Ok(end)) = (s.parse::<u32>(), e.parse::<u32>()) {
                    if value >= start && value <= end {
                        return true;
                    }
                }
                continue;
            }
            // Exact: N
            if let Ok(n) = part.parse::<u32>() {
                if value == n {
                    return true;
                }
            }
        }
        false
    }

    /// Check if a DateTime matches a 5-field cron expression.
    /// Fields: minute hour day-of-month month day-of-week (0=Sunday).
    fn cron_matches(fields: &[&str], dt: &chrono::DateTime<chrono::Utc>) -> bool {
        use chrono::Datelike;
        use chrono::Timelike;
        if fields.len() != 5 { return false; }
        let minute = dt.minute();
        let hour = dt.hour();
        let dom = dt.day();
        let month = dt.month();
        let dow = dt.weekday().num_days_from_sunday(); // 0 = Sunday

        Self::cron_field_matches(fields[0], minute)
            && Self::cron_field_matches(fields[1], hour)
            && Self::cron_field_matches(fields[2], dom)
            && Self::cron_field_matches(fields[3], month)
            && Self::cron_field_matches(fields[4], dow)
    }

    /// Find the next time (from `from`) that matches the cron expression.
    /// Iterates forward minute-by-minute, capped at 366 days.
    fn next_cron_time(fields: &[&str], from: chrono::DateTime<chrono::Utc>) -> Option<chrono::DateTime<chrono::Utc>> {
        // Start from the next whole minute
        let mut candidate = from
            .with_second(0).unwrap_or(from)
            .with_nanosecond(0).unwrap_or(from)
            + chrono::Duration::minutes(1);
        let limit = from + chrono::Duration::days(366);

        while candidate < limit {
            if Self::cron_matches(fields, &candidate) {
                return Some(candidate);
            }
            candidate += chrono::Duration::minutes(1);
        }
        None
    }

    /// Compute next run time from a schedule expression.
    fn compute_next_run_from_schedule(schedule: &str) -> String {
        let s = schedule.trim().to_lowercase();
        // Cron expression: find next matching time
        let fields: Vec<&str> = s.split_whitespace().collect();
        if fields.len() == 5 && (s.contains('*') || fields.iter().any(|f| f.contains(',') || f.contains('-') || f.contains('/'))) {
            let now = chrono::Utc::now();
            if let Some(next) = Self::next_cron_time(&fields, now) {
                return next.to_rfc3339();
            }
        }
        // "every N" syntax: use interval
        let interval = Self::parse_interval(schedule);
        Self::compute_next_run(interval)
    }

    /// Compute next run time from now + interval.
    fn compute_next_run(interval_secs: u64) -> String {
        let next = chrono::Utc::now() + chrono::Duration::seconds(interval_secs as i64);
        next.to_rfc3339()
    }

    /// List all tasks.
    pub fn list(&self) -> &[CronTask] {
        &self.tasks
    }

    /// Create a new task.
    pub fn create(&mut self, mut task: CronTask) -> &CronTask {
        task.id = uuid::Uuid::new_v4().to_string();
        task.interval_secs = Self::parse_interval(&task.schedule);
        task.next_run = Some(Self::compute_next_run_from_schedule(&task.schedule));
        self.tasks.push(task);
        self.save();
        self.tasks.last().unwrap()
    }

    /// Update an existing task.
    pub fn update(&mut self, id: &str, name: Option<String>, schedule: Option<String>,
                  message: Option<String>, model: Option<String>) -> bool {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.id == id) {
            if let Some(n) = name { task.name = n; }
            if let Some(s) = schedule {
                task.schedule = s;
                task.interval_secs = Self::parse_interval(&task.schedule);
                task.next_run = Some(Self::compute_next_run_from_schedule(&task.schedule));
            }
            if let Some(m) = message { task.message = m; }
            if let Some(m) = model { task.model = m; }
            self.save();
            true
        } else {
            false
        }
    }

    /// Delete a task.
    pub fn delete(&mut self, id: &str) -> bool {
        let len_before = self.tasks.len();
        self.tasks.retain(|t| t.id != id);
        if self.tasks.len() != len_before {
            self.save();
            true
        } else {
            false
        }
    }

    /// Toggle a task's enabled state.
    pub fn toggle(&mut self, id: &str) -> bool {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.id == id) {
            task.enabled = !task.enabled;
            if task.enabled {
                task.next_run = Some(Self::compute_next_run_from_schedule(&task.schedule));
            }
            self.save();
            true
        } else {
            false
        }
    }

    /// Check for due tasks and execute them. Called every 30 seconds.
    pub async fn tick(&mut self) {
        let now = chrono::Utc::now();
        let mut due_indices = Vec::new();

        for (i, task) in self.tasks.iter().enumerate() {
            if !task.enabled {
                continue;
            }
            if let Some(ref next_run_str) = task.next_run {
                if let Ok(next_run) = chrono::DateTime::parse_from_rfc3339(next_run_str) {
                    if now >= next_run {
                        due_indices.push(i);
                    }
                }
            }
        }

        let had_due = !due_indices.is_empty();
        for &i in &due_indices {
            let task = &self.tasks[i];
            info!("CRON task '{}' triggered: {}", task.name, task.message);

            // Update last_run and next_run
            let task = &mut self.tasks[i];
            task.last_run = Some(now.to_rfc3339());
            task.next_run = Some(Self::compute_next_run_from_schedule(&task.schedule));

            let model = if task.model.is_empty() {
                let mc = self.model_configs.read().await;
                mc.first().map(|m| m.name.clone()).unwrap_or_default()
            } else {
                task.model.clone()
            };

            let message = task.message.clone();
            let runner = self.runner.clone();
            let permissions = self.permissions.clone();
            let permission_pending = self.permission_pending.clone();
            let max_iter = self.max_iterations;
            let rabbit_hole = self.rabbit_hole_threshold;
            let ctx_window = self.context_window;
            let ctx_window_threshold = self.context_window_threshold;
            let tool_timeout = self.tool_timeout_secs;
            let task_name = task.name.clone();
            let notify_tx = self.notify_tx.clone();

            // Execute the task as an independent sub-agent (own session, empty history)
            tokio::spawn(async move {
                let session_id = format!("cron-{}", uuid::Uuid::new_v4());
                let start = std::time::Instant::now();
                match runner.run(
                    &message, &session_id, &model, max_iter, vec![],
                    permissions, permission_pending,
                    None, rabbit_hole,
                    ctx_window, ctx_window_threshold,
                    tool_timeout,
                    2,     // default max_tool_retries for scheduled tasks
                    vec![],  // no images for scheduled tasks
                    None, None,  // no checkpoint for scheduled tasks
                ).await {
                    Ok(mut stream) => {
                        use futures::StreamExt;
                        let mut text = String::new();
                        while let Some(result) = stream.next().await {
                            match result {
                                Ok(event) => {
                                    if let AgentEvent::TextDelta { content, .. } = &event {
                                        text.push_str(content);
                                    }
                                    if event.is_done() {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    error!("CRON task '{}' error: {}", task_name, e);
                                    break;
                                }
                            }
                        }
                        let elapsed = start.elapsed().as_secs();
                        info!("CRON task '{}' completed in {}s ({} chars output)", task_name, elapsed, text.len());

                        // Broadcast summary to all connected web chat clients
                        let summary = if text.trim().is_empty() {
                            format!("⚙️ CRON task '{}' completed (no output)", task_name)
                        } else {
                            format!("⚙️ **CRON: {}** ({}s)\n\n{}", task_name, elapsed, text)
                        };
                        let ws_msg = serde_json::json!({
                            "type": "notification",
                            "message": summary,
                            "timestamp": chrono::Utc::now().to_rfc3339()
                        }).to_string();
                        let _ = notify_tx.send(ws_msg);
                    }
                    Err(e) => {
                        error!("CRON task '{}' failed to start: {}", task_name, e);
                        let ws_msg = serde_json::json!({
                            "type": "notification",
                            "message": format!("❌ CRON task '{}' failed: {}", task_name, e),
                            "timestamp": chrono::Utc::now().to_rfc3339()
                        }).to_string();
                        let _ = notify_tx.send(ws_msg);
                    }
                }
            });
        }

        // Save if any tasks were updated
        if had_due {
            self.save();
        }
    }

    /// Run the scheduler loop — checks every 30 seconds.
    pub async fn run_loop(self_arc: Arc<Mutex<Self>>) {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let mut scheduler = self_arc.lock().await;
            scheduler.tick().await;
        }
    }
}
