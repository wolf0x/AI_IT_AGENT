//! CRON Task Scheduler — periodic task execution via chat-style prompts.
//!
//! Tasks are stored in cron_tasks.json and checked every 30 seconds.
//! Supports simple interval syntax: "every 5m", "every 1h", "every 30s"
//! and basic 5-field cron expressions: "*/5 * * * *"

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn, error};

use crate::agent::AgentEvent;
use crate::permission::PendingMap;
use crate::runner::Runner;

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
    model_names: Vec<String>,
    permissions: Arc<Mutex<HashMap<String, bool>>>,
    permission_pending: PendingMap,
    max_iterations: usize,
    rabbit_hole_threshold: usize,
}

impl Scheduler {
    pub fn new(
        storage_path: &str,
        runner: Arc<Runner>,
        model_names: Vec<String>,
        permissions: Arc<Mutex<HashMap<String, bool>>>,
        permission_pending: PendingMap,
        max_iterations: usize,
        rabbit_hole_threshold: usize,
    ) -> Self {
        let mut scheduler = Self {
            tasks: Vec::new(),
            storage_path: storage_path.to_string(),
            runner,
            model_names,
            permissions,
            permission_pending,
            max_iterations,
            rabbit_hole_threshold,
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
    pub fn parse_interval(schedule: &str) -> u64 {
        let s = schedule.trim().to_lowercase();

        // "every Ns/Nm/Nh" syntax
        if let Some(rest) = s.strip_prefix("every ") {
            let rest = rest.trim();
            if let Some(num_str) = rest.strip_suffix('s') {
                if let Ok(n) = num_str.trim().parse::<u64>() {
                    return n;
                }
            } else if let Some(num_str) = rest.strip_suffix('m') {
                if let Ok(n) = num_str.trim().parse::<u64>() {
                    return n * 60;
                }
            } else if let Some(num_str) = rest.strip_suffix('h') {
                if let Ok(n) = num_str.trim().parse::<u64>() {
                    return n * 3600;
                }
            }
            // Try parsing as plain number (seconds)
            if let Ok(n) = rest.parse::<u64>() {
                return n;
            }
        }

        // Basic 5-field cron: just return a default of 60s for anything that looks like cron
        // A full cron parser would be more complex; for now we support "every N" syntax primarily
        if s.contains('*') || s.split_whitespace().count() == 5 {
            return 60; // Default to 1 minute for cron expressions
        }

        60 // Default fallback
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
        task.next_run = Some(Self::compute_next_run(task.interval_secs));
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
                task.next_run = Some(Self::compute_next_run(task.interval_secs));
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
                task.next_run = Some(Self::compute_next_run(task.interval_secs));
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
            task.next_run = Some(Self::compute_next_run(task.interval_secs));

            let model = if task.model.is_empty() {
                self.model_names.first().cloned().unwrap_or_default()
            } else {
                task.model.clone()
            };

            let message = task.message.clone();
            let runner = self.runner.clone();
            let permissions = self.permissions.clone();
            let permission_pending = self.permission_pending.clone();
            let max_iter = self.max_iterations;
            let rabbit_hole = self.rabbit_hole_threshold;
            let task_name = task.name.clone();

            // Execute the task in a background task
            tokio::spawn(async move {
                let session_id = format!("cron-{}", uuid::Uuid::new_v4());
                match runner.run(
                    &message, &session_id, &model, max_iter, vec![],
                    permissions, permission_pending,
                    None, rabbit_hole,
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
                        info!("CRON task '{}' completed ({} chars output)", task_name, text.len());
                    }
                    Err(e) => {
                        error!("CRON task '{}' failed to start: {}", task_name, e);
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
