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

use std::collections::{HashMap, HashSet};

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
    /// Optional active window start date (YYYY-MM-DD, inclusive). Empty = no lower bound.
    #[serde(default)]
    pub start_date: Option<String>,
    /// Optional active window end date (YYYY-MM-DD, inclusive). Empty = no upper bound.
    #[serde(default)]
    pub end_date: Option<String>,
    /// Optional active window start time (HH:MM, local 24h). Empty = no lower bound.
    #[serde(default)]
    pub start_time: Option<String>,
    /// Optional active window end time (HH:MM, local 24h). Empty = no upper bound.
    #[serde(default)]
    pub end_time: Option<String>,
}

fn default_true() -> bool { true }
/// Directive appended to every CRON task so it runs unattended: execute the full goal
/// autonomously, report only verified facts/findings, and never ask the user for
/// permission, clarification, or offer follow-up questions/recommendations.
/// Used with string concat (not a format arg), so braces are fine as-is.
const CRON_MODE_DIRECTIVE: &str =
    "[CRON定时任务] 这是一条无人值守的定时任务。请自主完整地执行任务目标，一次性完成全部工作。只陈述已核实的事实和发现，不要向用户询问许可或澄清，不要反问“是否需要我……”，不要给出建议、推荐或下一步行动指引。若某项信息不可得，直接作为事实说明。完成后即停止。";


/// Normalize an optional date string: trim and treat empty as None.
fn normalize_opt_date(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() { None } else { Some(t.to_string()) }
}

/// Normalize an optional clock-time string: trim and treat empty as None.
fn normalize_opt_time(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() { None } else { Some(t.to_string()) }
}

/// Parse a "HH:MM" clock string into minutes-since-midnight; None if malformed.
fn parse_hhmm(s: &str) -> Option<u32> {
    let t = s.trim();
    let mut it = t.split(':');
    let hh: u32 = it.next()?.trim().parse().ok()?;
    let mm: u32 = it.next()?.trim().parse().ok()?;
    if it.next().is_some() || hh >= 24 || mm >= 60 { return None; }
    Some(hh * 60 + mm)
}

/// The scheduler manages periodic tasks.
pub struct Scheduler {
    tasks: Vec<CronTask>,
    storage_path: String,
    /// Global switch: auto-approve arbitrary commands for CRON tasks (default off).
    auto_approve: bool,
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
    /// Task ids currently executing, so an overlapping trigger is skipped
    /// (in-flight dedup) instead of spawning a concurrent duplicate run.
    running: HashSet<String>,
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
            auto_approve: false,
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
            running: HashSet::new(),
        };
        scheduler.load();
        scheduler.load_settings();
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
                            // Backfill next_run for enabled tasks missing it (legacy or
                            // malformed JSON) so they do not silently never fire.
                            let mut changed = false;
                            for t in self.tasks.iter_mut() {
                                if t.enabled && t.next_run.is_none() {
                                    t.next_run = Some(Self::compute_next_run_from_schedule(&t.schedule));
                                    changed = true;
                                }
                            }
                            if changed { self.save(); }
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


    /// Path to the cron settings file (sibling of cron_tasks.json).
    fn settings_path(&self) -> String {
        if self.storage_path.ends_with("cron_tasks.json") {
            self.storage_path[..self.storage_path.len() - "cron_tasks.json".len()].to_string() + "cron_settings.json"
        } else {
            self.storage_path.clone() + ".settings"
        }
    }

    /// Load the global CRON auto-approve flag from the settings file (default off).
    fn load_settings(&mut self) {
        let path = self.settings_path();
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Some(v) = serde_json::from_str::<serde_json::Value>(&content).ok()
                .and_then(|j| j["auto_approve"].as_bool()) {
                self.auto_approve = v;
            }
        }
    }

    fn save_settings(&self) {
        let json = serde_json::json!({ "auto_approve": self.auto_approve });
        if let Err(e) = std::fs::write(self.settings_path(), serde_json::to_string_pretty(&json).unwrap_or_default()) {
            error!("Failed to save cron settings: {}", e);
        }
    }

    /// Whether CRON tasks auto-approve arbitrary commands.
    pub fn auto_approve(&self) -> bool {
        self.auto_approve
    }

    /// Set the global CRON auto-approve flag and persist it.
    pub fn set_auto_approve(&mut self, on: bool) {
        if self.auto_approve != on {
            self.auto_approve = on;
            self.save_settings();
            info!("CRON auto-approve set to {}", on);
        }
    }

    /// Parse schedule expression into interval seconds.
    /// Supports: "every 10m", "every 10 min", "every 10 mins", "every 10 minutes",
    /// "every 1h", "every 1 hour", "every 2 hours", "every 30s", "every 30 sec", etc.
    pub fn parse_interval(schedule: &str) -> u64 {
        let s = schedule.trim().to_lowercase();

        // Accept both "every 5m" and a bare "5m" / "5 min". Previously a bare
        // schedule (e.g. "5m") skipped interval parsing and silently fell back to
        // 60s -- so "run every 5 minutes" actually ran every ~1 minute.
        let body = s.strip_prefix("every ").map(str::trim).unwrap_or(&s);

        // Extract the number and the unit
        let (num_str, unit) = body.split_at(
            body.find(|c: char| c.is_alphabetic()).unwrap_or(body.len())
        );
        let num_str = num_str.trim();
        let unit = unit.trim();

        if let Ok(n) = num_str.parse::<u64>() {
            // Match unit: seconds, minutes, hours (and abbreviations).
            // Empty unit = plain number in seconds (e.g. "every 30" or "30").
            if unit.is_empty() || unit == "s" || unit.starts_with("sec") {
                return n;
            } else if unit == "m" || unit.starts_with("min") {
                return n * 60;
            } else if unit == "h" || unit.starts_with("hour") || unit.starts_with("hr") {
                return n * 3600;
            } else if unit == "d" || unit.starts_with("day") {
                return n * 86400;
            }
            // Unrecognized unit (e.g. a typo) -> fall through to warn + default.
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

        warn!("[scheduler] Unrecognized schedule '{}', defaulting to 60s", schedule);
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

    /// Whether `now` falls within the task's optional [start_date, end_date] window.
    /// Dates are compared as YYYY-MM-DD strings (lexicographic == chronological).
    fn within_active_window(task: &CronTask, now: &chrono::DateTime<chrono::Utc>) -> bool {
        // Interpret the date/time window in the LOCAL calendar so a UTC+8 user setting
        // "Sep 1 - Sep 10" or "09:00-17:00" gets the intended local days/hours.
        let local = now.with_timezone(&chrono::Local);
        let today = local.format("%Y-%m-%d").to_string();
        // Only enforce bounds that are well-formed; a bad string does not disable the task.
        let well_formed = |d: &String| d.len() == 10 && d.chars().nth(4) == Some('-') && d.chars().nth(7) == Some('-');
        if let Some(ref st) = task.start_date {
            if well_formed(st) && today < *st { return false; }
        }
        if let Some(ref en) = task.end_date {
            if well_formed(en) && today > *en { return false; }
        }
        // Time-of-day window (local), inclusive, with overnight wraparound (start > end).
        let cur = local.hour() * 60 + local.minute();
        match (
            task.start_time.as_deref().and_then(parse_hhmm),
            task.end_time.as_deref().and_then(parse_hhmm),
        ) {
            (Some(s), Some(e)) => {
                if s <= e {
                    if cur < s || cur > e { return false; }
                } else if cur < s && cur > e {
                    return false;
                }
            }
            (Some(s), None) => { if cur < s { return false; } }
            (None, Some(e)) => { if cur > e { return false; } }
            (None, None) => {}
        }
        true
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
                  message: Option<String>, model: Option<String>,
                  start_date: Option<String>, end_date: Option<String>,
                  start_time: Option<String>, end_time: Option<String>) -> bool {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.id == id) {
            if let Some(n) = name { task.name = n; }
            if let Some(s) = schedule {
                task.schedule = s;
                task.interval_secs = Self::parse_interval(&task.schedule);
                task.next_run = Some(Self::compute_next_run_from_schedule(&task.schedule));
            }
            if let Some(m) = message { task.message = m; }
            if let Some(m) = model { task.model = m; }
            if let Some(d) = start_date { task.start_date = normalize_opt_date(&d); }
            if let Some(d) = end_date { task.end_date = normalize_opt_date(&d); }
            if let Some(t) = start_time { task.start_time = normalize_opt_time(&t); }
            if let Some(t) = end_time { task.end_time = normalize_opt_time(&t); }
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
    pub async fn tick(&mut self, self_arc: &Arc<Mutex<Self>>) {
        let now = chrono::Utc::now();
        let mut due_indices = Vec::new();

        for (i, task) in self.tasks.iter().enumerate() {
            if !task.enabled {
                continue;
            }
            // Skip tasks outside their optional active date window.
            if !Self::within_active_window(task, &now) {
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
            // In-flight dedup: skip a trigger for a task that is already
            // running, so slow CRON jobs never overlap duplicate runs.
            let task_id = self.tasks[i].id.clone();
            if self.running.contains(&task_id) {
                info!("CRON task '{}' already running; skipping overlapping trigger", self.tasks[i].name);
                continue;
            }
            self.running.insert(task_id.clone());
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

            // CRON runs unattended: append the mode directive so the agent completes the
            // full goal and reports only facts, instead of asking permission or follow-ups.
            let mut message = task.message.clone();
            message.push_str(CRON_MODE_DIRECTIVE);
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
            let auto_approve = self.auto_approve;
            // Scheduler handle + task id to clear the in-flight marker on exit.
            let scheduler_arc = self_arc.clone();
            let ctask_id = task_id.clone();

            // Execute the task as an independent sub-agent (own session, empty history)
            tokio::spawn(async move {
                let session_id = format!("cron-{}", uuid::Uuid::new_v4());
                let start = std::time::Instant::now();
                let preauth = if auto_approve {
                    let mut profile = crate::managed::permission_profile::PermissionProfile::new(session_id.clone());
                    profile.allow_all = true;
                    Some(std::sync::Arc::new(profile))
                } else {
                    None
                };
                match runner.run(
                    &message, &session_id, &model, max_iter, vec![],
                    permissions, permission_pending,
                    preauth, // allow_all when CRON auto-approve toggle is on (default off)
                    None, rabbit_hole,
                    ctx_window, ctx_window_threshold,
                    tool_timeout,
                    2,     // default max_tool_retries for scheduled tasks
                    vec![],  // no images for scheduled tasks
                    None, None,  // no checkpoint for scheduled tasks
                    None,        // no per-round output override (scheduled task)
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
                // Release the in-flight marker so the next scheduled trigger runs.
                let mut scheduler = scheduler_arc.lock().await;
                scheduler.running.remove(&ctask_id);
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
            scheduler.tick(&self_arc).await;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn cron_task(schedule: &str) -> CronTask {
        CronTask {
            id: String::new(),
            name: String::new(),
            schedule: schedule.to_string(),
            message: String::new(),
            model: String::new(),
            enabled: true,
            last_run: None,
            next_run: None,
            interval_secs: 0,
            start_date: None,
            end_date: None,
            start_time: None,
            end_time: None,
        }
    }

    #[test]
    fn parse_interval_accepts_bare_and_every() {
        assert_eq!(Scheduler::parse_interval("5m"), 300);
        assert_eq!(Scheduler::parse_interval("every 5m"), 300);
        assert_eq!(Scheduler::parse_interval("5 min"), 300);
        assert_eq!(Scheduler::parse_interval("1h"), 3600);
        assert_eq!(Scheduler::parse_interval("30s"), 30);
        assert_eq!(Scheduler::parse_interval("every 1d"), 86400);
        assert_eq!(Scheduler::parse_interval("every 2 hours"), 7200);
        assert_eq!(Scheduler::parse_interval("90"), 90);
    }

    #[test]
    fn parse_interval_cron_and_invalid() {
        let cron = Scheduler::parse_interval("*/5 * * * *");
        assert!((60..=300).contains(&cron), "cron gave {}", cron);
        assert_eq!(Scheduler::parse_interval("bogus"), 60);
        assert_eq!(Scheduler::parse_interval("5x"), 60);
    }

    #[test]
    fn active_window_inclusive_and_bounds() {
        let mut t = cron_task("5m");
        t.start_date = Some("2026-09-01".into());
        t.end_date = Some("2026-09-10".into());
        let dc = |r: &str| chrono::DateTime::parse_from_rfc3339(r).unwrap().with_timezone(&chrono::Utc);
        assert!(Scheduler::within_active_window(&t, &dc("2026-09-05T00:00:00Z")));
        assert!(!Scheduler::within_active_window(&t, &dc("2026-08-20T00:00:00Z")));
        assert!(!Scheduler::within_active_window(&t, &dc("2026-09-20T00:00:00Z")));
    }

    #[test]
    fn active_window_ignores_malformed_date() {
        let mut t = cron_task("5m");
        t.start_date = Some("not-a-date".into());
        assert!(Scheduler::within_active_window(&t, &chrono::Utc::now()));
    }

    #[test]
    fn active_window_time_range() {
        let mut t = cron_task("5m");
        t.start_time = Some("09:00".into());
        t.end_time = Some("17:00".into());
        let local = |h: u32, m: u32| {
            chrono::Local.with_ymd_and_hms(2026, 9, 5, h, m, 0).single().unwrap().with_timezone(&chrono::Utc)
        };
        assert!(Scheduler::within_active_window(&t, &local(9, 0)));
        assert!(Scheduler::within_active_window(&t, &local(12, 0)));
        assert!(Scheduler::within_active_window(&t, &local(17, 0)));
        assert!(!Scheduler::within_active_window(&t, &local(8, 59)));
        assert!(!Scheduler::within_active_window(&t, &local(17, 1)));
    }

    #[test]
    fn active_window_time_overnight() {
        let mut t = cron_task("5m");
        t.start_time = Some("22:00".into());
        t.end_time = Some("06:00".into());
        let local = |h: u32, m: u32| {
            chrono::Local.with_ymd_and_hms(2026, 9, 5, h, m, 0).single().unwrap().with_timezone(&chrono::Utc)
        };
        assert!(Scheduler::within_active_window(&t, &local(23, 0)));
        assert!(Scheduler::within_active_window(&t, &local(2, 0)));
        assert!(!Scheduler::within_active_window(&t, &local(12, 0)));
    }
}
