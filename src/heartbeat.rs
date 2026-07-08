//! Heartbeat system — periodically reads HEARTBEAT.md from the workspace
//! and executes the checklist via the agent, sending alerts when issues are found.

use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn, error};

use crate::agent::AgentEvent;
use crate::permission::PendingMap;
use crate::runner::Runner;
use crate::server::NotifyTx;
use crate::config::ModelConfig;

use std::collections::HashMap;

/// Default heartbeat interval in seconds (30 minutes).
const DEFAULT_HEARTBEAT_INTERVAL: u64 = 1800;

/// The heartbeat module runs periodic health checks defined in HEARTBEAT.md.
pub struct Heartbeat {
    runner: Arc<Runner>,
    model_configs: Arc<tokio::sync::RwLock<Vec<ModelConfig>>>,
    permissions: Arc<Mutex<HashMap<String, bool>>>,
    permission_pending: PendingMap,
    max_iterations: usize,
    rabbit_hole_threshold: usize,
    context_window: usize,
    context_window_threshold: usize,
    tool_timeout_secs: u64,
    notify_tx: NotifyTx,
    workspace_dir: String,
    interval_secs: u64,
}

impl Heartbeat {
    pub fn new(
        runner: Arc<Runner>,
        model_configs: Arc<tokio::sync::RwLock<Vec<ModelConfig>>>,
        permissions: Arc<Mutex<HashMap<String, bool>>>,
        permission_pending: PendingMap,
        max_iterations: usize,
        rabbit_hole_threshold: usize,
        context_window: usize,
        context_window_threshold: usize,
        tool_timeout_secs: u64,
        notify_tx: NotifyTx,
        workspace_dir: String,
    ) -> Self {
        Self {
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
            workspace_dir,
            interval_secs: DEFAULT_HEARTBEAT_INTERVAL,
        }
    }

    /// Read HEARTBEAT.md from workspace. Returns None if missing or empty.
    fn read_heartbeat_file(&self) -> Option<String> {
        let path = Path::new(&self.workspace_dir).join("HEARTBEAT.md");
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                if content.trim().is_empty() {
                    None
                } else {
                    Some(content)
                }
            }
            Err(_) => None,
        }
    }

    /// Run one heartbeat cycle: read HEARTBEAT.md, execute via agent, send alerts.
    async fn run_once(&self) {
        let heartbeat_content = match self.read_heartbeat_file() {
            Some(c) => c,
            None => {
                info!("Heartbeat: HEARTBEAT.md not found or empty, skipping");
                return;
            }
        };

        // Resolve model name
        let model = {
            let mc = self.model_configs.read().await;
            mc.first().map(|m| m.name.clone()).unwrap_or_default()
        };

        if model.is_empty() {
            warn!("Heartbeat: no model available, skipping");
            return;
        }

        let message = format!(
            "This is an automated HEARTBEAT check. Execute the following checklist items \
             and report ONLY items that need attention (alerts/warnings). \
             If everything is normal, respond with just 'All clear'.\n\n\
             Checklist:\n{}",
            heartbeat_content
        );

        let session_id = format!("heartbeat-{}", uuid::Uuid::new_v4());
        let start = std::time::Instant::now();
        let runner = self.runner.clone();
        let permissions = self.permissions.clone();
        let permission_pending = self.permission_pending.clone();
        let max_iter = self.max_iterations;
        let rabbit_hole = self.rabbit_hole_threshold;
        let ctx_window = self.context_window;
        let ctx_window_threshold = self.context_window_threshold;
        let tool_timeout = self.tool_timeout_secs;
        let notify_tx = self.notify_tx.clone();

        info!("Heartbeat: starting check (session: {})", session_id);

        match runner.run(
            &message, &session_id, &model, max_iter, vec![],
            permissions, permission_pending,
            None, rabbit_hole,
            ctx_window, ctx_window_threshold,
            tool_timeout,
            vec![],  // no images for heartbeat
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
                            error!("Heartbeat error: {}", e);
                            break;
                        }
                    }
                }

                let elapsed = start.elapsed().as_secs();
                info!("Heartbeat completed in {}s ({} chars output)", elapsed, text.len());

                // Only send notification if there's something to report
                // Skip "all clear" type responses
                let text_lower = text.to_lowercase();
                let is_all_clear = text_lower.contains("all clear")
                    || text_lower.contains("一切正常")
                    || text_lower.contains("全部正常")
                    || text_lower.contains("没有异常")
                    || text_lower.contains("no issues")
                    || text_lower.contains("no alerts")
                    || text_lower.contains("no warnings")
                    || text_lower.contains("无需告警");

                if !is_all_clear && text.trim().len() > 20 {
                    let alert = format!(
                        "🩺 **Heartbeat Alert** ({}s)\n\n{}",
                        elapsed, text
                    );
                    let ws_msg = serde_json::json!({
                        "type": "notification",
                        "message": alert,
                        "timestamp": chrono::Utc::now().to_rfc3339()
                    }).to_string();
                    let _ = notify_tx.send(ws_msg);
                    info!("Heartbeat: alert sent to clients");
                } else {
                    info!("Heartbeat: all clear, no alert needed");
                }
            }
            Err(e) => {
                error!("Heartbeat failed to start: {}", e);
            }
        }
    }

    /// Run the heartbeat loop — checks every `interval_secs`.
    pub async fn run_loop(self) {
        info!(
            "Heartbeat loop started (interval: {}s, workspace: {})",
            self.interval_secs, self.workspace_dir
        );

        // Wait one full interval before the first check
        tokio::time::sleep(std::time::Duration::from_secs(self.interval_secs)).await;

        loop {
            self.run_once().await;
            tokio::time::sleep(std::time::Duration::from_secs(self.interval_secs)).await;
        }
    }
}
