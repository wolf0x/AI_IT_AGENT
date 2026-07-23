//! Tool permission control — async gate for user endorsement of high-risk tools.
//!
//! When the agent wants to execute a tool in a restricted category (e.g., "delete", "execute"),
//! the ToolPermission pauses execution, emits a permission_request event to the client,
//! and waits for the user's response (allow/deny) via a oneshot channel.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};
use serde_json::Value;
use tracing::info;

use crate::agent::AgentEvent;
use crate::error::AgentResult;

/// Maps tool names to their permission category.
pub fn tool_category(name: &str) -> &'static str {
    match name {
        // Read
        "file_read" | "file_list" | "sys_info" | "sys_eventlog" | "browser_open" | "web_fetch"
        | "ir_weblog_scan" | "ir_evtx_parse" | "ir_log_parse" | "ir_pcap_analyze" => "read",
        // Write
        "file_write" => "write",
        // Delete
        "file_delete" => "delete",
        // Modify
        "file_modify" | "sys_process" | "sys_service" => "modify",
        // Execute
        "shell_exec" | "app_launch" => "execute",
        // Default: unknown tools require endorsement
        _ => "execute",
    }
}

/// Default permissions: read/write/modify allowed, delete/execute require endorsement.
pub fn default_permissions() -> HashMap<String, bool> {
    let mut m = HashMap::new();
    m.insert("read".to_string(), true);
    m.insert("write".to_string(), true);
    m.insert("delete".to_string(), false);
    m.insert("modify".to_string(), true);
    m.insert("execute".to_string(), false);
    m
}

/// Shared state between PermissionChecker (agent side) and PermissionResolver (server side).
pub type PendingMap = Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>;

/// Server-side handle — resolves pending permission requests from client responses.
#[derive(Clone)]
pub struct PermissionResolver {
    pending: PendingMap,
}

impl PermissionResolver {
    pub fn new() -> (Self, PendingMap) {
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        (Self { pending: pending.clone() }, pending)
    }

    /// Resolve a pending permission request with the user's decision.
    pub async fn resolve(&self, request_id: &str, allowed: bool) {
        let sender = {
            let mut pending = self.pending.lock().await;
            pending.remove(request_id)
        };
        if let Some(sender) = sender {
            let _ = sender.send(allowed);
        }
    }
}

/// Agent-side gate — checks permissions and pauses for user endorsement if needed.
pub struct PermissionChecker {
    pending: PendingMap,
    tx: mpsc::Sender<AgentResult<AgentEvent>>,
    permissions: Arc<Mutex<HashMap<String, bool>>>,
    invocation_id: String,
    author: String,
}

impl PermissionChecker {
    pub fn new(
        pending: PendingMap,
        tx: mpsc::Sender<AgentResult<AgentEvent>>,
        permissions: Arc<Mutex<HashMap<String, bool>>>,
        invocation_id: String,
        author: String,
    ) -> Self {
        Self {
            pending,
            tx,
            permissions,
            invocation_id,
            author,
        }
    }

    /// Check if a tool call is allowed.
    /// - If the category is allowed: returns `true` immediately.
    /// - If the category requires endorsement: emits permission_request, waits for user response.
    /// Returns `true` if allowed, `false` if denied.
    pub async fn check(&self, tool_name: &str, args: &Value) -> bool {
        let category = tool_category(tool_name);

        // Check if category is auto-allowed
        {
            let perms = self.permissions.lock().await;
            if perms.get(category).copied().unwrap_or(false) {
                return true;
            }
        }

        // Category requires endorsement — pause and ask user
        let request_id = uuid::Uuid::new_v4().to_string();
        info!(
            "Permission required for tool '{}' (category: {}), request_id: {}",
            tool_name, category, request_id
        );

        // Create oneshot channel for user response
        let (tx_resp, rx_resp) = oneshot::channel::<bool>();

        // Store the sender in pending map
        {
            let mut pending = self.pending.lock().await;
            pending.insert(request_id.clone(), tx_resp);
        }

        // Emit permission_request event to client
        let event = AgentEvent::permission_request(
            &request_id,
            tool_name,
            category,
            args.clone(),
            &self.invocation_id,
            &self.author,
        );
        let _ = self.tx.send(Ok(event)).await;

        // Wait for user response
        match rx_resp.await {
            Ok(allowed) => {
                info!(
                    "Permission {} for tool '{}' (request_id: {})",
                    if allowed { "granted" } else { "denied" },
                    tool_name,
                    request_id
                );
                allowed
            }
            Err(_) => {
                info!("Permission channel dropped for tool '{}', denying by default", tool_name);
                false
            }
        }
    }
}
