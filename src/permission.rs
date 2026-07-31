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
        // Read — pure information gathering, no side effects
        "file_read" | "file_list" | "sys_info" | "sys_eventlog" | "browser_open" | "web_fetch"
        | "ir_scan" | "ir_account" | "ir_persistence" | "ir_network" | "ir_eventlog"
        | "ir_file" | "ir_artifacts" | "ir_driver" | "ir_analyzer" | "ir_report"
        | "ir_weblog_scan" | "ir_evtx_parse" | "ir_log_parse" | "ir_pcap_analyze"
        | "malware_scan" | "malware_deep"
        | "cu_screenshot" | "cu_window_list" | "cu_clipboard_read" | "cu_display_info"
        | "cu_cursor_position" | "cu_process_list" | "cu_ui_tree" | "cu_ui_find" => "read",
        // Write — creates/overwrites content
        "file_write" | "memory_md" | "todo_update" | "cu_clipboard_write" => "write",
        // Delete
        "file_delete" => "delete",
        // Modify — changes state of existing resources
        "file_modify" | "sys_process" | "sys_service" | "ir_process"
        | "browser_cdp" | "browser_skill" | "cron_manage" | "cu_window_activate" => "modify",
        // Execute — arbitrary code execution
        "shell_exec" | "app_launch" | "cu_mouse" | "cu_keyboard" | "cu_process_kill" | "cu_ui_interact" => "execute",
        // Default: unknown tools (MCP, external) require endorsement
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
    /// - Cross-category bypass detection: if shell_exec is auto-allowed but the command
    ///   intent maps to a DENIED category (e.g., delete), still requires confirmation.
    /// Returns `true` if allowed, `false` if denied.
    pub async fn check(&self, tool_name: &str, args: &Value) -> bool {
        let category = tool_category(tool_name);

        // Check if category is auto-allowed
        {
            let perms = self.permissions.lock().await;
            if perms.get(category).copied().unwrap_or(false) {
                // Cross-category bypass detection for execute-category tools:
                // If shell_exec/app_launch is pre-authorized, but the command's intent
                // matches a DENIED permission category, escalate to confirmation.
                // This prevents the LLM from using shell_exec to bypass file_delete denial.
                if category == "execute" {
                    if let Some(bypassed_category) = detect_intent_category(tool_name, args) {
                        if !perms.get(bypassed_category).copied().unwrap_or(false) {
                            // The intent maps to a denied category — fall through to confirmation
                            info!(
                                "Cross-category bypass detected: tool '{}' (execute:allowed) \
                                 intent maps to '{}' (denied). Requiring confirmation.",
                                tool_name, bypassed_category
                            );
                            drop(perms);
                            return self.request_confirmation(tool_name, bypassed_category, args).await;
                        }
                    }
                }
                return true;
            }
        }

        // Category requires endorsement — pause and ask user
        self.request_confirmation(tool_name, category, args).await
    }

    /// Internal: emit permission_request and wait for user response.
    async fn request_confirmation(&self, tool_name: &str, category: &str, args: &Value) -> bool {
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

/// Detect if a shell_exec/app_launch command's intent maps to a different permission category.
/// Returns Some(category) if the command performs an action that belongs to another category,
/// None if the intent is normal execution or cannot be determined.
fn detect_intent_category(tool_name: &str, args: &Value) -> Option<&'static str> {
    if tool_name != "shell_exec" && tool_name != "app_launch" {
        return None;
    }

    let command = args["command"].as_str().unwrap_or("");
    if command.is_empty() {
        return None;
    }

    let shell = args["shell"].as_str().unwrap_or("powershell");
    let intent = crate::policy::parse::parse_intent(command, shell);

    use crate::policy::parse::Verb;
    match intent.verb {
        // Deletion via shell_exec bypasses file_delete permission
        Verb::Delete => Some("delete"),
        // Format/disk operations bypass modify permission
        Verb::Format => Some("modify"),
        _ => None,
    }
}
