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
        | "ir_usn" | "ir_timeline"
        | "malware_scan" | "malware_deep"
        | "cu_screenshot" | "cu_window_list" | "cu_clipboard_read" | "cu_display_info"
        | "cu_cursor_position" | "cu_process_list" | "cu_ui_tree" | "cu_ui_find" => "read",
        // Write — creates/overwrites content
        "file_write" | "memory_md" | "todo_update" | "cu_clipboard_write" => "write",
        // Delete
        "file_delete" => "delete",
        // Modify — changes state of existing resources
        "file_modify" | "sys_process" | "sys_service" | "ir_process" | "ir_vss"
        | "browser_cdp" | "cron_manage" | "cu_window_activate" => "modify",
        // Execute — arbitrary code execution
        "shell_exec" | "app_launch" | "ir_memdump" | "cu_mouse" | "cu_keyboard" | "cu_process_kill" | "cu_ui_interact" => "execute",
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
    /// Pre-authorization profile for managed tasks (Phase 6).
    /// Matching tool calls bypass the permission gate entirely.
    preauth_profile: Option<Arc<crate::managed::permission_profile::PermissionProfile>>,
}

impl PermissionChecker {
    pub fn new(
        pending: PendingMap,
        tx: mpsc::Sender<AgentResult<AgentEvent>>,
        permissions: Arc<Mutex<HashMap<String, bool>>>,
        invocation_id: String,
        author: String,
        preauth_profile: Option<Arc<crate::managed::permission_profile::PermissionProfile>>,
    ) -> Self {
        Self {
            pending,
            tx,
            permissions,
            invocation_id,
            author,
            preauth_profile,
        }
    }

    /// Check if a tool call is allowed.
    /// - If the action is pre-authorized by the managed-task profile: returns `true` immediately.
    /// - If the category is allowed: returns `true` immediately.
    /// - If the category requires endorsement: emits permission_request, waits for user response.
    /// - Cross-category bypass detection: if shell_exec is auto-allowed but the command
    ///   intent maps to a DENIED category (e.g., delete), still requires confirmation.
    /// Returns `true` if allowed, `false` if denied.
    pub async fn check(&self, tool_name: &str, args: &Value) -> bool {
        // Phase 6: pre-authorized actions (managed mode) bypass the permission gate.
        // Intent-level matching keeps the bypass narrow (e.g., shell_exec taskkill only).
        if let Some(profile) = &self.preauth_profile {
            if crate::managed::permission_profile::check_preauthorization(profile, tool_name, args) {
                return true;
            }
        }

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

        // Plain-language one-line explanation of what this action does, so the
        // user can approve/deny without reading a wall of raw code.
        let explanation = explain_tool_call(tool_name, &args);
        // Emit permission_request event to client
        let event = AgentEvent::permission_request(
            &request_id,
            tool_name,
            category,
            args.clone(),
            &explanation,
            &self.invocation_id,
            &self.author,
        );
        let _ = self.tx.send(Ok(event)).await;

        // Wait for user response (with timeout to prevent hanging in headless sessions)
        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            rx_resp,
        ).await {
            Ok(Ok(allowed)) => {
                info!(
                    "Permission {} for tool '{}' (request_id: {})",
                    if allowed { "granted" } else { "denied" },
                    tool_name,
                    request_id
                );
                allowed
            }
            Ok(Err(_)) => {
                info!("Permission channel dropped for tool '{}', denying by default", tool_name);
                false
            }
            Err(_) => {
                info!("Permission request timed out for tool '{}', denying by default", tool_name);
                // Clean up: remove the pending entry
                let mut pending = self.pending.lock().await;
                pending.remove(&request_id);
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

/// Produce a concise, plain-language one-line explanation of what executing
/// `tool_name` with `args` does, so a user reviewing a permission gate can
/// approve/deny without reading a wall of raw code. Text is Chinese to match
/// the default UI language.
pub fn explain_tool_call(tool_name: &str, args: &Value) -> String {
    let field = |k: &str| args.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());

    // ---------- Arbitrary code execution ----------
    if tool_name == "shell_exec" || tool_name == "app_launch" {
        let cmd = field("command")
            .or_else(|| field("program"))
            .or_else(|| field("app"))
            .or_else(|| field("cmd"))
            .unwrap_or_default()
            .trim()
            .to_string();
        if !cmd.is_empty() {
            let purpose = explain_shell_command(&cmd);
            return format!("用途：{}；命令：{}", purpose, trim_str(&cmd, 120));
        }
        let kind = if tool_name == "app_launch" { "程序" } else { "Shell 命令" };
        return format!("执行一条 {}（参数未注明）", kind);
    }

    // ---------- File / path operations ----------
    match tool_name {
        "file_read" => return format!("读取文件：{}", field("path").as_deref().unwrap_or("?")),
        "file_write" => return format!("写入文件：{}", field("path").as_deref().unwrap_or("?")),
        "file_modify" => return format!("修改文件：{}", field("path").as_deref().unwrap_or("?")),
        "file_delete" => return format!("删除文件：{}", field("path").as_deref().unwrap_or("?")),
        "file_list" => return format!("列出目录：{}", field("path").as_deref().unwrap_or("?")),
        _ => {}
    }

    // ---------- Network ----------
    if tool_name == "web_fetch" || tool_name == "browser_open" || tool_name == "browser_cdp" {
        if let Some(url) = field("url") {
            if !url.trim().is_empty() {
                return format!("访问网页：{}", trim_str(url.trim(), 140));
            }
        }
    }

    // ---------- Generic fallback ----------
    let action = match tool_category(tool_name) {
        "read" => "读取/查询",
        "write" => "写入",
        "delete" => "删除",
        "modify" => "修改",
        _ => "执行",
    };
    let tool = tool_name.replace('_', " ");
    let details = summarize_args(args);
    format!("{}操作：{}{}", action, tool, details)
}

fn trim_str(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        let t: String = s.chars().take(n).collect();
        format!("{}…", t)
    } else {
        s.to_string()
    }
}

/// Summarize a couple of key (non-code) parameters for the fallback message.
fn summarize_args(args: &Value) -> String {
    let mut parts = Vec::new();
    if let Some(obj) = args.as_object() {
        for (k, v) in obj.iter() {
            if matches!(k.as_str(), "command" | "args" | "arguments" | "content" | "prompt") {
                continue;
            }
            if let Some(s) = v.as_str() {
                if !s.is_empty() {
                    parts.push(format!("{}={}", k, trim_str(s, 60)));
                    if parts.len() >= 2 {
                        break;
                    }
                }
            }
        }
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("（{}）", parts.join("，"))
    }
}

/// Best-effort plain-language description of a shell command's purpose.
/// Ordered longest/most-specific first so specific matches win.
fn explain_shell_command(cmd: &str) -> String {
    let c = cmd.trim();
    let lower = c.to_lowercase();
    const PAIRS: &[(&str, &str)] = &[
        ("Get-NetIPConfiguration", "查看网络配置"),
        ("Get-Volume", "查看磁盘卷信息"),
        ("Get-PSDrive", "查看驱动器/磁盘容量信息"),
        ("wmic logicaldisk", "查看磁盘容量信息"),
        ("Get-NetTCPConnection", "查看网络连接"),
        ("Get-ItemProperty", "读取注册表或对象属性"),
        ("Get-WinEvent", "查询事件日志"),
        ("wevtutil", "查询/导出事件日志"),
        ("gpresult", "查看组策略结果"),
        ("query user", "查看当前登录用户"),
        ("ipconfig", "查看网络配置"),
        ("netstat", "查看网络连接"),
        ("Get-Process", "查看进程信息"),
        ("tasklist", "查看进程列表"),
        ("Get-Service", "查询服务状态"),
        ("sc query", "查询服务状态"),
        ("Get-ChildItem", "列出目录/文件"),
        ("Get-Content", "读取文件内容"),
        ("type ", "读取文件内容"),
        ("systeminfo", "查看系统信息"),
        ("whoami", "查看当前用户"),
        ("Get-CimInstance", "查询系统/硬件信息"),
        ("reg query", "查询注册表"),
        ("quser", "查看登录用户"),
        ("auditpol", "查看/修改审核策略"),
        ("ping", "测试网络连通性"),
        ("curl", "请求/抓取网页或接口"),
        ("invoke-webrequest", "请求网页/接口"),
        ("git ", "执行 Git 操作"),
        ("dir ", "列出目录/文件"),
    ];
    // Case-insensitive match: `PAIRS` needles (e.g. Get-NetTCPConnection) are
    // compared against the lowercased command, so uppercase cmdlets actually hit.
    for (needle, purpose) in PAIRS {
        if lower.contains(&needle.to_lowercase()) {
            return purpose.to_string();
        }
    }
    // Fallback: derive a semantic purpose from the policy intent parser when no
    // static keyword matched. Gives a meaningful one-liner for compound scripts
    // (e.g. a multi-line Remove-Item cleanup) instead of "执行命令 <首个词>".
    if let Some(purpose) = describe_shell_intent(c) {
        return purpose;
    }

    let first = c.split_whitespace().next().unwrap_or(c).to_string();
    format!("执行命令 {}", first)
}

/// Structured plain-language description built on the policy intent parser.
fn describe_shell_intent(cmd: &str) -> Option<String> {
    use crate::policy::parse::Verb;

    let lower = cmd.to_lowercase();
    let shell = if lower.contains("cmd.exe")
        || lower.contains("cmd /c")
        || lower.starts_with("del ")
        || lower.starts_with("rmdir ")
        || lower.starts_with("rd ")
    {
        "cmd"
    } else {
        "powershell"
    };

    let intent = crate::policy::parse::parse_intent(cmd, shell);
    if intent.confidence < 0.6 || matches!(intent.verb, Verb::Unknown) {
        return None;
    }

    let action = match intent.verb {
        Verb::Delete => "删除",
        Verb::Format => "格式化",
        Verb::Stop => "停止",
        Verb::Disable => "禁用",
        Verb::Write => "写入/修改",
        Verb::ClearLog => "清除日志",
        Verb::Read => "查看",
        Verb::Execute | Verb::Unknown => return None,
    };

    let mut seen = Vec::new();
    let mut names = Vec::new();
    for t in &intent.targets {
        let name = readable_target(t);
        let key = name.to_lowercase();
        if name.is_empty() || seen.contains(&key) {
            continue;
        }
        seen.push(key);
        names.push(name);
    }

    if names.is_empty() {
        return Some(format!("{}目标（未指明具体对象）", action));
    }

    if names.len() <= 3 {
        Some(format!("{} {}", action, names.join("、")))
    } else {
        Some(format!("{} {} 等 {} 项", action, names[..3].join("、"), names.len()))
    }
}

/// Reduce a raw target to a readable, human-friendly name.
fn readable_target(t: &str) -> String {
    let trimmed = t.trim().trim_matches('"').trim_matches('\'');
    if trimmed.is_empty() {
        return String::new();
    }
    // Keep the last meaningful segment when the target looks like a path.
    let normalized = trimmed.replace('\\', "/");
    let last = normalized.rsplit('/').next().unwrap_or(&normalized).trim();
    if !last.is_empty() && last != &normalized {
        last.to_string()
    } else {
        trimmed.to_string()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explain_delete_cleanup_script() {
        // Multi-line Remove-Item cleanup should produce a semantic "删除 ..." line,
        // not a raw "执行命令 $dirs" from the first token.
        let cmd = "$dirs = @(\"$env:APPDATA\\Programs\\Zero Install\", \"$env:LOCALAPPDATA\\0install.net\", \"$env:APPDATA\\0install.net\"); foreach ($d in $dirs) { if (Test-Path $d) { Remove-Item $d -Recurse -Force } }; $logs = @(\"$env:TEMP\\0install Bbb Log.txt\"); foreach ($l in $logs) { if (Test-Path $l) { Remove-Item $l -Force } }";
        let purpose = explain_shell_command(cmd);
        assert!(purpose.contains("删除"), "got: {purpose}");
        // The purpose should name the targeted software, not a shell variable.
        assert!(!purpose.contains(r"\$dirs"), "got: {purpose}");
        assert!(purpose.contains("Zero Install"), "got: {purpose}");
    }

    #[test]
    fn explain_read_keeps_exact_pairs() {
        assert_eq!(explain_shell_command("ipconfig /all"), "查看网络配置");
        assert_eq!(explain_shell_command("Get-NetTCPConnection"), "查看网络连接");
    }

    #[test]
    fn explain_unknown_falls_back() {
        let p = explain_shell_command("some-obscure-tool --flag");
        assert!(p.starts_with("执行命令"), "got: {p}");
    }
}
