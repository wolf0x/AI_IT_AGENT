/// Browser automation via BrowserSkill (`bsk`) CLI.
///
/// Wraps the Tencent BrowserSkill CLI tool to automate Chromium-based browsers
/// through an isolated "Agent Window". Supports session management, navigation,
/// interaction (click/fill/press/select), observation (snapshot/screenshot/get-html),
/// tab management, JS evaluation, and human-in-the-loop assistance.
///
/// Requires: `bsk` CLI installed and on PATH, bsk daemon running, Chrome extension installed.
/// Coexists with `browser_cdp` — use this tool when you need the user's existing login sessions.

use std::sync::Arc;
use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tracing::info;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

const MAX_SNAPSHOT_LEN: usize = 8000;
const MAX_HTML_LEN: usize = 5000;
const BSK_TIMEOUT_SECS: u64 = 60;

pub struct BrowserSkillTool {
    /// Active session ID (auto-managed — created on first use, cleared on session_stop).
    session_id: Mutex<Option<String>>,
    workspace_dir: String,
}

impl BrowserSkillTool {
    pub fn new(workspace_dir: String) -> Arc<Self> {
        Arc::new(Self {
            session_id: Mutex::new(None),
            workspace_dir,
        })
    }

    /// Get the active session ID, or auto-start a new session if none exists.
    async fn get_or_start_session(&self) -> Result<String, String> {
        let mut guard = self.session_id.lock().await;
        if let Some(ref id) = *guard {
            return Ok(id.clone());
        }
        // Auto-start a session
        info!("[browser_skill] No active session, auto-starting...");
        let result = self.run_bsk(&["session", "start", "--json"], None).await?;
        let sid = result.get("session_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "bsk session start returned no session_id".to_string())?
            .to_string();
        info!("[browser_skill] Auto-started session: {}", sid);
        *guard = Some(sid.clone());
        Ok(sid)
    }

    /// Resolve bsk binary using the standard 3-tier search:
    /// app dir → workspace/tools/ → system PATH
    fn bsk_bin(&self) -> String {
        let bin_name = if cfg!(windows) { "bsk.exe" } else { "bsk" };
        super::resolve_binary(bin_name, &self.workspace_dir)
    }

    /// Run a bsk CLI command and return parsed JSON output.
    async fn run_bsk(&self, args: &[&str], session_id: Option<&str>) -> Result<Value, String> {
        let mut cmd_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

        // Inject --session if provided and not already present
        if let Some(sid) = session_id {
            if !cmd_args.iter().any(|a| a == "--session") {
                cmd_args.push("--session".to_string());
                cmd_args.push(sid.to_string());
            }
        }

        let bsk = self.bsk_bin();
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(BSK_TIMEOUT_SECS),
            tokio::process::Command::new(&bsk)
                .args(&cmd_args)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| format!("bsk command timed out after {}s", BSK_TIMEOUT_SECS))?
        .map_err(|e| format!("Failed to execute bsk (tried: {}): {}. Install BrowserSkill CLI to workspace/tools/ or system PATH. (https://github.com/Tencent/BrowserSkill)", bsk, e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            let exit_code = output.status.code().unwrap_or(-1);
            let err_type = match exit_code {
                1 => "User error",
                2 => "Protocol error",
                3 => "Browser error",
                4 => "Timeout",
                5 => "Version mismatch",
                _ => "Unknown error",
            };
            return Err(format!("bsk failed (exit {} — {}): {}", exit_code, err_type,
                if stderr.is_empty() { &stdout } else { &stderr }));
        }

        // Try to parse as JSON; if it fails, return as plain text
        match serde_json::from_str::<Value>(&stdout) {
            Ok(v) => Ok(v),
            Err(_) => Ok(json!({ "output": stdout.trim() })),
        }
    }

    fn output_dir(&self) -> std::path::PathBuf {
        let dir = std::path::Path::new(&self.workspace_dir).join("output");
        let _ = std::fs::create_dir_all(&dir);
        dir
    }
}

#[async_trait]
impl Tool for BrowserSkillTool {
    fn name(&self) -> &str { "browser_skill" }

    fn description(&self) -> &str {
        "Browser automation via BrowserSkill (bsk CLI). \
         Automates Chromium browsers using the user's existing login sessions. \
         Actions: \
         - status: Check bsk daemon and browser connection status \
         - session_start: Start a new browser session (auto-called if needed) \
         - session_stop: Stop the current session \
         - navigate: Go to a URL (requires 'url') \
         - snapshot: Get accessibility tree with @eN element refs for interaction \
         - screenshot: Take a screenshot (saved to workspace/output/) \
         - get_html: Get page or element HTML (optional 'ref' to scope) \
         - click: Click an element (requires 'ref' from snapshot, or 'selector') \
         - fill: Fill an input field (requires 'ref'/'selector' + 'text') \
         - press: Press a key (requires 'key', e.g. Enter, Tab) \
         - select_option: Select dropdown option (requires 'ref'/'selector' + 'text') \
         - evaluate: Run JavaScript expression (requires 'js') \
         - tab_list: List tabs in current session \
         - tab_create: Create a new tab (optional 'url') \
         - tab_close: Close a tab (requires 'tab_id') \
         - tab_select: Switch to a tab (requires 'tab_id') \
         - tab_borrow: Move a user tab into the Agent Window (requires 'tab_id') \
         - tab_return: Return a borrowed tab to its original window (requires 'tab_id') \
         - navigate_back: Go back one step in history \
         - navigate_forward: Go forward one step in history \
         - reload: Reload the current page (optional 'hard'=true to bypass cache) \
         - wait_for_navigation: Wait for page load/DOM idle (optional 'wait_until', 'timeout') \
         - observe: Semantic VOM observation with bounded perception probes \
         - request_help: Pause and ask the user for help (requires 'text' as prompt)"
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "status", "session_start", "session_stop",
                        "navigate", "snapshot", "screenshot", "get_html",
                        "click", "fill", "press", "select_option", "evaluate",
                        "tab_list", "tab_create", "tab_close", "tab_select",
                        "tab_borrow", "tab_return",
                        "navigate_back", "navigate_forward", "reload",
                        "wait_for_navigation", "observe",
                        "request_help"
                    ],
                    "description": "The browser action to perform"
                },
                "url": { "type": "string", "description": "URL for navigate or tab_create" },
                "ref": { "type": "string", "description": "Element reference (@eN) from snapshot" },
                "selector": { "type": "string", "description": "CSS selector (alternative to ref)" },
                "text": { "type": "string", "description": "Text value for fill, select_option, or request_help prompt" },
                "key": { "type": "string", "description": "Key name for press (e.g. Enter, Tab, Escape)" },
                "js": { "type": "string", "description": "JavaScript expression for evaluate" },
                "tab_id": { "type": "integer", "description": "Tab ID for tab_close, tab_select, tab_borrow, or tab_return" },
                "path": { "type": "string", "description": "Output path for screenshot (optional)" },
                "hard": { "type": "boolean", "description": "Hard reload (bypass cache) for reload action" },
                "wait_until": { "type": "string", "description": "Wait condition for wait_for_navigation: load, domcontentloaded, networkidle (default: load)" },
                "timeout": { "type": "integer", "description": "Timeout in seconds for wait_for_navigation (default: 30)" }
            },
            "required": ["action"]
        })
    }

    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { false }
    fn category(&self) -> &str { "write" }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value> {
        let action = args.get("action")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing 'action' parameter".to_string())?;

        match action {
            "status" => {
                self.run_bsk(&["status", "--json"], None).await
                    .map_err(|e| e.into())
            }

            "session_start" => {
                let result = self.run_bsk(&["session", "start", "--json"], None).await?;
                let sid = result.get("session_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let mut guard = self.session_id.lock().await;
                *guard = Some(sid.clone());
                Ok(result)
            }

            "session_stop" => {
                // Take the session ID out atomically to avoid TOCTOU race
                let sid_opt = {
                    let mut guard = self.session_id.lock().await;
                    guard.take() // removes and returns the value
                };
                if let Some(sid) = sid_opt {
                    let result = self.run_bsk(&["session", "stop", &sid], None).await;
                    result.map_err(|e| e.into())
                } else {
                    Ok(json!({ "message": "No active session to stop" }))
                }
            }

            "navigate" => {
                let url = args.get("url")
                    .and_then(|v| v.as_str())
                    .ok_or("Missing 'url' parameter for navigate")?;
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                self.run_bsk(&["navigate", url, "--json"], Some(&sid)).await
                    .map_err(|e| e.into())
            }

            "snapshot" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                let result = self.run_bsk(&["snapshot", "--json"], Some(&sid)).await?;
                // Truncate snapshot text if too large
                if let Some(text) = result.get("text").and_then(|v| v.as_str()) {
                    if text.len() > MAX_SNAPSHOT_LEN {
                        let truncated: String = text.chars().take(MAX_SNAPSHOT_LEN).collect();
                        let mut r = result.clone();
                        r["text"] = json!(format!("{}\n\n... [truncated from {} chars]", truncated, text.len()));
                        return Ok(r);
                    }
                }
                Ok(result)
            }

            "screenshot" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                let screenshot_path = if let Some(p) = args.get("path").and_then(|v| v.as_str()) {
                    p.to_string()
                } else {
                    let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S");
                    let out = std::path::PathBuf::from(ctx.output_dir());
                    let _ = std::fs::create_dir_all(&out);
                    out.join(format!("bsk_{}.png", ts)).to_string_lossy().to_string()
                };
                let result = self.run_bsk(&["screenshot", "--out", &screenshot_path, "--json"], Some(&sid)).await?;
                // Return workspace-relative URL for display
                let workspace_url = if let Ok(rel) = std::path::Path::new(&screenshot_path)
                    .strip_prefix(&self.workspace_dir) {
                    format!("/workspace/{}", rel.to_string_lossy().replace('\\', "/"))
                } else {
                    screenshot_path.clone()
                };
                Ok(json!({
                    "path": screenshot_path,
                    "url": workspace_url,
                    "bsk_result": result
                }))
            }

            "get_html" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                let mut cmd_args = vec!["get-html"];
                let ref_val;
                if let Some(r) = args.get("ref").and_then(|v| v.as_str()) {
                    ref_val = r.to_string();
                    cmd_args.push("--ref");
                    cmd_args.push(&ref_val);
                }
                let result = self.run_bsk(&cmd_args, Some(&sid)).await?;
                // Truncate HTML
                let html = if let Some(s) = result.as_str() {
                    s.to_string()
                } else if let Some(s) = result.get("output").and_then(|v| v.as_str()) {
                    s.to_string()
                } else {
                    result.to_string()
                };
                if html.len() > MAX_HTML_LEN {
                    let truncated: String = html.chars().take(MAX_HTML_LEN).collect();
                    Ok(json!(format!("{}\n\n... [truncated from {} chars]", truncated, html.len())))
                } else {
                    Ok(json!(html))
                }
            }

            "click" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                let mut cmd_args = vec!["click"];
                let target_val;
                if let Some(r) = args.get("ref").and_then(|v| v.as_str()) {
                    target_val = r.to_string();
                    cmd_args.push("--ref");
                    cmd_args.push(&target_val);
                } else if let Some(s) = args.get("selector").and_then(|v| v.as_str()) {
                    target_val = s.to_string();
                    cmd_args.push("--selector");
                    cmd_args.push(&target_val);
                } else {
                    return Err("Missing 'ref' or 'selector' for click".into());
                }
                self.run_bsk(&cmd_args, Some(&sid)).await.map_err(|e| e.into())
            }

            "fill" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                let text = args.get("text")
                    .and_then(|v| v.as_str())
                    .ok_or("Missing 'text' parameter for fill")?;
                let mut cmd_args = vec!["fill", "--value", text];
                let target_val;
                if let Some(r) = args.get("ref").and_then(|v| v.as_str()) {
                    target_val = r.to_string();
                    cmd_args.push("--ref");
                    cmd_args.push(&target_val);
                } else if let Some(s) = args.get("selector").and_then(|v| v.as_str()) {
                    target_val = s.to_string();
                    cmd_args.push("--selector");
                    cmd_args.push(&target_val);
                } else {
                    return Err("Missing 'ref' or 'selector' for fill".into());
                }
                self.run_bsk(&cmd_args, Some(&sid)).await.map_err(|e| e.into())
            }

            "press" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                let key = args.get("key")
                    .and_then(|v| v.as_str())
                    .ok_or("Missing 'key' parameter for press")?;
                self.run_bsk(&["press", key], Some(&sid)).await.map_err(|e| e.into())
            }

            "select_option" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                let text = args.get("text")
                    .and_then(|v| v.as_str())
                    .ok_or("Missing 'text' parameter for select_option")?;
                let mut cmd_args = vec!["select", "--value", text];
                let target_val;
                if let Some(r) = args.get("ref").and_then(|v| v.as_str()) {
                    target_val = r.to_string();
                    cmd_args.push("--ref");
                    cmd_args.push(&target_val);
                } else if let Some(s) = args.get("selector").and_then(|v| v.as_str()) {
                    target_val = s.to_string();
                    cmd_args.push("--selector");
                    cmd_args.push(&target_val);
                } else {
                    return Err("Missing 'ref' or 'selector' for select_option".into());
                }
                self.run_bsk(&cmd_args, Some(&sid)).await.map_err(|e| e.into())
            }

            "evaluate" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                let js = args.get("js")
                    .and_then(|v| v.as_str())
                    .ok_or("Missing 'js' parameter for evaluate")?;
                self.run_bsk(&["evaluate", js, "--json"], Some(&sid)).await.map_err(|e| e.into())
            }

            "tab_list" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                self.run_bsk(&["tab", "list", "--json"], Some(&sid)).await.map_err(|e| e.into())
            }

            "tab_create" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                let mut cmd_args = vec!["tab", "create"];
                let url_val;
                if let Some(u) = args.get("url").and_then(|v| v.as_str()) {
                    url_val = u.to_string();
                    cmd_args.push("--url");
                    cmd_args.push(&url_val);
                }
                self.run_bsk(&cmd_args, Some(&sid)).await.map_err(|e| e.into())
            }

            "tab_close" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                let tab_id = args.get("tab_id")
                    .and_then(|v| v.as_i64())
                    .ok_or("Missing 'tab_id' parameter for tab_close")?;
                let tab_str = tab_id.to_string();
                self.run_bsk(&["tab", "close", &tab_str], Some(&sid)).await.map_err(|e| e.into())
            }

            "tab_select" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                let tab_id = args.get("tab_id")
                    .and_then(|v| v.as_i64())
                    .ok_or("Missing 'tab_id' parameter for tab_select")?;
                let tab_str = tab_id.to_string();
                self.run_bsk(&["tab", "select", &tab_str], Some(&sid)).await.map_err(|e| e.into())
            }

            "tab_borrow" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                let tab_id = args.get("tab_id")
                    .and_then(|v| v.as_i64())
                    .ok_or("Missing 'tab_id' parameter for tab_borrow")?;
                let tab_str = tab_id.to_string();
                self.run_bsk(&["tab", "borrow", &tab_str, "--json"], Some(&sid)).await.map_err(|e| e.into())
            }

            "tab_return" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                let tab_id = args.get("tab_id")
                    .and_then(|v| v.as_i64())
                    .ok_or("Missing 'tab_id' parameter for tab_return")?;
                let tab_str = tab_id.to_string();
                self.run_bsk(&["tab", "return", &tab_str, "--json"], Some(&sid)).await.map_err(|e| e.into())
            }

            "navigate_back" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                self.run_bsk(&["navigate-back", "--json"], Some(&sid)).await.map_err(|e| e.into())
            }

            "navigate_forward" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                self.run_bsk(&["navigate-forward", "--json"], Some(&sid)).await.map_err(|e| e.into())
            }

            "reload" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                let mut cmd_args = vec!["reload"];
                if args.get("hard").and_then(|v| v.as_bool()).unwrap_or(false) {
                    cmd_args.push("--hard");
                }
                self.run_bsk(&cmd_args, Some(&sid)).await.map_err(|e| e.into())
            }

            "wait_for_navigation" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                let mut cmd_args = vec!["wait-for-navigation"];
                if let Some(wu) = args.get("wait_until").and_then(|v| v.as_str()) {
                    cmd_args.push("--wait-until");
                    cmd_args.push(wu);
                }
                let timeout_str;
                if let Some(t) = args.get("timeout").and_then(|v| v.as_u64()) {
                    timeout_str = t.to_string();
                    cmd_args.push("--timeout");
                    cmd_args.push(&timeout_str);
                }
                self.run_bsk(&cmd_args, Some(&sid)).await.map_err(|e| e.into())
            }

            "observe" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                self.run_bsk(&["observe", "--json"], Some(&sid)).await.map_err(|e| e.into())
            }

            "request_help" => {
                let sid = self.get_or_start_session().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
                let text = args.get("text")
                    .and_then(|v| v.as_str())
                    .ok_or("Missing 'text' parameter for request_help")?;
                self.run_bsk(&["request-help", "--prompt", text], Some(&sid)).await.map_err(|e| e.into())
            }

            _ => Err(format!("Unknown action '{}'. Valid actions: status, session_start, session_stop, navigate, snapshot, screenshot, get_html, click, fill, press, select_option, evaluate, tab_list, tab_create, tab_close, tab_select, tab_borrow, tab_return, navigate_back, navigate_forward, reload, wait_for_navigation, observe, request_help", action).into()),
        }
    }
}
