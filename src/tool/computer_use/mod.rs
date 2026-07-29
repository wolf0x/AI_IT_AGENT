//! Computer Use module — native Windows desktop control tools.
//! Provides screenshot, mouse, keyboard, window management, clipboard,
//! display info, process management, and UI automation capabilities.

pub mod automation;
pub mod clipboard;
pub mod display;
pub mod input;
pub mod process;
pub mod screenshot;
pub mod window;

use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::context::ToolContext;
use crate::error::AgentResult;

use super::{Tool, ToolRegistry};

/// All Computer Use tool names (for registration/unregistration).
pub const CU_TOOL_NAMES: &[&str] = &[
    "cu_screenshot",
    "cu_mouse",
    "cu_keyboard",
    "cu_window_list",
    "cu_window_activate",
    "cu_clipboard_read",
    "cu_clipboard_write",
    "cu_display_info",
    "cu_cursor_position",
    "cu_process_list",
    "cu_process_kill",
    "cu_ui_tree",
    "cu_ui_find",
    "cu_ui_interact",
];

/// Register all Computer Use tools into the registry.
pub fn register_computer_use_tools(registry: &mut ToolRegistry) {
    registry.register(Arc::new(CuScreenshotTool));
    registry.register(Arc::new(CuMouseTool));
    registry.register(Arc::new(CuKeyboardTool));
    registry.register(Arc::new(CuWindowListTool));
    registry.register(Arc::new(CuWindowActivateTool));
    registry.register(Arc::new(CuClipboardReadTool));
    registry.register(Arc::new(CuClipboardWriteTool));
    registry.register(Arc::new(CuDisplayInfoTool));
    registry.register(Arc::new(CuCursorPositionTool));
    registry.register(Arc::new(CuProcessListTool));
    registry.register(Arc::new(CuProcessKillTool));
    registry.register(Arc::new(CuUiTreeTool));
    registry.register(Arc::new(CuUiFindTool));
    registry.register(Arc::new(CuUiInteractTool));
}

/// Unregister all Computer Use tools from the registry.
pub fn unregister_computer_use_tools(registry: &mut ToolRegistry) {
    for name in CU_TOOL_NAMES {
        registry.unregister(name);
    }
}

// ============================================================
// cu_screenshot
// ============================================================

pub struct CuScreenshotTool;

#[async_trait]
impl Tool for CuScreenshotTool {
    fn name(&self) -> &str { "cu_screenshot" }
    fn description(&self) -> &str {
        "Capture a screenshot of the entire screen or a specific window. Returns image URL and dimensions. Use for visual evidence collection."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn category(&self) -> &str { "read" }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "width": { "type": "integer", "description": "Max width in pixels (downscaled if larger). Omit for native resolution." },
                "quality": { "type": "integer", "description": "JPEG quality 1-100. Omit for PNG format." },
                "window_id": { "type": "integer", "description": "HWND of specific window to capture. Omit for full screen." }
            }
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value> {
        let width = args.get("width").and_then(|v| v.as_u64()).map(|v| v as u32);
        let quality = args.get("quality").and_then(|v| v.as_u64()).map(|v| v as u32);
        let window_id = args.get("window_id").and_then(|v| v.as_i64()).map(|v| v as isize);

        let result = tokio::task::spawn_blocking(move || {
            screenshot::take_screenshot(width, quality, window_id)
        }).await.map_err(|e| format!("Task join error: {}", e))?
         .map_err(|e| format!("Screenshot failed: {}", e))?;

        // Save to workspace/output/
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let ext = if result.mime_type.contains("jpeg") { "jpg" } else { "png" };
        let filename = format!("cu_screenshot_{}.{}", timestamp, ext);
        let output_dir = std::path::Path::new(&ctx.workspace_dir).join("output");
        std::fs::create_dir_all(&output_dir).map_err(|e| format!("Failed to create output dir: {}", e))?;
        let filepath = output_dir.join(&filename);
        std::fs::write(&filepath, &result.data).map_err(|e| format!("Failed to save screenshot: {}", e))?;

        Ok(json!({
            "status": "ok",
            "path": filepath.to_string_lossy(),
            "url": format!("/workspace/output/{}", filename),
            "width": result.width,
            "height": result.height,
            "mime_type": result.mime_type,
            "size_bytes": result.data.len(),
        }))
    }
}

// ============================================================
// cu_mouse
// ============================================================

pub struct CuMouseTool;

#[async_trait]
impl Tool for CuMouseTool {
    fn name(&self) -> &str { "cu_mouse" }
    fn description(&self) -> &str {
        "Control the mouse: move, click, double-click, right-click, drag, or scroll at screen coordinates."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { false }
    fn category(&self) -> &str { "execute" }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["move", "click", "double_click", "right_click", "drag", "scroll", "down", "up"],
                    "description": "Mouse action to perform"
                },
                "x": { "type": "number", "description": "X coordinate (pixels from left)" },
                "y": { "type": "number", "description": "Y coordinate (pixels from top)" },
                "x2": { "type": "number", "description": "End X for drag" },
                "y2": { "type": "number", "description": "End Y for drag" },
                "button": { "type": "string", "enum": ["left", "right", "middle"], "description": "Mouse button (default: left)" },
                "scroll_y": { "type": "integer", "description": "Vertical scroll clicks (positive=up, negative=down)" },
                "scroll_x": { "type": "integer", "description": "Horizontal scroll clicks (positive=right, negative=left)" }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let action = args["action"].as_str().ok_or_else(|| "Missing 'action'".to_string())?.to_string();
        let x = args.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let y = args.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let button = args.get("button").and_then(|v| v.as_str()).unwrap_or("left").to_string();
        let x2 = args.get("x2").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let y2 = args.get("y2").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let scroll_y = args.get("scroll_y").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
        let scroll_x = args.get("scroll_x").and_then(|v| v.as_i64()).unwrap_or(0) as i32;

        tokio::task::spawn_blocking(move || {
            match action.as_str() {
                "move" => {
                    input::mouse_move(x, y);
                    Ok(json!({ "status": "ok", "action": "move", "x": x, "y": y }))
                }
                "click" => {
                    if x > 0.0 || y > 0.0 { input::mouse_move(x, y); std::thread::sleep(std::time::Duration::from_millis(20)); }
                    input::mouse_click(&button, 1);
                    Ok(json!({ "status": "ok", "action": "click", "button": button, "x": x, "y": y }))
                }
                "double_click" => {
                    if x > 0.0 || y > 0.0 { input::mouse_move(x, y); std::thread::sleep(std::time::Duration::from_millis(20)); }
                    input::mouse_click(&button, 2);
                    Ok(json!({ "status": "ok", "action": "double_click", "button": button }))
                }
                "right_click" => {
                    if x > 0.0 || y > 0.0 { input::mouse_move(x, y); std::thread::sleep(std::time::Duration::from_millis(20)); }
                    input::mouse_click("right", 1);
                    Ok(json!({ "status": "ok", "action": "right_click", "x": x, "y": y }))
                }
                "drag" => {
                    let dx2 = if x2 != 0.0 { x2 } else { x };
                    let dy2 = if y2 != 0.0 { y2 } else { y };
                    input::mouse_drag(x, y, dx2, dy2, &button);
                    Ok(json!({ "status": "ok", "action": "drag", "from": [x, y], "to": [dx2, dy2] }))
                }
                "scroll" => {
                    if x > 0.0 || y > 0.0 { input::mouse_move(x, y); }
                    input::mouse_scroll(scroll_y, scroll_x);
                    Ok(json!({ "status": "ok", "action": "scroll", "dy": scroll_y, "dx": scroll_x }))
                }
                "down" => {
                    input::mouse_button_down(&button);
                    Ok(json!({ "status": "ok", "action": "down", "button": button }))
                }
                "up" => {
                    input::mouse_button_up(&button);
                    Ok(json!({ "status": "ok", "action": "up", "button": button }))
                }
                _ => Err(format!("Unknown mouse action: '{}'", action)),
            }
        }).await.map_err(|e| format!("Task join error: {}", e))?.map_err(Into::into)
    }
}

// ============================================================
// cu_keyboard
// ============================================================

pub struct CuKeyboardTool;

#[async_trait]
impl Tool for CuKeyboardTool {
    fn name(&self) -> &str { "cu_keyboard" }
    fn description(&self) -> &str {
        "Type text (Unicode) or press key combinations (e.g., ctrl+c, alt+f4, enter, shift+a)."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { false }
    fn category(&self) -> &str { "execute" }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["type", "press"],
                    "description": "'type' for text input, 'press' for key combination"
                },
                "text": { "type": "string", "description": "Text to type (for action=type)" },
                "keys": { "type": "string", "description": "Key combo like 'ctrl+c', 'alt+f4', 'enter' (for action=press)" }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let action = args["action"].as_str().ok_or_else(|| "Missing 'action'".to_string())?;

        match action {
            "type" => {
                let text = args["text"].as_str().ok_or_else(|| "Missing 'text' for type action".to_string())?.to_string();
                tokio::task::spawn_blocking(move || {
                    input::type_text(&text);
                    Ok::<_, String>(json!({ "status": "ok", "action": "type", "chars": text.len() }))
                }).await.map_err(|e| format!("Task join error: {}", e))?.map_err(Into::into)
            }
            "press" => {
                let keys = args["keys"].as_str().ok_or_else(|| "Missing 'keys' for press action".to_string())?.to_string();
                tokio::task::spawn_blocking(move || {
                    input::key_press(&keys)?;
                    Ok::<_, String>(json!({ "status": "ok", "action": "press", "keys": keys }))
                }).await.map_err(|e| format!("Task join error: {}", e))?.map_err(Into::into)
            }
            _ => Err(format!("Unknown keyboard action: '{}'", action).into()),
        }
    }
}

// ============================================================
// cu_window_list
// ============================================================

pub struct CuWindowListTool;

#[async_trait]
impl Tool for CuWindowListTool {
    fn name(&self) -> &str { "cu_window_list" }
    fn description(&self) -> &str {
        "List all top-level windows with title, PID, HWND, position, and visibility state."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn category(&self) -> &str { "read" }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "visible_only": { "type": "boolean", "description": "Only return visible windows (default: true)" }
            }
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let visible_only = args.get("visible_only").and_then(|v| v.as_bool()).unwrap_or(true);

        let windows = tokio::task::spawn_blocking(move || {
            window::list_windows()
        }).await.map_err(|e| format!("Task join error: {}", e))?;

        let filtered: Vec<Value> = windows.iter()
            .filter(|w| !visible_only || w.visible)
            .map(|w| w.to_json())
            .collect();

        Ok(json!({ "status": "ok", "count": filtered.len(), "windows": filtered }))
    }
}

// ============================================================
// cu_window_activate
// ============================================================

pub struct CuWindowActivateTool;

#[async_trait]
impl Tool for CuWindowActivateTool {
    fn name(&self) -> &str { "cu_window_activate" }
    fn description(&self) -> &str {
        "Bring a window to the foreground by HWND or by title (case-insensitive substring match)."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { false }
    fn category(&self) -> &str { "modify" }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "hwnd": { "type": "integer", "description": "Window handle (HWND) to activate" },
                "title": { "type": "string", "description": "Window title to search for (substring match)" }
            }
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let hwnd = args.get("hwnd").and_then(|v| v.as_i64()).map(|v| v as isize);
        let title = args.get("title").and_then(|v| v.as_str()).map(|s| s.to_string());

        tokio::task::spawn_blocking(move || {
            if let Some(hwnd) = hwnd {
                window::activate_window(hwnd)?;
                Ok(json!({ "status": "ok", "activated_hwnd": hwnd }))
            } else if let Some(title) = title {
                let info = window::activate_by_title(&title)?;
                Ok(json!({ "status": "ok", "window": info.to_json() }))
            } else {
                Err("Provide either 'hwnd' or 'title'".to_string())
            }
        }).await.map_err(|e| format!("Task join error: {}", e))?.map_err(Into::into)
    }
}

// ============================================================
// cu_clipboard_read
// ============================================================

pub struct CuClipboardReadTool;

#[async_trait]
impl Tool for CuClipboardReadTool {
    fn name(&self) -> &str { "cu_clipboard_read" }
    fn description(&self) -> &str { "Read text content from the system clipboard." }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn category(&self) -> &str { "read" }

    fn parameters_schema(&self) -> Value {
        json!({ "type": "object", "properties": {} })
    }

    async fn execute(&self, _args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let text = tokio::task::spawn_blocking(|| clipboard::read_clipboard())
            .await.map_err(|e| format!("Task join error: {}", e))?
            .map_err(|e| format!("Clipboard read failed: {}", e))?;
        Ok(json!({ "status": "ok", "text": text, "length": text.len() }))
    }
}

// ============================================================
// cu_clipboard_write
// ============================================================

pub struct CuClipboardWriteTool;

#[async_trait]
impl Tool for CuClipboardWriteTool {
    fn name(&self) -> &str { "cu_clipboard_write" }
    fn description(&self) -> &str { "Write text to the system clipboard." }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { false }
    fn category(&self) -> &str { "write" }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "text": { "type": "string", "description": "Text to write to clipboard" }
            },
            "required": ["text"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let text = args["text"].as_str().ok_or_else(|| "Missing 'text'".to_string())?.to_string();
        let text_len = text.len();
        tokio::task::spawn_blocking(move || clipboard::write_clipboard(&text))
            .await.map_err(|e| format!("Task join error: {}", e))?
            .map_err(|e| format!("Clipboard write failed: {}", e))?;
        Ok(json!({ "status": "ok", "written_bytes": text_len }))
    }
}

// ============================================================
// cu_display_info
// ============================================================

pub struct CuDisplayInfoTool;

#[async_trait]
impl Tool for CuDisplayInfoTool {
    fn name(&self) -> &str { "cu_display_info" }
    fn description(&self) -> &str { "Get display/monitor information: dimensions, DPI, monitor count." }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn category(&self) -> &str { "read" }

    fn parameters_schema(&self) -> Value {
        json!({ "type": "object", "properties": {} })
    }

    async fn execute(&self, _args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let displays = tokio::task::spawn_blocking(|| display::list_displays())
            .await.map_err(|e| format!("Task join error: {}", e))?;

        let (w, h, dpi) = display::get_display_size();
        let display_json: Vec<Value> = displays.iter().map(|d| d.to_json()).collect();

        Ok(json!({
            "status": "ok",
            "primary": { "width": w, "height": h, "dpi": dpi },
            "monitor_count": displays.len(),
            "monitors": display_json,
        }))
    }
}

// ============================================================
// cu_cursor_position
// ============================================================

pub struct CuCursorPositionTool;

#[async_trait]
impl Tool for CuCursorPositionTool {
    fn name(&self) -> &str { "cu_cursor_position" }
    fn description(&self) -> &str { "Get the current mouse cursor X/Y position in screen coordinates." }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn category(&self) -> &str { "read" }

    fn parameters_schema(&self) -> Value {
        json!({ "type": "object", "properties": {} })
    }

    async fn execute(&self, _args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let (x, y) = tokio::task::spawn_blocking(|| input::cursor_position())
            .await.map_err(|e| format!("Task join error: {}", e))?;
        Ok(json!({ "status": "ok", "x": x, "y": y }))
    }
}

// ============================================================
// cu_process_list
// ============================================================

pub struct CuProcessListTool;

#[async_trait]
impl Tool for CuProcessListTool {
    fn name(&self) -> &str { "cu_process_list" }
    fn description(&self) -> &str {
        "List running processes with name, PID, memory usage, and thread count."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn category(&self) -> &str { "read" }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "filter": { "type": "string", "description": "Filter by process name (substring match)" }
            }
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let filter = args.get("filter").and_then(|v| v.as_str()).map(|s| s.to_lowercase());

        let processes = tokio::task::spawn_blocking(|| process::list_processes())
            .await.map_err(|e| format!("Task join error: {}", e))?
            .map_err(|e| format!("Process list failed: {}", e))?;

        let filtered: Vec<Value> = processes.iter()
            .filter(|p| filter.as_ref().map_or(true, |f| p.name.to_lowercase().contains(f)))
            .map(|p| p.to_json())
            .collect();

        Ok(json!({ "status": "ok", "count": filtered.len(), "processes": filtered }))
    }
}

// ============================================================
// cu_process_kill
// ============================================================

pub struct CuProcessKillTool;

#[async_trait]
impl Tool for CuProcessKillTool {
    fn name(&self) -> &str { "cu_process_kill" }
    fn description(&self) -> &str { "Kill a process by PID or by name (kills all matching)." }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { false }
    fn category(&self) -> &str { "execute" }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "pid": { "type": "integer", "description": "Process ID to kill" },
                "name": { "type": "string", "description": "Process name to kill (e.g., notepad.exe)" }
            }
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let pid = args.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32);
        let name = args.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());

        tokio::task::spawn_blocking(move || {
            if let Some(pid) = pid {
                process::kill_process_by_pid(pid)?;
                Ok(json!({ "status": "ok", "killed_pid": pid }))
            } else if let Some(name) = name {
                let count = process::kill_process_by_name(&name)?;
                Ok(json!({ "status": "ok", "killed_count": count, "name": name }))
            } else {
                Err("Provide either 'pid' or 'name'".to_string())
            }
        }).await.map_err(|e| format!("Task join error: {}", e))?.map_err(Into::into)
    }
}

// ============================================================
// cu_ui_tree
// ============================================================

pub struct CuUiTreeTool;

#[async_trait]
impl Tool for CuUiTreeTool {
    fn name(&self) -> &str { "cu_ui_tree" }
    fn description(&self) -> &str {
        "Get the accessibility (UI Automation) tree for a window. Shows roles, names, bounds, and available patterns."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn category(&self) -> &str { "read" }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "hwnd": { "type": "integer", "description": "Window handle (HWND). Omit for foreground window." },
                "max_depth": { "type": "integer", "description": "Maximum tree depth (default: 5)" }
            }
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let hwnd = args.get("hwnd").and_then(|v| v.as_i64()).map(|v| v as isize);
        let max_depth = args.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(5) as u32;

        tokio::task::spawn_blocking(move || {
            let target_hwnd = match hwnd {
                Some(h) => h,
                None => window::get_frontmost()
                    .map(|w| w.hwnd)
                    .ok_or_else(|| "No foreground window found".to_string())?,
            };
            let elements = automation::get_ui_tree(target_hwnd, max_depth)?;
            let json_elements: Vec<Value> = elements.iter().map(|e| e.to_json()).collect();
            Ok::<_, String>(json!({ "status": "ok", "hwnd": target_hwnd, "element_count": json_elements.len(), "elements": json_elements }))
        }).await.map_err(|e| format!("Task join error: {}", e))?.map_err(Into::into)
    }
}

// ============================================================
// cu_ui_find
// ============================================================

pub struct CuUiFindTool;

#[async_trait]
impl Tool for CuUiFindTool {
    fn name(&self) -> &str { "cu_ui_find" }
    fn description(&self) -> &str {
        "Find UI elements by role, name, or class name within a window using UI Automation."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn category(&self) -> &str { "read" }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "hwnd": { "type": "integer", "description": "Window handle. Omit for foreground window." },
                "role": { "type": "string", "description": "Control type: button, edit, checkbox, combobox, list, menu, text, etc." },
                "name": { "type": "string", "description": "Element name to search for" },
                "class_name": { "type": "string", "description": "Win32 class name filter" }
            }
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let hwnd = args.get("hwnd").and_then(|v| v.as_i64()).map(|v| v as isize);
        let role = args.get("role").and_then(|v| v.as_str()).map(|s| s.to_string());
        let name = args.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
        let class_name = args.get("class_name").and_then(|v| v.as_str()).map(|s| s.to_string());

        tokio::task::spawn_blocking(move || {
            let target_hwnd = match hwnd {
                Some(h) => h,
                None => window::get_frontmost()
                    .map(|w| w.hwnd)
                    .ok_or_else(|| "No foreground window found".to_string())?,
            };
            let elements = automation::find_element(
                target_hwnd,
                role.as_deref(),
                name.as_deref(),
                class_name.as_deref(),
            )?;
            let json_elements: Vec<Value> = elements.iter().map(|e| e.to_json()).collect();
            Ok::<_, String>(json!({ "status": "ok", "count": json_elements.len(), "elements": json_elements }))
        }).await.map_err(|e| format!("Task join error: {}", e))?.map_err(Into::into)
    }
}

// ============================================================
// cu_ui_interact
// ============================================================

pub struct CuUiInteractTool;

#[async_trait]
impl Tool for CuUiInteractTool {
    fn name(&self) -> &str { "cu_ui_interact" }
    fn description(&self) -> &str {
        "Interact with a UI element: click a button or set a text value. Finds element by role+name."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { false }
    fn category(&self) -> &str { "execute" }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["click", "set_value"],
                    "description": "Interaction type"
                },
                "hwnd": { "type": "integer", "description": "Window handle. Omit for foreground window." },
                "role": { "type": "string", "description": "Control type (button, edit, etc.)" },
                "name": { "type": "string", "description": "Element name" },
                "value": { "type": "string", "description": "Value to set (for set_value action)" }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let action = args["action"].as_str().ok_or_else(|| "Missing 'action'".to_string())?.to_string();
        let hwnd = args.get("hwnd").and_then(|v| v.as_i64()).map(|v| v as isize);
        let role = args.get("role").and_then(|v| v.as_str()).map(|s| s.to_string());
        let name = args.get("name").and_then(|v| v.as_str()).map(|s| s.to_string());
        let value = args.get("value").and_then(|v| v.as_str()).map(|s| s.to_string());

        tokio::task::spawn_blocking(move || {
            let target_hwnd = match hwnd {
                Some(h) => h,
                None => window::get_frontmost()
                    .map(|w| w.hwnd)
                    .ok_or_else(|| "No foreground window found".to_string())?,
            };

            match action.as_str() {
                "click" => {
                    let result = automation::click_element(target_hwnd, role.as_deref(), name.as_deref())?;
                    Ok(json!({ "status": "ok", "result": result }))
                }
                "set_value" => {
                    let val = value.ok_or_else(|| "Missing 'value' for set_value action".to_string())?;
                    let result = automation::set_value(target_hwnd, role.as_deref(), name.as_deref(), &val)?;
                    Ok(json!({ "status": "ok", "result": result }))
                }
                _ => Err(format!("Unknown ui_interact action: '{}'", action)),
            }
        }).await.map_err(|e| format!("Task join error: {}", e))?.map_err(Into::into)
    }
}
