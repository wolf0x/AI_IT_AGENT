//! Window enumeration, activation, and management via Win32 APIs.
//! Pure Rust, Windows-only.

use serde_json::json;
use windows::Win32::Foundation::*;
use windows::Win32::System::Threading::*;
use windows::Win32::UI::WindowsAndMessaging::*;

/// Information about a single window.
#[derive(Debug, Clone)]
pub struct WindowInfo {
    pub hwnd: isize,
    pub title: String,
    pub pid: u32,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub visible: bool,
    pub minimized: bool,
}

impl WindowInfo {
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "hwnd": self.hwnd,
            "title": self.title,
            "pid": self.pid,
            "rect": { "x": self.x, "y": self.y, "width": self.width, "height": self.height },
            "visible": self.visible,
            "minimized": self.minimized,
        })
    }
}

// ============================================================
// Window enumeration
// ============================================================

/// List all top-level windows (including hidden ones).
pub fn list_windows() -> Vec<WindowInfo> {
    let mut windows: Vec<WindowInfo> = Vec::new();

    unsafe {
        let _ = EnumWindows(
            Some(enum_windows_callback),
            LPARAM(&mut windows as *mut Vec<WindowInfo> as isize),
        );
    }

    windows
}

/// EnumWindows callback — collects window info into the Vec.
unsafe extern "system" fn enum_windows_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let windows = &mut *(lparam.0 as *mut Vec<WindowInfo>);

    // Get window title
    let mut title_buf = [0u16; 512];
    let len = GetWindowTextW(hwnd, &mut title_buf);
    let title = if len > 0 {
        String::from_utf16_lossy(&title_buf[..len as usize])
    } else {
        String::new()
    };

    // Get window rect
    let mut rect = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    let _ = GetWindowRect(hwnd, &mut rect);

    // Get PID
    let mut pid: u32 = 0;
    let _ = GetWindowThreadProcessId(hwnd, Some(&mut pid));

    // Visibility and state
    let visible = IsWindowVisible(hwnd).as_bool();
    let minimized = IsIconic(hwnd).as_bool();

    windows.push(WindowInfo {
        hwnd: hwnd.0 as isize,
        title,
        pid,
        x: rect.left,
        y: rect.top,
        width: rect.right - rect.left,
        height: rect.bottom - rect.top,
        visible,
        minimized,
    });

    BOOL(1) // Continue enumeration
}

// ============================================================
// Window queries
// ============================================================

/// Get info for a specific window by HWND.
pub fn get_window(hwnd_val: isize) -> Option<WindowInfo> {
    let hwnd = HWND(hwnd_val as *mut _);
    unsafe {
        if !IsWindow(hwnd).as_bool() {
            return None;
        }

        let mut title_buf = [0u16; 512];
        let len = GetWindowTextW(hwnd, &mut title_buf);
        let title = if len > 0 {
            String::from_utf16_lossy(&title_buf[..len as usize])
        } else {
            String::new()
        };

        let mut rect = RECT { left: 0, top: 0, right: 0, bottom: 0 };
        let _ = GetWindowRect(hwnd, &mut rect);

        let mut pid: u32 = 0;
        let _ = GetWindowThreadProcessId(hwnd, Some(&mut pid));

        let visible = IsWindowVisible(hwnd).as_bool();
        let minimized = IsIconic(hwnd).as_bool();

        Some(WindowInfo {
            hwnd: hwnd_val,
            title,
            pid,
            x: rect.left,
            y: rect.top,
            width: rect.right - rect.left,
            height: rect.bottom - rect.top,
            visible,
            minimized,
        })
    }
}

/// Get the window currently under the cursor.
pub fn get_cursor_window() -> Option<WindowInfo> {
    unsafe {
        let mut pt = POINT { x: 0, y: 0 };
        if GetCursorPos(&mut pt).is_err() {
            return None;
        }
        let hwnd = WindowFromPoint(pt);
        if hwnd.0.is_null() {
            return None;
        }
        // Get the top-level owner
        let root = GetAncestor(hwnd, GA_ROOT);
        let target = if root.0.is_null() { hwnd } else { root };
        get_window(target.0 as isize)
    }
}

/// Get the current foreground (focused) window.
pub fn get_frontmost() -> Option<WindowInfo> {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.0.is_null() {
            return None;
        }
        get_window(hwnd.0 as isize)
    }
}

// ============================================================
// Window activation
// ============================================================

/// Bring a window to the foreground by HWND.
/// Uses AttachThreadInput trick for reliability.
pub fn activate_window(hwnd_val: isize) -> Result<(), String> {
    let hwnd = HWND(hwnd_val as *mut _);
    unsafe {
        if !IsWindow(hwnd).as_bool() {
            return Err(format!("Invalid window handle: {}", hwnd_val));
        }

        // Restore if minimized
        if IsIconic(hwnd).as_bool() {
            let _ = ShowWindow(hwnd, SW_RESTORE);
        }

        // AttachThreadInput trick to bypass foreground lock
        let fore_thread = GetWindowThreadProcessId(GetForegroundWindow(), None);
        let target_thread = GetWindowThreadProcessId(hwnd, None);

        if fore_thread != target_thread {
            let _ = AttachThreadInput(fore_thread, target_thread, true);
            let _ = SetForegroundWindow(hwnd);
            let _ = BringWindowToTop(hwnd);
            let _ = AttachThreadInput(fore_thread, target_thread, false);
        } else {
            let _ = SetForegroundWindow(hwnd);
            let _ = BringWindowToTop(hwnd);
        }

        Ok(())
    }
}

/// Find a window by title (case-insensitive substring match) and activate it.
pub fn activate_by_title(title: &str) -> Result<WindowInfo, String> {
    let windows = list_windows();
    let lower = title.to_lowercase();

    // First try exact match, then substring
    let found = windows
        .iter()
        .find(|w| w.visible && w.title.to_lowercase() == lower)
        .or_else(|| windows.iter().find(|w| w.visible && w.title.to_lowercase().contains(&lower)));

    match found {
        Some(w) => {
            activate_window(w.hwnd)?;
            Ok(w.clone())
        }
        None => Err(format!("No visible window matching title: '{}'", title)),
    }
}
