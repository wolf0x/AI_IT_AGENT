//! Mouse and keyboard input simulation via Win32 SendInput.
//! Pure Rust, Windows-only.

use windows::Win32::Foundation::POINT;
use windows::Win32::UI::Input::KeyboardAndMouse::*;
use windows::Win32::UI::WindowsAndMessaging::*;

// ============================================================
// Screen metrics
// ============================================================

/// Get primary screen dimensions (width, height) in pixels.
pub fn screen_size() -> (i32, i32) {
    unsafe {
        let w = GetSystemMetrics(SM_CXSCREEN);
        let h = GetSystemMetrics(SM_CYSCREEN);
        (w, h)
    }
}

/// Convert screen pixel coordinates to normalized absolute coordinates (0–65535).
fn to_absolute(x: f64, y: f64) -> (i32, i32) {
    let (sw, sh) = screen_size();
    let ax = ((x * 65535.0) / sw as f64) as i32;
    let ay = ((y * 65535.0) / sh as f64) as i32;
    (ax, ay)
}

// ============================================================
// Low-level SendInput helpers
// ============================================================

/// Send a single mouse input event.
fn send_mouse(dx: i32, dy: i32, flags: MOUSE_EVENT_FLAGS, data: i32) {
    let input = INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: data as u32,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };
    unsafe {
        SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
    }
}

/// Send a single keyboard input event.
fn send_key(vk: u16, flags: KEYBD_EVENT_FLAGS) {
    let input = INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(vk),
                wScan: 0,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };
    unsafe {
        SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
    }
}

/// Send a Unicode character via KEYEVENTF_UNICODE.
fn send_unicode(ch: u16, down: bool) {
    let mut flags = KEYEVENTF_UNICODE;
    if !down {
        flags |= KEYEVENTF_KEYUP;
    }
    let input = INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(0),
                wScan: ch,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };
    unsafe {
        SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
    }
}

// ============================================================
// Mouse operations
// ============================================================

/// Move the cursor to absolute screen coordinates (pixels).
pub fn mouse_move(x: f64, y: f64) {
    let (ax, ay) = to_absolute(x, y);
    send_mouse(ax, ay, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, 0);
}

/// Click a mouse button at the current cursor position.
/// button: "left", "right", "middle"
/// count: 1 = single click, 2 = double click
pub fn mouse_click(button: &str, count: u32) {
    let (down, up) = match button {
        "right" => (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
        "middle" => (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
        _ => (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
    };
    for _ in 0..count.max(1) {
        send_mouse(0, 0, down, 0);
        send_mouse(0, 0, up, 0);
        if count > 1 {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

/// Press a mouse button (hold down).
pub fn mouse_button_down(button: &str) {
    let flags = match button {
        "right" => MOUSEEVENTF_RIGHTDOWN,
        "middle" => MOUSEEVENTF_MIDDLEDOWN,
        _ => MOUSEEVENTF_LEFTDOWN,
    };
    send_mouse(0, 0, flags, 0);
}

/// Release a mouse button.
pub fn mouse_button_up(button: &str) {
    let flags = match button {
        "right" => MOUSEEVENTF_RIGHTUP,
        "middle" => MOUSEEVENTF_MIDDLEUP,
        _ => MOUSEEVENTF_LEFTUP,
    };
    send_mouse(0, 0, flags, 0);
}

/// Scroll the mouse wheel.
/// dy: vertical scroll (positive = up, negative = down), in "clicks" (1 click = 120 units)
/// dx: horizontal scroll (positive = right, negative = left)
pub fn mouse_scroll(dy: i32, dx: i32) {
    if dy != 0 {
        send_mouse(0, 0, MOUSEEVENTF_WHEEL, dy * WHEEL_DELTA as i32);
    }
    if dx != 0 {
        send_mouse(0, 0, MOUSEEVENTF_HWHEEL, dx * WHEEL_DELTA as i32);
    }
}

/// Drag from current position to (x2, y2) with the specified button held.
pub fn mouse_drag(x1: f64, y1: f64, x2: f64, y2: f64, button: &str) {
    // Move to start
    mouse_move(x1, y1);
    std::thread::sleep(std::time::Duration::from_millis(20));

    // Press
    mouse_button_down(button);
    std::thread::sleep(std::time::Duration::from_millis(20));

    // Move to end in small steps for smoother drag
    let steps = 10;
    for i in 1..=steps {
        let t = i as f64 / steps as f64;
        let cx = x1 + (x2 - x1) * t;
        let cy = y1 + (y2 - y1) * t;
        mouse_move(cx, cy);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // Release
    mouse_button_up(button);
}

// ============================================================
// Keyboard operations
// ============================================================

/// Type text using Unicode key events (supports any Unicode characters).
/// Sends in chunks of 20 UTF-16 code units with small gaps for reliability.
pub fn type_text(text: &str) {
    let utf16: Vec<u16> = text.encode_utf16().collect();
    for chunk in utf16.chunks(20) {
        for &ch in chunk {
            send_unicode(ch, true);
            send_unicode(ch, false);
        }
        // Small gap between chunks for target app to process
        std::thread::sleep(std::time::Duration::from_millis(3));
    }
}

/// Press a key combination like "ctrl+c", "alt+f4", "shift+enter", "ctrl+alt+delete".
/// Also supports single keys like "enter", "tab", "escape", "f5", etc.
pub fn key_press(combo: &str) -> Result<(), String> {
    let parts: Vec<&str> = combo.split('+').map(|s| s.trim()).collect();
    if parts.is_empty() {
        return Err("Empty key combination".to_string());
    }

    let mut vks: Vec<u16> = Vec::new();
    for part in &parts {
        let vk = parse_vk(part)?;
        vks.push(vk);
    }

    // Press all keys in order (modifiers first)
    for &vk in &vks {
        send_key(vk, KEYBD_EVENT_FLAGS(0));
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // Release in reverse order
    for &vk in vks.iter().rev() {
        send_key(vk, KEYEVENTF_KEYUP);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    Ok(())
}

/// Get the current cursor position in screen coordinates.
pub fn cursor_position() -> (i32, i32) {
    unsafe {
        let mut pt = POINT { x: 0, y: 0 };
        let _ = GetCursorPos(&mut pt);
        (pt.x, pt.y)
    }
}

// ============================================================
// Virtual key code mapping
// ============================================================

/// Parse a key name to a Windows virtual key code.
fn parse_vk(name: &str) -> Result<u16, String> {
    let lower = name.to_lowercase();
    let vk = match lower.as_str() {
        // Modifiers
        "ctrl" | "control" => 0x11, // VK_CONTROL
        "alt" | "menu" => 0x12,     // VK_MENU
        "shift" => 0x10,            // VK_SHIFT
        "win" | "windows" | "super" | "meta" => 0x5B, // VK_LWIN

        // Navigation
        "enter" | "return" => 0x0D,
        "tab" => 0x09,
        "escape" | "esc" => 0x1B,
        "space" | "spacebar" => 0x20,
        "backspace" | "back" => 0x08,
        "delete" | "del" => 0x2E,
        "insert" | "ins" => 0x2D,

        // Arrow keys
        "up" | "arrowup" => 0x26,
        "down" | "arrowdown" => 0x28,
        "left" | "arrowleft" => 0x25,
        "right" | "arrowright" => 0x27,

        // Home/End/Page
        "home" => 0x24,
        "end" => 0x23,
        "pageup" | "pgup" => 0x21,
        "pagedown" | "pgdn" => 0x22,

        // Function keys
        "f1" => 0x70, "f2" => 0x71, "f3" => 0x72, "f4" => 0x73,
        "f5" => 0x74, "f6" => 0x75, "f7" => 0x76, "f8" => 0x77,
        "f9" => 0x78, "f10" => 0x79, "f11" => 0x7A, "f12" => 0x7B,

        // Editing
        "copy" => 0x43,      // 'C' (use with ctrl)
        "paste" => 0x56,     // 'V' (use with ctrl)
        "cut" => 0x58,       // 'X' (use with ctrl)
        "selectall" | "select_all" => 0x41, // 'A' (use with ctrl)
        "undo" => 0x5A,      // 'Z' (use with ctrl)
        "redo" => 0x59,      // 'Y' (use with ctrl)

        // Misc
        "printscreen" | "prtsc" => 0x2C,
        "scrolllock" => 0x91,
        "numlock" => 0x90,
        "capslock" => 0x14,
        "pause" | "break" => 0x13,
        "context" | "contextmenu" | "apps" => 0x5D,

        // Single character — map A-Z, 0-9
        _ => {
            if lower.len() == 1 {
                let ch = lower.chars().next().unwrap();
                if ch.is_ascii_alphabetic() {
                    ch.to_ascii_uppercase() as u16
                } else if ch.is_ascii_digit() {
                    ch as u16
                } else {
                    return Err(format!("Unknown key: '{}'", name));
                }
            } else {
                return Err(format!("Unknown key: '{}'", name));
            }
        }
    };
    Ok(vk)
}
