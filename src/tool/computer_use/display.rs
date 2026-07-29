//! Display/monitor information via Win32 APIs.
//! Pure Rust, Windows-only.

use serde_json::json;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::UI::HiDpi::*;
use windows::Win32::UI::WindowsAndMessaging::*;

/// Information about a single display/monitor.
#[derive(Debug, Clone)]
pub struct DisplayInfo {
    pub name: String,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub dpi: u32,
    pub is_primary: bool,
}

impl DisplayInfo {
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "name": self.name,
            "rect": { "x": self.x, "y": self.y, "width": self.width, "height": self.height },
            "dpi": self.dpi,
            "is_primary": self.is_primary,
        })
    }
}

/// Get the primary display dimensions and DPI.
pub fn get_display_size() -> (i32, i32, u32) {
    unsafe {
        let w = GetSystemMetrics(SM_CXSCREEN);
        let h = GetSystemMetrics(SM_CYSCREEN);

        // Try to get DPI for the primary monitor
        let dpi = get_primary_dpi();
        (w, h, dpi)
    }
}

/// List all connected monitors with their properties.
pub fn list_displays() -> Vec<DisplayInfo> {
    let mut displays: Vec<DisplayInfo> = Vec::new();

    unsafe {
        let _ = EnumDisplayMonitors(
            HDC(std::ptr::null_mut()),
            None,
            Some(enum_monitors_callback),
            LPARAM(&mut displays as *mut Vec<DisplayInfo> as isize),
        );
    }

    displays
}

/// EnumDisplayMonitors callback.
unsafe extern "system" fn enum_monitors_callback(
    hmonitor: HMONITOR,
    _hdc: HDC,
    _rect: *mut RECT,
    lparam: LPARAM,
) -> BOOL {
    let displays = &mut *(lparam.0 as *mut Vec<DisplayInfo>);

    // Get monitor info
    let mut info = MONITORINFOEXW {
        monitorInfo: MONITORINFO {
            cbSize: std::mem::size_of::<MONITORINFOEXW>() as u32,
            rcMonitor: RECT::default(),
            rcWork: RECT::default(),
            dwFlags: 0,
        },
        szDevice: [0u16; 32],
    };

    let monitor_info_ptr = &mut info as *mut MONITORINFOEXW as *mut MONITORINFO;
    if GetMonitorInfoW(hmonitor, monitor_info_ptr).as_bool() {
        let rc = info.monitorInfo.rcMonitor;
        let is_primary = (info.monitorInfo.dwFlags & MONITORINFOF_PRIMARY) != 0;

        // Get device name
        let name_len = info.szDevice.iter().position(|&c| c == 0).unwrap_or(32);
        let name = String::from_utf16_lossy(&info.szDevice[..name_len]);

        // Get DPI
        let dpi = get_monitor_dpi(hmonitor);

        displays.push(DisplayInfo {
            name,
            x: rc.left,
            y: rc.top,
            width: rc.right - rc.left,
            height: rc.bottom - rc.top,
            dpi,
            is_primary,
        });
    }

    BOOL(1) // Continue enumeration
}

/// Get DPI for a specific monitor handle.
unsafe fn get_monitor_dpi(hmonitor: HMONITOR) -> u32 {
    let mut dpi_x: u32 = 96;
    let mut dpi_y: u32 = 96;
    let result = GetDpiForMonitor(hmonitor, MDT_EFFECTIVE_DPI, &mut dpi_x, &mut dpi_y);
    if result.is_ok() {
        dpi_x
    } else {
        96 // Default DPI
    }
}

/// Get the DPI of the primary monitor.
unsafe fn get_primary_dpi() -> u32 {
    // Use GetDpiForSystem if available
    match GetDpiForSystem() {
        0 => 96,
        dpi => dpi,
    }
}
