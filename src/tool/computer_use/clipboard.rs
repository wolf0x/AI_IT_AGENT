//! Clipboard read/write via Win32 APIs.
//! Pure Rust, Windows-only.

use windows::Win32::Foundation::*;
use windows::Win32::System::DataExchange::*;
use windows::Win32::System::Memory::*;

/// CF_UNICODETEXT = 13
const CF_UNICODETEXT: u32 = 13;

/// Read text content from the system clipboard.
pub fn read_clipboard() -> Result<String, String> {
    unsafe {
        if OpenClipboard(HWND(std::ptr::null_mut())).is_err() {
            return Err("Failed to open clipboard".to_string());
        }

        let result = (|| {
            let handle = GetClipboardData(CF_UNICODETEXT);
            let handle = handle.map_err(|_| "Clipboard is empty or does not contain text".to_string())?;

            let ptr = GlobalLock(HGLOBAL(handle.0));
            if ptr.is_null() {
                return Err("Failed to lock clipboard memory".to_string());
            }

            // Read null-terminated UTF-16 string
            let wide_ptr = ptr as *const u16;
            let mut len = 0;
            while *wide_ptr.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(wide_ptr, len);
            let text = String::from_utf16_lossy(slice);

            let _ = GlobalUnlock(HGLOBAL(handle.0));
            Ok(text)
        })();

        let _ = CloseClipboard();
        result
    }
}

/// Write text to the system clipboard.
pub fn write_clipboard(text: &str) -> Result<(), String> {
    unsafe {
        if OpenClipboard(HWND(std::ptr::null_mut())).is_err() {
            return Err("Failed to open clipboard".to_string());
        }

        let result = (|| {
            if EmptyClipboard().is_err() {
                return Err("Failed to empty clipboard".to_string());
            }

            // Convert to UTF-16 with null terminator
            let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
            let byte_len = wide.len() * std::mem::size_of::<u16>();

            let handle = GlobalAlloc(GMEM_MOVEABLE, byte_len);
            let handle = handle.map_err(|_| "Failed to allocate clipboard memory".to_string())?;

            let ptr = GlobalLock(handle);
            if ptr.is_null() {
                let _ = GlobalFree(handle);
                return Err("Failed to lock allocated memory".to_string());
            }

            // Copy UTF-16 data
            std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr as *mut u16, wide.len());
            let _ = GlobalUnlock(handle);

            // SetClipboardData takes ownership of the handle
            SetClipboardData(CF_UNICODETEXT, HANDLE(handle.0))
                .map_err(|_| "Failed to set clipboard data".to_string())?;

            Ok(())
        })();

        let _ = CloseClipboard();
        result
    }
}
