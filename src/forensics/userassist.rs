//! UserAssist parser — reads execution counters from the live registry.
//!
//! UserAssist keys track GUI program launches with run counts and
//! last execution timestamps. Value names are ROT13-encoded.
//!
//! Reads from HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist

use serde::Serialize;

use super::{filetime_to_iso, read_u32, read_u64};
use super::regapi;

#[derive(Debug, Serialize)]
pub struct UserAssistEntry {
    pub decoded_name: String,
    pub raw_name: String,
    pub run_count: u32,
    pub last_execution: Option<String>,
    pub focus_count: u32,
    pub focus_time_ms: u32,
    pub guid: String,
}

/// Read all UserAssist entries from the live registry.
pub fn read_userassist() -> Result<Vec<UserAssistEntry>, String> {
    let base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
    let guids = regapi::enum_keys("HKCU", base);
    if guids.is_empty() {
        return Err("No UserAssist GUIDs found".into());
    }

    let mut entries = Vec::new();
    for guid in &guids {
        let count_path = format!(r"{}\{}\Count", base, guid);
        let values = regapi::enum_values("HKCU", &count_path);
        for v in &values {
            let decoded = rot13(&v.name);
            let (run_count, last_exec, focus_count, focus_time) = parse_ua_data(&v.data);
            entries.push(UserAssistEntry {
                decoded_name: decoded,
                raw_name: v.name.clone(),
                run_count,
                last_execution: last_exec,
                focus_count,
                focus_time_ms: focus_time,
                guid: guid.clone(),
            });
        }
    }
    // Sort by last execution (most recent first)
    entries.sort_by(|a, b| b.last_execution.cmp(&a.last_execution));
    Ok(entries)
}

/// ROT13 decode (only alphabetic ASCII characters).
fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='M' | 'a'..='m' => (c as u8 + 13) as char,
            'N'..='Z' | 'n'..='z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect()
}

/// Parse UserAssist value data (Win7+ format, 68-72 bytes).
/// Returns (run_count, last_execution_iso, focus_count, focus_time_ms).
fn parse_ua_data(data: &[u8]) -> (u32, Option<String>, u32, u32) {
    if data.len() < 16 {
        return (0, None, 0, 0);
    }
    // Win7+ format:
    // 0x00: Version (4)
    // 0x04: Count (4)
    // 0x08: FocusCount (4)
    // 0x0C: FocusTime (4) — ms
    // ...
    // 0x3C: LastExecution FILETIME (8) — for 68+ byte entries
    let run_count = read_u32(data, 0x04).unwrap_or(0);
    let focus_count = read_u32(data, 0x08).unwrap_or(0);
    let focus_time = read_u32(data, 0x0C).unwrap_or(0);
    let last_exec = if data.len() >= 0x44 {
        let ft = read_u64(data, 0x3C).unwrap_or(0);
        filetime_to_iso(ft)
    } else {
        None
    };
    (run_count, last_exec, focus_count, focus_time)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rot13() {
        assert_eq!(rot13("URYYB"), "HELLO");
        assert_eq!(rot13("uryyb"), "hello");
        assert_eq!(rot13("N"), "A");
        assert_eq!(rot13("123"), "123");
    }

    #[test]
    fn test_parse_ua_data_short() {
        let (rc, le, fc, ft) = parse_ua_data(&[0u8; 4]);
        assert_eq!(rc, 0);
        assert!(le.is_none());
        assert_eq!(fc, 0);
        assert_eq!(ft, 0);
    }

    #[test]
    fn test_parse_ua_data_win7() {
        let mut data = vec![0u8; 68];
        // Version = 5
        data[0..4].copy_from_slice(&5u32.to_le_bytes());
        // Run count = 42
        data[4..8].copy_from_slice(&42u32.to_le_bytes());
        // Focus count = 10
        data[8..12].copy_from_slice(&10u32.to_le_bytes());
        // Focus time = 5000ms
        data[12..16].copy_from_slice(&5000u32.to_le_bytes());
        // Last execution: a valid FILETIME
        // 2026-07-20 00:00:00 UTC = 134289792000000000
        data[0x3C..0x44].copy_from_slice(&134289792000000000u64.to_le_bytes());
        let (rc, le, fc, ft) = parse_ua_data(&data);
        assert_eq!(rc, 42);
        assert!(le.is_some());
        assert_eq!(fc, 10);
        assert_eq!(ft, 5000);
    }
}
