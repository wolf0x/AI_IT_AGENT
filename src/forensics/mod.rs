//! Windows forensic artifact parsers — pure Rust, no external tools.
//!
//! Modules:
//! - `prefetch`  — SCCA prefetch binary parser (execution count, run times, loaded modules)
//! - `lnk`       — MS-SHLLINK shortcut parser (target path, arguments, working dir)
//! - `hive`      — Windows registry hive file parser (regf/hbin/nk/vk cells)
//! - `shimcache` — AppCompatCache binary blob parser
//! - `regapi`    — Safe wrapper over Win32 registry API (live system reads)
//! - `userassist`— UserAssist ROT13-decoded execution counters
//! - `browser`   — Chrome/Edge/Firefox SQLite history readers

pub mod browser;
pub mod hive;
pub mod lnk;
pub mod prefetch;
pub mod regapi;
pub mod shimcache;
pub mod userassist;

/// Convert a Windows FILETIME (100ns intervals since 1601-01-01) to ISO string.
/// Returns None for zero, max-value, or pre-1970 timestamps.
pub fn filetime_to_iso(ft: u64) -> Option<String> {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000; // 1601→1970 in 100ns ticks
    if ft == 0 || ft == 0x7FFF_FFFF_FFFF_FFFF || ft < EPOCH_DIFF {
        return None;
    }
    let unix_secs = ((ft - EPOCH_DIFF) / 10_000_000) as i64;
    chrono::DateTime::from_timestamp(unix_secs, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
}

/// Convert a Chrome/WebKit timestamp (microseconds since 1601-01-01) to ISO string.
pub fn webkit_to_iso(webkit: u64) -> Option<String> {
    const EPOCH_DIFF: u64 = 11_644_473_600_000_000; // 1601→1970 in µs
    if webkit == 0 || webkit < EPOCH_DIFF {
        return None;
    }
    let unix_secs = ((webkit - EPOCH_DIFF) / 1_000_000) as i64;
    chrono::DateTime::from_timestamp(unix_secs, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
}

/// Convert a Unix timestamp (seconds) to ISO string.
pub fn unix_to_iso(ts: i64) -> Option<String> {
    if ts <= 0 {
        return None;
    }
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
}

/// Read a little-endian u32 from a byte slice with bounds checking.
pub fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a little-endian u64 from a byte slice with bounds checking.
pub fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    data.get(offset..offset + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Read a little-endian u16 from a byte slice with bounds checking.
pub fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

/// Decode a null-terminated UTF-16LE string from a byte slice.
pub fn utf16_from_bytes(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_prefetch_parse() {
        let dir = Path::new("C:\\Windows\\Prefetch");
        if !dir.exists() {
            println!("SKIP: Prefetch dir not found");
            return;
        }
        let entries = prefetch::parse_prefetch_dir(dir.to_str().unwrap(), 5).unwrap();
        println!("Prefetch: {} entries", entries.len());
        for e in entries.iter().take(3) {
            println!("  {} — run_count={}, timestamps={}", e.executable, e.run_count, e.execution_times.len());
        }
        assert!(!entries.is_empty(), "Prefetch should have entries");
    }

    #[test]
    fn test_lnk_parse() {
        let recent_path = format!(
            "C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
            std::env::var("USERNAME").unwrap_or_else(|_| "BUWO".into())
        );
        let recent = Path::new(&recent_path);
        if !recent.exists() {
            println!("SKIP: Recent folder not found");
            return;
        }
        let entries = lnk::parse_lnk_dir(recent.to_str().unwrap(), 5).unwrap();
        println!("LNK: {} entries", entries.len());
        for e in entries.iter().take(3) {
            println!("  {} -> {:?}", e.file_name, e.target_path);
        }
        assert!(!entries.is_empty(), "LNK should have entries");
    }

    #[test]
    fn test_browser_history() {
        let entries = browser::read_all_history(7, 10);
        println!("Browser: {} history entries", entries.len());
        for e in entries.iter().take(3) {
            println!("  [{}] {:?} — {}", e.browser, e.last_visit, e.url);
        }
        // Don't assert — user may not have recent history
    }

    #[test]
    fn test_userassist() {
        let entries = userassist::read_userassist().unwrap();
        println!("UserAssist: {} entries", entries.len());
        for e in entries.iter().take(3) {
            println!("  {} — run={}, last={:?}", e.decoded_name, e.run_count, e.last_execution);
        }
        assert!(!entries.is_empty(), "UserAssist should have entries");
    }

    #[test]
    fn test_shimcache() {
        // ShimCache needs raw binary from registry
        use crate::forensics::regapi;
        let data = match regapi::read_binary_value(
            "HKLM",
            "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
            "AppCompatCache",
        ) {
            Some(d) => d,
            None => {
                println!("SKIP: ShimCache registry read failed");
                return;
            }
        };
        let entries = shimcache::parse_shimcache(&data).unwrap();
        println!("ShimCache: {} entries", entries.len());
        for e in entries.iter().take(3) {
            println!("  [{}] {} — modified={:?}", e.index, e.path, e.last_modified);
        }
        assert!(!entries.is_empty(), "ShimCache should have entries");
    }

    #[test]
    fn test_amcache_hve() {
        let hve = Path::new("C:\\Windows\\AppCompat\\Programs\\Amcache.hve");
        if !hve.exists() {
            println!("SKIP: Amcache.hve not found");
            return;
        }
        // Copy to temp to avoid file lock (os error 32)
        let tmp = std::env::temp_dir().join("Amcache_test.hve");
        if let Err(e) = std::fs::copy(hve, &tmp) {
            println!("SKIP: Cannot copy Amcache.hve (admin required?): {}", e);
            return;
        }
        let hive = hive::HiveFile::open(tmp.to_str().unwrap()).unwrap();
        println!("Amcache hive opened successfully");
        // Try to find the root key
        if let Some(root) = hive.find_key("Root") {
            let subkeys = hive.enum_subkeys(root);
            println!("Root subkeys: {}", subkeys.len());
            for sk in subkeys.iter().take(5) {
                println!("  {}", sk);
            }
        }
        let _ = std::fs::remove_file(&tmp);
    }
}
