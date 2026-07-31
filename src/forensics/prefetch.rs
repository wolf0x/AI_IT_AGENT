//! Windows Prefetch (.pf) binary parser — SCCA format.
//!
//! Supports versions:
//! - 0x17 (23): Windows Vista / 7 / Server 2008
//! - 0x1A (26): Windows 8 / 8.1 / Server 2012
//! - 0x1E (30): Windows 10 / 11 / Server 2016+
//!
//! Extracts: executable name, path hash, run count, up to 8 execution
//! timestamps (Win10+), volume info, and all referenced file paths
//! (loaded DLLs/executables — high-value IOC source).

use serde::Serialize;

use super::{filetime_to_iso, read_u16, read_u32, read_u64, utf16_from_bytes};

#[derive(Debug, Serialize)]
pub struct PrefetchEntry {
    pub file_name: String,
    pub executable: String,
    pub path_hash: String,
    pub version: u32,
    pub file_size: u32,
    pub run_count: u32,
    /// Execution timestamps, most recent first (up to 8 on Win10+).
    pub execution_times: Vec<String>,
    /// Volume device paths (e.g. \\DEVICE\\HARDDISKVOLUME3).
    pub volumes: Vec<String>,
    /// Volume serial numbers.
    pub volume_serials: Vec<String>,
    /// All referenced file paths (executable + loaded DLLs).
    pub referenced_files: Vec<String>,
    /// File last-modified timestamp (filesystem).
    pub file_modified: Option<String>,
}

const SCCA_SIGNATURE: u32 = 0x5343_4341; // "SCCA"

/// Parse all .pf files in the given directory (default: C:\Windows\Prefetch).
pub fn parse_prefetch_dir(dir: &str, limit: usize) -> Result<Vec<PrefetchEntry>, String> {
    let path = std::path::Path::new(dir);
    if !path.exists() {
        return Err(format!("Prefetch directory not found: {}", dir));
    }
    let mut entries = Vec::new();
    let mut files: Vec<_> = std::fs::read_dir(path)
        .map_err(|e| format!("Cannot read prefetch dir (admin required?): {}", e))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|x| x.eq_ignore_ascii_case("pf"))
                .unwrap_or(false)
        })
        .collect();
    // Most recently modified first
    files.sort_by(|a, b| {
        let ta = a.metadata().and_then(|m| m.modified()).ok();
        let tb = b.metadata().and_then(|m| m.modified()).ok();
        tb.cmp(&ta)
    });
    for f in files.iter().take(limit) {
        let data = match std::fs::read(f.path()) {
            Ok(d) => d,
            Err(_) => continue,
        };
        if let Some(mut entry) = parse_prefetch(&data) {
            entry.file_name = f.file_name().to_string_lossy().to_string();
            entry.file_modified = f
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| {
                    t.duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|d| {
                            chrono::DateTime::from_timestamp(d.as_secs() as i64, 0)
                                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        })
                        .flatten()
                });
            entries.push(entry);
        }
    }
    Ok(entries)
}

/// Parse a single prefetch file from raw bytes.
/// Handles both MAM-compressed (Win10/11) and raw SCCA (older Windows) files.
pub fn parse_prefetch(data: &[u8]) -> Option<PrefetchEntry> {
    if data.len() < 0x54 {
        return None;
    }

    // Check for MAM wrapper (Windows 10/11 compressed prefetch)
    if data.len() > 8 && &data[0..4] == b"MAM\x04" {
        return parse_mam_prefetch(data);
    }

    parse_scca_prefetch(data)
}

/// Parse MAM-compressed prefetch using the prefetch-core crate.
fn parse_mam_prefetch(data: &[u8]) -> Option<PrefetchEntry> {
    let info = prefetch_core::parse(data).ok()?;
    let execution_times: Vec<String> = info
        .last_run_times
        .iter()
        .filter_map(|&ft| filetime_to_iso(ft as u64))
        .collect();
    let volumes: Vec<String> = info.volumes.iter().map(|v| v.device_path.clone()).collect();
    let volume_serials: Vec<String> = info
        .volumes
        .iter()
        .map(|v| format!("{:08X}", v.serial))
        .collect();
    Some(PrefetchEntry {
        file_name: String::new(), // filled by caller
        executable: info.executable,
        path_hash: String::new(),
        version: info.version,
        file_size: 0,
        run_count: info.run_count,
        execution_times,
        volumes,
        volume_serials,
        referenced_files: info.filenames,
        file_modified: None,
    })
}

/// Parse a raw (uncompressed) SCCA prefetch file.
fn parse_scca_prefetch(data: &[u8]) -> Option<PrefetchEntry> {
    let version = read_u32(data, 0)?;
    let signature = read_u32(data, 4)?;
    if signature != SCCA_SIGNATURE {
        return None;
    }
    let file_size = read_u32(data, 0x0C).unwrap_or(0);

    // Executable name: UTF-16LE, 30 chars at offset 0x10
    let name_bytes = data.get(0x10..0x4C)?;
    let executable = utf16_from_bytes(name_bytes);

    let hash = read_u32(data, 0x4C).unwrap_or(0);

    // Version-dependent offsets
    let (run_count, exec_times, fn_strings_off, fn_strings_size, volume_off, volume_count) =
        match version {
            0x17 => {
                // Vista/7: single timestamp at 0x78, run count at 0x80
                let last = read_u64(data, 0x78).unwrap_or(0);
                let rc = read_u32(data, 0x80).unwrap_or(0);
                let times = if last != 0 { vec![last] } else { vec![] };
                (
                    rc,
                    times,
                    read_u32(data, 0x98).unwrap_or(0) as usize,
                    read_u32(data, 0x9C).unwrap_or(0) as usize,
                    read_u32(data, 0xA0).unwrap_or(0) as usize,
                    read_u32(data, 0xA4).unwrap_or(0) as usize,
                )
            }
            0x1A => {
                // Win8: single timestamp at 0x80, run count at 0x88
                let last = read_u64(data, 0x80).unwrap_or(0);
                let rc = read_u32(data, 0x88).unwrap_or(0);
                let times = if last != 0 { vec![last] } else { vec![] };
                (
                    rc,
                    times,
                    read_u32(data, 0xA0).unwrap_or(0) as usize,
                    read_u32(data, 0xA4).unwrap_or(0) as usize,
                    read_u32(data, 0xA8).unwrap_or(0) as usize,
                    read_u32(data, 0xAC).unwrap_or(0) as usize,
                )
            }
            0x1E | 0x1F => {
                // Win10/11: 8 timestamps at 0x80..0xC0, run count at 0xC8
                let mut times = Vec::new();
                for i in 0..8 {
                    let t = read_u64(data, 0x80 + i * 8).unwrap_or(0);
                    if t != 0 {
                        times.push(t);
                    }
                }
                let rc = read_u32(data, 0xC8).unwrap_or(0);
                (
                    rc,
                    times,
                    read_u32(data, 0xE0).unwrap_or(0) as usize,
                    read_u32(data, 0xE4).unwrap_or(0) as usize,
                    read_u32(data, 0xE8).unwrap_or(0) as usize,
                    read_u32(data, 0xEC).unwrap_or(0) as usize,
                )
            }
            _ => return None, // Unknown version
        };

    // Execution times: most recent first (they're stored newest→oldest)
    let execution_times: Vec<String> = exec_times
        .iter()
        .filter_map(|&t| filetime_to_iso(t))
        .collect();

    // Filename strings section: consecutive null-terminated UTF-16LE paths
    let referenced_files = parse_filename_strings(data, fn_strings_off, fn_strings_size);

    // Volume info
    let (volumes, volume_serials) = parse_volumes(data, version, volume_off, volume_count);

    Some(PrefetchEntry {
        file_name: String::new(),
        executable,
        path_hash: format!("{:08X}", hash),
        version,
        file_size,
        run_count,
        execution_times,
        volumes,
        volume_serials,
        referenced_files,
        file_modified: None,
    })
}

/// Parse the filename strings section — consecutive null-terminated UTF-16LE strings.
fn parse_filename_strings(data: &[u8], offset: usize, size: usize) -> Vec<String> {
    let mut files = Vec::new();
    if offset == 0 || size == 0 || offset >= data.len() {
        return files;
    }
    let end = (offset + size).min(data.len());
    let section = &data[offset..end];
    let mut pos = 0;
    while pos + 1 < section.len() {
        // Find null terminator (UTF-16)
        let mut str_end = pos;
        let mut found = false;
        while str_end + 1 < section.len() {
            if section[str_end] == 0 && section[str_end + 1] == 0 && str_end > pos {
                found = true;
                break;
            }
            // Also handle odd alignment: check u16 == 0
            if let Some(u) = read_u16(section, str_end) {
                if u == 0 && str_end > pos {
                    found = true;
                    break;
                }
            }
            str_end += 2;
        }
        if str_end <= pos {
            break;
        }
        let s = utf16_from_bytes(&section[pos..str_end.min(section.len())]);
        let s = s.trim_matches('\0').trim().to_string();
        if !s.is_empty() && s.chars().any(|c| !c.is_control()) {
            files.push(s);
        }
        if !found {
            break;
        }
        pos = str_end + 2;
    }
    files
}

/// Parse volume information section.
fn parse_volumes(
    data: &[u8],
    version: u32,
    offset: usize,
    count: usize,
) -> (Vec<String>, Vec<String>) {
    let mut paths = Vec::new();
    let mut serials = Vec::new();
    if offset == 0 || count == 0 || offset >= data.len() {
        return (paths, serials);
    }

    if version >= 0x1E {
        // Win10+: volume info entries are chained. First entry at `offset`.
        // Entry layout:
        //   0x00: next volume info offset (relative to volume section start)
        //   0x04: volume path offset (relative to this entry)
        //   0x08: volume path size (bytes)
        //   0x0C: creation time FILETIME (8)
        //   0x14: volume serial (4)
        let mut entry_off = offset;
        for _ in 0..count.min(16) {
            if entry_off + 0x18 > data.len() {
                break;
            }
            let path_rel = read_u32(data, entry_off + 0x04).unwrap_or(0) as usize;
            let path_size = read_u32(data, entry_off + 0x08).unwrap_or(0) as usize;
            let serial = read_u32(data, entry_off + 0x14).unwrap_or(0);
            if path_rel > 0 && path_size > 0 {
                let abs = entry_off + path_rel;
                if abs + path_size <= data.len() {
                    let p = utf16_from_bytes(&data[abs..abs + path_size]);
                    let p = p.trim_matches('\0').to_string();
                    if !p.is_empty() {
                        paths.push(p);
                        serials.push(format!("{:08X}", serial));
                    }
                }
            }
            // Next entry
            let next = read_u32(data, entry_off).unwrap_or(0) as usize;
            if next == 0 || next <= entry_off - offset {
                break;
            }
            entry_off = offset + next;
            if entry_off <= offset {
                break;
            }
        }
    } else {
        // Vista/7/8: single volume info entry at offset
        //   0x00: volume path offset (relative to entry)
        //   0x04: volume path size
        //   0x08: creation time (8)
        //   0x10: serial (4)
        if offset + 0x14 <= data.len() {
            let path_rel = read_u32(data, offset).unwrap_or(0) as usize;
            let path_size = read_u32(data, offset + 0x04).unwrap_or(0) as usize;
            let serial = read_u32(data, offset + 0x10).unwrap_or(0);
            if path_rel > 0 && path_size > 0 {
                let abs = offset + path_rel;
                if abs + path_size <= data.len() {
                    let p = utf16_from_bytes(&data[abs..abs + path_size]);
                    let p = p.trim_matches('\0').to_string();
                    if !p.is_empty() {
                        paths.push(p);
                        serials.push(format!("{:08X}", serial));
                    }
                }
            }
        }
    }
    (paths, serials)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reject_short_data() {
        assert!(parse_prefetch(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_reject_bad_signature() {
        let mut data = vec![0u8; 0x100];
        data[0] = 0x1E; // version
        // signature stays 0 → invalid
        assert!(parse_prefetch(&data).is_none());
    }
}
