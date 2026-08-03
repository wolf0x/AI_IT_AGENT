//! AppCompatCache (ShimCache) binary blob parser.
//!
//! Supports Windows 10/11 format (signature 0x00000080).
//! Extracts: executable paths and embedded timestamps.
//! Entry ordering reflects execution recency (index 0 = most recent).

use serde::Serialize;

use super::{filetime_to_iso, read_u16, read_u32, read_u64};

#[derive(Debug, Serialize)]
pub struct ShimCacheEntry {
    pub index: usize,
    pub path: String,
    pub last_modified: Option<String>,
    pub data_size: u16,
}

const WIN10_SIGNATURE: u32 = 0x0000_0080;
const WIN7_SIGNATURE: u32 = 0xBADC_0FEE;

/// Parse an AppCompatCache binary blob.
/// `data` is the raw REG_BINARY value from the registry.
pub fn parse_shimcache(data: &[u8]) -> Result<Vec<ShimCacheEntry>, String> {
    if data.len() < 16 {
        return Err("ShimCache data too short".into());
    }
    let sig = read_u32(data, 0).ok_or("Cannot read signature")?;
    match sig {
        WIN10_SIGNATURE => parse_win10(data),
        WIN7_SIGNATURE => parse_win7(data),
        other => Err(format!("Unknown ShimCache signature: 0x{:08X}", other)),
    }
}

/// Windows 10/11 format:
///   Header: 0x30 bytes (build 10240) or 0x34 bytes (build 14316+, Win11)
///   Signature: 0x00000080
///   Entries: [entry_sig(4)] + path_size(2) + path(UTF-16) + data_size(2) + data(data_size)
fn parse_win10(data: &[u8]) -> Result<Vec<ShimCacheEntry>, String> {
    let mut entries = Vec::new();
    // Win10/11 header size: 0x34 (52 bytes) for build 14316+ / Win11,
    // 0x30 (48 bytes) for earlier Win10 builds. Detect from data length.
    let header_size = if data.len() >= 0x34 { 0x34usize } else { 0x30usize };
    let mut pos = header_size;
    let mut index = 0;

    while pos + 4 < data.len() {
        // Check for per-entry signature (0x30 or 0x34) and skip it
        if let Some(entry_sig) = read_u32(data, pos) {
            if entry_sig == 0x00000030 || entry_sig == 0x00000034 {
                pos += 4;
            }
        }

        let path_size = match read_u16(data, pos) {
            Some(s) => s as usize,
            None => break,
        };
        pos += 2;
        if path_size == 0 || path_size > 0x10000 || pos + path_size > data.len() {
            break;
        }
        // Path: UTF-16LE
        let path_bytes = &data[pos..pos + path_size];
        let path = super::utf16_from_bytes(path_bytes)
            .trim_matches('\0')
            .to_string();
        pos += path_size;

        if pos + 2 > data.len() {
            break;
        }
        let data_size = read_u16(data, pos).unwrap_or(0);
        pos += 2;

        let mut last_modified = None;
        if data_size > 0 && pos + data_size as usize <= data.len() {
            let blob = &data[pos..pos + data_size as usize];
            // Timestamp at offset 0x10 in the data blob (Win10)
            if blob.len() >= 0x18 {
                let ft = read_u64(blob, 0x10).unwrap_or(0);
                last_modified = filetime_to_iso(ft);
            }
            pos += data_size as usize;
        }

        if !path.is_empty() {
            entries.push(ShimCacheEntry {
                index,
                path,
                last_modified,
                data_size,
            });
            index += 1;
        }
    }
    Ok(entries)
}

/// Windows 7 format (simplified):
///   Header: 128 bytes
///   Entry: path_size(2) + max_path(2) + path_offset(4) + FILETIME(8) + flags(4) + padding(4)
fn parse_win7(data: &[u8]) -> Result<Vec<ShimCacheEntry>, String> {
    let mut entries = Vec::new();
    let mut pos = 128; // Skip header
    let mut index = 0;

    while pos + 24 <= data.len() {
        let path_size = match read_u16(data, pos) {
            Some(s) => s as usize,
            None => break,
        };
        let _max_path = read_u16(data, pos + 2).unwrap_or(0);
        let path_offset = read_u32(data, pos + 4).unwrap_or(0) as usize;
        let ft = read_u64(data, pos + 8).unwrap_or(0);

        // Advance past this entry (24 bytes for the fixed part)
        pos += 24;

        let path = if path_offset > 0 && path_offset + path_size <= data.len() {
            super::utf16_from_bytes(&data[path_offset..path_offset + path_size])
                .trim_matches('\0')
                .to_string()
        } else {
            continue;
        };

        if !path.is_empty() {
            entries.push(ShimCacheEntry {
                index,
                path,
                last_modified: filetime_to_iso(ft),
                data_size: 0,
            });
            index += 1;
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reject_short() {
        assert!(parse_shimcache(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_reject_unknown_sig() {
        let mut data = vec![0u8; 64];
        data[0] = 0xFF;
        assert!(parse_shimcache(&data).is_err());
    }

    #[test]
    fn test_win10_empty() {
        let mut data = vec![0u8; 32];
        // Win10 signature
        data[0..4].copy_from_slice(&WIN10_SIGNATURE.to_le_bytes());
        let entries = parse_shimcache(&data).unwrap();
        assert!(entries.is_empty());
    }
}
