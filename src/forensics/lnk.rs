//! Windows LNK (MS-SHLLINK) shortcut file parser.
//!
//! Extracts: target path, arguments, working directory, file timestamps,
//! file size, icon location. Useful for identifying attacker-dropped
//! shortcuts and revealing original tool locations.

use serde::Serialize;

use super::{filetime_to_iso, read_u16, read_u32, read_u64, utf16_from_bytes};

#[derive(Debug, Serialize, Default)]
pub struct LnkEntry {
    pub file_name: String,
    pub target_path: String,
    pub arguments: String,
    pub working_dir: String,
    pub relative_path: String,
    pub icon_location: String,
    pub file_size: u32,
    pub creation_time: Option<String>,
    pub access_time: Option<String>,
    pub write_time: Option<String>,
    pub attributes: u32,
}

const LNK_HEADER_SIZE: u32 = 0x4C;
const LNK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

// LinkFlags bits
const HAS_LINK_TARGET_ID_LIST: u32 = 0x01;
const HAS_LINK_INFO: u32 = 0x02;
const HAS_NAME: u32 = 0x04;
const HAS_RELATIVE_PATH: u32 = 0x08;
const HAS_WORKING_DIR: u32 = 0x10;
const HAS_ARGUMENTS: u32 = 0x20;
const HAS_ICON_LOCATION: u32 = 0x40;
const IS_UNICODE: u32 = 0x80;

/// Parse all .lnk files in the given directory.
pub fn parse_lnk_dir(dir: &str, limit: usize) -> Result<Vec<LnkEntry>, String> {
    let path = std::path::Path::new(dir);
    if !path.exists() {
        return Err(format!("Directory not found: {}", dir));
    }
    let mut entries = Vec::new();
    let mut files: Vec<_> = std::fs::read_dir(path)
        .map_err(|e| format!("Cannot read dir: {}", e))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|x| x.eq_ignore_ascii_case("lnk"))
                .unwrap_or(false)
        })
        .collect();
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
        if let Some(mut entry) = parse_lnk(&data) {
            entry.file_name = f.file_name().to_string_lossy().to_string();
            entries.push(entry);
        }
    }
    Ok(entries)
}

/// Parse a single .lnk file from raw bytes.
pub fn parse_lnk(data: &[u8]) -> Option<LnkEntry> {
    if data.len() < LNK_HEADER_SIZE as usize {
        return None;
    }
    let header_size = read_u32(data, 0)?;
    if header_size != LNK_HEADER_SIZE {
        return None;
    }
    // Verify CLSID
    let clsid = data.get(4..20)?;
    if clsid != LNK_CLSID {
        return None;
    }

    let flags = read_u32(data, 0x14)?;
    let file_attrs = read_u32(data, 0x18)?;
    let creation = read_u64(data, 0x1C).unwrap_or(0);
    let access = read_u64(data, 0x24).unwrap_or(0);
    let write = read_u64(data, 0x2C).unwrap_or(0);
    let file_size = read_u32(data, 0x34).unwrap_or(0);

    let mut pos: usize = LNK_HEADER_SIZE as usize;
    let mut entry = LnkEntry {
        file_size,
        attributes: file_attrs,
        creation_time: filetime_to_iso(creation),
        access_time: filetime_to_iso(access),
        write_time: filetime_to_iso(write),
        ..Default::default()
    };

    // Skip LinkTargetIDList if present
    if flags & HAS_LINK_TARGET_ID_LIST != 0 {
        if let Some(id_list_size) = read_u16(data, pos) {
            pos += 2 + id_list_size as usize;
        }
    }

    // Parse LinkInfo for target path
    if flags & HAS_LINK_INFO != 0 {
        if let Some((path, new_pos)) = parse_link_info(data, pos) {
            entry.target_path = path;
            pos = new_pos;
        }
    }

    // Parse StringData (order: Name, RelativePath, WorkingDir, Arguments, IconLocation)
    let string_flags = [HAS_NAME, HAS_RELATIVE_PATH, HAS_WORKING_DIR, HAS_ARGUMENTS, HAS_ICON_LOCATION];
    let mut string_results: Vec<(u32, String)> = Vec::new();
    for flag in &string_flags {
        if flags & *flag != 0 {
            if let Some((s, new_pos)) = parse_string_data(data, pos, flags & IS_UNICODE != 0) {
                string_results.push((*flag, s));
                pos = new_pos;
            }
        }
    }
    for (flag, s) in string_results {
        match flag {
            HAS_NAME => entry.file_name = s,
            HAS_RELATIVE_PATH => entry.relative_path = s,
            HAS_WORKING_DIR => entry.working_dir = s,
            HAS_ARGUMENTS => entry.arguments = s,
            HAS_ICON_LOCATION => entry.icon_location = s,
            _ => {}
        }
    }

    // If target_path is empty but relative_path has content, use relative_path
    if entry.target_path.is_empty() && !entry.relative_path.is_empty() {
        entry.target_path = entry.relative_path.clone();
    }

    Some(entry)
}

/// Parse LinkInfo structure — returns (local_base_path, new_position).
fn parse_link_info(data: &[u8], start: usize) -> Option<(String, usize)> {
    if start + 0x1C > data.len() {
        return None;
    }
    let info_size = read_u32(data, start)?;
    let header_size = read_u32(data, start + 4)?;
    let info_flags = read_u32(data, start + 8)?;
    // VolumeIDOffset — reserved for future volume serial/label extraction.
    let _vol_id_off = read_u32(data, start + 0x0C)? as usize;
    let local_base_off = read_u32(data, start + 0x10)? as usize;

    let mut path = String::new();

    // VolumeIDAndLocalBasePath flag
    if info_flags & 0x01 != 0 && local_base_off > 0 {
        let abs = start + local_base_off;
        if abs < data.len() {
            // ANSI null-terminated string
            let end = data[abs..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| abs + p)
                .unwrap_or(data.len());
            path = String::from_utf8_lossy(&data[abs..end]).to_string();
        }

        // Unicode variant (header size >= 0x24)
        if header_size >= 0x24 && start + 0x20 <= data.len() {
            let unicode_off = read_u32(data, start + 0x1C)? as usize;
            if unicode_off > 0 {
                let abs = start + unicode_off;
                if abs < data.len() {
                    let end = data[abs..]
                        .chunks_exact(2)
                        .position(|c| u16::from_le_bytes([c[0], c[1]]) == 0)
                        .map(|i| abs + i * 2)
                        .unwrap_or(data.len());
                    let upath = utf16_from_bytes(&data[abs..end]);
                    if !upath.is_empty() {
                        path = upath;
                    }
                }
            }
        }
    }

    let new_pos = start + info_size as usize;
    Some((path, new_pos))
}

/// Parse a StringData entry — returns (string, new_position).
fn parse_string_data(data: &[u8], start: usize, unicode: bool) -> Option<(String, usize)> {
    if start + 2 > data.len() {
        return None;
    }
    let char_count = read_u16(data, start)? as usize;
    if char_count == 0 {
        return Some((String::new(), start + 2));
    }
    let str_start = start + 2;
    if unicode {
        let byte_count = char_count * 2;
        if str_start + byte_count > data.len() {
            return None;
        }
        let s = utf16_from_bytes(&data[str_start..str_start + byte_count]);
        Some((s, str_start + byte_count))
    } else {
        let byte_count = char_count;
        if str_start + byte_count > data.len() {
            return None;
        }
        let s = String::from_utf8_lossy(&data[str_start..str_start + byte_count]).to_string();
        Some((s, str_start + byte_count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reject_short() {
        assert!(parse_lnk(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_reject_bad_header_size() {
        let mut data = vec![0u8; 0x100];
        data[0] = 0x50; // wrong header size
        assert!(parse_lnk(&data).is_none());
    }
}
