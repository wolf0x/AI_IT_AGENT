//! Windows Registry hive file parser (offline, read-only).
//!
//! Supports the regf/hbin/nk/vk cell format used by Windows NT+ hives.
//! Used for parsing Amcache.hve (program execution evidence with SHA1 hashes)
//! and other standalone hive files.

use serde::Serialize;

use super::{read_u16, read_u32, read_u64};

const REGF_SIGNATURE: u32 = 0x6866_6772; // "regf" in LE
const HBIN_SIGNATURE: u32 = 0x6E69_6268; // "hbin" in LE
const NK_SIGNATURE: u16 = 0x6B6E; // "nk"
const VK_SIGNATURE: u16 = 0x6B76; // "vk"

// Registry value types
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

#[derive(Debug, Serialize)]
pub struct HiveValue {
    pub name: String,
    pub value_type: u32,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct HiveFile {
    data: Vec<u8>,
    root_offset: u32,
}

impl HiveFile {
    /// Load a registry hive from disk.
    pub fn open(path: &str) -> Result<Self, String> {
        let data = std::fs::read(path).map_err(|e| format!("Cannot read hive '{}': {}", path, e))?;
        Self::from_bytes(data)
    }

    /// Parse from raw bytes.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, String> {
        if data.len() < 0x1000 {
            return Err("Hive too small".into());
        }
        let sig = read_u32(&data, 0).unwrap_or(0);
        if sig != REGF_SIGNATURE {
            return Err(format!("Not a registry hive (bad signature: 0x{:08X})", sig));
        }
        let root_offset = read_u32(&data, 0x24).unwrap_or(0);
        Ok(Self { data, root_offset })
    }

    /// Get the root key name.
    pub fn root_key_name(&self) -> String {
        // Typically "<NO NAME>" or the hive filename — we just return the nk name
        let cell_off = self.root_offset as usize;
        self.nk_name(cell_off).unwrap_or_else(|| "Root".into())
    }

    /// Navigate to a subkey by path (case-insensitive).
    /// Path components separated by '\' or '/'.
    pub fn find_key(&self, path: &str) -> Option<usize> {
        let components: Vec<&str> = path
            .split(|c| c == '\\' || c == '/')
            .filter(|s| !s.is_empty())
            .collect();
        let mut cell_off = self.root_offset as usize;
        for component in &components {
            let found = self.find_subkey(cell_off, component)?;
            cell_off = found;
        }
        Some(cell_off)
    }

    /// Enumerate all values under a key.
    pub fn enum_values(&self, key_offset: usize) -> Vec<HiveValue> {
        let nk_abs = self.hive_data_start() + key_offset;
        if nk_abs + 0x50 > self.data.len() {
            return Vec::new();
        }
        let num_values = read_u32(&self.data, nk_abs + 0x24).unwrap_or(0);
        let values_list_off = read_u32(&self.data, nk_abs + 0x28).unwrap_or(0);
        if num_values == 0 || values_list_off == 0 {
            return Vec::new();
        }
        let list_abs = self.hive_data_start() + values_list_off as usize;
        // Values list cell: size(4) + array of u32 offsets
        let list_data_start = list_abs + 4; // skip cell size
        let mut values = Vec::new();
        for i in 0..num_values.min(200) {
            let vk_off_pos = list_data_start + (i as usize) * 4;
            if vk_off_pos + 4 > self.data.len() {
                break;
            }
            let vk_off = read_u32(&self.data, vk_off_pos).unwrap_or(0);
            if let Some(v) = self.parse_vk(self.hive_data_start() + vk_off as usize) {
                values.push(v);
            }
        }
        values
    }

    /// Enumerate all subkey names under a key.
    pub fn enum_subkeys(&self, key_offset: usize) -> Vec<String> {
        let nk_abs = self.hive_data_start() + key_offset;
        if nk_abs + 0x50 > self.data.len() {
            return Vec::new();
        }
        let num_subkeys = read_u32(&self.data, nk_abs + 0x14).unwrap_or(0);
        let subkeys_list_off = read_u32(&self.data, nk_abs + 0x1C).unwrap_or(0);
        if num_subkeys == 0 || subkeys_list_off == 0 {
            return Vec::new();
        }
        let list_abs = self.hive_data_start() + subkeys_list_off as usize;
        if list_abs + 4 > self.data.len() {
            return Vec::new();
        }
        let list_sig = read_u16(&self.data, list_abs + 4).unwrap_or(0);
        match list_sig {
            0x686C | 0x666C => {
                // "lh" or "lf" — entries: count(2) + [offset(4) + hash(4)]...
                self.enum_lf_lh(list_abs)
            }
            0x6972 => {
                // "ri" — indirect: count(2) + [offset(4)]... each pointing to lf/lh
                let count = read_u16(&self.data, list_abs + 6).unwrap_or(0);
                let mut names = Vec::new();
                for i in 0..count.min(200) {
                    let sub_list_off = read_u32(&self.data, list_abs + 8 + (i as usize) * 4).unwrap_or(0);
                    let sub_abs = self.hive_data_start() + sub_list_off as usize;
                    if sub_abs + 6 <= self.data.len() {
                        let mut sub = self.enum_lf_lh(sub_abs);
                        names.append(&mut sub);
                    }
                }
                names
            }
            0x696C => {
                // "li" — direct list: count(2) + [offset(4)]...
                let count = read_u16(&self.data, list_abs + 6).unwrap_or(0);
                let mut names = Vec::new();
                for i in 0..count.min(200) {
                    let child_off = read_u32(&self.data, list_abs + 8 + (i as usize) * 4).unwrap_or(0);
                    let child_abs = self.hive_data_start() + child_off as usize;
                    if let Some(name) = self.nk_name(child_abs) {
                        names.push(name);
                    }
                }
                names
            }
            _ => Vec::new(),
        }
    }

    /// Get a specific value's data by name (case-insensitive).
    pub fn get_value(&self, key_offset: usize, name: &str) -> Option<HiveValue> {
        let name_lower = name.to_lowercase();
        self.enum_values(key_offset)
            .into_iter()
            .find(|v| v.name.to_lowercase() == name_lower)
    }

    // ─── Internal helpers ───

    fn hive_data_start(&self) -> usize {
        0x1000 // Base block is always 4096 bytes
    }

    /// Find a direct subkey of a given key by name (case-insensitive).
    pub fn find_subkey(&self, parent_offset: usize, name: &str) -> Option<usize> {
        let name_lower = name.to_lowercase();
        let nk_abs = self.hive_data_start() + parent_offset;
        if nk_abs + 0x50 > self.data.len() {
            return None;
        }
        let num_subkeys = read_u32(&self.data, nk_abs + 0x14).unwrap_or(0);
        let subkeys_list_off = read_u32(&self.data, nk_abs + 0x1C).unwrap_or(0);
        if num_subkeys == 0 || subkeys_list_off == 0 {
            return None;
        }
        let list_abs = self.hive_data_start() + subkeys_list_off as usize;
        if list_abs + 6 > self.data.len() {
            return None;
        }
        let list_sig = read_u16(&self.data, list_abs + 4).unwrap_or(0);
        match list_sig {
            0x686C | 0x666C => {
                // lh/lf
                let count = read_u16(&self.data, list_abs + 6).unwrap_or(0);
                for i in 0..count.min(200) {
                    let child_off = read_u32(&self.data, list_abs + 8 + (i as usize) * 8).unwrap_or(0);
                    let child_abs = self.hive_data_start() + child_off as usize;
                    if let Some(child_name) = self.nk_name(child_abs) {
                        if child_name.to_lowercase() == name_lower {
                            return Some(child_off as usize);
                        }
                    }
                }
                None
            }
            0x6972 => {
                // ri — indirect
                let count = read_u16(&self.data, list_abs + 6).unwrap_or(0);
                for i in 0..count.min(200) {
                    let sub_list_off = read_u32(&self.data, list_abs + 8 + (i as usize) * 4).unwrap_or(0);
                    let sub_abs = self.hive_data_start() + sub_list_off as usize;
                    if sub_abs + 6 <= self.data.len() {
                        if let Some(off) = self.find_subkey_in_lf_lh(sub_abs, name_lower.as_str()) {
                            return Some(off);
                        }
                    }
                }
                None
            }
            0x696C => {
                // li
                let count = read_u16(&self.data, list_abs + 6).unwrap_or(0);
                for i in 0..count.min(200) {
                    let child_off = read_u32(&self.data, list_abs + 8 + (i as usize) * 4).unwrap_or(0);
                    let child_abs = self.hive_data_start() + child_off as usize;
                    if let Some(child_name) = self.nk_name(child_abs) {
                        if child_name.to_lowercase() == name_lower {
                            return Some(child_off as usize);
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn find_subkey_in_lf_lh(&self, list_abs: usize, name_lower: &str) -> Option<usize> {
        let count = read_u16(&self.data, list_abs + 6).unwrap_or(0);
        for i in 0..count.min(200) {
            let child_off = read_u32(&self.data, list_abs + 8 + (i as usize) * 8).unwrap_or(0);
            let child_abs = self.hive_data_start() + child_off as usize;
            if let Some(child_name) = self.nk_name(child_abs) {
                if child_name.to_lowercase() == name_lower {
                    return Some(child_off as usize);
                }
            }
        }
        None
    }

    fn enum_lf_lh(&self, list_abs: usize) -> Vec<String> {
        let count = read_u16(&self.data, list_abs + 6).unwrap_or(0);
        let mut names = Vec::new();
        for i in 0..count.min(200) {
            let child_off = read_u32(&self.data, list_abs + 8 + (i as usize) * 8).unwrap_or(0);
            let child_abs = self.hive_data_start() + child_off as usize;
            if let Some(name) = self.nk_name(child_abs) {
                names.push(name);
            }
        }
        names
    }

    fn nk_name(&self, cell_abs: usize) -> Option<String> {
        if cell_abs + 0x50 > self.data.len() {
            return None;
        }
        let sig = read_u16(&self.data, cell_abs)?;
        if sig != NK_SIGNATURE {
            return None;
        }
        let name_size = read_u16(&self.data, cell_abs + 0x48).unwrap_or(0);
        if name_size == 0 {
            return Some(String::new());
        }
        let flags = read_u16(&self.data, cell_abs + 0x02).unwrap_or(0);
        let name_start = cell_abs + 0x50;
        if name_start + name_size as usize > self.data.len() {
            return None;
        }
        let raw = &self.data[name_start..name_start + name_size as usize];
        if flags & 0x20 != 0 {
            // KEY_COMP_NAME — ASCII
            Some(String::from_utf8_lossy(raw).to_string())
        } else {
            // UTF-16LE
            let units: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Some(String::from_utf16_lossy(&units))
        }
    }

    fn parse_vk(&self, cell_abs: usize) -> Option<HiveValue> {
        if cell_abs + 0x18 > self.data.len() {
            return None;
        }
        let sig = read_u16(&self.data, cell_abs)?;
        if sig != VK_SIGNATURE {
            return None;
        }
        let name_size = read_u16(&self.data, cell_abs + 0x02).unwrap_or(0);
        let data_size_raw = read_u32(&self.data, cell_abs + 0x04).unwrap_or(0);
        let data_off = read_u32(&self.data, cell_abs + 0x08).unwrap_or(0);
        let data_type = read_u32(&self.data, cell_abs + 0x0C).unwrap_or(0);
        let flags = read_u16(&self.data, cell_abs + 0x10).unwrap_or(0);

        // Value name
        let name = if name_size == 0 {
            String::from("(Default)")
        } else {
            let name_start = cell_abs + 0x18;
            if name_start + name_size as usize > self.data.len() {
                String::new()
            } else {
                let raw = &self.data[name_start..name_start + name_size as usize];
                if flags & 0x01 != 0 {
                    String::from_utf8_lossy(raw).to_string()
                } else {
                    let units: Vec<u16> = raw
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    String::from_utf16_lossy(&units)
                }
            }
        };

        // Data
        let is_resident = data_size_raw & 0x8000_0000 != 0;
        let data = if is_resident {
            // Data stored in the offset field itself (up to 4 bytes)
            let size = (data_size_raw & 0x7FFF_FFFF) as usize;
            let mut d = vec![0u8; size.min(4)];
            let bytes = data_off.to_le_bytes();
            for i in 0..size.min(4) {
                d[i] = bytes[i];
            }
            d
        } else {
            let size = data_size_raw as usize;
            if size == 0 || size > 0x0100_0000 {
                // Skip huge or zero data
                Vec::new()
            } else {
                let data_abs = self.hive_data_start() + data_off as usize + 4; // skip cell size
                if data_abs + size <= self.data.len() {
                    self.data[data_abs..data_abs + size].to_vec()
                } else {
                    Vec::new()
                }
            }
        };

        Some(HiveValue {
            name,
            value_type: data_type,
            data,
        })
    }
}

/// Helper: extract a string value (REG_SZ or REG_EXPAND_SZ) from a HiveValue.
pub fn value_to_string(v: &HiveValue) -> String {
    if v.data.len() < 2 {
        return String::new();
    }
    // Registry strings are UTF-16LE, possibly null-terminated
    let units: Vec<u16> = v
        .data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Helper: extract a DWORD value.
pub fn value_to_dword(v: &HiveValue) -> Option<u32> {
    if v.data.len() >= 4 {
        Some(u32::from_le_bytes([v.data[0], v.data[1], v.data[2], v.data[3]]))
    } else {
        None
    }
}

/// Helper: extract a QWORD value.
pub fn value_to_qword(v: &HiveValue) -> Option<u64> {
    if v.data.len() >= 8 {
        Some(read_u64(&v.data, 0)?)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reject_small() {
        assert!(HiveFile::from_bytes(vec![0u8; 100]).is_err());
    }

    #[test]
    fn test_reject_bad_sig() {
        let mut data = vec![0u8; 0x1000];
        assert!(HiveFile::from_bytes(data).is_err());
    }
}
