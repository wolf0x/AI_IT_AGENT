//! Safe wrapper over Win32 Registry API for live system reads.
//!
//! Used by ShimCache and UserAssist parsers to read binary values
//! from the live registry without exporting hive files.

use serde::Serialize;
use windows::Win32::System::Registry::REG_VALUE_TYPE;

#[derive(Debug, Serialize)]
pub struct RegValue {
    pub name: String,
    pub value_type: u32,
    pub data: Vec<u8>,
}

/// Read a binary value from the registry.
pub fn read_binary_value(root: &str, subkey: &str, value_name: &str) -> Option<Vec<u8>> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER,
        HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY,
    };

    let hkey: HKEY = match root {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        _ => return None,
    };

    let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let value_wide: Vec<u16> = value_name.encode_utf16().chain(std::iter::once(0)).collect();

    let mut result_key = HKEY::default();
    // HKCU is not affected by WOW64 redirection
    let sam = if root == "HKLM" || root == "HKEY_LOCAL_MACHINE" {
        KEY_READ | KEY_WOW64_64KEY
    } else {
        KEY_READ
    };
    unsafe {
        let hr = RegOpenKeyExW(
            hkey,
            windows::core::PCWSTR(subkey_wide.as_ptr()),
            0,
            sam,
            &mut result_key,
        );
        if hr.is_err() {
            return None;
        }
        // First call: get data size
        let mut data_size: u32 = 0;
        let mut val_type = REG_VALUE_TYPE(0);
        let hr = RegQueryValueExW(
            result_key,
            windows::core::PCWSTR(value_wide.as_ptr()),
            None,
            Some(&mut val_type),
            None,
            Some(&mut data_size),
        );
        if hr.is_err() || data_size == 0 {
            let _ = RegCloseKey(result_key);
            return None;
        }
        // Second call: get data
        let mut buf = vec![0u8; data_size as usize];
        let hr = RegQueryValueExW(
            result_key,
            windows::core::PCWSTR(value_wide.as_ptr()),
            None,
            Some(&mut val_type),
            Some(buf.as_mut_ptr()),
            Some(&mut data_size),
        );
        let _ = RegCloseKey(result_key);
        if hr.is_err() {
            return None;
        }
        buf.truncate(data_size as usize);
        Some(buf)
    }
}

/// Enumerate all values under a registry key.
pub fn enum_values(root: &str, subkey: &str) -> Vec<RegValue> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER,
        HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY,
    };

    let hkey: HKEY = match root {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        _ => return Vec::new(),
    };
    // HKCU is not affected by WOW64 redirection; don't use KEY_WOW64_64KEY for it
    let sam = if root == "HKLM" || root == "HKEY_LOCAL_MACHINE" {
        KEY_READ | KEY_WOW64_64KEY
    } else {
        KEY_READ
    };

    let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let mut result_key = HKEY::default();

    unsafe {
        let hr = RegOpenKeyExW(
            hkey,
            windows::core::PCWSTR(subkey_wide.as_ptr()),
            0,
            sam,
            &mut result_key,
        );
        if hr.is_err() {
            return Vec::new();
        }
        let mut values = Vec::new();
        let mut index: u32 = 0;
        loop {
            // Use a large buffer for name + data in a single call
            let mut name_buf = vec![0u16; 16384];
            let mut name_len: u32 = name_buf.len() as u32;
            let mut val_type: u32 = 0;
            let mut data_buf = vec![0u8; 65536];
            let mut data_size: u32 = data_buf.len() as u32;
            let hr = RegEnumValueW(
                result_key,
                index,
                windows::core::PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                Some(&mut val_type as *mut u32),
                Some(data_buf.as_mut_ptr()),
                Some(&mut data_size),
            );
            if hr.is_err() {
                break;
            }
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            data_buf.truncate(data_size as usize);
            values.push(RegValue {
                name,
                value_type: val_type,
                data: data_buf,
            });
            index += 1;
        }
        let _ = RegCloseKey(result_key);
        values
    }
}

/// Enumerate all subkey names under a registry key.
pub fn enum_keys(root: &str, subkey: &str) -> Vec<String> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER,
        HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY,
    };

    let hkey: HKEY = match root {
        "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
        "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
        _ => return Vec::new(),
    };

    let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let mut result_key = HKEY::default();
    // HKCU is not affected by WOW64 redirection
    let sam = if root == "HKLM" || root == "HKEY_LOCAL_MACHINE" {
        KEY_READ | KEY_WOW64_64KEY
    } else {
        KEY_READ
    };

    unsafe {
        let hr = RegOpenKeyExW(
            hkey,
            windows::core::PCWSTR(subkey_wide.as_ptr()),
            0,
            sam,
            &mut result_key,
        );
        if hr.is_err() {
            return Vec::new();
        }
        let mut keys = Vec::new();
        let mut index: u32 = 0;
        loop {
            let mut name_buf = vec![0u16; 256];
            let mut name_len: u32 = name_buf.len() as u32;
            let hr = RegEnumKeyExW(
                result_key,
                index,
                windows::core::PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                windows::core::PWSTR::null(),
                None,
                None,
            );
            if hr.is_err() {
                break;
            }
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            keys.push(name);
            index += 1;
        }
        let _ = RegCloseKey(result_key);
        keys
    }
}
