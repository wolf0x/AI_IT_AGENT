//! USN Journal (Change Journal) analysis tool — native Rust implementation.
//!
//! Uses DeviceIoControl with FSCTL_READ_USN_JOURNAL for kernel-level ReasonMask
//! filtering, and Rust-side timestamp filtering with early termination.
//! No PowerShell/fsutil dependency. Constant memory (~64KB buffer per read).
//!
//! Actions:
//! - `query`: Read journal entries with reason/time/path filters (source-filtered)
//! - `stats`: Journal metadata (size, USN range, entry count estimate)
//! - `config`: Journal configuration via FSCTL_QUERY_USN_JOURNAL

use async_trait::async_trait;
use serde_json::{json, Value};
use std::mem;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct IrUsnTool;

// ============================================================
// Windows API constants and structures (stable ABI)
// ============================================================

const GENERIC_READ: u32 = 0x8000_0000;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_SHARE_WRITE: u32 = 0x2;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const INVALID_HANDLE_VALUE: isize = -1;

const FSCTL_QUERY_USN_JOURNAL: u32 = 0x0009_00F4;
const FSCTL_READ_USN_JOURNAL: u32 = 0x0009_00BB;

// USN reason codes
const USN_REASON_DATA_OVERWRITE: u32 = 0x0000_0001;
const USN_REASON_DATA_EXTEND: u32 = 0x0000_0002;
const USN_REASON_DATA_TRUNCATION: u32 = 0x0000_0004;
const USN_REASON_FILE_CREATE: u32 = 0x0000_0100;
const USN_REASON_FILE_DELETE: u32 = 0x0000_8000;
const USN_REASON_RENAME_OLD_NAME: u32 = 0x0000_1000;
const USN_REASON_RENAME_NEW_NAME: u32 = 0x0000_2000;
const USN_REASON_SECURITY_CHANGE: u32 = 0x0008_0000;
const USN_REASON_CLOSE: u32 = 0x8000_0000;

#[repr(C)]
#[derive(Clone, Copy)]
struct UsnJournalDataV0 {
    usn_journal_id: i64,
    first_usn: i64,
    next_usn: i64,
    lowest_valid_usn: i64,
    max_usn: i64,
    maximum_size: i64,
    allocation_delta: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ReadUsnJournalDataV0 {
    start_usn: i64,
    reason_mask: u32,
    return_only_on_close: u32,
    timeout: i64,
    bytes_to_wait_for: i64,
    usn_journal_id: i64,
}

#[repr(C)]
struct UsnRecordV2 {
    record_length: u32,
    major_version: u16,
    minor_version: u16,
    file_reference_number: u64,
    parent_file_reference_number: u64,
    usn: i64,
    time_stamp: i64, // FILETIME
    reason: u32,
    source_info: u32,
    security_id: u32,
    file_attributes: u32,
    file_name_length: u16,
    file_name_offset: u16,
    // file_name follows (WCHAR[])
}

// ============================================================
// FFI declarations
// ============================================================

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *const (),
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: isize,
    ) -> isize;

    fn DeviceIoControl(
        hDevice: isize,
        dwIoControlCode: u32,
        lpInBuffer: *const (),
        nInBufferSize: u32,
        lpOutBuffer: *mut u8,
        nOutBufferSize: u32,
        lpBytesReturned: *mut u32,
        lpOverlapped: *const (),
    ) -> i32;

    fn CloseHandle(hObject: isize) -> i32;

    fn GetCurrentProcess() -> isize;

    fn OpenProcessToken(
        hProcess: isize,
        dwDesiredAccess: u32,
        phToken: *mut isize,
    ) -> i32;

    fn LookupPrivilegeValueW(
        lpSystemName: *const (),
        lpName: *const u16,
        lpLuid: *mut i64,
    ) -> i32;

    fn AdjustTokenPrivileges(
        hToken: isize,
        bDisableAllPrivileges: i32,
        pNewState: *const TokenPrivileges,
        cbBufferLength: u32,
        pPreviousState: *const (),
        pReturnLength: *const (),
    ) -> i32;
}

#[repr(C)]
struct TokenPrivileges {
    privilege_count: u32,
    luid: i64,
    attributes: u32,
}

const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
const TOKEN_QUERY: u32 = 0x0008;
const SE_PRIVILEGE_ENABLED: u32 = 0x0002;

/// Enable SE_MANAGE_VOLUME_NAME on the current process token.
/// Required for FSCTL_READ_USN_JOURNAL on non-elevated admin tokens.
fn enable_manage_volume_privilege() {
    unsafe {
        let mut token: isize = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 {
            return;
        }
        let priv_name: Vec<u16> = "SeManageVolumePrivilege".encode_utf16().chain(std::iter::once(0)).collect();
        let mut luid: i64 = 0;
        if LookupPrivilegeValueW(std::ptr::null(), priv_name.as_ptr(), &mut luid) == 0 {
            CloseHandle(token);
            return;
        }
        let tp = TokenPrivileges {
            privilege_count: 1,
            luid,
            attributes: SE_PRIVILEGE_ENABLED,
        };
        AdjustTokenPrivileges(token, 0, &tp, mem::size_of::<TokenPrivileges>() as u32, std::ptr::null(), std::ptr::null());
        CloseHandle(token);
    }
}

// ============================================================
// Tool implementation
// ============================================================

#[async_trait]
impl Tool for IrUsnTool {
    fn name(&self) -> &str { "ir_usn" }
    fn description(&self) -> &str {
        "NTFS USN Journal analysis (native, zero-overhead). \
         Actions: 'query' (filtered journal read — reason mask applied at kernel level, \
         time filter with early stop), 'stats' (journal metadata), 'config' (journal settings). \
         Reads USN records via FSCTL_READ_USN_JOURNAL with constant 64KB memory. \
         Supports reason filters: create, delete, modify, rename, security, all."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["query", "stats", "config"],
                    "description": "Operation to perform"
                },
                "volume": {
                    "type": "string",
                    "description": "Volume drive letter (default 'C:')"
                },
                "hours_ago": {
                    "type": "integer",
                    "description": "Time window in hours (default 24). Records older than this are skipped."
                },
                "reason_filter": {
                    "type": "string",
                    "enum": ["all", "create", "delete", "modify", "rename", "security"],
                    "description": "Filter by change reason (kernel-level). Default 'all'."
                },
                "path_filter": {
                    "type": "string",
                    "description": "Substring match on filename (Rust-side filter)"
                },
                "max_entries": {
                    "type": "integer",
                    "description": "Max records to return (default 100, max 500)"
                }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let action = args["action"].as_str().unwrap_or("query").to_string();
        let volume = args["volume"].as_str().unwrap_or("C:").to_string();
        let hours_ago = args["hours_ago"].as_u64().unwrap_or(24);
        let reason_filter = args["reason_filter"].as_str().unwrap_or("all").to_string();
        let path_filter = args["path_filter"].as_str().unwrap_or("").to_string();
        let max_entries = args["max_entries"].as_u64().unwrap_or(100).min(500) as usize;

        // Try native FFI first (fastest, constant memory)
        let native_args = (action.clone(), volume.clone(), hours_ago, reason_filter.clone(), path_filter.clone(), max_entries);
        let native_result = tokio::task::spawn_blocking(move || {
            match native_args.0.as_str() {
                "query" => usn_query(&native_args.1, native_args.2, &native_args.3, &native_args.4, native_args.5),
                "stats" | "config" => usn_stats(&native_args.1),
                _ => Err(format!("Unknown action: {}", native_args.0)),
            }
        })
        .await
        .map_err(|e| format!("spawn_blocking failed: {}", e))?;

        match native_result {
            Ok(v) => Ok(v),
            Err(e) => {
                // Fallback to PowerShell if native fails (typically permission)
                let ps_script = ps_fallback_script(&action, &volume, hours_ago, &reason_filter, &path_filter, max_entries);
                let full = format!("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; {}", ps_script);
                let mut cmd = tokio::process::Command::new("powershell.exe");
                cmd.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &full]);
                cmd.creation_flags(0x08000000);
                cmd.kill_on_drop(true);
                cmd.stdout(std::process::Stdio::piped());
                cmd.stderr(std::process::Stdio::piped());

                let output = tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    cmd.output(),
                )
                .await
                .map_err(|_| "USN PowerShell fallback timed out (60s)".to_string())?
                .map_err(|e| format!("PowerShell exec failed: {}", e))?;

                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.trim().is_empty() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Ok(json!({
                        "success": false,
                        "error": format!("Native: {}. PowerShell: {}", e, stderr.trim()),
                        "hint": "Run RustAgent as Administrator (elevated) for direct USN access."
                    }));
                }
                match serde_json::from_str::<Value>(stdout.trim()) {
                    Ok(v) => Ok(v),
                    Err(_) => Ok(json!({"success": true, "output": stdout.trim(), "note": "PowerShell fallback (native unavailable)"})),
                }
            }
        }
    }
}

/// Generate optimized PowerShell fallback script (streaming, filtered, early-stop).
fn ps_fallback_script(
    action: &str, volume: &str, hours_ago: u64,
    reason_filter: &str, path_filter: &str, max_entries: usize,
) -> String {
    let vol = volume.trim_end_matches(':');

    if action == "stats" || action == "config" {
        return format!(
            r#"fsutil usn queryjournal {vol}: 2>&1 | ForEach-Object {{ $_.ToString() }} | ConvertTo-Json"#
        );
    }

    // Reason code hex for PowerShell filter
    let reason_check = match reason_filter {
        "create" => "0x100",
        "delete" => "0x8000",
        "modify" => "0x7",
        "rename" => "0x3000",
        "security" => "0x80000",
        _ => "0",
    };

    let path_clause = if path_filter.is_empty() {
        String::new()
    } else {
        format!(r#"if ($fname -notlike '*{}*') {{ return }}"#, path_filter.replace('\'', "''"))
    };

    format!(
        r#"
$cutoff = (Get-Date).AddHours(-{hours_ago})
$entries = @()
$scanned = 0
fsutil usn readjournal {vol}: csv 2>&1 | ForEach-Object {{
    if ($entries.Count -ge {max_entries}) {{ return }}
    $line = $_.ToString().Trim()
    if (-not $line -or $line -match '^Usn Journal|^Volume') {{ return }}
    $parts = $line -split ','
    if ($parts.Count -lt 4) {{ return }}
    $scanned++
    $fname = $parts[0].Trim()
    $reasonHex = $parts[1].Trim()
    $usn = $parts[2].Trim()
    {path_clause}
    $rc = 0
    try {{ $rc = [Convert]::ToInt32($reasonHex, 16) }} catch {{}}
    if ({reason_check} -ne 0 -and ($rc -band {reason_check}) -eq 0) {{ return }}
    $reason = if ($rc -band 0x100) {{'CREATE'}} elseif ($rc -band 0x8000) {{'DELETE'}} elseif ($rc -band 0x2000) {{'RENAME'}} elseif ($rc -band 0x1) {{'WRITE'}} elseif ($rc -band 0x80000) {{'SECURITY'}} else {{'OTHER'}}
    $entries += @{{file=$fname; reason=$reason; usn=$usn}}
}}
@{{success=$true; volume='{vol}:'; filter=@{{reason='{reason_filter}'; hours_ago={hours_ago}; path='{path_filter}'}}; returned=$entries.Count; scanned=$scanned; entries=$entries; note='PowerShell fallback'}} | ConvertTo-Json -Depth 3 -Compress
"#
    )
}

// ============================================================
// Core logic
// ============================================================

fn open_volume(volume: &str) -> Result<isize, String> {
    enable_manage_volume_privilege();
    let path = format!("\\\\.\\{}", volume.trim_end_matches(':'));
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(format!("Cannot open volume {} (need Administrator)", volume));
    }
    Ok(handle)
}

fn query_journal(handle: isize) -> Result<UsnJournalDataV0, String> {
    let mut out = UsnJournalDataV0 {
        usn_journal_id: 0, first_usn: 0, next_usn: 0,
        lowest_valid_usn: 0, max_usn: 0, maximum_size: 0, allocation_delta: 0,
    };
    let mut returned: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(
            handle, FSCTL_QUERY_USN_JOURNAL,
            std::ptr::null(), 0,
            &mut out as *mut _ as *mut u8,
            mem::size_of::<UsnJournalDataV0>() as u32,
            &mut returned, std::ptr::null(),
        )
    };
    if ok == 0 {
        return Err("FSCTL_QUERY_USN_JOURNAL failed (journal may not exist on this volume)".into());
    }
    Ok(out)
}

fn reason_mask(filter: &str) -> u32 {
    match filter {
        "create" => USN_REASON_FILE_CREATE,
        "delete" => USN_REASON_FILE_DELETE,
        "modify" => USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_EXTEND | USN_REASON_DATA_TRUNCATION,
        "rename" => USN_REASON_RENAME_OLD_NAME | USN_REASON_RENAME_NEW_NAME,
        "security" => USN_REASON_SECURITY_CHANGE,
        _ => 0xFFFF_FFFF, // all reasons
    }
}

fn reason_to_str(reason: u32) -> &'static str {
    if reason & USN_REASON_FILE_CREATE != 0 { "CREATE" }
    else if reason & USN_REASON_FILE_DELETE != 0 { "DELETE" }
    else if reason & USN_REASON_RENAME_NEW_NAME != 0 { "RENAME" }
    else if reason & USN_REASON_RENAME_OLD_NAME != 0 { "RENAME_OLD" }
    else if reason & USN_REASON_DATA_OVERWRITE != 0 { "WRITE" }
    else if reason & USN_REASON_DATA_EXTEND != 0 { "EXTEND" }
    else if reason & USN_REASON_SECURITY_CHANGE != 0 { "SECURITY" }
    else if reason & USN_REASON_CLOSE != 0 { "CLOSE" }
    else { "OTHER" }
}

/// FILETIME (100ns since 1601-01-01) → Unix seconds
fn filetime_to_unix(ft: i64) -> i64 {
    ft / 10_000_000 - 11_644_473_600
}

/// Binary search for the USN closest to (but before) cutoff_ft.
/// Uses ALL-reason probes to read timestamps at arbitrary USN positions.
/// Returns the USN to start the filtered read from.
fn seek_to_time(handle: isize, journal: &UsnJournalDataV0, cutoff_ft: i64) -> i64 {
    let mut lo = journal.first_usn;
    let mut hi = journal.next_usn;
    let mut probe_buf = [0u8; 4096]; // small buffer for single-record probes

    // ~23 iterations converges a 10M USN range
    for _ in 0..24 {
        if hi - lo < 4096 { break; } // close enough (USN granularity)
        let mid = lo + (hi - lo) / 2;

        let input = ReadUsnJournalDataV0 {
            start_usn: mid,
            reason_mask: 0xFFFF_FFFF, // probe with ALL reasons
            return_only_on_close: 0,
            timeout: 0,
            bytes_to_wait_for: 0,
            usn_journal_id: journal.usn_journal_id,
        };

        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle, FSCTL_READ_USN_JOURNAL,
                &input as *const _ as *const (),
                mem::size_of::<ReadUsnJournalDataV0>() as u32,
                probe_buf.as_mut_ptr(), probe_buf.len() as u32,
                &mut returned, std::ptr::null(),
            )
        };

        if ok == 0 || returned < 8 + mem::size_of::<UsnRecordV2>() as u32 {
            // No records at this position → search lower
            hi = mid;
            continue;
        }

        // Read first record's timestamp
        let rec = unsafe { &*(probe_buf.as_ptr().add(8) as *const UsnRecordV2) };
        if rec.record_length < mem::size_of::<UsnRecordV2>() as u32 {
            hi = mid;
            continue;
        }

        if rec.time_stamp < cutoff_ft {
            lo = mid; // record is too old, search upper half
        } else {
            hi = mid; // record is within window, search lower half
        }
    }

    lo
}

fn usn_query(
    volume: &str,
    hours_ago: u64,
    reason_filter: &str,
    path_filter: &str,
    max_entries: usize,
) -> Result<Value, String> {
    let handle = open_volume(volume)?;
    let journal = query_journal(handle)?;

    let mask = reason_mask(reason_filter);
    let cutoff_unix = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        now - (hours_ago as i64) * 3600
    };
    // Convert cutoff to FILETIME for comparison
    let cutoff_ft = (cutoff_unix + 11_644_473_600) * 10_000_000;

    let mut entries: Vec<Value> = Vec::new();
    let mut total_scanned: u64 = 0;
    // Binary search to skip directly to the time window (O(log N) probes)
    let mut current_usn = seek_to_time(handle, &journal, cutoff_ft);
    let buf_size: u32 = 65536; // 64KB read buffer
    let mut buf: Vec<u8> = vec![0u8; buf_size as usize];

    loop {
        if entries.len() >= max_entries { break; }
        if current_usn >= journal.next_usn { break; }

        let input = ReadUsnJournalDataV0 {
            start_usn: current_usn,
            reason_mask: mask, // kernel-level filter
            return_only_on_close: 0,
            timeout: 0,
            bytes_to_wait_for: 0,
            usn_journal_id: journal.usn_journal_id,
        };

        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle, FSCTL_READ_USN_JOURNAL,
                &input as *const _ as *const (),
                mem::size_of::<ReadUsnJournalDataV0>() as u32,
                buf.as_mut_ptr(), buf_size,
                &mut returned, std::ptr::null(),
            )
        };

        if ok == 0 || returned < 8 { break; }

        // First 8 bytes = next USN to read from
        let next_usn = i64::from_le_bytes(buf[0..8].try_into().unwrap());
        let mut offset: usize = 8;

        while offset + mem::size_of::<UsnRecordV2>() <= returned as usize {
            let rec = unsafe { &*(buf.as_ptr().add(offset) as *const UsnRecordV2) };
            if rec.record_length < mem::size_of::<UsnRecordV2>() as u32 { break; }
            if rec.major_version != 2 { offset += rec.record_length as usize; continue; }

            total_scanned += 1;

            // Time filter: skip records older than cutoff
            if rec.time_stamp < cutoff_ft {
                offset += rec.record_length as usize;
                continue;
            }

            // Extract filename
            let name_offset = rec.file_name_offset as usize;
            let name_len = rec.file_name_length as usize;
            let name_start = offset + name_offset;
            let filename = if name_start + name_len <= returned as usize {
                let wide: &[u16] = unsafe {
                    std::slice::from_raw_parts(
                        buf.as_ptr().add(name_start) as *const u16,
                        name_len / 2,
                    )
                };
                String::from_utf16_lossy(wide)
            } else {
                String::from("?")
            };

            // Path filter (Rust-side)
            if !path_filter.is_empty()
                && !filename.to_lowercase().contains(&path_filter.to_lowercase())
            {
                offset += rec.record_length as usize;
                continue;
            }

            let ts_unix = filetime_to_unix(rec.time_stamp);
            entries.push(json!({
                "file": if filename.len() > 80 { &filename[..80] } else { &filename },
                "reason": reason_to_str(rec.reason),
                "time": ts_unix,
                "usn": rec.usn,
            }));

            offset += rec.record_length as usize;
            if entries.len() >= max_entries { break; }
        }

        current_usn = next_usn;
        if next_usn <= current_usn && next_usn == input.start_usn { break; } // safety: no progress
    }

    unsafe { CloseHandle(handle); }

    Ok(json!({
        "success": true,
        "volume": volume,
        "filter": { "reason": reason_filter, "hours_ago": hours_ago, "path": path_filter },
        "returned": entries.len(),
        "scanned": total_scanned,
        "entries": entries,
    }))
}

fn usn_stats(volume: &str) -> Result<Value, String> {
    let handle = open_volume(volume)?;
    let j = query_journal(handle)?;
    unsafe { CloseHandle(handle); }

    Ok(json!({
        "success": true,
        "volume": volume,
        "journal_id": j.usn_journal_id,
        "first_usn": j.first_usn,
        "next_usn": j.next_usn,
        "max_usn": j.max_usn,
        "maximum_size_mb": j.maximum_size / (1024 * 1024),
        "allocation_delta_mb": j.allocation_delta / (1024 * 1024),
        "note": "Use 'query' action with reason_filter for filtered record reading.",
    }))
}
