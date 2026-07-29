//! Process enumeration and management via Win32 Toolhelp32 APIs.
//! Pure Rust, Windows-only.

use serde_json::json;
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::ProcessStatus::*;
use windows::Win32::System::Threading::*;

/// Information about a running process.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub threads: u32,
    pub parent_pid: u32,
    pub memory_bytes: u64,
}

impl ProcessInfo {
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "pid": self.pid,
            "name": self.name,
            "threads": self.threads,
            "parent_pid": self.parent_pid,
            "memory_mb": format!("{:.1}", self.memory_bytes as f64 / 1_048_576.0),
        })
    }
}

/// List all running processes.
pub fn list_processes() -> Result<Vec<ProcessInfo>, String> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| format!("Failed to create process snapshot: {}", e))?;

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let mut processes = Vec::new();

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name_len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..name_len]);

                // Get memory usage via OpenProcess
                let memory = get_process_memory(entry.th32ProcessID);

                processes.push(ProcessInfo {
                    pid: entry.th32ProcessID,
                    name,
                    threads: entry.cntThreads,
                    parent_pid: entry.th32ParentProcessID,
                    memory_bytes: memory,
                });

                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
        Ok(processes)
    }
}

/// Get working set memory for a process (bytes). Returns 0 on failure.
unsafe fn get_process_memory(pid: u32) -> u64 {
    let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
    match handle {
        Ok(h) => {
            let mut counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
            counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            let ok = K32GetProcessMemoryInfo(h, &mut counters, counters.cb);
            let _ = CloseHandle(h);
            if ok.as_bool() {
                counters.WorkingSetSize as u64
            } else {
                0
            }
        }
        Err(_) => 0,
    }
}

/// Kill a process by PID.
pub fn kill_process_by_pid(pid: u32) -> Result<(), String> {
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid)
            .map_err(|e| format!("Cannot open process {}: {}", pid, e))?;

        let result = TerminateProcess(handle, 1);
        let _ = CloseHandle(handle);

        result.map_err(|e| format!("Failed to terminate process {}: {}", pid, e))
    }
}

/// Kill all processes matching a name (case-insensitive).
/// Returns the number of processes killed.
pub fn kill_process_by_name(name: &str) -> Result<u32, String> {
    let processes = list_processes()?;
    let lower = name.to_lowercase();
    let mut killed = 0u32;

    for proc in &processes {
        if proc.name.to_lowercase() == lower {
            if kill_process_by_pid(proc.pid).is_ok() {
                killed += 1;
            }
        }
    }

    if killed == 0 {
        Err(format!("No process found with name: '{}'", name))
    } else {
        Ok(killed)
    }
}
