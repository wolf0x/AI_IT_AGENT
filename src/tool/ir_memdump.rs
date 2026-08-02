//! Process memory dump tool for forensic analysis.
//!
//! Actions:
//! - `list`: Enumerate running processes with PID, name, memory size, and architecture
//! - `dump`: Create a memory dump of a target process (mini/full/withheap)
//!
//! Uses Windows dbghelp.dll MiniDumpWriteDump API via PowerShell P/Invoke.

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct IrMemdumpTool;

const PS_PREFIX: &str = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ";
const DUMP_TIMEOUT_SECS: u64 = 120;

#[async_trait]
impl Tool for IrMemdumpTool {
    fn name(&self) -> &str { "ir_memdump" }
    fn description(&self) -> &str {
        "Process memory dump for forensic analysis. \
         Actions: 'list' (enumerate dumpable processes with PID/memory/arch), \
         'dump' (create memory dump file via MiniDumpWriteDump). \
         Dump types: 'mini' (threads+stacks, ~small), 'full' (all accessible memory), \
         'withheap' (full + heap details). Output is a .dmp file compatible with \
         WinDbg/Volatility. Requires SeDebugPrivilege for system/other-user processes."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { false }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "dump"],
                    "description": "Operation: 'list' processes or 'dump' a specific process"
                },
                "pid": {
                    "type": "integer",
                    "description": "Target process ID for 'dump' action"
                },
                "output_path": {
                    "type": "string",
                    "description": "Output .dmp file path. Default: workspace/output/<name>_<pid>.dmp"
                },
                "dump_type": {
                    "type": "string",
                    "enum": ["mini", "full", "withheap"],
                    "description": "Dump type: 'mini' (default, small), 'full' (all memory), 'withheap' (full+heap)"
                },
                "name_filter": {
                    "type": "string",
                    "description": "Filter process list by name substring (for 'list' action)"
                }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value> {
        let action = args["action"].as_str().unwrap_or("list");

        let script = match action {
            "list" => script_list(&args),
            "dump" => script_dump(&args, ctx)?,
            _ => return Ok(json!({"error": format!("Unknown action: {}", action)})),
        };

        let full_script = format!("{}{}", PS_PREFIX, script);

        let mut cmd = Command::new("powershell.exe");
        cmd.args(["-NoProfile", "-NonInteractive", "-Command", &full_script]);
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        cmd.kill_on_drop(true);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let output = tokio::time::timeout(
            std::time::Duration::from_secs(DUMP_TIMEOUT_SECS),
            cmd.output(),
        )
        .await
        .map_err(|_| format!("memdump command timed out after {}s", DUMP_TIMEOUT_SECS))?
        .map_err(|e| format!("Failed to execute powershell: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            return Ok(json!({
                "success": false,
                "error": if stderr.is_empty() { &stdout } else { &stderr },
                "exit_code": output.status.code().unwrap_or(-1)
            }));
        }

        // Try to parse JSON output
        match serde_json::from_str::<Value>(&stdout) {
            Ok(v) => Ok(v),
            Err(_) => Ok(json!({ "success": true, "output": stdout.trim() })),
        }
    }
}

/// List running processes with forensic-relevant metadata.
fn script_list(args: &Value) -> String {
    let name_filter = args["name_filter"].as_str().unwrap_or("");

    let filter_clause = if name_filter.is_empty() {
        String::new()
    } else {
        format!(
            r#" | Where-Object {{ $_.ProcessName -like '*{}*' }}"#,
            name_filter.replace('\'', "''")
        )
    };

    format!(
        r#"
$procs = Get-Process{filter} | Select-Object Id, ProcessName, Path, WorkingSet64, StartTime, @{{N='Arch';E={{
    if ($_.Path) {{
        try {{
            $fs = [System.IO.File]::OpenRead($_.Path)
            $br = New-Object System.IO.BinaryReader($fs)
            $fs.Seek(0x3C, 'Begin') | Out-Null
            $peOffset = $br.ReadInt32()
            $fs.Seek($peOffset + 4, 'Begin') | Out-Null
            $machine = $br.ReadUInt16()
            $br.Close(); $fs.Close()
            if ($machine -eq 0x8664) {{ 'x64' }} elseif ($machine -eq 0x14c) {{ 'x86' }} elseif ($machine -eq 0xAA64) {{ 'ARM64' }} else {{ "0x$($machine.ToString('X4'))" }}
        }} catch {{ 'unknown' }}
    }} else {{ 'N/A' }}
}}}} | Sort-Object WorkingSet64 -Descending

$result = @{{
    success = $true
    count = $procs.Count
    processes = @($procs | ForEach-Object {{
        @{{
            pid = $_.Id
            name = $_.ProcessName
            path = $_.Path
            memory_mb = [math]::Round($_.WorkingSet64 / 1MB, 1)
            arch = $_.Arch
            start_time = if ($_.StartTime) {{ $_.StartTime.ToString('yyyy-MM-dd HH:mm:ss') }} else {{ $null }}
        }}
    }})
}}
$result | ConvertTo-Json -Depth 4 -Compress
"#,
        filter = filter_clause
    )
}

/// Create a process memory dump using MiniDumpWriteDump.
fn script_dump(args: &Value, ctx: &ToolContext) -> Result<String, String> {
    let pid = args["pid"]
        .as_u64()
        .ok_or("Parameter 'pid' is required for dump action")?;

    let dump_type = args["dump_type"].as_str().unwrap_or("mini");

    // Determine output path
    let output_path = if let Some(p) = args["output_path"].as_str() {
        p.to_string()
    } else {
        format!(r"{}\output\proc_{}.dmp", ctx.workspace_dir, pid)
    };

    // MiniDumpWriteDump flags:
    // MiniDumpNormal = 0x00000000
    // MiniDumpWithFullMemory = 0x00000002
    // MiniDumpWithFullMemoryInfo = 0x00000800
    // MiniDumpWithHandleData = 0x00000004
    // MiniDumpWithUnloadedModules = 0x00000020
    // MiniDumpWithThreadInfo = 0x00001000
    let dump_flags = match dump_type {
        "mini" => "0x00000000", // MiniDumpNormal
        "full" => "0x00001826", // FullMemory + FullMemoryInfo + HandleData + UnloadedModules + ThreadInfo
        "withheap" => "0x00001826 | 0x00000001", // + MiniDumpWithDataSegs (heap segments)
        _ => "0x00000000",
    };

    Ok(format!(
        r#"
# Enable SeDebugPrivilege
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class DbgHelp {{
    [DllImport("dbghelp.dll", SetLastError = true)]
    public static extern bool MiniDumpWriteDump(
        IntPtr hProcess, uint ProcessId, IntPtr hFile,
        uint DumpType, IntPtr ExceptionParam,
        IntPtr UserStreamParam, IntPtr CallbackParam);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
}}
'@ -ErrorAction SilentlyContinue

# Enable debug privilege
try {{
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
        # Try to enable SeDebugPrivilege via token manipulation
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class TokenOps {{
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr h, uint d, out IntPtr t);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupPrivilegeValue(string s, string n, ref long l);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr t, bool d, ref TOKEN_PRIVILEGES n, uint l, IntPtr p, IntPtr r);
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {{
        public uint PrivilegeCount;
        public long Luid;
        public uint Attributes;
    }}
    public static void EnableDebug() {{
        IntPtr token;
        OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, 0x28, out token);
        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.PrivilegeCount = 1;
        tp.Attributes = 0x2; // SE_PRIVILEGE_ENABLED
        LookupPrivilegeValue(null, "SeDebugPrivilege", ref tp.Luid);
        AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }}
}}
'@ -ErrorAction SilentlyContinue
        [TokenOps]::EnableDebug()
    }}
}} catch {{}}

$targetPid = {pid}
$outPath = '{output_path}'

# Validate process exists
$proc = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
if (-not $proc) {{
    @{{ success = $false; error = "Process PID $targetPid not found" }} | ConvertTo-Json -Compress
    exit
}}

# Ensure output directory exists
$outDir = Split-Path $outPath -Parent
if (-not (Test-Path $outDir)) {{ New-Item -ItemType Directory -Path $outDir -Force | Out-Null }}

# Open process handle (PROCESS_ALL_ACCESS = 0x1F0FFF)
$hProcess = [DbgHelp]::OpenProcess(0x1F0FFF, $false, $targetPid)
if ($hProcess -eq [IntPtr]::Zero) {{
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    @{{ success = $false; error = "OpenProcess failed (Win32 error $err). May need admin/SeDebugPrivilege."; pid = $targetPid; process_name = $proc.ProcessName }} | ConvertTo-Json -Compress
    exit
}}

# Create dump file
$hFile = [System.IO.File]::Create($outPath).SafeFileHandle.DangerousGetHandle()
$dumpType = [uint32]({dump_flags})

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$success = [DbgHelp]::MiniDumpWriteDump($hProcess, $targetPid, $hFile, $dumpType, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
$sw.Stop()

[System.IO.File]::WriteAllBytes($outPath, [System.IO.File]::ReadAllBytes($outPath)) # flush
# Close handles properly
try {{ [System.IO.File]::OpenWrite($outPath).Close() }} catch {{}}
[DbgHelp]::CloseHandle($hProcess) | Out-Null

if ($success) {{
    $fileInfo = Get-Item $outPath
    @{{
        success = $true
        pid = $targetPid
        process_name = $proc.ProcessName
        dump_type = '{dump_type}'
        output_path = $outPath
        file_size_mb = [math]::Round($fileInfo.Length / 1MB, 2)
        elapsed_seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        note = "Dump created. Analyze with WinDbg or Volatility (windows.memdump / windows.malfind)."
    }} | ConvertTo-Json -Compress
}} else {{
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    # Clean up failed dump
    if (Test-Path $outPath) {{ Remove-Item $outPath -Force -ErrorAction SilentlyContinue }}
    @{{ success = $false; error = "MiniDumpWriteDump failed (Win32 error $err)"; pid = $targetPid; process_name = $proc.ProcessName }} | ConvertTo-Json -Compress
}}
"#,
        pid = pid,
        output_path = output_path.replace('\'', "\\\\"),
        dump_type = dump_type,
        dump_flags = dump_flags
    ))
}
