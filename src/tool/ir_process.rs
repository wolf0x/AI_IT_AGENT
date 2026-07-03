use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct IrProcessTool;

const PS_PREFIX: &str = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ";

/// PowerShell script that enumerates processes with full details (JSON output).
const PROCESS_ENUM_SCRIPT: &str = r#"
$ErrorActionPreference='SilentlyContinue'
$gpMap=@{}
try {
  Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $name=[string]$_.ProcessName
    if($name -and $name -notmatch '\.exe$'){ $name=$name + '.exe' }
    $path=''; try { $path=[string]$_.Path } catch {}
    $start=''; try { if($_.StartTime){ $start=$_.StartTime.ToString('o') } } catch {}
    $cpu=0; try { if($_.CPU){ $cpu=[double]([math]::Round($_.CPU,2)) } } catch {}
    $mem=0; try { $mem=[double]([math]::Round($_.WorkingSet64/1MB,1)) } } catch {}
    $gpMap[[int]$_.Id]=[PSCustomObject]@{name=$name; path=$path; creationDate=$start; cpu=$cpu; memoryMB=$mem}
  }
} catch {}
$items=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
  $procId=[int]$_.ProcessId
  $gp=$gpMap[$procId]
  $name=[string]$_.Name
  $path=[string]$_.ExecutablePath
  $start=''
  if($_.CreationDate){ $start=$_.CreationDate.ToString('o') }
  $cpu=0; $mem=0
  if($gp){
    if(-not $name){ $name=[string]$gp.name }
    if(-not $path){ $path=[string]$gp.path }
    if(-not $start){ $start=[string]$gp.creationDate }
    $cpu=[double]$gp.cpu
    $mem=[double]$gp.memoryMB
  }
  [PSCustomObject]@{
    pid=$procId
    ppid=[int]$_.ParentProcessId
    name=$name
    path=$path
    commandLine=[string]$_.CommandLine
    creationDate=$start
    cpu=$cpu
    memoryMB=$mem
  }
})
@($items) | ConvertTo-Json -Depth 4 -Compress
"#;

#[async_trait]
impl Tool for IrProcessTool {
    fn name(&self) -> &str { "ir_process" }
    fn description(&self) -> &str {
        "Incident response process analysis. 'list' enumerates all processes with risk classification (high/medium/low/safe). 'kill' terminates a process by PID. Risk filter available via risk_filter parameter."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "enum": ["list", "kill"], "description": "Action: 'list' (default) enumerates processes, 'kill' terminates by PID" },
                "pid": { "type": "integer", "description": "Process ID to kill (required for kill action)" },
                "risk_filter": { "type": "string", "enum": ["all", "high", "medium", "low"], "description": "Filter by risk level (default 'all')" }
            }
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let action = args["action"].as_str().unwrap_or("list");
        match action {
            "list" => {
                let risk_filter = args["risk_filter"].as_str().unwrap_or("all");
                let script = format!("{}{}", PS_PREFIX, PROCESS_ENUM_SCRIPT);
                let raw = run_ps_raw(&script).await?;

                // Parse JSON array of processes
                let processes: Vec<Value> = match serde_json::from_str(raw.trim()) {
                    Ok(Value::Array(arr)) => arr,
                    Ok(single) => vec![single],
                    Err(_) => return Ok(json!({ "status": "ok", "raw": raw.trim(), "classified": [] })),
                };

                let mut classified = Vec::new();
                for proc in processes {
                    let mut risk_level = String::from("safe");
                    let mut risk_reasons: Vec<String> = Vec::new();

                    let name = proc["name"].as_str().unwrap_or("").to_lowercase();
                    let path = proc["path"].as_str().unwrap_or("").to_lowercase();
                    let cmdline = proc["command_line"].as_str().unwrap_or("").to_lowercase();
                    let cpu = proc["cpu"].as_f64().unwrap_or(0.0);
                    let mem = proc["memoryMB"].as_f64().unwrap_or(0.0);

                    // 1. Suspicious path (temp/appdata/downloads/public)
                    if !path.is_empty() && (
                        path.contains("\\temp\\") || path.contains("\\appdata\\") ||
                        path.contains("\\downloads\\") || path.contains("\\users\\public\\")
                    ) {
                        risk_reasons.push("executable in suspicious directory".into());
                        risk_level = "medium".into();
                    }

                    // 2. ProgramData executable
                    if !path.is_empty() && path.contains("\\programdata\\") && path.ends_with(".exe") {
                        risk_reasons.push("executable in ProgramData".into());
                        risk_level = "medium".into();
                    }

                    // 3. System process name spoofing
                    let system_procs = ["svchost.exe", "lsass.exe", "csrss.exe", "services.exe",
                                        "smss.exe", "wininit.exe", "winlogon.exe", "lsm.exe"];
                    if system_procs.contains(&name.as_str()) && !path.is_empty()
                        && !path.contains("\\system32\\") && !path.contains("\\syswow64\\")
                    {
                        risk_reasons.push(format!("spoofed system process (path: {})", path));
                        risk_level = "high".into();
                    }

                    // 4. EncodedCommand detection + decode
                    if cmdline.contains("-encodedcommand") || cmdline.contains("-enc ") {
                        risk_reasons.push("EncodedCommand detected".into());
                        risk_level = "high".into();
                        // Try to decode base64 portion
                        if let Some(decoded) = try_decode_encoded(&cmdline) {
                            risk_reasons.push(format!("decoded: {}", decoded));
                        }
                    }

                    // 5. LOLBin suspicious patterns
                    let lolbin_suspicious = [
                        (["mshta", "rundll32", "certutil", "bitsadmin", "regsvr32", "cmstp"],
                         ["http", "temp", "appdata", "downloadstring", "invoke-expression"]),
                    ];
                    for (bins, patterns) in &lolbin_suspicious {
                        let is_lolbin = bins.iter().any(|b| name.contains(b));
                        let has_suspicious = patterns.iter().any(|p| cmdline.contains(p));
                        if is_lolbin && has_suspicious {
                            risk_reasons.push("LOLBin with suspicious pattern".into());
                            risk_level = "high".into();
                        }
                    }

                    // 6. Encoded execution/download patterns
                    let danger_patterns = ["-enc ", "downloadstring", "invoke-expression",
                                           "iex(", "meterpreter", "cobalt", "mimikatz"];
                    for pat in &danger_patterns {
                        if cmdline.contains(pat) {
                            risk_reasons.push(format!("dangerous pattern: {}", pat));
                            risk_level = "high".into();
                        }
                    }

                    // 7. High resource usage
                    if cpu >= 60.0 {
                        risk_reasons.push(format!("high CPU: {:.1}%", cpu));
                        if risk_level == "safe" { risk_level = "low".into(); }
                    }
                    if mem >= 2048.0 {
                        risk_reasons.push(format!("high memory: {:.0}MB", mem));
                        if risk_level == "safe" { risk_level = "low".into(); }
                    }

                    // Apply risk filter
                    let include = match risk_filter {
                        "high" => risk_level == "high",
                        "medium" => risk_level == "high" || risk_level == "medium",
                        "low" => risk_level != "safe",
                        _ => true,
                    };

                    if include {
                        classified.push(json!({
                            "pid": proc["pid"],
                            "ppid": proc["ppid"],
                            "name": proc["name"],
                            "path": proc["path"],
                            "command_line": proc["command_line"],
                            "cpu": proc["cpu"],
                            "memoryMB": proc["memoryMB"],
                            "risk_level": risk_level,
                            "risk_reasons": risk_reasons,
                        }));
                    }
                }

                let high_count = classified.iter().filter(|p| p["risk_level"] == "high").count();
                let med_count = classified.iter().filter(|p| p["risk_level"] == "medium").count();
                let low_count = classified.iter().filter(|p| p["risk_level"] == "low").count();
                let safe_count = classified.iter().filter(|p| p["risk_level"] == "safe").count();

                Ok(json!({
                    "status": "ok",
                    "total_processes": classified.len(),
                    "summary": { "high": high_count, "medium": med_count, "low": low_count, "safe": safe_count },
                    "processes": classified,
                }))
            }
            "kill" => {
                let pid = args["pid"].as_u64().ok_or("Missing 'pid' for kill action")?;
                let cmd = format!("{}taskkill /F /T /PID {} 2>&1", PS_PREFIX, pid);
                let output = run_ps_raw(&cmd).await?;
                Ok(json!({ "status": "ok", "output": output.trim() }))
            }
            _ => Err(format!("Unknown action: {}", action).into()),
        }
    }
}

/// Try to find and decode a base64 EncodedCommand from a command line string.
fn try_decode_encoded(cmdline: &str) -> Option<String> {
    // Look for -EncodedCommand followed by base64 data
    let lower = cmdline.to_lowercase();
    let markers = ["-encodedcommand ", "-enc "];
    for marker in &markers {
        if let Some(idx) = lower.find(marker) {
            let b64_start = idx + marker.len();
            let b64_str: String = cmdline[b64_start..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
                .collect();
            if b64_str.len() > 10 {
                if let Ok(decoded_bytes) = base64_decode(&b64_str) {
                    // EncodedCommand is UTF-16LE
                    let utf16: Vec<u16> = decoded_bytes
                        .chunks_exact(2)
                        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect();
                    if let Ok(text) = String::from_utf16(&utf16) {
                        let trimmed = text.trim().to_string();
                        if !trimmed.is_empty() {
                            return Some(trimmed);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Simple base64 decoder (no external crate needed).
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, &b) in table.iter().enumerate() {
        lookup[b as usize] = i as u8;
    }

    let input = input.trim_end_matches('=');
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len() * 3 / 4);

    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in bytes {
        let val = lookup[b as usize];
        if val == 255 {
            return Err(format!("Invalid base64 char: {}", b as char));
        }
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(output)
}

async fn run_ps_raw(cmd: &str) -> AgentResult<String> {
    let mut c = Command::new("powershell");
    c.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd]);
    c.creation_flags(0x08000000);
    match c.output().await {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(stdout)
        }
        Err(e) => Err(format!("PowerShell command failed: {}", e).into()),
    }
}
