use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct IrScanTool;

const PS_PREFIX: &str = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ";

#[async_trait]
impl Tool for IrScanTool {
    fn name(&self) -> &str { "ir_scan" }
    fn description(&self) -> &str {
        "Incident response scan: run one or all 17 collection tasks (basic, processes, network, autoruns, tasks, services, wmi, files, security-events, system-events, powershell-events, web-logs, defender, defender-history, sysmon, lateral, drivers). Returns raw collection output."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Which collection task to run. Use 'all' to run every task.",
                    "enum": ["all","basic","processes","network","autoruns","tasks","services","wmi","files","security-events","system-events","powershell-events","web-logs","defender","defender-history","sysmon","lateral","drivers"]
                },
                "days": { "type": "integer", "description": "Lookback days for event-log tasks (default 7)" },
                "max_events": { "type": "integer", "description": "Max events per event-log category (default 500)" }
            }
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let category = args["category"].as_str().unwrap_or("all");
        let days = args["days"].as_u64().unwrap_or(7);
        let max_events = args["max_events"].as_u64().unwrap_or(500);

        let categories: Vec<&str> = if category == "all" {
            vec!["basic","processes","network","autoruns","tasks","services","wmi","files",
                 "security-events","system-events","powershell-events","web-logs","defender",
                 "defender-history","sysmon","lateral","drivers"]
        } else {
            vec![category]
        };

        let mut combined = String::new();
        for cat in categories {
            let script = match cat {
                "basic" => script_basic(),
                "processes" => script_processes(),
                "network" => script_network(),
                "autoruns" => script_autoruns(),
                "tasks" => script_tasks(),
                "services" => script_services(),
                "wmi" => script_wmi(),
                "files" => script_files(),
                "security-events" => script_security_events(days, max_events),
                "system-events" => script_system_events(days, max_events),
                "powershell-events" => script_powershell_events(days, max_events),
                "web-logs" => script_web_logs(),
                "defender" => script_defender(),
                "defender-history" => script_defender_history(),
                "sysmon" => script_sysmon(days, max_events),
                "lateral" => script_lateral(),
                "drivers" => script_drivers(),
                _ => { combined.push_str(&format!("=== Unknown category: {} ===\n", cat)); continue; }
            };
            let full = format!("{}{}", PS_PREFIX, script);
            match run_ps(&full).await {
                Ok(output) => {
                    let stdout = output["stdout"].as_str().unwrap_or("");
                    let stderr = output["stderr"].as_str().unwrap_or("");
                    combined.push_str(&format!("=== {} ===\n{}\n", cat, stdout));
                    if !stderr.is_empty() {
                        combined.push_str(&format!("STDERR: {}\n", stderr));
                    }
                    combined.push('\n');
                }
                Err(e) => {
                    combined.push_str(&format!("=== {} === ERROR: {}\n\n", cat, e));
                }
            }
        }
        Ok(json!({ "status": "ok", "output": combined }))
    }
}

async fn run_ps(cmd: &str) -> AgentResult<Value> {
    let mut c = Command::new("powershell");
    c.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd]);
    c.creation_flags(0x08000000);
    match c.output().await {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            Ok(json!({ "stdout": stdout.trim(), "stderr": stderr.trim() }))
        }
        Err(e) => Err(format!("PowerShell command failed: {}", e).into()),
    }
}

// -- PowerShell script fragments (ported from yinghuo tasks.go) --

fn script_basic() -> String {
    r#"
"=== System Info ==="
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime | Format-List
"=== Hotfixes (last 20) ==="
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 HotFixID, Description, InstalledOn | Format-Table -AutoSize
"=== Disk Usage ==="
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, @{N='SizeGB';E={[math]::Round($_.Size/1GB,1)}}, @{N='FreeGB';E={[math]::Round($_.FreeSpace/1GB,1)}}, @{N='UsedPct';E={[math]::Round(($_.Size-$_.FreeSpace)/$_.Size*100,1)}} | Format-Table -AutoSize
"=== Network Adapters ==="
Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne '127.0.0.1'} | Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table -AutoSize
"#.to_string()
}

fn script_processes() -> String {
    r#"
"=== Top 30 Processes by Memory ==="
Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 30 Id, ProcessName, CPU, @{N='MemMB';E={[math]::Round($_.WorkingSet64/1MB,1)}}, Path | Format-Table -AutoSize
"=== Processes in Temp/AppData ==="
Get-Process | Where-Object { $_.Path -and ($_.Path -match 'Temp|AppData|Downloads|\\Users\\Public') } | Select-Object Id, ProcessName, Path | Format-Table -AutoSize
"#.to_string()
}

fn script_network() -> String {
    r#"
"=== Active TCP Connections ==="
Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Format-Table -AutoSize
"=== DNS Cache ==="
Get-DnsClientCache | Select-Object -First 50 Name, Type, Data | Format-Table -AutoSize
"=== Route Table ==="
Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.DestinationPrefix -ne '0.0.0.0/0'} | Select-Object -First 30 DestinationPrefix, NextHop, RouteMetric, InterfaceAlias | Format-Table -AutoSize
"=== Firewall Profile ==="
Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize
"#.to_string()
}

fn script_autoruns() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== Run Keys (HKCU) ==="
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object Name, @{N='Value';E={$_.Value}} }
"=== Run Keys (HKLM) ==="
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object Name, @{N='Value';E={$_.Value}} }
"=== RunOnce Keys ==="
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue | ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object Name, @{N='Value';E={$_.Value}} }
"=== Startup Folder ==="
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Select-Object Name, FullName, LastWriteTime
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Select-Object Name, FullName, LastWriteTime
"#.to_string()
}

fn script_tasks() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== Scheduled Tasks (non-Microsoft) ==="
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | Select-Object TaskName, TaskPath, State, @{N='Actions';E={($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; '}} | Format-Table -AutoSize
"=== Recently Created Tasks ==="
Get-ScheduledTask | Sort-Object Date -Descending -ErrorAction SilentlyContinue | Select-Object -First 20 TaskName, TaskPath, State, Date | Format-Table -AutoSize
"#.to_string()
}

fn script_services() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== Non-Microsoft Services (Running) ==="
Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' -and $_.PathName -notmatch 'Windows|Microsoft|svchost' } | Select-Object Name, DisplayName, State, StartMode, PathName | Format-Table -AutoSize
"=== Services with Suspicious Paths ==="
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'Temp|AppData|Downloads|Users\\Public|ProgramData' } | Select-Object Name, DisplayName, State, PathName | Format-Table -AutoSize
"#.to_string()
}

fn script_wmi() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== WMI Event Subscriptions ==="
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Select-Object Name, Query, QueryLanguage | Format-Table -AutoSize
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | Select-Object Name, __CLASS | Format-Table -AutoSize
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Select-Object Filter, Consumer | Format-Table -AutoSize
"=== WMI Auto-start Commands ==="
Get-CimInstance -Namespace root\cimv2 -ClassName Win32_StartupCommand -ErrorAction SilentlyContinue | Select-Object Name, Command, Location | Format-Table -AutoSize
"#.to_string()
}

fn script_files() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== Recently Modified Executables (last 7 days) ==="
$cutoff = (Get-Date).AddDays(-7)
Get-ChildItem -Path C:\ -Recurse -Include *.exe,*.dll,*.ps1,*.vbs,*.bat -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $cutoff -and $_.FullName -notmatch '\\Windows\\|\\Program Files\\' } | Select-Object -First 100 FullName, LastWriteTime, Length | Sort-Object LastWriteTime -Descending | Format-Table -AutoSize
"=== Suspicious Locations ==="
Get-ChildItem -Path "$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA","C:\Users\Public" -Recurse -Include *.exe,*.dll,*.ps1,*.vbs -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $cutoff } | Select-Object -First 50 FullName, LastWriteTime, Length | Sort-Object LastWriteTime -Descending | Format-Table -AutoSize
"#.to_string()
}

fn script_security_events(days: u64, max: u64) -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
$days = {}
$maxEv = {}
$start = (Get-Date).AddDays(-$days)
"=== Failed Logons (4625) ==="
Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4625;StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | Select-Object TimeCreated, @{{N='User';E={{($_.Properties[5]).Value}}}}, @{{N='SourceIP';E={{($_.Properties[19]).Value}}}}, @{{N='FailReason';E={{($_.Properties[7]).Value}}}} | Format-Table -AutoSize
"=== Successful Logons (4624) ==="
Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4624;StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | Select-Object TimeCreated, @{{N='User';E={{($_.Properties[5]).Value}}}}, @{{N='LogonType';E={{($_.Properties[8]).Value}}}}, @{{N='SourceIP';E={{($_.Properties[18]).Value}}}} | Format-Table -AutoSize
"=== Account Changes ==="
Get-WinEvent -FilterHashtable @{{LogName='Security';Id=@(4720,4722,4723,4724,4725,4726,4728,4729,4732,4733);StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | Format-Table -AutoSize
"=== Log Cleared (1102) ==="
Get-WinEvent -FilterHashtable @{{LogName='Security';Id=1102;StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Format-Table -AutoSize
"#, days, max)
}

fn script_system_events(days: u64, max: u64) -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
$days = {}
$maxEv = {}
$start = (Get-Date).AddDays(-$days)
"=== System Boot/Shutdown (6005/6006/6008) ==="
Get-WinEvent -FilterHashtable @{{LogName='System';Id=@(6005,6006,6008);StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | Format-Table -AutoSize
"=== New Service Installed (7045) ==="
Get-WinEvent -FilterHashtable @{{LogName='System';Id=7045;StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | Select-Object TimeCreated, @{{N='ServiceName';E={{($_.Properties[0]).Value}}}}, @{{N='ImagePath';E={{($_.Properties[1]).Value}}}}, @{{N='StartType';E={{($_.Properties[2]).Value}}}} | Format-Table -AutoSize
"#, days, max)
}

fn script_powershell_events(days: u64, max: u64) -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
$days = {}
$maxEv = {}
$start = (Get-Date).AddDays(-$days)
"=== PowerShell Script Block Logs (4104) ==="
Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | Select-Object TimeCreated, @{{N='ScriptBlock';E={{($_.Properties[2]).Value}}}} | Format-Table -AutoSize
"=== PowerShell Module Logs (4103) ==="
Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-PowerShell/Operational';Id=4103;StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Format-Table -AutoSize
"#, days, max)
}

fn script_web_logs() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== IIS Access Logs (last 100 lines) ==="
$iisLogDir = "$env:SystemRoot\System32\LogFiles\W3SVC1"
if (Test-Path $iisLogDir) {
    Get-ChildItem $iisLogDir -Filter *.log | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | ForEach-Object {
        Get-Content $_.FullName -Tail 100
    }
} else {
    "No IIS log directory found"
}
"=== IIS Sites ==="
Get-WebSite -ErrorAction SilentlyContinue | Select-Object Name, State, PhysicalPath, @{N='Bindings';E={$_.Bindings.Collection.bindingInformation}} | Format-Table -AutoSize
"#.to_string()
}

fn script_defender() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== Defender Status ==="
Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object AMRunningMode, AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, BehaviorMonitorEnabled, RealTimeProtectionEnabled, QuickScanEndTime, FullScanEndTime | Format-List
"=== Defender Threat History ==="
Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 50 ThreatID, ActionSuccess, InitialDetectionTime, Resources | Format-Table -AutoSize
"=== Defender Exclusions ==="
Get-MpPreference -ErrorAction SilentlyContinue | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension | Format-List
"#.to_string()
}

fn script_defender_history() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== Defender Scan History ==="
Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object QuickScanStartTime, QuickScanEndTime, FullScanStartTime, FullScanEndTime, AntivirusSignatureLastUpdated | Format-List
"=== Recent Threats ==="
Get-MpThreat -ErrorAction SilentlyContinue | Select-Object -First 30 ThreatName, SeverityID, IsActive, DidThreatExecute | Format-Table -AutoSize
"#.to_string()
}

fn script_sysmon(days: u64, max: u64) -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
$days = {}
$maxEv = {}
$start = (Get-Date).AddDays(-$days)
"=== Sysmon Service ==="
Get-Service Sysmon -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | Format-List
"=== Sysmon Process Creates (Event 1) ==="
Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Sysmon/Operational';Id=1;StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | Select-Object TimeCreated, @{{N='Image';E={{($_.Properties[4]).Value}}}}, @{{N='CommandLine';E={{($_.Properties[9]).Value}}}}, @{{N='ParentImage';E={{($_.Properties[19]).Value}}}} | Format-Table -AutoSize
"=== Sysmon Network (Event 3) ==="
Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Sysmon/Operational';Id=3;StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | Select-Object TimeCreated, @{{N='Image';E={{($_.Properties[4]).Value}}}}, @{{N='DestIP';E={{($_.Properties[13]).Value}}}}, @{{N='DestPort';E={{($_.Properties[14]).Value}}}} | Format-Table -AutoSize
"#, days, max)
}

fn script_lateral() -> String {
    r#"
$ErrorActionPreference='Continue'
"=== SMB Shares ==="
Get-SmbShare -ErrorAction SilentlyContinue | Format-Table Name,Path,Description,ConcurrentUserLimit -AutoSize
"=== Open Files ==="
Get-SmbOpenFile -ErrorAction SilentlyContinue | Select-Object -First 100 ClientUserName,ClientComputerName,Path,SessionID | Format-Table -AutoSize
"=== SMB Sessions ==="
Get-SmbSession -ErrorAction SilentlyContinue | Select-Object ClientUserName,ClientComputerName,Dialect,SessionID | Format-Table -AutoSize
"=== SMB Connections ==="
Get-SmbConnection -ErrorAction SilentlyContinue | Select-Object ServerName,ShareName,UserName,Dialect | Format-Table -AutoSize
"=== SMB Mappings ==="
Get-SmbMapping -ErrorAction SilentlyContinue | Select-Object LocalPath,RemotePath,Status | Format-Table -AutoSize
"=== PsExec Traces ==="
Get-Service -Name PSEXESVC -ErrorAction SilentlyContinue | Format-List Name,Status,StartType
"=== Remote Desktop Users ==="
try { net localgroup "Remote Desktop Users" 2>$null } catch {}
"#.to_string()
}

fn script_drivers() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
$dirs = @("$env:WINDIR\System32\drivers")
"=== Driver File Signature Scan ==="
$all = Get-ChildItem -Path $dirs -Filter *.sys -File -ErrorAction SilentlyContinue
"Total driver files: $($all.Count)"
$unsigned = @(); $nonMs = @(); $revoked = @()
foreach($f in $all){
  $sig = Get-AuthenticodeSignature -FilePath $f.FullName -ErrorAction SilentlyContinue
  if(-not $sig){ continue }
  if($sig.Status -eq 'NotSigned'){ $unsigned += $f.Name }
  elseif($sig.SignerCertificate){ $subj = $sig.SignerCertificate.Subject; if($subj -notmatch 'Microsoft'){ $nonMs += ($f.Name + ' | ' + ($subj -replace ',.*$','')) } }
  if($sig.Status -eq 'HashMismatch' -or $sig.Status -eq 'NotTrusted'){ $revoked += $f.Name }
}
"--- Unsigned ($($unsigned.Count)) ---"; $unsigned | Select-Object -First 50
"--- Non-MS Signed ($($nonMs.Count)) ---"; $nonMs | Select-Object -First 50
"--- Revoked/Mismatch ($($revoked.Count)) ---"; $revoked | Select-Object -First 50
"=== Loaded Kernel Drivers ==="
driverquery /v /fo csv 2>$null | ConvertFrom-Csv -ErrorAction SilentlyContinue | Select-Object -First 200 'Display Name','Link Date','Path' | Format-Table -AutoSize
"#.to_string()
}
