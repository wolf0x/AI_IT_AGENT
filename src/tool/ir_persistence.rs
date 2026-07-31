use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct IrPersistenceTool;

const PS_PREFIX: &str = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ";

#[async_trait]
impl Tool for IrPersistenceTool {
    fn name(&self) -> &str { "ir_persistence" }
    fn description(&self) -> &str {
        "Incident response persistence enumeration. Checks autoruns (Run keys, startup folder), scheduled tasks, services, WMI subscriptions, startup directories, deep registry persistence (ServiceDlls, AppInit_DLLs, Winlogon, SilentProcessExit, AutodialDLL, .NET hooks, AMSI, AppCertDlls), and LSA packages (extensions, password filters, auth/security packages). Uses Authenticode signature checks to filter Microsoft-signed binaries."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["all", "autoruns", "tasks", "services", "wmi", "startup", "registry_deep", "lsa"],
                    "description": "Which persistence category to check (default 'all'). registry_deep: DLL hijacking, Winlogon, SilentProcessExit, AMSI, .NET hooks. lsa: LSASS-loaded packages."
                }
            }
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let category = args["category"].as_str().unwrap_or("all");

        let categories: Vec<&str> = if category == "all" {
            vec!["autoruns", "tasks", "services", "wmi", "startup", "registry_deep", "lsa"]
        } else {
            vec![category]
        };

        let mut combined = String::new();
        for cat in categories {
            let script = match cat {
                "autoruns" => script_autoruns(),
                "tasks" => script_tasks(),
                "services" => script_services(),
                "wmi" => script_wmi(),
                "startup" => script_startup(),
                "registry_deep" => script_registry_deep(),
                "lsa" => script_lsa(),
                _ => { combined.push_str(&format!("=== Unknown category: {} ===\n", cat)); continue; }
            };
            let full = format!("{}{}", PS_PREFIX, script);
            match run_ps_raw(&full).await {
                Ok(output) => {
                    combined.push_str(&format!("=== {} ===\n{}\n\n", cat, output.trim()));
                }
                Err(e) => {
                    combined.push_str(&format!("=== {} === ERROR: {}\n\n", cat, e));
                }
            }
        }
        Ok(json!({ "status": "ok", "output": combined }))
    }
}

fn script_autoruns() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== Run Keys (HKCU) ==="
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object Name, @{N='Value';E={$_.Value}} | Format-Table -AutoSize }
"=== Run Keys (HKLM) ==="
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object Name, @{N='Value';E={$_.Value}} | Format-Table -AutoSize }
"=== RunOnce Keys (HKLM) ==="
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue | ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object Name, @{N='Value';E={$_.Value}} | Format-Table -AutoSize }
"=== RunOnce Keys (HKCU) ==="
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue | ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object Name, @{N='Value';E={$_.Value}} | Format-Table -AutoSize }
"=== Boot Execute ==="
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name BootExecute -ErrorAction SilentlyContinue | Select-Object BootExecute
"=== Known DLLs ==="
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs' -ErrorAction SilentlyContinue | ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object Name, @{N='Value';E={$_.Value}} | Format-Table -AutoSize }
"#.to_string()
}

fn script_tasks() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== Non-Microsoft Scheduled Tasks ==="
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | Select-Object TaskName, TaskPath, State, @{N='Actions';E={($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; '}} | Format-Table -AutoSize
"=== Tasks with Suspicious Commands ==="
Get-ScheduledTask | ForEach-Object {
  $actions = ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; '
  if ($actions -match 'powershell|cmd|wscript|cscript|mshta|rundll32|certutil|bitsadmin') {
    [PSCustomObject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; State=$_.State; Actions=$actions}
  }
} | Format-Table -AutoSize
"=== Recently Created Tasks (last 30 days) ==="
Get-ScheduledTask | Where-Object { $_.Date -and $_.Date -gt (Get-Date).AddDays(-30) } | Select-Object TaskName, TaskPath, State, Date | Sort-Object Date -Descending | Format-Table -AutoSize
"#.to_string()
}

fn script_services() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== Non-Microsoft Running Services ==="
Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' -and $_.PathName -notmatch 'Windows|Microsoft|svchost' } | Select-Object Name, DisplayName, State, StartMode, PathName | Format-Table -AutoSize
"=== Services with Suspicious Paths ==="
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'Temp|AppData|Downloads|Users\\Public|ProgramData' } | Select-Object Name, DisplayName, State, PathName | Format-Table -AutoSize
"=== Recently Installed Services (Event 7045, last 30 days) ==="
$start = (Get-Date).AddDays(-30)
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=$start} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, @{N='ServiceName';E={($_.Properties[0]).Value}}, @{N='ImagePath';E={($_.Properties[1]).Value}}, @{N='StartType';E={($_.Properties[2]).Value}} | Format-Table -AutoSize
"#.to_string()
}

fn script_wmi() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== WMI Event Filters ==="
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Select-Object Name, Query, QueryLanguage | Format-Table -AutoSize
"=== WMI Event Consumers ==="
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | Select-Object Name, __CLASS | Format-Table -AutoSize
"=== WMI Filter-to-Consumer Bindings ==="
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Select-Object Filter, Consumer | Format-Table -AutoSize
"=== WMI Startup Commands ==="
Get-CimInstance -Namespace root\cimv2 -ClassName Win32_StartupCommand -ErrorAction SilentlyContinue | Select-Object Name, Command, Location | Format-Table -AutoSize
"#.to_string()
}

fn script_startup() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== User Startup Folder ==="
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Select-Object Name, FullName, LastWriteTime, Length | Format-Table -AutoSize
"=== All Users Startup Folder ==="
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Select-Object Name, FullName, LastWriteTime, Length | Format-Table -AutoSize
"=== Shell Folders (User Init) ==="
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction SilentlyContinue | Select-Object Startup, @{N='CommonStartup';E={(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction SilentlyContinue).CommonStartup}}
"=== Image File Execution Options (Debugger) ==="
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object {
  $debugger = (Get-ItemProperty $_.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
  if ($debugger) { [PSCustomObject]@{Key=$_.PSChildName; Debugger=$debugger} }
} | Format-Table -AutoSize
"#.to_string()
}

/// Helper: returns $true if the file exists and is NOT a Microsoft OS binary.
/// Used to filter out legitimate signed DLLs and reduce false positives.
const PS_IS_UNSAFE: &str = r#"function IsUnsafe($p){if([string]::IsNullOrWhiteSpace($p)){return $false};$p=[Environment]::ExpandEnvironmentVariables($p);if(-not [IO.Path]::IsPathRooted($p)){$p="C:\Windows\System32\$p"};if(Test-Path $p){return -not (Get-AuthenticodeSignature $p).IsOSBinary};return $true}"#;

fn script_registry_deep() -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
{}
"=== ServiceDlls (svchost DLL hijacking) ==="
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue | ForEach-Object {{
  $img = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ImagePath
  if ($img -and $img -like '*svchost*') {{
    $sd = $null
    if (Test-Path "$($_.PSPath)\Parameters") {{ $sd = (Get-ItemProperty "$($_.PSPath)\Parameters" -ErrorAction SilentlyContinue).ServiceDll }}
    else {{ $sd = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ServiceDll }}
    if ($sd -and (IsUnsafe $sd)) {{ [PSCustomObject]@{{Service=$_.PSChildName; ServiceDll=$sd}} }}
  }}
}} | Format-Table -AutoSize
"=== AppInit_DLLs (T1546.010) ==="
$ai = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue).AppInit_DLLs
if ($ai) {{ "HKLM: $ai" }}
$ai32 = (Get-ItemProperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue).AppInit_DLLs
if ($ai32) {{ "Wow6432Node: $ai32" }}
if (-not $ai -and -not $ai32) {{ "(not set)" }}
"=== Winlogon Userinit (T1547.004) ==="
$ui = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue).Userinit
if ($ui -and $ui -ne 'C:\Windows\system32\userinit.exe,') {{ "[!] Non-default: $ui" }} else {{ "OK: $ui" }}
"=== Winlogon Shell (T1547.004) ==="
$sh = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue).Shell
if ($sh -and $sh -ne 'explorer.exe') {{ "[!] Non-default: $sh" }} else {{ "OK: $sh" }}
"=== Winlogon Notify Packages (T1547.004) ==="
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify' -ErrorAction SilentlyContinue | ForEach-Object {{ $_.PSObject.Properties | Where-Object {{ $_.Name -notlike 'PS*' }} | Select-Object Name, @{{N='DLL';E={{$_.Value}}}} | Format-Table -AutoSize }}
"=== SilentProcessExit Monitor (T1546.012) ==="
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -ErrorAction SilentlyContinue | ForEach-Object {{
  $mp = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).MonitorProcess
  if ($mp) {{ [PSCustomObject]@{{MonitoredApp=$_.PSChildName; MonitorProcess=$mp}} }}
}} | Format-Table -AutoSize
"=== AutodialDLL (Winsock injection) ==="
$ad = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters' -ErrorAction SilentlyContinue).AutodialDLL
if ($ad -and (IsUnsafe $ad)) {{ "[!] Non-MS AutodialDLL: $ad" }} elseif ($ad) {{ "OK (MS-signed): $ad" }} else {{ "(not set)" }}
"=== .NET Startup Hooks (T1574.002) ==="
$dh = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -ErrorAction SilentlyContinue).DOTNET_STARTUP_HOOKS
if ($dh) {{ "[!] System: $dh" }}
$dhu = (Get-ItemProperty 'HKCU:\Environment' -ErrorAction SilentlyContinue).DOTNET_STARTUP_HOOKS
if ($dhu) {{ "[!] User: $dhu" }}
if (-not $dh -and -not $dhu) {{ "(not set)" }}
"=== AMSI Providers (non-Microsoft) ==="
$legit = '{{2781761E-28E0-4109-99FE-B9D127C57AFE}}'
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction SilentlyContinue | Where-Object {{ $_.PSChildName -ne $legit }} | ForEach-Object {{
  $dll = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$($_.PSChildName)\InprocServer32" -ErrorAction SilentlyContinue).'(Default)'
  [PSCustomObject]@{{GUID=$_.PSChildName; DLL=$dll}}
}} | Format-Table -AutoSize
"=== AppCertDlls (T1574.009) ==="
$ac = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue).AppCertDlls
if ($ac) {{ foreach ($d in $ac) {{ if (IsUnsafe $d) {{ "[!] $d" }} }} }} else {{ "(not set)" }}
"#, PS_IS_UNSAFE)
}

fn script_lsa() -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
{}
"=== LSA Extensions (loaded by LSASS at boot) ==="
$le = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\LsaExtensionConfig\LsaSrv' -ErrorAction SilentlyContinue).Extensions
if ($le) {{ foreach ($d in ($le -split '\s+')) {{ if (IsUnsafe $d) {{ "[!] $d" }} }} }} else {{ "(not set)" }}
"=== LSA Notification Packages / Password Filters (T1556.002) ==="
$np = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).'Notification Packages'
if ($np) {{ foreach ($d in ($np -split '\s+')) {{ $p = "C:\Windows\System32\$d"; if (-not $p.EndsWith('.dll')) {{ $p += '.dll' }}; if (IsUnsafe $p) {{ "[!] $p" }} }} }} else {{ "(not set)" }}
"=== LSA Authentication Packages (T1547.002) ==="
$ap = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).'Authentication Packages'
if ($ap) {{ foreach ($d in ($ap -split '\s+')) {{ $p = "C:\Windows\System32\$d.dll"; if (IsUnsafe $p) {{ "[!] $p" }} }} }} else {{ "(not set)" }}
"=== LSA Security Packages (T1547.005) ==="
$sp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).'Security Packages'
if ($sp) {{ foreach ($d in (($sp -replace '"','') -split '\s+')) {{ if ($d -eq '') {{ continue }}; $p = "C:\Windows\System32\$d.dll"; if (IsUnsafe $p) {{ "[!] $p" }} }} }} else {{ "(not set)" }}
"#, PS_IS_UNSAFE)
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
