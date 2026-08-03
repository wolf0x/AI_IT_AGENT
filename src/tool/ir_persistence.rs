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
        "Incident response persistence enumeration. Checks autoruns (Run keys, startup folder), scheduled tasks, services, WMI subscriptions, startup directories, deep registry persistence (ServiceDlls, AppInit_DLLs, Winlogon, SilentProcessExit, AutodialDLL, .NET hooks, AMSI, AppCertDlls), LSA packages (extensions, password filters, auth/security packages), COM hijacking (T1546.015), accessibility features (T1546.008), port monitors/time providers/print processors (T1547.010/T1547.003), browser extensions, and Office add-ins. Uses Authenticode signature checks to filter Microsoft-signed binaries."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["all", "autoruns", "tasks", "services", "wmi", "startup", "registry_deep", "lsa", "com", "accessibility", "port_time", "browser", "office"],
                    "description": "Which persistence category to check (default 'all'). registry_deep: DLL hijacking, Winlogon, SilentProcessExit, AMSI, .NET hooks. lsa: LSASS-loaded packages. com: COM object hijacking. accessibility: sethc/utilman/osk debugger hooks. port_time: port monitors, time providers, print processors. browser: Chrome/Edge/Firefox extensions. office: Office add-ins."
                }
            }
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let category = args["category"].as_str().unwrap_or("all");

        let categories: Vec<&str> = if category == "all" {
            vec!["autoruns", "tasks", "services", "wmi", "startup", "registry_deep", "lsa", "com", "accessibility", "port_time", "browser", "office"]
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
                "com" => script_com(),
                "accessibility" => script_accessibility(),
                "port_time" => script_port_time(),
                "browser" => script_browser(),
                "office" => script_office(),
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

fn script_com() -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
{}
"=== COM Hijacking — HKCU overrides of HKLM CLSIDs (T1546.015) ==="
$hkcu = Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction SilentlyContinue
$count = 0
foreach ($clsid in $hkcu) {{
  $guid = $clsid.PSChildName
  $hklmPath = "HKLM:\SOFTWARE\Classes\CLSID\$guid\InprocServer32"
  $hkcuPath = "$($clsid.PSPath)\InprocServer32"
  if ((Test-Path $hklmPath) -and (Test-Path $hkcuPath)) {{
    $hklmDll = (Get-ItemProperty $hklmPath -ErrorAction SilentlyContinue).'(Default)'
    $hkcuDll = (Get-ItemProperty $hkcuPath -ErrorAction SilentlyContinue).'(Default)'
    if ($hkcuDll -and $hkcuDll -ne $hklmDll -and (IsUnsafe $hkcuDll)) {{
      [PSCustomObject]@{{CLSID=$guid; HKCU_DLL=$hkcuDll; Original=$hklmDll}}
      $count++
    }}
  }}
  if ($count -ge 30) {{ break }}
}}
if ($count -eq 0) {{ "(no suspicious HKCU COM overrides found)" }}
"=== COM LocalServer32 overrides (EXE hijacking) ==="
$count2 = 0
foreach ($clsid in $hkcu) {{
  $guid = $clsid.PSChildName
  $hklmPath = "HKLM:\SOFTWARE\Classes\CLSID\$guid\LocalServer32"
  $hkcuPath = "$($clsid.PSPath)\LocalServer32"
  if ((Test-Path $hklmPath) -and (Test-Path $hkcuPath)) {{
    $hkcuExe = (Get-ItemProperty $hkcuPath -ErrorAction SilentlyContinue).'(Default)'
    if ($hkcuExe -and (IsUnsafe $hkcuExe)) {{
      [PSCustomObject]@{{CLSID=$guid; HKCU_EXE=$hkcuExe}}
      $count2++
    }}
  }}
  if ($count2 -ge 20) {{ break }}
}}
if ($count2 -eq 0) {{ "(no suspicious LocalServer32 overrides)" }}
"=== TreatAs / ProgID redirects ==="
$count3 = 0
foreach ($clsid in $hkcu) {{
  $guid = $clsid.PSChildName
  $treatAs = Get-ItemProperty "$($clsid.PSPath)\TreatAs" -ErrorAction SilentlyContinue
  if ($treatAs -and $treatAs.'(Default)') {{
    $target = $treatAs.'(Default)'
    $targetDll = (Get-ItemProperty "HKCU:\Software\Classes\CLSID\$target\InprocServer32" -ErrorAction SilentlyContinue).'(Default)'
    if ($targetDll -and (IsUnsafe $targetDll)) {{
      [PSCustomObject]@{{CLSID=$guid; TreatAs=$target; DLL=$targetDll}}
      $count3++
    }}
  }}
  if ($count3 -ge 10) {{ break }}
}}
if ($count3 -eq 0) {{ "(no suspicious TreatAs redirects)" }}
"#, PS_IS_UNSAFE)
}

fn script_accessibility() -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
{}
"=== Accessibility Feature Hijacking (T1546.008) ==="
$targets = @('sethc.exe','utilman.exe','osk.exe','magnify.exe','narrator.exe','displayswitch.exe','atbroker.exe','DisplaySwitch.exe')
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
foreach ($t in $targets) {{
  $dbg = (Get-ItemProperty "$ifeo\$t" -Name Debugger -ErrorAction SilentlyContinue).Debugger
  if ($dbg) {{
    if (IsUnsafe $dbg) {{ "[!] $t -> Debugger: $dbg" }}
    else {{ "OK (MS-signed): $t -> $dbg" }}
  }}
}}
"=== Direct binary replacement check (hash mismatch vs System32 originals) ==="
$sys32 = "$env:WINDIR\System32"
$bins = @('sethc.exe','utilman.exe','osk.exe','magnify.exe','narrator.exe')
foreach ($b in $bins) {{
  $path = "$sys32\$b"
  if (Test-Path $path) {{
    $sig = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
    if (-not $sig -or $sig.Status -ne 'Valid' -or -not $sig.IsOSBinary) {{
      "[!] $b — signature invalid or not MS: Status=$($sig.Status)"
    }}
  }}
}}
"=== Sticky Keys / Filter Keys registry flags ==="
$sk = (Get-ItemProperty 'HKCU:\Control Panel\Accessibility\StickyKeys' -Name Flags -ErrorAction SilentlyContinue).Flags
$fk = (Get-ItemProperty 'HKCU:\Control Panel\Accessibility\Keyboard Response' -Name Flags -ErrorAction SilentlyContinue).Flags
"StickyKeys Flags: $sk (default 510)"
"FilterKeys Flags: $fk (default 122)"
"#, PS_IS_UNSAFE)
}

fn script_port_time() -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
{}
"=== Port Monitors (T1547.010) ==="
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' -ErrorAction SilentlyContinue | ForEach-Object {{
  $drv = (Get-ItemProperty $_.PSPath -Name Driver -ErrorAction SilentlyContinue).Driver
  if ($drv) {{
    $full = "C:\Windows\System32\$drv"
    if (IsUnsafe $full) {{ "[!] Monitor=$($_.PSChildName) Driver=$drv" }}
  }}
}}
"=== Print Processors ==="
$envs = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments' -ErrorAction SilentlyContinue
foreach ($env in $envs) {{
  $pp = Get-ChildItem "$($env.PSPath)\Print Processors" -ErrorAction SilentlyContinue
  foreach ($p in $pp) {{
    $drv = (Get-ItemProperty $p.PSPath -Name Driver -ErrorAction SilentlyContinue).Driver
    if ($drv) {{
      $full = "C:\Windows\System32\$drv"
      if (IsUnsafe $full) {{ "[!] Env=$($env.PSChildName) Processor=$($p.PSChildName) Driver=$drv" }}
    }}
  }}
}}
"=== Time Providers (T1547.003) ==="
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders' -ErrorAction SilentlyContinue | ForEach-Object {{
  $dll = (Get-ItemProperty $_.PSPath -Name DllName -ErrorAction SilentlyContinue).DllName
  $enabled = (Get-ItemProperty $_.PSPath -Name Enabled -ErrorAction SilentlyContinue).Enabled
  if ($dll -and $enabled -eq 1) {{
    if (IsUnsafe $dll) {{ "[!] Provider=$($_.PSChildName) DLL=$dll" }}
    else {{ "OK: $($_.PSChildName) -> $dll" }}
  }}
}}
"=== Network Providers (T1547.008) ==="
$np = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order' -Name ProviderOrder -ErrorAction SilentlyContinue).ProviderOrder
if ($np) {{
  foreach ($name in ($np -split ',')) {{
    $dll = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$name\NetworkProvider" -Name ProviderPath -ErrorAction SilentlyContinue).ProviderPath
    if ($dll -and (IsUnsafe $dll)) {{ "[!] Provider=$name DLL=$dll" }}
  }}
}} else {{ "(ProviderOrder not set)" }}
"#, PS_IS_UNSAFE)
}

fn script_browser() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== Chrome Extensions ==="
$chromePaths = @(
  "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions",
  "$env:LOCALAPPDATA\Google\Chrome\User Data\Profile 1\Extensions"
)
foreach ($cp in $chromePaths) {
  if (Test-Path $cp) {
    Get-ChildItem $cp -Directory -ErrorAction SilentlyContinue | ForEach-Object {
      $manifest = Get-ChildItem $_.FullName -Recurse -Filter manifest.json -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($manifest) {
        $j = Get-Content $manifest.FullName -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
        $perms = ($j.permissions -join ', ')
        $hostPerms = ($j.content_scripts | ForEach-Object { $_.matches }) -join ', '
        [PSCustomObject]@{ID=$_.Name; Name=$j.name; Version=$j.version; Permissions=$perms; HostPerms=$hostPerms}
      }
    } | Format-Table -AutoSize
  }
}
"=== Edge Extensions ==="
$edgePaths = @(
  "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions",
  "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Profile 1\Extensions"
)
foreach ($ep in $edgePaths) {
  if (Test-Path $ep) {
    Get-ChildItem $ep -Directory -ErrorAction SilentlyContinue | ForEach-Object {
      $manifest = Get-ChildItem $_.FullName -Recurse -Filter manifest.json -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($manifest) {
        $j = Get-Content $manifest.FullName -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
        $perms = ($j.permissions -join ', ')
        [PSCustomObject]@{ID=$_.Name; Name=$j.name; Version=$j.version; Permissions=$perms}
      }
    } | Format-Table -AutoSize
  }
}
"=== Firefox Extensions (user profile) ==="
$ffProfiles = "$env:APPDATA\Mozilla\Firefox\Profiles"
if (Test-Path $ffProfiles) {
  Get-ChildItem $ffProfiles -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $extDir = "$($_.FullName)\extensions"
    if (Test-Path $extDir) {
      Get-ChildItem $extDir -Filter *.xpi -ErrorAction SilentlyContinue | Select-Object Name, Length, LastWriteTime
      Get-ChildItem $extDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $manifest = "$($_.FullName)\manifest.json"
        if (Test-Path $manifest) {
          $j = Get-Content $manifest -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
          [PSCustomObject]@{ID=$_.Name; Name=$j.name; Version=$j.version}
        }
      }
    }
  } | Format-Table -AutoSize
}
"=== Suspicious extension permissions (flagged) ==="
$suspPerms = 'debugger','webRequest','webRequestBlocking','tabs','<all_urls>','nativeMessaging','downloads'
foreach ($cp in $chromePaths) {
  if (Test-Path $cp) {
    Get-ChildItem $cp -Directory -ErrorAction SilentlyContinue | ForEach-Object {
      $manifest = Get-ChildItem $_.FullName -Recurse -Filter manifest.json -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($manifest) {
        $j = Get-Content $manifest.FullName -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
        $hits = @($j.permissions | Where-Object { $suspPerms -contains $_ })
        if ($hits.Count -ge 2) {
          "[!] $($_.Name) ($($j.name)): $($hits -join ', ')"
        }
      }
    }
  }
}
"#.to_string()
}

fn script_office() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== Office COM Add-ins (all apps) ==="
$apps = @('Word','Excel','PowerPoint','Outlook','Access','OneNote')
foreach ($app in $apps) {
  $paths = @(
    "HKCU:\Software\Microsoft\Office\$app\Addins",
    "HKLM:\Software\Microsoft\Office\$app\Addins",
    "HKLM:\Software\WOW6432Node\Microsoft\Office\$app\Addins"
  )
  foreach ($p in $paths) {
    if (Test-Path $p) {
      Get-ChildItem $p -ErrorAction SilentlyContinue | ForEach-Object {
        $desc = (Get-ItemProperty $_.PSPath -Name Description -ErrorAction SilentlyContinue).Description
        $friendly = (Get-ItemProperty $_.PSPath -Name FriendlyName -ErrorAction SilentlyContinue).FriendlyName
        $load = (Get-ItemProperty $_.PSPath -Name LoadBehavior -ErrorAction SilentlyContinue).LoadBehavior
        [PSCustomObject]@{App=$app; Addin=$_.PSChildName; Friendly=$friendly; Load=$load; Source=$p.Split(':')[0]}
      }
    }
  }
} | Format-Table -AutoSize
"=== Office VBA Project References (macro persistence) ==="
$trustKey = 'HKCU:\Software\Microsoft\Office\16.0\Common\Security'
$vbaWarn = (Get-ItemProperty $trustKey -Name VBAWarnings -ErrorAction SilentlyContinue).VBAWarnings
$accessNotif = (Get-ItemProperty $trustKey -Name AccessVBOM -ErrorAction SilentlyContinue).AccessVBOM
"VBAWarnings: $vbaWarn (1=enable all [DANGEROUS], 2=disable with notification, 3=disable all except signed, 4=disable all)"
"AccessVBOM (programmatic access): $accessNotif (1=enabled [DANGEROUS])"
"=== Office Trusted Locations ==="
foreach ($app in $apps) {
  $tlPath = "HKCU:\Software\Microsoft\Office\16.0\$app\Security\Trusted Locations"
  if (Test-Path $tlPath) {
    Get-ChildItem $tlPath -ErrorAction SilentlyContinue | ForEach-Object {
      $loc = (Get-ItemProperty $_.PSPath -Name Path -ErrorAction SilentlyContinue).Path
      $allSub = (Get-ItemProperty $_.PSPath -Name AllLocationsDisabled -ErrorAction SilentlyContinue).AllLocationsDisabled
      if ($loc) { [PSCustomObject]@{App=$app; Location=$loc; SubFolders=$allSub} }
    }
  }
} | Format-Table -AutoSize
"=== Office Startup folder add-ins ==="
$xlStart = "$env:APPDATA\Microsoft\Excel\XLSTART"
$wbStart = "$env:APPDATA\Microsoft\Word\STARTUP"
if (Test-Path $xlStart) { "XLSTART:"; Get-ChildItem $xlStart -ErrorAction SilentlyContinue | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize }
if (Test-Path $wbStart) { "Word STARTUP:"; Get-ChildItem $wbStart -ErrorAction SilentlyContinue | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize }
"#.to_string()
}

async fn run_ps_raw(cmd: &str) -> AgentResult<String> {
    let mut c = Command::new("powershell");
    c.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd]);
    c.creation_flags(0x08000000);
    c.kill_on_drop(true);
    c.stdout(std::process::Stdio::piped());
    c.stderr(std::process::Stdio::piped());

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        c.output(),
    )
    .await
    .map_err(|_| "PowerShell command timed out (120s)".to_string())?
    .map_err(|e| format!("PowerShell command failed: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // Return stdout; append stderr if stdout is empty
    if stdout.trim().is_empty() && !stderr.trim().is_empty() {
        Ok(stderr)
    } else {
        Ok(stdout)
    }
}
