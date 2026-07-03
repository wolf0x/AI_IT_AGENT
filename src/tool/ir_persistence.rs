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
        "Incident response persistence enumeration. Checks autoruns (registry Run keys, startup folder), scheduled tasks, services, WMI subscriptions, and startup directories for persistence mechanisms."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["all", "autoruns", "tasks", "services", "wmi", "startup"],
                    "description": "Which persistence category to check (default 'all')"
                }
            }
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let category = args["category"].as_str().unwrap_or("all");

        let categories: Vec<&str> = if category == "all" {
            vec!["autoruns", "tasks", "services", "wmi", "startup"]
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
