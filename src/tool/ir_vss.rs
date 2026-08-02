//! VSS (Volume Shadow Copy Service) operations tool.
//!
//! Actions:
//! - `list`: Enumerate all shadow copies with install date, path, and status
//! - `create`: Create a new shadow copy of a specified volume
//! - `delete`: Delete a specific shadow copy (by install date or "all")
//! - `query`: Query VSS provider/service status and diff area usage
//! - `expose`: Expose a shadow copy as a drive letter for file access

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct IrVssTool;

const PS_PREFIX: &str = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ";

#[async_trait]
impl Tool for IrVssTool {
    fn name(&self) -> &str { "ir_vss" }
    fn description(&self) -> &str {
        "Volume Shadow Copy Service (VSS) operations for forensic file access. \
         Actions: 'list' (enumerate shadow copies), 'create' (new shadow copy of a volume), \
         'delete' (remove shadow copy by date or 'all'), 'query' (VSS status/diff area), \
         'expose' (mount shadow copy as drive letter for file recovery). \
         Shadow copies preserve historical file states — critical for recovering deleted/modified \
         evidence without altering the live filesystem."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { false }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "create", "delete", "query", "expose"],
                    "description": "VSS operation to perform"
                },
                "volume": {
                    "type": "string",
                    "description": "Volume path for create (e.g. 'C:\\'). Default 'C:\\'"
                },
                "date": {
                    "type": "string",
                    "description": "Install date for delete (format from 'list' output), or 'all'"
                },
                "shadow_id": {
                    "type": "string",
                    "description": "Shadow copy ID (GUID) or install date string for expose/delete"
                },
                "drive_letter": {
                    "type": "string",
                    "description": "Drive letter to expose shadow copy as (e.g. 'Z:'). For 'expose' action."
                }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let action = args["action"].as_str().unwrap_or("list");

        let script = match action {
            "list" => script_list(),
            "create" => {
                let volume = args["volume"].as_str().unwrap_or("C:\\");
                script_create(volume)
            }
            "delete" => {
                let date = args["date"].as_str().unwrap_or("");
                let shadow_id = args["shadow_id"].as_str().unwrap_or("");
                script_delete(date, shadow_id)
            }
            "query" => script_query(),
            "expose" => {
                let shadow_id = args["shadow_id"].as_str().unwrap_or("");
                let drive_letter = args["drive_letter"].as_str().unwrap_or("Z:");
                script_expose(shadow_id, drive_letter)
            }
            _ => return Err(format!("Unknown action: {}", action).into()),
        };

        let full = format!("{}{}", PS_PREFIX, script);
        let output = run_ps(&full).await?;
        Ok(json!({ "status": "ok", "action": action, "output": output }))
    }
}

fn script_list() -> String {
    r#"
$ErrorActionPreference = 'SilentlyContinue'
"=== Shadow Copies ==="
$shadows = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
if (-not $shadows) { "(no shadow copies found)" }
else {
  $shadows | Sort-Object InstallDate -Descending | ForEach-Object {
    [PSCustomObject]@{
      InstallDate = $_.InstallDate.ToString('yyyy-MM-dd HH:mm:ss')
      Volume      = $_.VolumeName
      ShadowID    = $_.ShadowID
      ClientPath  = $_.ClientAccessiblePath
      Status      = $_.Status
      UsedSpace   = "{0:N0} MB" -f ($_.UsedSpace / 1MB)
    }
  } | Format-Table -AutoSize
}
"=== Summary ==="
"Total shadow copies: $(@($shadows).Count)"
"#.to_string()
}

fn script_create(volume: &str) -> String {
    let vol = volume.replace('\'', "''");
    format!(r#"
$ErrorActionPreference = 'Stop'
"Creating shadow copy of {vol}..."
$result = vssadmin create shadow /for={vol} 2>&1
$result | Out-String
"#)
}

fn script_delete(date: &str, shadow_id: &str) -> String {
    if !shadow_id.is_empty() {
        let id = shadow_id.replace('\'', "''");
        format!(r#"
$ErrorActionPreference = 'Stop'
"Deleting shadow copy: {id}"
$sc = Get-CimInstance Win32_ShadowCopy | Where-Object {{ $_.ShadowID -eq '{id}' -or $_.InstallDate.ToString('yyyy-MM-dd HH:mm:ss') -eq '{id}' }}
if ($sc) {{
  $sc | ForEach-Object {{
    "Deleting: $($_.InstallDate) - $($_.VolumeName)"
    Remove-CimInstance -InputObject $_
  }}
  "Done."
}} else {{
  "No shadow copy found matching: {id}"
}}
"#)
    } else if date == "all" {
        r#"
$ErrorActionPreference = 'Stop'
"Deleting ALL shadow copies..."
vssadmin delete shadows /all /quiet 2>&1 | Out-String
"Done."
"#.to_string()
    } else {
        let d = date.replace('\'', "''");
        format!(r#"
$ErrorActionPreference = 'Stop'
"Deleting shadow copies matching date: {d}"
$sc = Get-CimInstance Win32_ShadowCopy | Where-Object {{ $_.InstallDate.ToString('yyyy-MM-dd HH:mm:ss') -le '{d}' }}
if ($sc) {{
  $sc | ForEach-Object {{
    "Deleting: $($_.InstallDate) - $($_.VolumeName)"
    Remove-CimInstance -InputObject $_
  }}
  "Deleted $(@($sc).Count) shadow cop(ies)."
}} else {{
  "No shadow copies found matching date: {d}"
}}
"#)
    }
}

fn script_query() -> String {
    r#"
$ErrorActionPreference = 'SilentlyContinue'
"=== VSS Service Status ==="
Get-Service VSS | Select-Object Name, Status, StartType | Format-Table -AutoSize
"=== VSS Providers ==="
vssadmin list providers 2>&1 | Out-String
"=== Shadow Copy Storage (Diff Area) ==="
vssadmin list shadowstorage 2>&1 | Out-String
"#.to_string()
}

fn script_expose(shadow_id: &str, drive_letter: &str) -> String {
    let id = shadow_id.replace('\'', "''");
    let letter = drive_letter.trim_end_matches(':');
    format!(r#"
$ErrorActionPreference = 'Stop'
"Exposing shadow copy as {letter}:"
$sc = Get-CimInstance Win32_ShadowCopy | Where-Object {{
  $_.ShadowID -eq '{id}' -or $_.InstallDate.ToString('yyyy-MM-dd HH:mm:ss') -eq '{id}'
}} | Select-Object -First 1
if (-not $sc) {{
  "ERROR: No shadow copy found matching: {id}"
  "Use action='list' to see available shadow copies."
  exit 1
}}
"Found: $($sc.InstallDate) - $($sc.VolumeName)"
$clientPath = $sc.ClientAccessiblePath
if ($clientPath -and (Test-Path $clientPath)) {{
  "Client-accessible path: $clientPath"
  "Historical files are directly accessible at this path."
}} else {{
  "Device path: $($sc.DeviceObject)"
  "Client path not available. Try: mklink /D C:\shadow_mount $($sc.DeviceObject)"
}}
"#)
}

async fn run_ps(cmd: &str) -> AgentResult<String> {
    let mut c = Command::new("powershell");
    c.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd]);
    c.creation_flags(0x08000000);
    c.kill_on_drop(true);
    match c.output().await {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            if stdout.trim().is_empty() && !stderr.trim().is_empty() {
                Ok(stderr)
            } else {
                Ok(stdout)
            }
        }
        Err(e) => Err(format!("PowerShell command failed: {}", e).into()),
    }
}
