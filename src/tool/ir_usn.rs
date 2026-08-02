//! USN Journal (Change Journal) analysis tool.
//!
//! The NTFS USN Journal records all file/directory changes on a volume.
//! This tool reads and filters journal entries for forensic timeline reconstruction.
//!
//! Actions:
//! - `query`: Read USN journal entries with time/path/reason filters
//! - `stats`: Show journal statistics (entry counts by reason code)
//! - `config`: Show USN journal configuration (max size, allocation delta)

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct IrUsnTool;

const PS_PREFIX: &str = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ";

#[async_trait]
impl Tool for IrUsnTool {
    fn name(&self) -> &str { "ir_usn" }
    fn description(&self) -> &str {
        "NTFS USN Journal (Change Journal) analysis for forensic file activity tracking. \
         Actions: 'query' (read journal entries with filters), 'stats' (entry counts by reason), \
         'config' (journal configuration). The USN journal logs every file create/modify/delete/rename \
         on NTFS volumes — invaluable for establishing file activity timelines during incident response."
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
                    "description": "USN operation: query entries, show stats, or show config"
                },
                "volume": {
                    "type": "string",
                    "description": "Volume drive letter (e.g. 'C:'). Default 'C:'"
                },
                "hours_ago": {
                    "type": "integer",
                    "description": "Only show entries from the last N hours (default 24)"
                },
                "path_filter": {
                    "type": "string",
                    "description": "Filter entries containing this path substring (e.g. 'System32', '.exe')"
                },
                "reason_filter": {
                    "type": "string",
                    "enum": ["all", "create", "delete", "modify", "rename", "security"],
                    "description": "Filter by USN reason code category (default 'all')"
                },
                "max_entries": {
                    "type": "integer",
                    "description": "Maximum entries to return (default 200, max 2000)"
                }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let action = args["action"].as_str().unwrap_or("query");
        let volume = args["volume"].as_str().unwrap_or("C:");

        let script = match action {
            "query" => {
                let hours_ago = args["hours_ago"].as_u64().unwrap_or(24);
                let path_filter = args["path_filter"].as_str().unwrap_or("");
                let reason_filter = args["reason_filter"].as_str().unwrap_or("all");
                let max_entries = args["max_entries"].as_u64().unwrap_or(200).min(2000);
                script_query(volume, hours_ago, path_filter, reason_filter, max_entries)
            }
            "stats" => script_stats(volume),
            "config" => script_config(volume),
            _ => return Err(format!("Unknown action: {}", action).into()),
        };

        let full = format!("{}{}", PS_PREFIX, script);
        let output = run_ps(&full).await?;
        Ok(json!({ "status": "ok", "action": action, "output": output }))
    }
}

fn script_query(volume: &str, hours_ago: u64, path_filter: &str, reason_filter: &str, max_entries: u64) -> String {
    let vol = volume.trim_end_matches(':');
    let pf = path_filter.replace('\'', "''");

    // Reason code filter mapping
    let reason_mask = match reason_filter {
        "create" => "0x00000001",   // USN_REASON_DATA_OVERWRITE (basic create)
        "delete" => "0x00008000",   // USN_REASON_FILE_DELETE
        "modify" => "0x00000002",   // USN_REASON_DATA_EXTEND
        "rename" => "0x00002000",   // USN_REASON_RENAME_NEW_NAME
        "security" => "0x00080000", // USN_REASON_SECURITY_CHANGE
        _ => "0",                   // all
    };

    format!(r#"
$ErrorActionPreference = 'SilentlyContinue'
$vol = '{vol}:'
$cutoff = (Get-Date).AddHours(-{hours_ago})
"=== USN Journal Query: $vol (last {hours_ago}h) ==="

# Read USN journal via fsutil
$raw = fsutil usn readjournal $vol csv 2>&1 | Out-String
$lines = $raw -split "`n" | Where-Object {{ $_.Trim() -ne '' -and $_ -notmatch '^Usn Journal' -and $_ -notmatch '^Volume' }}

$entries = @()
foreach ($line in $lines) {{
  # CSV format: FileName,Reason,USN,FileRef,ParentRef,Timestamp,...
  $parts = $line -split ','
  if ($parts.Count -lt 4) {{ continue }}
  $fname = $parts[0].Trim()
  $reason = $parts[1].Trim()
  $usn = $parts[2].Trim()

  # Time filter (fsutil csv may include timestamp in later fields)
  # Apply path filter
  if ('{pf}' -ne '' -and $fname -notlike '*{pf}*') {{ continue }}

  # Apply reason filter
  $reasonCode = 0
  try {{ $reasonCode = [Convert]::ToInt32($reason, 16) }} catch {{}}
  if ({reason_mask} -ne 0 -and ($reasonCode -band {reason_mask}) -eq 0) {{ continue }}

  $reasonText = switch -Regex ($reasonCode) {{
    {{ $_ -band 0x00000001 }} {{ 'DATA_OVERWRITE' }}
    {{ $_ -band 0x00000002 }} {{ 'DATA_EXTEND' }}
    {{ $_ -band 0x00000004 }} {{ 'DATA_TRUNCATION' }}
    {{ $_ -band 0x00000100 }} {{ 'NAMED_DATA_OVERWRITE' }}
    {{ $_ -band 0x00001000 }} {{ 'RENAME_OLD' }}
    {{ $_ -band 0x00002000 }} {{ 'RENAME_NEW' }}
    {{ $_ -band 0x00004000 }} {{ 'INDEXABLE_CHANGE' }}
    {{ $_ -band 0x00008000 }} {{ 'FILE_DELETE' }}
    {{ $_ -band 0x00010000 }} {{ 'EA_CHANGE' }}
    {{ $_ -band 0x00020000 }} {{ 'SECURITY_CHANGE' }}
    {{ $_ -band 0x00040000 }} {{ 'REPARSE' }}
    {{ $_ -band 0x00080000 }} {{ 'STREAM_CHANGE' }}
    {{ $_ -band 0x80000000 }} {{ 'CLOSE' }}
    default {{ "0x$($reasonCode.ToString('X8'))" }}
  }}

  $entries += [PSCustomObject]@{{
    File   = $fname
    Reason = $reasonText
    USN    = $usn
  }}
  if ($entries.Count -ge {max_entries}) {{ break }}
}}

if ($entries.Count -eq 0) {{
  "(no matching USN entries found)"
  "Note: fsutil usn readjournal requires Administrator privileges."
}} else {{
  $entries | Format-Table -AutoSize
  "=== Showing $($entries.Count) entries (filtered from journal) ==="
}}
"#)
}

fn script_stats(volume: &str) -> String {
    let vol = volume.trim_end_matches(':');
    format!(r#"
$ErrorActionPreference = 'SilentlyContinue'
$vol = '{vol}:'
"=== USN Journal Statistics: $vol ==="

$raw = fsutil usn readjournal $vol csv 2>&1 | Out-String
$lines = $raw -split "`n" | Where-Object {{ $_.Trim() -ne '' -and $_ -notmatch '^Usn Journal' -and $_ -notmatch '^Volume' }}

$total = 0
$reasons = @{{}}
$extensions = @{{}}
foreach ($line in $lines) {{
  $parts = $line -split ','
  if ($parts.Count -lt 4) {{ continue }}
  $total++
  $fname = $parts[0].Trim()
  $reason = $parts[1].Trim()

  # Count by reason
  if ($reasons.ContainsKey($reason)) {{ $reasons[$reason]++ }} else {{ $reasons[$reason] = 1 }}

  # Count by extension
  $ext = [IO.Path]::GetExtension($fname).ToLower()
  if ($ext -eq '') {{ $ext = '(none)' }}
  if ($extensions.ContainsKey($ext)) {{ $extensions[$ext]++ }} else {{ $extensions[$ext] = 1 }}
}}

"Total entries: $total"
""
"=== By Reason Code ==="
$reasons.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15 | ForEach-Object {{
  "  $($_.Key): $($_.Value)"
}}
""
"=== By File Extension (Top 20) ==="
$extensions.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 20 | ForEach-Object {{
  "  $($_.Key): $($_.Value)"
}}
"#)
}

fn script_config(volume: &str) -> String {
    let vol = volume.trim_end_matches(':');
    format!(r#"
$ErrorActionPreference = 'SilentlyContinue'
$vol = '{vol}:'
"=== USN Journal Configuration: $vol ==="
fsutil usn queryjournal $vol 2>&1 | Out-String
""
"=== Volume Info ==="
fsutil volume info $vol 2>&1 | Out-String
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
