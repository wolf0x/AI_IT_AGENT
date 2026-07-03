use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct IrFileTool;

const PS_PREFIX: &str = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ";

#[async_trait]
impl Tool for IrFileTool {
    fn name(&self) -> &str { "ir_file" }
    fn description(&self) -> &str {
        "File forensics: scan temp directories, downloads, recent executables, prefetch, alternate data streams (ADS), and compute file hashes. Returns risk-classified file listings."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["all", "temp", "downloads", "executables", "prefetch", "ads", "hash"],
                    "description": "File forensics category (default 'all')"
                },
                "path": {
                    "type": "string",
                    "description": "File path for hash computation (required for category='hash')"
                },
                "days": {
                    "type": "integer",
                    "description": "Lookback days for file modification time (default 7)"
                }
            }
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let category = args["category"].as_str().unwrap_or("all");
        let days = args["days"].as_u64().unwrap_or(7);

        if category == "hash" {
            let path = args["path"].as_str().ok_or("Missing 'path' for hash action")?;
            let script = format!("{}{}", PS_PREFIX, script_hash(path));
            let raw = run_ps_raw(&script).await?;
            return Ok(json!({ "status": "ok", "category": "hash", "result": raw.trim() }));
        }

        let categories: Vec<&str> = if category == "all" {
            vec!["temp", "downloads", "executables", "prefetch", "ads"]
        } else {
            vec![category]
        };

        let mut combined = String::new();
        for cat in categories {
            let script = match cat {
                "temp" => script_temp(days),
                "downloads" => script_downloads(days),
                "executables" => script_executables(days),
                "prefetch" => script_prefetch(),
                "ads" => script_ads(),
                _ => continue,
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

fn script_temp(days: u64) -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
$cutoff = (Get-Date).AddDays(-{})
$roots = @("$env:TEMP", "$env:WINDIR\Temp", "$env:LOCALAPPDATA\Temp")
$out=@()
foreach($root in $roots){{
  if(-not (Test-Path $root)){{ continue }}
  Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {{ $_.LastWriteTime -gt $cutoff }} |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 120 |
    ForEach-Object {{
      $risk='low'
      $ext=$_.Extension.ToLower()
      if($ext -in @('.exe','.dll','.ps1','.vbs','.js','.bat','.cmd')){{ $risk='medium' }}
      $out+=[PSCustomObject]@{{
        path=$_.FullName
        size=$_.Length
        lastWrite=$_.LastWriteTime.ToString('o')
        extension=$ext
        risk=$risk
      }}
    }}
}}
@($out) | ConvertTo-Json -Depth 3 -Compress
"#, days)
}

fn script_downloads(days: u64) -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
$cutoff = (Get-Date).AddDays(-{})
$root = "$env:USERPROFILE\Downloads"
$out=@()
if(Test-Path $root){{
  Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {{ $_.LastWriteTime -gt $cutoff }} |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 120 |
    ForEach-Object {{
      $risk='low'
      $ext=$_.Extension.ToLower()
      if($ext -in @('.exe','.dll','.msi','.ps1','.vbs','.js','.bat','.cmd')){{ $risk='medium' }}
      $out+=[PSCustomObject]@{{
        path=$_.FullName
        size=$_.Length
        lastWrite=$_.LastWriteTime.ToString('o')
        extension=$ext
        risk=$risk
      }}
    }}
}}
@($out) | ConvertTo-Json -Depth 3 -Compress
"#, days)
}

fn script_executables(days: u64) -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
$cutoff = (Get-Date).AddDays(-{})
$roots = @("$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA","$env:USERPROFILE\Downloads","C:\Users\Public","$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
$out=@()
foreach($root in $roots){{
  if(-not (Test-Path $root)){{ continue }}
  Get-ChildItem -Path $root -Recurse -Include *.exe,*.dll,*.ps1,*.vbs,*.js,*.bat,*.cmd -File -ErrorAction SilentlyContinue |
    Where-Object {{ $_.LastWriteTime -gt $cutoff }} |
    ForEach-Object {{
      $risk='low'
      $ext=$_.Extension.ToLower()
      $p=$_.FullName.ToLower()
      if($ext -in @('.ps1','.vbs','.js','.bat','.cmd')){{ $risk='medium' }}
      if($ext -eq '.exe' -and ($p -match 'temp|appdata|downloads|public')){{ $risk='medium' }}
      $out+=[PSCustomObject]@{{
        path=$_.FullName
        size=$_.Length
        lastWrite=$_.LastWriteTime.ToString('o')
        extension=$ext
        risk=$risk
      }}
    }}
}}
@($out) | Sort-Object lastWrite -Descending | Select-Object -First 180 | ConvertTo-Json -Depth 3 -Compress
"#, days)
}

fn script_prefetch() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
$root = "$env:WINDIR\Prefetch"
$out=@()
if(Test-Path $root){
  Get-ChildItem -Path $root -Filter *.pf -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 160 |
    ForEach-Object {
      $out+=[PSCustomObject]@{
        name=$_.Name
        path=$_.FullName
        size=$_.Length
        lastWrite=$_.LastWriteTime.ToString('o')
        lastAccess=$_.LastAccessTime.ToString('o')
      }
    }
}
@($out) | ConvertTo-Json -Depth 3 -Compress
"#.to_string()
}

fn script_ads() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
$roots = @("$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA","$env:USERPROFILE\Downloads")
$out=@()
foreach($root in $roots){
  if(-not (Test-Path $root)){ continue }
  Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
    Select-Object -First 200 |
    ForEach-Object {
      try {
        $streams = Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue
        $nonData = $streams | Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne '' }
        foreach($s in $nonData){
          $out+=[PSCustomObject]@{
            filePath=$_.FullName
            streamName=$s.Stream
            streamSize=$s.Length
          }
        }
      } catch {}
    }
}
@($out) | Select-Object -First 120 | ConvertTo-Json -Depth 3 -Compress
"#.to_string()
}

fn script_hash(path: &str) -> String {
    let escaped = path.replace('\'', "\\'").replace('"', "\\\"");
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
$filePath = '{}'
if(-not (Test-Path $filePath)){{
  '{{"error":"file not found"}}'
  exit
}}
$fi = Get-Item $filePath -ErrorAction SilentlyContinue
$md5 = (Get-FileHash $filePath -Algorithm MD5 -ErrorAction SilentlyContinue).Hash
$sha1 = (Get-FileHash $filePath -Algorithm SHA1 -ErrorAction SilentlyContinue).Hash
$sha256 = (Get-FileHash $filePath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
$sig = Get-AuthenticodeSignature $filePath -ErrorAction SilentlyContinue
$sigStatus = 'unknown'
$sigSubject = ''
if($sig){{
  $sigStatus = [string]$sig.Status
  if($sig.SignerCertificate){{ $sigSubject = $sig.SignerCertificate.Subject }}
}}
[PSCustomObject]@{{
  path=$filePath
  size=$fi.Length
  lastWrite=$fi.LastWriteTime.ToString('o')
  md5=$md5
  sha1=$sha1
  sha256=$sha256
  signatureStatus=$sigStatus
  signatureSubject=$sigSubject
}} | ConvertTo-Json -Depth 3 -Compress
"#, escaped)
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
