use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct IrDriverTool;

const PS_PREFIX: &str = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ";

#[async_trait]
impl Tool for IrDriverTool {
    fn name(&self) -> &str { "ir_driver" }
    fn description(&self) -> &str {
        "Driver signature analysis. Scans system driver files (.sys) for Authenticode signature validity, categorizes into unsigned/non-MS/revoked, and lists loaded kernel drivers."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["all", "signature-scan", "loaded", "third-party"],
                    "description": "Driver analysis category (default 'all')"
                }
            }
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let category = args["category"].as_str().unwrap_or("all");

        let categories: Vec<&str> = if category == "all" {
            vec!["signature-scan", "loaded", "third-party"]
        } else {
            vec![category]
        };

        let mut combined = String::new();
        for cat in categories {
            let script = match cat {
                "signature-scan" => script_signature_scan(),
                "loaded" => script_loaded_drivers(),
                "third-party" => script_third_party(),
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

fn script_signature_scan() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
$dirs = @("$env:WINDIR\System32\drivers", "$env:WINDIR\SysWOW64\drivers")
$out = @{total=0; unsigned=@(); nonMs=@(); revoked=@(); msSigned=0}
foreach($dir in $dirs){
  if(-not (Test-Path $dir)){ continue }
  $all = Get-ChildItem -Path $dir -Filter *.sys -File -ErrorAction SilentlyContinue
  $out.total += $all.Count
  foreach($f in $all){
    $sig = Get-AuthenticodeSignature -FilePath $f.FullName -ErrorAction SilentlyContinue
    if(-not $sig){ continue }
    if($sig.Status -eq 'NotSigned' -or $sig.Status -eq 'UnknownError'){
      $out.unsigned += $f.Name
    }
    elseif($sig.Status -eq 'HashMismatch' -or $sig.Status -eq 'NotTrusted' -or $sig.Status -eq 'Distrusted'){
      $out.revoked += $f.Name
    }
    elseif($sig.SignerCertificate){
      $subj = $sig.SignerCertificate.Subject
      if($subj -notmatch 'Microsoft'){
        $out.nonMs += ($f.Name + ' | ' + ($subj -replace ',.*$',''))
      } else {
        $out.msSigned++
      }
    }
  }
}
"Total driver files: $($out.total)"
"Microsoft-signed: $($out.msSigned)"
"--- Unsigned ($($out.unsigned.Count)) ---"
$out.unsigned | Select-Object -First 80
"--- Non-Microsoft signed ($($out.nonMs.Count)) ---"
$out.nonMs | Select-Object -First 80
"--- Revoked/Mismatch/Untrusted ($($out.revoked.Count)) ---"
$out.revoked | Select-Object -First 80
"#.to_string()
}

fn script_loaded_drivers() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== Loaded Kernel Drivers ==="
driverquery /v /fo csv 2>$null | ConvertFrom-Csv -ErrorAction SilentlyContinue |
  Select-Object 'Display Name','Module Name',Status,'Link Date',Path |
  Sort-Object 'Link Date' -Descending |
  Select-Object -First 300 |
  Format-Table -AutoSize
"#.to_string()
}

fn script_third_party() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== Third-Party Drivers (non-Microsoft, loaded) ==="
driverquery /v /fo csv 2>$null | ConvertFrom-Csv -ErrorAction SilentlyContinue |
  Where-Object { $_.Path -and $_.Path -notmatch 'Microsoft|Windows|\\System32\\' } |
  Select-Object -First 100 'Display Name','Module Name',Status,'Link Date',Path |
  Format-Table -AutoSize
"=== Driver Store (pnputil) ==="
pnputil /enum-drivers 2>$null | Select-Object -First 100
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
