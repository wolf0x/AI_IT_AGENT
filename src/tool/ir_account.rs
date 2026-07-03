use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct IrAccountTool;

const PS_PREFIX: &str = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ";

/// PowerShell script that enumerates local accounts with hidden/admin detection.
const ACCOUNT_SCRIPT: &str = r#"
$ErrorActionPreference='SilentlyContinue'
$adminMap=@{}
try {
  Get-LocalGroupMember -Group 'Administrators' | ForEach-Object {
    $n=[string]$_.Name
    if($n){ $adminMap[$n.ToLower()]=$true; $adminMap[(($n -split '\\')[-1]).ToLower()]=$true }
  }
} catch {}
$hiddenMap=@{}
try {
  $hiddenKey='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
  $hiddenProps=Get-ItemProperty -Path $hiddenKey -ErrorAction SilentlyContinue
  if($hiddenProps){
    $hiddenProps.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
      $hiddenMap[$_.Name.ToLowerInvariant()] = ([int]$_.Value -eq 0)
    }
  }
} catch {}
$items = Get-LocalUser | ForEach-Object {
  $accountName=[string]$_.Name
  $accountKey=$accountName.ToLowerInvariant()
  [PSCustomObject]@{
    name = $accountName
    enabled = [bool]$_.Enabled
    sid = [string]$_.SID
    lastLogon = if ($_.LastLogon) { $_.LastLogon.ToString('o') } else { '' }
    passwordLastSet = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('o') } else { '' }
    description = [string]$_.Description
    passwordRequired = [bool]$_.PasswordRequired
    userMayChangePassword = [bool]$_.UserMayChangePassword
    admin = [bool]$adminMap.ContainsKey($accountKey)
    hidden = [bool]($accountName.EndsWith('$') -or ($hiddenMap.ContainsKey($accountKey) -and $hiddenMap[$accountKey]))
  }
}
@($items) | ConvertTo-Json -Depth 4 -Compress
"#;

#[async_trait]
impl Tool for IrAccountTool {
    fn name(&self) -> &str { "ir_account" }
    fn description(&self) -> &str {
        "Incident response account audit. Enumerates all local user accounts with hidden account detection, administrator group membership, password policy, and last logon times."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {}
        })
    }

    async fn execute(&self, _args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let script = format!("{}{}", PS_PREFIX, ACCOUNT_SCRIPT);
        let raw = run_ps_raw(&script).await?;

        let accounts: Vec<Value> = match serde_json::from_str(raw.trim()) {
            Ok(Value::Array(arr)) => arr,
            Ok(single) => vec![single],
            Err(_) => return Ok(json!({ "status": "ok", "raw": raw.trim(), "accounts": [] })),
        };

        // Add anomaly flags
        let mut flagged = Vec::new();
        for acct in &accounts {
            let mut anomalies: Vec<String> = Vec::new();
            let name = acct["name"].as_str().unwrap_or("");
            let enabled = acct["enabled"].as_bool().unwrap_or(false);
            let hidden = acct["hidden"].as_bool().unwrap_or(false);
            let admin = acct["admin"].as_bool().unwrap_or(false);
            let pwd_required = acct["passwordRequired"].as_bool().unwrap_or(false);
            let last_logon = acct["lastLogon"].as_str().unwrap_or("");

            if hidden { anomalies.push("hidden account".into()); }
            if enabled && !pwd_required && name != "Guest" {
                anomalies.push("enabled without password requirement".into());
            }
            if admin && hidden { anomalies.push("hidden admin account (HIGH RISK)".into()); }
            if enabled && last_logon.is_empty() && name != "DefaultAccount"
                && name != "WDAGUtilityAccount" && name != "Guest"
            {
                anomalies.push("enabled but never logged on (possible backdoor)".into());
            }

            if !anomalies.is_empty() {
                flagged.push(json!({
                    "name": name,
                    "enabled": enabled,
                    "admin": admin,
                    "hidden": hidden,
                    "anomalies": anomalies,
                    "full": acct,
                }));
            }
        }

        let total = accounts.len();
        let admin_count = accounts.iter().filter(|a| a["admin"].as_bool().unwrap_or(false)).count();
        let hidden_count = accounts.iter().filter(|a| a["hidden"].as_bool().unwrap_or(false)).count();
        let enabled_count = accounts.iter().filter(|a| a["enabled"].as_bool().unwrap_or(false)).count();

        Ok(json!({
            "status": "ok",
            "summary": {
                "total_accounts": total,
                "enabled": enabled_count,
                "admins": admin_count,
                "hidden": hidden_count,
                "flagged": flagged.len(),
            },
            "flagged_accounts": flagged,
            "all_accounts": accounts,
        }))
    }
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
