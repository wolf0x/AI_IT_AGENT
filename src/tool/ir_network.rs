use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct IrNetworkTool;

const PS_PREFIX: &str = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ";

#[async_trait]
impl Tool for IrNetworkTool {
    fn name(&self) -> &str { "ir_network" }
    fn description(&self) -> &str {
        "Incident response network analysis. Checks active connections, DNS cache, routing table, proxy settings, firewall rules, and lateral movement traces (SMB shares, sessions, PsExec)."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["all", "connections", "dns", "routes", "proxy", "firewall", "lateral"],
                    "description": "Which network category to check (default 'all')"
                }
            }
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let category = args["category"].as_str().unwrap_or("all");

        let categories: Vec<&str> = if category == "all" {
            vec!["connections", "dns", "routes", "proxy", "firewall", "lateral"]
        } else {
            vec![category]
        };

        let mut combined = String::new();
        for cat in categories {
            let script = match cat {
                "connections" => script_connections(),
                "dns" => script_dns(),
                "routes" => script_routes(),
                "proxy" => script_proxy(),
                "firewall" => script_firewall(),
                "lateral" => script_lateral(),
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

fn script_connections() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== Established TCP Connections ==="
Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Format-Table -AutoSize
"=== Listening Ports ==="
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess, @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Sort-Object LocalPort | Format-Table -AutoSize
"=== UDP Listeners ==="
Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess, @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Sort-Object LocalPort | Format-Table -AutoSize
"#.to_string()
}

fn script_dns() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== DNS Cache ==="
Get-DnsClientCache | Select-Object -First 100 Name, Type, Data, TimeToLive | Format-Table -AutoSize
"=== DNS Client Settings ==="
Get-DnsClientGlobalSetting | Select-Object SuffixSearchList, Devolution | Format-List
"=== DNS Server Addresses ==="
Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 } | Select-Object InterfaceAlias, ServerAddresses | Format-Table -AutoSize
"#.to_string()
}

fn script_routes() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== IPv4 Route Table ==="
Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias | Sort-Object DestinationPrefix | Format-Table -AutoSize
"=== Default Gateway ==="
Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } | Select-Object NextHop, RouteMetric, InterfaceAlias | Format-Table -AutoSize
"=== ARP Table ==="
Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne 'Unreachable' } | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias | Format-Table -AutoSize
"#.to_string()
}

fn script_proxy() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== WinHTTP Proxy ==="
netsh winhttp show proxy
"=== IE/System Proxy Settings ==="
$proxyKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$proxy = Get-ItemProperty $proxyKey -ErrorAction SilentlyContinue
"ProxyEnable: $($proxy.ProxyEnable)"
"ProxyServer: $($proxy.ProxyServer)"
"ProxyOverride: $($proxy.ProxyOverride)"
"AutoConfigURL: $($proxy.AutoConfigURL)"
"=== WinINET Proxy Auto Config ==="
if ($proxy.AutoConfigURL) {
  "Auto Config URL: $($proxy.AutoConfigURL)"
}
"#.to_string()
}

fn script_firewall() -> String {
    r#"
$ErrorActionPreference='SilentlyContinue'
"=== Firewall Profiles ==="
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize
"=== Recently Added Firewall Rules (last 30 days) ==="
$cutoff = (Get-Date).AddDays(-30)
Get-NetFirewallRule | Where-Object { $_.DateCreated -and $_.DateCreated -gt $cutoff } | Select-Object -First 50 DisplayName, Direction, Action, Enabled, Profile, @{N='Program';E={($_ | Get-NetFirewallApplicationFilter).Program}} | Format-Table -AutoSize
"=== Allow Rules with Programs ==="
Get-NetFirewallApplicationFilter | Where-Object { $_.Program -and $_.Program -ne 'Any' } | ForEach-Object {
  $rule = $_ | Get-NetFirewallRule
  if ($rule.Action -eq 'Allow' -and $rule.Enabled -eq 'True') {
    [PSCustomObject]@{Name=$rule.DisplayName; Direction=$rule.Direction; Program=$_.Program; Profile=$rule.Profile}
  }
} | Select-Object -First 50 | Format-Table -AutoSize
"#.to_string()
}

fn script_lateral() -> String {
    r#"
$ErrorActionPreference='Continue'
"=== SMB Shares ==="
Get-SmbShare -ErrorAction SilentlyContinue | Format-Table Name,Path,Description,ConcurrentUserLimit -AutoSize
"=== Open Files ==="
Get-SmbOpenFile -ErrorAction SilentlyContinue | Select-Object -First 100 ClientUserName,ClientComputerName,Path,SessionID | Format-Table -AutoSize
"=== SMB Sessions (Inbound) ==="
Get-SmbSession -ErrorAction SilentlyContinue | Select-Object ClientUserName,ClientComputerName,Dialect,SessionID | Format-Table -AutoSize
"=== SMB Connections (Outbound) ==="
Get-SmbConnection -ErrorAction SilentlyContinue | Select-Object ServerName,ShareName,UserName,Dialect | Format-Table -AutoSize
"=== SMB Mappings ==="
Get-SmbMapping -ErrorAction SilentlyContinue | Select-Object LocalPath,RemotePath,Status | Format-Table -AutoSize
"=== PsExec Traces (PSEXESVC) ==="
Get-Service -Name PSEXESVC -ErrorAction SilentlyContinue | Format-List Name,Status,StartType
"=== Remote Desktop Users ==="
try { net localgroup "Remote Desktop Users" 2>$null } catch {}
"=== Distributed COM Users ==="
try { net localgroup "Distributed COM Users" 2>$null } catch {}
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
