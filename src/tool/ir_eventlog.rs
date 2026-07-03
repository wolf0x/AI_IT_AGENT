use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct IrEventLogTool;

const PS_PREFIX: &str = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ";

#[async_trait]
impl Tool for IrEventLogTool {
    fn name(&self) -> &str { "ir_eventlog" }
    fn description(&self) -> &str {
        "Structured Windows event log extraction. Queries specific event categories (logons, failures, account-changes, service-install, log-cleared, powershell, sysmon, process-create) and returns parsed JSON with event properties."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["logons","failures","account-changes","service-install","log-cleared","powershell","sysmon","process-create","custom"],
                    "description": "Event category to extract (default 'logons')"
                },
                "days": { "type": "integer", "description": "Lookback days (default 7)" },
                "max_events": { "type": "integer", "description": "Max events to return (default 200)" },
                "log_name": { "type": "string", "description": "Custom log name (for category='custom')" },
                "event_ids": { "type": "string", "description": "Comma-separated event IDs (for category='custom')" }
            }
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let category = args["category"].as_str().unwrap_or("logons");
        let days = args["days"].as_u64().unwrap_or(7);
        let max_events = args["max_events"].as_u64().unwrap_or(200);

        let script = match category {
            "logons" => script_logons(days, max_events),
            "failures" => script_failures(days, max_events),
            "account-changes" => script_account_changes(days, max_events),
            "service-install" => script_service_install(days, max_events),
            "log-cleared" => script_log_cleared(days, max_events),
            "powershell" => script_powershell(days, max_events),
            "sysmon" => script_sysmon(days, max_events),
            "process-create" => script_process_create(days, max_events),
            "custom" => {
                let log_name = args["log_name"].as_str().unwrap_or("Security");
                let event_ids = args["event_ids"].as_str().unwrap_or("");
                script_custom(days, max_events, log_name, event_ids)
            }
            _ => return Err(format!("Unknown category: {}", category).into()),
        };

        let full = format!("{}{}", PS_PREFIX, script);
        let raw = run_ps_raw(&full).await?;

        // Try to parse as JSON array
        let events: Value = match serde_json::from_str(raw.trim()) {
            Ok(v) => v,
            Err(_) => json!({ "raw": raw.trim() }),
        };

        Ok(json!({
            "status": "ok",
            "category": category,
            "days": days,
            "events": events,
        }))
    }
}

/// Helper: PowerShell function to parse event XML properties
fn ps_read_event_data() -> &'static str {
    r#"
function Read-EventData($ev){
  $props=@{}
  try{
    $xml=[xml]$ev.ToXml()
    $ns=New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
    foreach($d in $xml.SelectNodes('//e:Data',$ns)){
      $n=[string]$d.GetAttribute('Name')
      if($n){ $props[$n]=[string]$d.InnerText }
    }
  }catch{}
  return $props
}
function Clean($v){ $s=[string]$v; if($s -eq '-'){return ''}; return $s.Trim() }
"#
}

fn script_logons(days: u64, max: u64) -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
{}
$days = {}
$maxEv = {}
$start = (Get-Date).AddDays(-$days)
$remoteTypes=@(2,3,4,7,8,9,10,11)
$out=@()
Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4624;StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | ForEach-Object {{
  $p=Read-EventData $_
  $user=Clean($p['TargetUserName'])
  $ip=Clean($p['IpAddress'])
  $logonType=[int]$p['LogonType']
  $isRemote=$remoteTypes -contains $logonType
  $out+=[PSCustomObject]@{{
    time=$_.TimeCreated.ToString('o')
    eventId=4624
    user=$user
    domain=Clean($p['TargetDomainName'])
    logonType=$logonType
    isRemote=$isRemote
    sourceIP=$ip
    workstation=Clean($p['WorkstationName'])
    processName=Clean($p['ProcessName'])
  }}
}}
@($out) | ConvertTo-Json -Depth 3 -Compress
"#, ps_read_event_data(), days, max)
}

fn script_failures(days: u64, max: u64) -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
{}
$days = {}
$maxEv = {}
$start = (Get-Date).AddDays(-$days)
$out=@()
Get-WinEvent -FilterHashtable @{{LogName='Security';Id=@(4625,4771,4776);StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | ForEach-Object {{
  $p=Read-EventData $_
  $user=Clean($p['TargetUserName'])
  $ip=Clean($p['IpAddress'])
  if(-not $ip){{ $ip=Clean($p['SourceNetworkAddress']) }}
  $out+=[PSCustomObject]@{{
    time=$_.TimeCreated.ToString('o')
    eventId=[int]$_.Id
    user=$user
    domain=Clean($p['TargetDomainName'])
    sourceIP=$ip
    failReason=Clean($p['Status'])
    subStatus=Clean($p['SubStatus'])
    processName=Clean($p['ProcessName'])
  }}
}}
@($out) | ConvertTo-Json -Depth 3 -Compress
"#, ps_read_event_data(), days, max)
}

fn script_account_changes(days: u64, max: u64) -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
{}
$days = {}
$maxEv = {}
$start = (Get-Date).AddDays(-$days)
$out=@()
Get-WinEvent -FilterHashtable @{{LogName='Security';Id=@(4720,4722,4723,4724,4725,4726,4728,4729,4732,4733,4738,4740);StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | ForEach-Object {{
  $p=Read-EventData $_
  $subject=Clean($p['SubjectUserName'])
  $target=Clean($p['TargetUserName'])
  $out+=[PSCustomObject]@{{
    time=$_.TimeCreated.ToString('o')
    eventId=[int]$_.Id
    action=(switch([int]$_.Id){{4720>{{'created'}}4722>{{'enabled'}}4723>{{'password_attempt'}}4724>{{'password_reset'}}4725>{{'disabled'}}4726>{{'deleted'}}4728>{{'added_to_group'}}4729>{{'removed_from_group'}}4732>{{'added_to_group'}}4733>{{'removed_from_group'}}4738>{{'changed'}}4740>{{'locked_out'}}default>{{'unknown'}}}})
    subject=$subject
    target=$target
    targetDomain=Clean($p['TargetDomainName'])
  }}
}}
@($out) | ConvertTo-Json -Depth 3 -Compress
"#, ps_read_event_data(), days, max)
}

fn script_service_install(days: u64, max: u64) -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
$days = {}
$maxEv = {}
$start = (Get-Date).AddDays(-$days)
$out=@()
Get-WinEvent -FilterHashtable @{{LogName='System';Id=7045;StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | ForEach-Object {{
  $p=@{{}}
  try{{
    $xml=[xml]$_.ToXml()
    $ns=New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
    $nodes=$xml.SelectNodes('//e:EventData/e:Data',$ns)
    if($nodes.Count -ge 3){{
      $p['ServiceName']=$nodes[0].InnerText
      $p['ImagePath']=$nodes[1].InnerText
      $p['StartType']=$nodes[2].InnerText
    }}
  }}catch{{}}
  $out+=[PSCustomObject]@{{
    time=$_.TimeCreated.ToString('o')
    eventId=7045
    serviceName=[string]$p['ServiceName']
    imagePath=[string]$p['ImagePath']
    startType=[string]$p['StartType']
    accountName=Clean($p['AccountName'])
  }}
}}
function Clean($v){{ $s=[string]$v; if($s -eq '-'){{return ''}}; return $s.Trim() }}
@($out) | ConvertTo-Json -Depth 3 -Compress
"#, days, max)
}

fn script_log_cleared(days: u64, max: u64) -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
$days = {}
$maxEv = {}
$start = (Get-Date).AddDays(-$days)
$out=@()
Get-WinEvent -FilterHashtable @{{LogName='Security';Id=1102;StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | ForEach-Object {{
  $out+=[PSCustomObject]@{{
    time=$_.TimeCreated.ToString('o')
    eventId=1102
    user=$_.UserId
    message=$_.Message.Substring(0, [Math]::Min(500, $_.Message.Length))
  }}
}}
# Also check System log for audit log cleared
Get-WinEvent -FilterHashtable @{{LogName='System';Id=@(6005,6006,6008);StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | ForEach-Object {{
  $out+=[PSCustomObject]@{{
    time=$_.TimeCreated.ToString('o')
    eventId=[int]$_.Id
    action=(switch([int]$_.Id){{6005{{'event_log_started'}}6006{{'event_log_stopped'}}6008{{'unexpected_shutdown'}}default{{'unknown'}}}})
    message=$_.Message.Substring(0, [Math]::Min(300, $_.Message.Length))
  }}
}}
@($out) | ConvertTo-Json -Depth 3 -Compress
"#, days, max)
}

fn script_powershell(days: u64, max: u64) -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
$days = {}
$maxEv = {}
$start = (Get-Date).AddDays(-$days)
$out=@()
Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | ForEach-Object {{
  $scriptBlock=''
  try{{
    $xml=[xml]$_.ToXml()
    $ns=New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
    $nodes=$xml.SelectNodes('//e:EventData/e:Data',$ns)
    if($nodes.Count -ge 3){{ $scriptBlock=$nodes[2].InnerText }}
  }}catch{{}}
  $out+=[PSCustomObject]@{{
    time=$_.TimeCreated.ToString('o')
    eventId=4104
    scriptBlockId=Clean($_.Properties[0].Value)
    path=Clean($_.Properties[1].Value)
    scriptBlock=$scriptBlock.Substring(0, [Math]::Min(2000, $scriptBlock.Length))
    userId=$_.UserId
  }}
}}
function Clean($v){{ $s=[string]$v; if($s -eq '-'){{return ''}}; return $s.Trim() }}
@($out) | ConvertTo-Json -Depth 3 -Compress
"#, days, max)
}

fn script_sysmon(days: u64, max: u64) -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
$days = {}
$maxEv = {}
$start = (Get-Date).AddDays(-$days)
$out=@()
# Process Create (1), Network Connect (3), Raw Access Read (9), Remote Thread (10)
foreach($eid in @(1,3,9,10)){{
  Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Sysmon/Operational';Id=$eid;StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | ForEach-Object {{
    $p=@{{}}
    try{{
      $xml=[xml]$_.ToXml()
      $ns=New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
      $ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
      foreach($d in $xml.SelectNodes('//e:Data',$ns)){{
        $n=[string]$d.GetAttribute('Name')
        if($n){{ $p[$n]=[string]$d.InnerText }}
      }}
    }}catch{{}}
    $out+=[PSCustomObject]@{{
      time=$_.TimeCreated.ToString('o')
      eventId=$eid
      image=Clean($p['Image'])
      commandLine=Clean($p['CommandLine'])
      parentImage=Clean($p['ParentImage'])
      user=Clean($p['User'])
      destIP=Clean($p['DestinationIp'])
      destPort=Clean($p['DestinationPort'])
      destHostname=Clean($p['DestinationHostname'])
      targetFilename=Clean($p['TargetFilename'])
    }}
  }}
}}
function Clean($v){{ $s=[string]$v; if($s -eq '-'){{return ''}}; return $s.Trim() }}
@($out) | ConvertTo-Json -Depth 3 -Compress
"#, days, max)
}

fn script_process_create(days: u64, max: u64) -> String {
    format!(r#"
$ErrorActionPreference='SilentlyContinue'
$days = {}
$maxEv = {}
$start = (Get-Date).AddDays(-$days)
$out=@()
Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4688;StartTime=$start}} -MaxEvents $maxEv -ErrorAction SilentlyContinue | ForEach-Object {{
  $p=@{{}}
  try{{
    $xml=[xml]$_.ToXml()
    $ns=New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
    foreach($d in $xml.SelectNodes('//e:Data',$ns)){{
      $n=[string]$d.GetAttribute('Name')
      if($n){{ $p[$n]=[string]$d.InnerText }}
    }}
  }}catch{{}}
  $out+=[PSCustomObject]@{{
    time=$_.TimeCreated.ToString('o')
    eventId=4688
    subjectUser=Clean($p['SubjectUserName'])
    newProcessId=Clean($p['NewProcessId'])
    newProcessName=Clean($p['NewProcessName'])
    commandLine=Clean($p['CommandLine'])
    parentProcessName=Clean($p['ParentProcessName'])
    tokenElevationType=Clean($p['TokenElevationType'])
  }}
}}
function Clean($v){{ $s=[string]$v; if($s -eq '-'){{return ''}}; return $s.Trim() }}
@($out) | ConvertTo-Json -Depth 3 -Compress
"#, days, max)
}

fn script_custom(days: u64, max: u64, log_name: &str, event_ids: &str) -> String {
    let ids_array = if event_ids.is_empty() {
        String::from("*")
    } else {
        let ids: Vec<&str> = event_ids.split(',').collect();
        format!("@({})", ids.join(","))
    };

    format!(r#"
$ErrorActionPreference='SilentlyContinue'
$days = {}
$maxEv = {}
$start = (Get-Date).AddDays(-$days)
$out=@()
$filter=@{{LogName='{}';StartTime=$start}}
if('{}' -ne '*'){{ $filter['Id']={} }}
Get-WinEvent -FilterHashtable $filter -MaxEvents $maxEv -ErrorAction SilentlyContinue | ForEach-Object {{
  $msg=[string]$_.Message
  if($msg.Length -gt 1000){{ $msg=$msg.Substring(0,1000)+'...' }}
  $out+=[PSCustomObject]@{{
    time=$_.TimeCreated.ToString('o')
    eventId=[int]$_.Id
    level=[int]$_.Level
    provider=$_.ProviderName
    message=$msg
  }}
}}
@($out) | ConvertTo-Json -Depth 3 -Compress
"#, days, max, log_name, ids_array, ids_array)
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
