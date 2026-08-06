use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::process::Command;

use super::{TimeoutStage, Tool};
use crate::context::ToolContext;
use crate::error::AgentResult;

/// Timeline reconstruction tool for incident response.
/// Correlates timestamped events from multiple Windows sources into a
/// unified chronological view, enabling analysts to reconstruct attack sequences.
pub struct IrTimelineTool;

const PS_PREFIX: &str = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ";

/// A single timeline event with risk scoring.
#[derive(Debug, Clone)]
struct TimelineEvent {
    timestamp: String,
    source: String,
    event_type: String,
    description: String,
    risk_score: u8,
    details: String,
}

#[async_trait]
impl Tool for IrTimelineTool {
    fn name(&self) -> &str { "ir_timeline" }
    fn description(&self) -> &str {
        "Reconstruct a chronological timeline of security-relevant events. Correlates process creation, \
         logon events, service installs, network connections, file modifications, and persistence \
         changes into a unified timeline with risk scoring. Use after IR collection to visualize the attack sequence."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn timeout_stage(&self) -> TimeoutStage { TimeoutStage::Long }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "hours": {
                    "type": "integer",
                    "description": "Lookback window in hours (default: 168 = 7 days). Use 720 for 30-day hunts."
                },
                "risk_filter": {
                    "type": "string",
                    "description": "Minimum risk level to include: 'low' (all), 'medium' (20+), 'high' (50+), 'critical' (80+)",
                    "enum": ["low", "medium", "high", "critical"]
                },
                "max_events": {
                    "type": "integer",
                    "description": "Maximum events to return (default: 200)"
                },
                "sources": {
                    "type": "string",
                    "description": "Comma-separated sources to include: processes,logons,services,network,persistence,powershell,defender. Default: all"
                }
            }
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let hours = args["hours"].as_u64().unwrap_or(168);
        let risk_filter = args["risk_filter"].as_str().unwrap_or("low");
        let max_events = args["max_events"].as_u64().unwrap_or(200) as usize;
        let sources_filter = args["sources"].as_str().unwrap_or("all");

        let min_risk: u8 = match risk_filter {
            "critical" => 80,
            "high" => 50,
            "medium" => 20,
            _ => 0,
        };

        let sources: Vec<&str> = if sources_filter == "all" {
            vec!["processes", "logons", "services", "network", "persistence", "powershell", "defender"]
        } else {
            sources_filter.split(',').map(|s| s.trim()).collect()
        };

        let mut events: Vec<TimelineEvent> = Vec::new();

        // Collect from each source concurrently where possible
        for source in &sources {
            match *source {
                "processes" => {
                    if let Ok(evts) = collect_process_events(hours).await {
                        events.extend(evts);
                    }
                }
                "logons" => {
                    if let Ok(evts) = collect_logon_events(hours).await {
                        events.extend(evts);
                    }
                }
                "services" => {
                    if let Ok(evts) = collect_service_events(hours).await {
                        events.extend(evts);
                    }
                }
                "network" => {
                    if let Ok(evts) = collect_network_snapshot().await {
                        events.extend(evts);
                    }
                }
                "persistence" => {
                    if let Ok(evts) = collect_persistence_events(hours).await {
                        events.extend(evts);
                    }
                }
                "powershell" => {
                    if let Ok(evts) = collect_powershell_events(hours).await {
                        events.extend(evts);
                    }
                }
                "defender" => {
                    if let Ok(evts) = collect_defender_events(hours).await {
                        events.extend(evts);
                    }
                }
                _ => {}
            }
        }

        // Sort chronologically (newest first for analyst review)
        events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Apply risk filter
        events.retain(|e| e.risk_score >= min_risk);

        // Truncate to max
        let total_before_truncate = events.len();
        events.truncate(max_events);

        // Compute summary statistics
        let critical = events.iter().filter(|e| e.risk_score >= 80).count();
        let high = events.iter().filter(|e| e.risk_score >= 50 && e.risk_score < 80).count();
        let medium = events.iter().filter(|e| e.risk_score >= 20 && e.risk_score < 50).count();
        let low = events.iter().filter(|e| e.risk_score < 20).count();

        // Build source breakdown
        let mut source_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for e in &events {
            *source_counts.entry(e.source.clone()).or_insert(0) += 1;
        }

        let events_json: Vec<Value> = events.iter().map(|e| {
            json!({
                "timestamp": e.timestamp,
                "source": e.source,
                "event_type": e.event_type,
                "description": e.description,
                "risk_score": e.risk_score,
                "risk_level": risk_level(e.risk_score),
                "details": e.details,
            })
        }).collect();

        Ok(json!({
            "status": "ok",
            "timeline": {
                "window_hours": hours,
                "total_events": total_before_truncate,
                "returned_events": events_json.len(),
                "risk_filter": risk_filter,
                "summary": {
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "low": low,
                },
                "source_breakdown": source_counts,
            },
            "events": events_json,
        }))
    }
}

fn risk_level(score: u8) -> &'static str {
    match score {
        80..=100 => "critical",
        50..=79 => "high",
        20..=49 => "medium",
        _ => "low",
    }
}

async fn run_ps(cmd: &str) -> AgentResult<String> {
    let full = format!("{}{}", PS_PREFIX, cmd);
    let mut c = Command::new("powershell");
    c.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &full]);
    c.creation_flags(0x08000000);
    c.kill_on_drop(true);
    match c.output().await {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(stdout.trim().to_string())
        }
        Err(e) => Err(format!("PowerShell execution failed: {}", e).into()),
    }
}

/// Collect recent process creation events from Security log (Event 4688) or Sysmon (Event 1).
async fn collect_process_events(hours: u64) -> AgentResult<Vec<TimelineEvent>> {
    let script = format!(
        r#"$cutoff = (Get-Date).AddHours(-{hours});
$events = @();
try {{
    $sysmon = Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=$cutoff}} -MaxEvents 100 -ErrorAction SilentlyContinue;
    if ($sysmon) {{
        foreach ($e in $sysmon) {{
            $xml = [xml]$e.ToXml();
            $data = $xml.Event.EventData.Data;
            $proc = ($data | Where-Object {{$_.Name -eq 'Image'}}).'#text';
            $cmdline = ($data | Where-Object {{$_.Name -eq 'CommandLine'}}).'#text';
            $parent = ($data | Where-Object {{$_.Name -eq 'ParentImage'}}).'#text';
            $events += "$($e.TimeCreated.ToString('o'))|PROCESS_CREATE|$proc|$cmdline|$parent";
        }}
    }}
}} catch {{}}
if ($events.Count -eq 0) {{
    try {{
        $sec = Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4688; StartTime=$cutoff}} -MaxEvents 100 -ErrorAction SilentlyContinue;
        if ($sec) {{
            foreach ($e in $sec) {{
                $xml = [xml]$e.ToXml();
                $data = $xml.Event.EventData.Data;
                $proc = ($data | Where-Object {{$_.Name -eq 'NewProcessName'}}).'#text';
                $cmdline = ($data | Where-Object {{$_.Name -eq 'CommandLine'}}).'#text';
                $parent = ($data | Where-Object {{$_.Name -eq 'ParentProcessName'}}).'#text';
                $events += "$($e.TimeCreated.ToString('o'))|PROCESS_CREATE|$proc|$cmdline|$parent";
            }}
        }}
    }} catch {{}}
}}
$events | Select-Object -First 100"#,
        hours = hours
    );

    let output = run_ps(&script).await?;
    let mut events = Vec::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.splitn(5, '|').collect();
        if parts.len() >= 4 {
            let timestamp = parts[0].to_string();
            let process = parts[2].to_string();
            let cmdline = parts[3].to_string();
            let parent = parts.get(4).unwrap_or(&"").to_string();

            let risk = score_process(&process, &cmdline, &parent);
            let desc = if cmdline.is_empty() {
                format!("Process created: {}", short_path(&process))
            } else {
                format!("Process created: {} ({})", short_path(&process), truncate_str(&cmdline, 120))
            };

            events.push(TimelineEvent {
                timestamp,
                source: "processes".to_string(),
                event_type: "ProcessCreate".to_string(),
                description: desc,
                risk_score: risk,
                details: format!("Process: {}\nCommandLine: {}\nParent: {}", process, cmdline, parent),
            });
        }
    }
    Ok(events)
}

/// Collect logon events (4624 success, 4625 failure, 4672 privileged).
async fn collect_logon_events(hours: u64) -> AgentResult<Vec<TimelineEvent>> {
    let script = format!(
        r#"$cutoff = (Get-Date).AddHours(-{hours});
$events = @();
try {{
    $logons = Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4624,4625,4672; StartTime=$cutoff}} -MaxEvents 150 -ErrorAction SilentlyContinue;
    if ($logons) {{
        foreach ($e in $logons) {{
            $xml = [xml]$e.ToXml();
            $data = $xml.Event.EventData.Data;
            $user = ($data | Where-Object {{$_.Name -eq 'TargetUserName'}}).'#text';
            $ip = ($data | Where-Object {{$_.Name -eq 'IpAddress'}}).'#text';
            $logonType = ($data | Where-Object {{$_.Name -eq 'LogonType'}}).'#text';
            $events += "$($e.TimeCreated.ToString('o'))|$($e.Id)|$user|$ip|$logonType";
        }}
    }}
}} catch {{}}
$events | Select-Object -First 150"#,
        hours = hours
    );

    let output = run_ps(&script).await?;
    let mut events = Vec::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.splitn(5, '|').collect();
        if parts.len() >= 4 {
            let timestamp = parts[0].to_string();
            let event_id = parts[1].to_string();
            let user = parts[2].to_string();
            let ip = parts[3].to_string();
            let logon_type = parts.get(4).unwrap_or(&"").to_string();

            let (event_type, risk, desc) = match event_id.as_str() {
                "4625" => (
                    "LogonFailure",
                    30u8,
                    format!("Failed logon: user={} from={}", user, ip),
                ),
                "4672" => (
                    "PrivilegedLogon",
                    60u8,
                    format!("Privileged logon (SeDebugPrivilege): user={} from={}", user, ip),
                ),
                _ => {
                    // 4624 - check logon type for risk
                    let risk = match logon_type.as_str() {
                        "3" => 15,  // Network logon
                        "10" => 25, // RemoteInteractive (RDP)
                        "7" => 10,  // Unlock
                        _ => 5,     // Interactive, etc.
                    };
                    (
                        "LogonSuccess",
                        risk,
                        format!("Logon: user={} type={} from={}", user, logon_type_name(&logon_type), ip),
                    )
                }
            };

            events.push(TimelineEvent {
                timestamp,
                source: "logons".to_string(),
                event_type: event_type.to_string(),
                description: desc,
                risk_score: risk,
                details: format!("EventID: {}\nUser: {}\nSourceIP: {}\nLogonType: {}", event_id, user, ip, logon_type),
            });
        }
    }
    Ok(events)
}

/// Collect service installation events (7045) and service start/stop (7036).
async fn collect_service_events(hours: u64) -> AgentResult<Vec<TimelineEvent>> {
    let script = format!(
        r#"$cutoff = (Get-Date).AddHours(-{hours});
$events = @();
try {{
    $svc = Get-WinEvent -FilterHashtable @{{LogName='System'; Id=7045,7036; StartTime=$cutoff}} -MaxEvents 80 -ErrorAction SilentlyContinue;
    if ($svc) {{
        foreach ($e in $svc) {{
            $xml = [xml]$e.ToXml();
            $data = $xml.Event.EventData.Data;
            $name = ($data | Where-Object {{$_.Name -eq 'ServiceName'}}).'#text';
            $path = ($data | Where-Object {{$_.Name -eq 'ImagePath'}}).'#text';
            $events += "$($e.TimeCreated.ToString('o'))|$($e.Id)|$name|$path";
        }}
    }}
}} catch {{}}
$events | Select-Object -First 80"#,
        hours = hours
    );

    let output = run_ps(&script).await?;
    let mut events = Vec::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.splitn(4, '|').collect();
        if parts.len() >= 3 {
            let timestamp = parts[0].to_string();
            let event_id = parts[1].to_string();
            let name = parts[2].to_string();
            let path = parts.get(3).unwrap_or(&"").to_string();

            let (event_type, risk, desc) = if event_id == "7045" {
                let risk = score_service_install(&name, &path);
                (
                    "ServiceInstall",
                    risk,
                    format!("Service installed: {} ({})", name, truncate_str(&path, 100)),
                )
            } else {
                (
                    "ServiceStateChange",
                    10u8,
                    format!("Service state change: {}", name),
                )
            };

            events.push(TimelineEvent {
                timestamp,
                source: "services".to_string(),
                event_type: event_type.to_string(),
                description: desc,
                risk_score: risk,
                details: format!("EventID: {}\nServiceName: {}\nImagePath: {}", event_id, name, path),
            });
        }
    }
    Ok(events)
}

/// Snapshot current network connections (point-in-time, not historical).
async fn collect_network_snapshot() -> AgentResult<Vec<TimelineEvent>> {
    let script = r#"Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object {$_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1'} |
    Select-Object -First 50 |
    ForEach-Object {
        $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName;
        "$($_.CreationTime.ToString('o'))|NET_CONNECTION|$($_.RemoteAddress):$($_.RemotePort)|$proc|$($_.LocalPort)"
    }"#;

    let output = run_ps(script).await?;
    let mut events = Vec::new();
    let now = chrono::Local::now().to_rfc3339();

    for line in output.lines() {
        let parts: Vec<&str> = line.splitn(5, '|').collect();
        if parts.len() >= 4 {
            let timestamp = if parts[0].is_empty() { now.clone() } else { parts[0].to_string() };
            let remote = parts[2].to_string();
            let process = parts[3].to_string();

            let risk = if is_external_ip(&remote) { 40 } else { 10 };

            events.push(TimelineEvent {
                timestamp,
                source: "network".to_string(),
                event_type: "NetworkConnection".to_string(),
                description: format!("Established connection: {} → {} (via {})", process, remote, parts.get(4).unwrap_or(&"?")),
                risk_score: risk,
                details: format!("Remote: {}\nProcess: {}\nLocalPort: {}", remote, process, parts.get(4).unwrap_or(&"")),
            });
        }
    }
    Ok(events)
}

/// Collect persistence-related events: scheduled task creation, registry Run keys.
async fn collect_persistence_events(hours: u64) -> AgentResult<Vec<TimelineEvent>> {
    let script = format!(
        r#"$cutoff = (Get-Date).AddHours(-{hours});
$events = @();
# Scheduled task creation (Event 4698)
try {{
    $tasks = Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4698; StartTime=$cutoff}} -MaxEvents 50 -ErrorAction SilentlyContinue;
    if ($tasks) {{
        foreach ($e in $tasks) {{
            $xml = [xml]$e.ToXml();
            $data = $xml.Event.EventData.Data;
            $name = ($data | Where-Object {{$_.Name -eq 'TaskName'}}).'#text';
            $events += "$($e.TimeCreated.ToString('o'))|TASK_CREATE|$name||";
        }}
    }}
}} catch {{}}
# Check Run keys modification time
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
);
foreach ($key in $runKeys) {{
    try {{
        $item = Get-Item $key -ErrorAction SilentlyContinue;
        if ($item) {{
            $props = $item | Get-ItemProperty;
            $props.PSObject.Properties | Where-Object {{$_.Name -notlike 'PS*'}} | ForEach-Object {{
                $events += "$(Get-Date -Format 'o')|REGISTRY_RUN|$($_.Name)|$($_.Value)|$key";
            }}
        }}
    }} catch {{}}
}}
$events | Select-Object -First 50"#,
        hours = hours
    );

    let output = run_ps(&script).await?;
    let mut events = Vec::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.splitn(5, '|').collect();
        if parts.len() >= 3 {
            let timestamp = parts[0].to_string();
            let event_type = parts[1].to_string();
            let name = parts[2].to_string();
            let value = parts.get(3).unwrap_or(&"").to_string();
            let key = parts.get(4).unwrap_or(&"").to_string();

            let risk = if event_type == "TASK_CREATE" { 45 } else { 25 };
            let desc = if event_type == "TASK_CREATE" {
                format!("Scheduled task created: {}", name)
            } else {
                format!("Registry Run key: {} = {}", name, truncate_str(&value, 80))
            };

            events.push(TimelineEvent {
                timestamp,
                source: "persistence".to_string(),
                event_type,
                description: desc,
                risk_score: risk,
                details: format!("Name: {}\nValue: {}\nKey: {}", name, value, key),
            });
        }
    }
    Ok(events)
}

/// Collect PowerShell script block logging events (4104) — indicates script execution.
async fn collect_powershell_events(hours: u64) -> AgentResult<Vec<TimelineEvent>> {
    let script = format!(
        r#"$cutoff = (Get-Date).AddHours(-{hours});
$events = @();
try {{
    $ps = Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=$cutoff}} -MaxEvents 80 -ErrorAction SilentlyContinue;
    if ($ps) {{
        foreach ($e in $ps) {{
            $xml = [xml]$e.ToXml();
            $data = $xml.Event.EventData.Data;
            $scriptBlock = ($data | Where-Object {{$_.Name -eq 'ScriptBlockText'}}).'#text';
            $path = ($data | Where-Object {{$_.Name -eq 'Path'}}).'#text';
            $events += "$($e.TimeCreated.ToString('o'))|PS_SCRIPT|$path|$scriptBlock";
        }}
    }}
}} catch {{}}
$events | Select-Object -First 80"#,
        hours = hours
    );

    let output = run_ps(&script).await?;
    let mut events = Vec::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.splitn(4, '|').collect();
        if parts.len() >= 3 {
            let timestamp = parts[0].to_string();
            let path = parts[2].to_string();
            let script_block = parts.get(3).unwrap_or(&"").to_string();

            let risk = score_powershell(&script_block);
            let desc = if path.is_empty() {
                format!("PowerShell script executed: {}", truncate_str(&script_block, 100))
            } else {
                format!("PowerShell script: {} ({})", short_path(&path), truncate_str(&script_block, 80))
            };

            events.push(TimelineEvent {
                timestamp,
                source: "powershell".to_string(),
                event_type: "ScriptBlock".to_string(),
                description: desc,
                risk_score: risk,
                details: format!("Path: {}\nScriptBlock: {}", path, truncate_str(&script_block, 500)),
            });
        }
    }
    Ok(events)
}

/// Collect Windows Defender detection events (1116, 1117, 1118, 1119).
async fn collect_defender_events(hours: u64) -> AgentResult<Vec<TimelineEvent>> {
    let script = format!(
        r#"$cutoff = (Get-Date).AddHours(-{hours});
$events = @();
try {{
    $def = Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1116,1117,1118,1119; StartTime=$cutoff}} -MaxEvents 50 -ErrorAction SilentlyContinue;
    if ($def) {{
        foreach ($e in $def) {{
            $xml = [xml]$e.ToXml();
            $data = $xml.Event.EventData.Data;
            $threat = ($data | Where-Object {{$_.Name -eq 'Threat Name'}}).'#text';
            $path = ($data | Where-Object {{$_.Name -eq 'Path'}}).'#text';
            $events += "$($e.TimeCreated.ToString('o'))|DEFENDER|$($e.Id)|$threat|$path";
        }}
    }}
}} catch {{}}
$events | Select-Object -First 50"#,
        hours = hours
    );

    let output = run_ps(&script).await?;
    let mut events = Vec::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.splitn(5, '|').collect();
        if parts.len() >= 4 {
            let timestamp = parts[0].to_string();
            let event_id = parts[2].to_string();
            let threat = parts[3].to_string();
            let path = parts.get(4).unwrap_or(&"").to_string();

            let action = match event_id.as_str() {
                "1116" => "detected",
                "1117" => "cleaned",
                "1118" => "quarantined",
                "1119" => "remediation failed",
                _ => "action",
            };

            events.push(TimelineEvent {
                timestamp,
                source: "defender".to_string(),
                event_type: "DefenderDetection".to_string(),
                description: format!("Defender {}: {} at {}", action, threat, truncate_str(&path, 80)),
                risk_score: 70,
                details: format!("EventID: {}\nThreat: {}\nPath: {}", event_id, threat, path),
            });
        }
    }
    Ok(events)
}

// ── Risk Scoring Helpers ──

fn score_process(process: &str, cmdline: &str, parent: &str) -> u8 {
    let lower_proc = process.to_lowercase();
    let lower_cmd = cmdline.to_lowercase();
    let lower_parent = parent.to_lowercase();

    // LOLBins with suspicious indicators
    let lolbins = ["mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "wmic"];
    let suspicious_args = ["http", "-enc", "downloadstring", "frombase64", "invoke-expression", "iex("];

    if lolbins.iter().any(|b| lower_proc.contains(b))
        && suspicious_args.iter().any(|a| lower_cmd.contains(a))
    {
        return 75;
    }

    // PowerShell with encoded commands
    if lower_proc.contains("powershell") && (lower_cmd.contains("-enc") || lower_cmd.contains("encodedcommand")) {
        return 70;
    }

    // Suspicious parent (script interpreters spawning processes)
    let suspicious_parents = ["wscript", "cscript", "mshta", "winword", "excel"];
    if suspicious_parents.iter().any(|p| lower_parent.contains(p)) {
        return 60;
    }

    // Execution from temp/appdata paths
    let suspicious_paths = ["\\temp\\", "\\appdata\\", "\\users\\public\\", "\\programdata\\"];
    if suspicious_paths.iter().any(|p| lower_proc.contains(p)) {
        return 55;
    }

    // cmd.exe with suspicious commands
    if lower_proc.contains("cmd.exe") && (lower_cmd.contains("powershell") || lower_cmd.contains("certutil")) {
        return 45;
    }

    5 // Normal process
}

fn score_service_install(name: &str, path: &str) -> u8 {
    let lower_path = path.to_lowercase();
    let lower_name = name.to_lowercase();

    // Service from suspicious path
    let suspicious_paths = ["\\temp\\", "\\appdata\\", "\\users\\public\\", "\\downloads\\"];
    if suspicious_paths.iter().any(|p| lower_path.contains(p)) {
        return 70;
    }

    // Known malicious service names
    let suspicious_names = ["psexesvc", "cobalt", "meterpreter", "beacon"];
    if suspicious_names.iter().any(|n| lower_name.contains(n)) {
        return 85;
    }

    // Unsigned or no path
    if path.is_empty() {
        return 30;
    }

    20 // Normal service install
}

fn score_powershell(script_block: &str) -> u8 {
    let lower = script_block.to_lowercase();

    let critical_indicators = ["invoke-mimikatz", "invoke-bloodhound", "invoke-dcsync",
                                "get-gpppassword", "invoke-kerberoast"];
    if critical_indicators.iter().any(|i| lower.contains(i)) {
        return 90;
    }

    let high_indicators = ["downloadstring", "frombase64string", "invoke-expression",
                           "iex(", "net.webclient", "start-bitstransfer",
                           "reflection.assembly", "add-type"];
    if high_indicators.iter().filter(|i| lower.contains(**i)).count() >= 2 {
        return 70;
    }
    if high_indicators.iter().any(|i| lower.contains(i)) {
        return 50;
    }

    let medium_indicators = ["get-process", "get-service", "get-nettcpconnection",
                             "get-wmiobject", "get-aduser"];
    if medium_indicators.iter().any(|i| lower.contains(i)) {
        return 15;
    }

    5
}

fn is_external_ip(addr: &str) -> bool {
    let ip = addr.split(':').next().unwrap_or(addr);
    !ip.starts_with("10.") && !ip.starts_with("192.168.") && !ip.starts_with("172.16.")
        && !ip.starts_with("172.17.") && !ip.starts_with("172.18.") && !ip.starts_with("172.19.")
        && !ip.starts_with("172.2") && !ip.starts_with("172.3")
        && !ip.starts_with("127.") && !ip.starts_with("::1") && !ip.starts_with("fe80")
}

fn logon_type_name(logon_type: &str) -> &'static str {
    match logon_type {
        "2" => "Interactive",
        "3" => "Network",
        "4" => "Batch",
        "5" => "Service",
        "7" => "Unlock",
        "8" => "NetworkCleartext",
        "9" => "NewCredentials",
        "10" => "RemoteInteractive",
        "11" => "CachedInteractive",
        _ => "Unknown",
    }
}

fn short_path(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_len).collect();
        format!("{}...", truncated)
    }
}
