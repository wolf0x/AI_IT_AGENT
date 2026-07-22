use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

/// Offline EVTX (Windows Event Log) file parser.
/// Reads .evtx binary files directly without requiring Windows Event Log service.
///
/// Ported from RavenEye's syslog-worker.js EVTX binary parser,
/// but using the Rust `evtx` crate for robust Binary XML decoding.
pub struct IrEvtxParseTool;

// ── Security-relevant Event ID classification ───────────────────
fn classify_event_id(eid: u64, channel: &str) -> (&'static str, u32) {
    // (category, risk_level)  risk: 0=info, 1=low, 2=medium, 3=high, 4=critical
    match (eid, channel) {
        // Authentication
        (4624, "Security") => ("Logon Success", 0),
        (4625, "Security") => ("Logon Failure", 2),
        (4634, "Security") => ("Logoff", 0),
        (4648, "Security") => ("Explicit Credential Logon", 2),
        (4672, "Security") => ("Special Privileges Assigned", 2),
        (4778, "Security") => ("RDP Session Reconnect", 1),
        (4779, "Security") => ("RDP Session Disconnect", 0),
        (4647, "Security") => ("User Initiated Logoff", 0),

        // Account management
        (4720, "Security") => ("Account Created", 3),
        (4722, "Security") => ("Account Enabled", 2),
        (4723, "Security") => ("Password Change Attempt", 2),
        (4724, "Security") => ("Password Reset Attempt", 3),
        (4725, "Security") => ("Account Disabled", 2),
        (4726, "Security") => ("Account Deleted", 3),
        (4732, "Security") => ("Member Added to Privileged Group", 3),
        (4728, "Security") => ("Member Added to Security Group", 2),
        (4756, "Security") => ("Member Added to Universal Group", 2),

        // Audit policy
        (4719, "Security") => ("Audit Policy Change", 3),
        (4908, "Security") => ("Special Groups Logon", 2),

        // Service installation
        (7045, "System")   => ("New Service Installed", 3),
        (7040, "System")   => ("Service Start Type Changed", 2),
        (7034, "System")   => ("Service Unexpectedly Terminated", 2),
        (7036, "System")   => ("Service State Change", 1),
        (7031, "System")   => ("Service Crashed", 2),

        // Process creation
        (4688, "Security") => ("Process Created", 1),
        (1,  "Microsoft-Windows-Sysmon/Operational") => ("Sysmon Process Created", 1),
        (11, "Microsoft-Windows-Sysmon/Operational") => ("Sysmon File Create", 2),
        (3,  "Microsoft-Windows-Sysmon/Operational") => ("Sysmon Network Connection", 2),
        (22, "Microsoft-Windows-Sysmon/Operational") => ("Sysmon DNS Query", 1),
        (7,  "Microsoft-Windows-Sysmon/Operational") => ("Sysmon Image Loaded", 2),
        (8,  "Microsoft-Windows-Sysmon/Operational") => ("Sysmon Create Remote Thread", 3),
        (10, "Microsoft-Windows-Sysmon/Operational") => ("Sysmon Process Access", 2),
        (13, "Microsoft-Windows-Sysmon/Operational") => ("Sysmon Registry Value Set", 2),

        // Log clearing
        (1102, "Security") => ("Audit Log Cleared", 4),
        (104,  "System")   => ("Event Log Cleared", 4),

        // PowerShell
        (4103, "Microsoft-Windows-PowerShell/Operational") => ("PowerShell Module Logging", 1),
        (4104, "Microsoft-Windows-PowerShell/Operational") => ("PowerShell Script Block", 2),
        (4105, "Microsoft-Windows-PowerShell/Operational") => ("PowerShell Start Context", 1),
        (4106, "Microsoft-Windows-PowerShell/Operational") => ("PowerShell End Context", 0),
        (400,  "Windows PowerShell") => ("PowerShell Engine Start", 0),
        (403,  "Windows PowerShell") => ("PowerShell Engine Stop", 0),

        // Scheduled tasks
        (4698, "Security") => ("Scheduled Task Created", 3),
        (4699, "Security") => ("Scheduled Task Deleted", 2),
        (4700, "Security") => ("Scheduled Task Enabled", 2),
        (4701, "Security") => ("Scheduled Task Disabled", 1),
        (4702, "Security") => ("Scheduled Task Updated", 2),
        (200, "Microsoft-Windows-TaskScheduler/Operational") => ("Task Action Started", 1),
        (201, "Microsoft-Windows-TaskScheduler/Operational") => ("Task Action Completed", 0),
        (106, "Microsoft-Windows-TaskScheduler/Operational") => ("Task Registered", 2),

        // Firewall
        (2003, "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall") => ("Firewall Rule Added", 2),
        (2004, "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall") => ("Firewall Rule Changed", 2),
        (2006, "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall") => ("Firewall Rule Deleted", 2),

        // Malware / Defender
        (1116, "Microsoft-Windows-Windows Defender/Operational") => ("Malware Detected", 4),
        (1117, "Microsoft-Windows-Windows Defender/Operational") => ("Malware Action Taken", 3),
        (1015, "Microsoft-Windows-Windows Defender/Operational") => ("Suspicious Behavior", 3),
        (1006, "Microsoft-Windows-Windows Defender/Operational") => ("Malware Signature Updated", 0),

        // System startup/shutdown
        (6005, "System") => ("Event Log Service Started", 0),
        (6006, "System") => ("Event Log Service Stopped", 1),
        (6008, "System") => ("Unexpected Shutdown", 3),
        (6009, "System") => ("Boot Processor Info", 0),
        (1074, "System") => ("System Shutdown/Restart", 1),
        (12, "Microsoft-Windows-Kernel-General/Operational") => ("System Boot", 0),
        (13, "Microsoft-Windows-Kernel-General/Operational") => ("System Shutdown", 0),

        // Default
        _ => ("Other", 0),
    }
}

fn risk_label(level: u32) -> &'static str {
    match level {
        0 => "info",
        1 => "low",
        2 => "medium",
        3 => "high",
        4 => "critical",
        _ => "unknown",
    }
}

#[async_trait]
impl Tool for IrEvtxParseTool {
    fn name(&self) -> &str { "ir_evtx_parse" }

    fn description(&self) -> &str {
        "Offline Windows Event Log (.evtx) file parser. Reads EVTX binary files directly \
         without requiring Windows Event Log service. Classifies events by security relevance \
         (authentication, account changes, service installs, process creation, log clearing, \
         PowerShell, scheduled tasks, malware detection). Returns structured events with \
         risk classification, statistics, and top event sources. Ideal for analyzing exported \
         event logs from any Windows machine."
    }

    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the .evtx file"
                },
                "max_events": {
                    "type": "integer",
                    "description": "Maximum events to return (default 500)"
                },
                "min_risk": {
                    "type": "integer",
                    "description": "Minimum risk level to include (0=info, 1=low, 2=medium, 3=high, 4=critical). Default 0"
                },
                "event_ids": {
                    "type": "string",
                    "description": "Comma-separated event IDs to filter (e.g. '4625,4624,7045'). Empty = all"
                },
                "time_from": {
                    "type": "string",
                    "description": "Filter events after this ISO timestamp (e.g. '2024-01-01T00:00:00')"
                },
                "time_to": {
                    "type": "string",
                    "description": "Filter events before this ISO timestamp"
                }
            },
            "required": ["file_path"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let file_path = args["file_path"].as_str()
            .ok_or_else(|| -> crate::error::AgentError { "Missing required parameter: file_path".into() })?;

        let max_events = args["max_events"].as_u64().unwrap_or(500) as usize;
        let min_risk = args["min_risk"].as_u64().unwrap_or(0) as u32;
        let event_ids_filter: Vec<u64> = args["event_ids"].as_str()
            .map(|s| s.split(',').filter_map(|id| id.trim().parse().ok()).collect())
            .unwrap_or_default();

        let time_from = args["time_from"].as_str();
        let time_to = args["time_to"].as_str();

        // Open EVTX file using the evtx crate
        let mut parser = evtx::EvtxParser::from_path(file_path)
            .map_err(|e| -> crate::error::AgentError { format!("Failed to open EVTX file: {}", e).into() })?;

        let mut events: Vec<Value> = Vec::new();
        let mut total_events: u64 = 0;
        let mut filtered_events: u64 = 0;
        let mut category_counts: HashMap<String, u64> = HashMap::new();
        let mut risk_level_counts: HashMap<String, u64> = HashMap::new();
        let mut eid_counts: HashMap<u64, u64> = HashMap::new();
        let mut source_counts: HashMap<String, u64> = HashMap::new();
        let mut computer_counts: HashMap<String, u64> = HashMap::new();

        for record_result in parser.records_json_value() {
            let record = match record_result {
                Ok(r) => r,
                Err(_) => { total_events += 1; continue; }
            };
            total_events += 1;

            // Extract basic fields from JSON data
            let data = &record.data;
            let eid = data.get("EventID").and_then(|v| v.as_u64())
                .or_else(|| data.pointer("/Event/System/EventID").and_then(|v| v.as_u64()))
                .unwrap_or(0);
            let channel = data.pointer("/Event/System/Channel")
                .and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
            let computer = data.pointer("/Event/System/Computer")
                .and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
            let timestamp = data.pointer("/Event/System/TimeCreated/#attributes/SystemTime")
                .and_then(|v| v.as_str()).unwrap_or("").to_string();

            // Apply event ID filter
            if !event_ids_filter.is_empty() && !event_ids_filter.contains(&eid) {
                continue;
            }

            // Apply time filter
            if let Some(from) = time_from {
                if timestamp.as_str() < from { continue; }
            }
            if let Some(to) = time_to {
                if timestamp.as_str() > to { continue; }
            }

            // Classify
            let (category, risk) = classify_event_id(eid, &channel);

            // Apply risk filter
            if risk < min_risk {
                continue;
            }

            filtered_events += 1;

            // Statistics
            *category_counts.entry(category.to_string()).or_insert(0) += 1;
            *risk_level_counts.entry(risk_label(risk).to_string()).or_insert(0) += 1;
            *eid_counts.entry(eid).or_insert(0) += 1;
            *source_counts.entry(format!("{}:{}", channel, eid)).or_insert(0) += 1;
            *computer_counts.entry(computer.clone()).or_insert(0) += 1;

            // Build event entry (limited fields to control output size)
            if events.len() < max_events {
                let mut event_json = json!({
                    "event_id": eid,
                    "timestamp": timestamp,
                    "channel": channel,
                    "computer": computer,
                    "category": category,
                    "risk": risk_label(risk),
                    "risk_level": risk,
                });

                // Include event data if available
                if let Value::Object(map) = data {
                    let mut data_map = serde_json::Map::new();
                    for (k, v) in map {
                        match v {
                            Value::String(s) => { data_map.insert(k.clone(), json!(s)); }
                            Value::Number(n) => { data_map.insert(k.clone(), json!(n)); }
                            _ => { data_map.insert(k.clone(), v.clone()); }
                        }
                    }
                    event_json.as_object_mut().unwrap().insert("data".to_string(), Value::Object(data_map));
                }

                events.push(event_json);
            }
        }

        // Build top-N lists
        let mut top_eids: Vec<(u64, u64)> = eid_counts.into_iter().collect();
        top_eids.sort_by(|a, b| b.1.cmp(&a.1));
        let top_eids: Vec<Value> = top_eids.into_iter().take(20)
            .map(|(eid, count)| json!({"event_id": eid, "count": count}))
            .collect();

        let mut top_sources: Vec<(String, u64)> = source_counts.into_iter().collect();
        top_sources.sort_by(|a, b| b.1.cmp(&a.1));
        let top_sources: Vec<Value> = top_sources.into_iter().take(20)
            .map(|(source, count)| json!({"source": source, "count": count}))
            .collect();

        let mut top_computers: Vec<(String, u64)> = computer_counts.into_iter().collect();
        top_computers.sort_by(|a, b| b.1.cmp(&a.1));
        let top_computers: Vec<Value> = top_computers.into_iter().take(10)
            .map(|(computer, count)| json!({"computer": computer, "count": count}))
            .collect();

        let risk_summary: Vec<Value> = risk_level_counts.into_iter()
            .map(|(level, count)| json!({"level": level, "count": count}))
            .collect();

        let category_summary: Vec<Value> = category_counts.into_iter()
            .map(|(cat, count)| json!({"category": cat, "count": count}))
            .collect();

        Ok(json!({
            "status": "ok",
            "file": file_path,
            "summary": {
                "total_records": total_events,
                "filtered_records": filtered_events,
                "returned_records": events.len(),
            },
            "risk_summary": risk_summary,
            "category_summary": category_summary,
            "top_event_ids": top_eids,
            "top_sources": top_sources,
            "top_computers": top_computers,
            "events": events,
        }))
    }
}
