use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

pub struct IrAnalyzerTool;

/// A single finding from the rule engine.
#[derive(Clone)]
struct Finding {
    id: String,
    rule_id: String,
    severity: String,  // critical, high, medium, low, pass
    category: String,
    title: String,
    evidence: String,
    recommendation: String,
    source: String,
}

/// A MITRE ATT&CK technique reference.
#[derive(Clone)]
struct MitreTechnique {
    id: String,        // e.g., "T1055"
    name: String,      // e.g., "Process Injection"
    tactic: String,    // e.g., "Defense Evasion"
}

/// Map a rule_id to its associated MITRE ATT&CK techniques.
fn mitre_mapping(rule_id: &str) -> Vec<MitreTechnique> {
    match rule_id {
        "win.suspicious_path" => vec![
            MitreTechnique { id: "T1204.002".into(), name: "User Execution: Malicious File".into(), tactic: "Execution".into() },
            MitreTechnique { id: "T1036.005".into(), name: "Masquerading: Match Legitimate Name".into(), tactic: "Defense Evasion".into() },
        ],
        "win.lolbin_exec" => vec![
            MitreTechnique { id: "T1218".into(), name: "System Binary Proxy Execution".into(), tactic: "Defense Evasion".into() },
            MitreTechnique { id: "T1059".into(), name: "Command and Scripting Interpreter".into(), tactic: "Execution".into() },
        ],
        "win.encoded_powershell" => vec![
            MitreTechnique { id: "T1059.001".into(), name: "PowerShell".into(), tactic: "Execution".into() },
            MitreTechnique { id: "T1027".into(), name: "Obfuscated Files or Information".into(), tactic: "Defense Evasion".into() },
        ],
        "win.eventlog_cleared" => vec![
            MitreTechnique { id: "T1070.001".into(), name: "Clear Windows Event Logs".into(), tactic: "Defense Evasion".into() },
        ],
        "win.service_install" => vec![
            MitreTechnique { id: "T1543.003".into(), name: "Windows Service".into(), tactic: "Persistence".into() },
            MitreTechnique { id: "T1569.002".into(), name: "Service Execution".into(), tactic: "Execution".into() },
        ],
        "win.account_change" => vec![
            MitreTechnique { id: "T1136.001".into(), name: "Local Account".into(), tactic: "Persistence".into() },
            MitreTechnique { id: "T1098".into(), name: "Account Manipulation".into(), tactic: "Persistence".into() },
        ],
        "win.bruteforce_many" | "win.bruteforce_some" => vec![
            MitreTechnique { id: "T1110.001".into(), name: "Password Guessing".into(), tactic: "Credential Access".into() },
            MitreTechnique { id: "T1110.003".into(), name: "Password Spraying".into(), tactic: "Credential Access".into() },
        ],
        "win.wmi_persistence" => vec![
            MitreTechnique { id: "T1546.003".into(), name: "WMI Event Subscription".into(), tactic: "Persistence".into() },
        ],
        "win.external_established" => vec![
            MitreTechnique { id: "T1071".into(), name: "Application Layer Protocol".into(), tactic: "Command and Control".into() },
            MitreTechnique { id: "T1571".into(), name: "Non-Standard Port".into(), tactic: "Command and Control".into() },
        ],
        "win.defender_disabled" => vec![
            MitreTechnique { id: "T1562.001".into(), name: "Disable or Modify Tools".into(), tactic: "Defense Evasion".into() },
        ],
        "win.defender_exclusion" => vec![
            MitreTechnique { id: "T1562.001".into(), name: "Disable or Modify Tools".into(), tactic: "Defense Evasion".into() },
            MitreTechnique { id: "T1055".into(), name: "Process Injection".into(), tactic: "Defense Evasion".into() },
        ],
        "win.unsigned_driver" => vec![
            MitreTechnique { id: "T1014".into(), name: "Rootkit".into(), tactic: "Defense Evasion".into() },
            MitreTechnique { id: "T1547.006".into(), name: "Kernel Modules and Extensions".into(), tactic: "Persistence".into() },
        ],
        "win.psexec_service" => vec![
            MitreTechnique { id: "T1570".into(), name: "Lateral Tool Transfer".into(), tactic: "Lateral Movement".into() },
            MitreTechnique { id: "T1021.002".into(), name: "SMB/Windows Admin Shares".into(), tactic: "Lateral Movement".into() },
        ],
        "web.suspicious_request" => vec![
            MitreTechnique { id: "T1505.003".into(), name: "Web Shell".into(), tactic: "Persistence".into() },
            MitreTechnique { id: "T1190".into(), name: "Exploit Public-Facing Application".into(), tactic: "Initial Access".into() },
        ],
        "win.dns_suspicious_cache" => vec![
            MitreTechnique { id: "T1071.004".into(), name: "DNS".into(), tactic: "Command and Control".into() },
            MitreTechnique { id: "T1568".into(), name: "Dynamic Resolution".into(), tactic: "Command and Control".into() },
        ],
        "win.hidden_account" => vec![
            MitreTechnique { id: "T1136.001".into(), name: "Local Account".into(), tactic: "Persistence".into() },
            MitreTechnique { id: "T1564.002".into(), name: "Hidden Users".into(), tactic: "Defense Evasion".into() },
        ],
        "win.unquoted_service_path" => vec![
            MitreTechnique { id: "T1574.009".into(), name: "Unquoted Path Interception".into(), tactic: "Privilege Escalation".into() },
        ],
        _ => vec![],
    }
}

#[async_trait]
impl Tool for IrAnalyzerTool {
    fn name(&self) -> &str { "ir_analyzer" }
    fn description(&self) -> &str {
        "Rule-based anomaly detection engine. Takes a JSON object with category keys (processes, network, services, autoruns, tasks, wmi, defender, drivers, eventlogs, accounts, lateral, web-logs) and raw text output as values. Applies detection rules and returns structured findings with severity ratings."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "data": {
                    "type": "object",
                    "description": "JSON object with category keys mapping to raw text output from IR tools"
                }
            },
            "required": ["data"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let data = args["data"].as_object().ok_or("Missing 'data' object")?;

        let mut findings: Vec<Finding> = Vec::new();
        let mut counter = 0u32;

        // Collect text for each category
        let get_text = |key: &str| -> String {
            data.get(key)
                .map(|v| match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .unwrap_or_default()
        };

        // ── Rule: Suspicious path executables ──
        let suspicious_paths = ["\\AppData\\", "\\Temp\\", "\\Windows\\Temp\\",
                                "\\Users\\Public\\", "\\Downloads\\", "\\ProgramData\\"];
        let exec_exts = [".exe", ".dll", ".ps1", ".vbs", ".js", ".bat", ".cmd"];

        for cat_key in &["processes", "services", "autoruns", "tasks"] {
            let text = get_text(cat_key);
            if text.is_empty() { continue }
            for line in text.lines() {
                let lower = line.to_lowercase();
                if suspicious_paths.iter().any(|p| lower.contains(&p.to_lowercase()))
                    && exec_exts.iter().any(|e| lower.contains(e))
                {
                    counter += 1;
                    findings.push(Finding {
                        id: format!("F-{:03}", counter),
                        rule_id: "win.suspicious_path".into(),
                        severity: "high".into(),
                        category: cat_key.to_string(),
                        title: format!("Executable in suspicious directory"),
                        evidence: truncate(line.trim(), 300),
                        recommendation: "Verify the legitimacy of this file. Check digital signature and compare with known-good baseline.".into(),
                        source: cat_key.to_string(),
                    });
                }
            }
        }

        // ── Rule: LOLBin execution ──
        let lolbins = ["mshta", "rundll32", "regsvr32", "wscript", "cscript",
                       "certutil", "bitsadmin", "wmic"];
        let lolbin_indicators = ["http", "\\appdata\\", "\\temp\\", "\\users\\public",
                                 "-enc", "-encodedcommand", "downloadstring",
                                 "frombase64string", "iex(", "invoke-expression"];

        for cat_key in &["processes", "tasks", "autoruns", "eventlogs"] {
            let text = get_text(cat_key);
            if text.is_empty() { continue }
            for line in text.lines() {
                let lower = line.to_lowercase();
                let is_lolbin = lolbins.iter().any(|b| lower.contains(b));
                let has_indicator = lolbin_indicators.iter().any(|i| lower.contains(i));
                if is_lolbin && has_indicator {
                    counter += 1;
                    findings.push(Finding {
                        id: format!("F-{:03}", counter),
                        rule_id: "win.lolbin_exec".into(),
                        severity: "high".into(),
                        category: cat_key.to_string(),
                        title: "LOLBin with suspicious indicators".into(),
                        evidence: truncate(line.trim(), 300),
                        recommendation: "Investigate the process tree and command line. Check for fileless malware or living-off-the-land attacks.".into(),
                        source: cat_key.to_string(),
                    });
                }
            }
        }

        // ── Rule: Encoded PowerShell ──
        let ps_indicators = ["-enc ", "-encodedcommand", "downloadstring",
                             "frombase64string", "invoke-expression", "iex("];
        for cat_key in &["processes", "eventlogs", "tasks"] {
            let text = get_text(cat_key);
            if text.is_empty() { continue }
            for line in text.lines() {
                let lower = line.to_lowercase();
                if lower.contains("powershell") && ps_indicators.iter().any(|i| lower.contains(i)) {
                    counter += 1;
                    findings.push(Finding {
                        id: format!("F-{:03}", counter),
                        rule_id: "win.encoded_powershell".into(),
                        severity: "high".into(),
                        category: cat_key.to_string(),
                        title: "Encoded/obfuscated PowerShell execution".into(),
                        evidence: truncate(line.trim(), 300),
                        recommendation: "Decode the EncodedCommand and analyze the script content. Check PowerShell Script Block Logging (Event 4104).".into(),
                        source: cat_key.to_string(),
                    });
                }
            }
        }

        // ── Rule: Event log cleared ──
        let log_text = get_text("eventlogs");
        let all_text_for_logs = format!("{} {}", log_text, get_text("basic"));
        if all_text_for_logs.contains("1102") || all_text_for_logs.to_lowercase().contains("audit log was cleared") {
            counter += 1;
            findings.push(Finding {
                id: format!("F-{:03}", counter),
                rule_id: "win.eventlog_cleared".into(),
                severity: "critical".into(),
                category: "eventlogs".into(),
                title: "Security event log was cleared".into(),
                evidence: "Event ID 1102 detected — indicates potential evidence tampering".into(),
                recommendation: "Immediately preserve remaining logs. Check for other indicators of compromise. This is a critical anti-forensics indicator.".into(),
                source: "eventlogs".into(),
            });
        }

        // ── Rule: Service installation (Event 7045) ──
        if all_text_for_logs.contains("7045") || all_text_for_logs.to_lowercase().contains("service was installed") {
            counter += 1;
            findings.push(Finding {
                id: format!("F-{:03}", counter),
                rule_id: "win.service_install".into(),
                severity: "high".into(),
                category: "eventlogs".into(),
                title: "New service installed (Event 7045)".into(),
                evidence: "System event log shows service installation events".into(),
                recommendation: "Review the service name and image path. Verify the service is legitimate and signed.".into(),
                source: "eventlogs".into(),
            });
        }

        // ── Rule: Account changes ──
        let account_change_ids = ["4720", "4722", "4726"];
        let has_account_changes = account_change_ids.iter().any(|id| all_text_for_logs.contains(id));
        if has_account_changes {
            counter += 1;
            findings.push(Finding {
                id: format!("F-{:03}", counter),
                rule_id: "win.account_change".into(),
                severity: "high".into(),
                category: "eventlogs".into(),
                title: "Account creation/enable/delete events detected".into(),
                evidence: "Security events 4720/4722/4726 found — possible backdoor account".into(),
                recommendation: "Review the target account names. Check if accounts were added to privileged groups.".into(),
                source: "eventlogs".into(),
            });
        }

        // ── Rule: Brute force detection ──
        let fail_4625_count = log_text.matches("4625").count()
            + get_text("failures").matches("4625").count();
        if fail_4625_count >= 50 {
            counter += 1;
            findings.push(Finding {
                id: format!("F-{:03}", counter),
                rule_id: "win.bruteforce_many".into(),
                severity: "high".into(),
                category: "eventlogs".into(),
                title: format!("Possible brute force: {} failed logon events", fail_4625_count),
                evidence: format!("{} occurrences of Event ID 4625 (failed logon)", fail_4625_count),
                recommendation: "Check source IPs and targeted accounts. Consider account lockout policies.".into(),
                source: "eventlogs".into(),
            });
        } else if fail_4625_count >= 10 {
            counter += 1;
            findings.push(Finding {
                id: format!("F-{:03}", counter),
                rule_id: "win.bruteforce_some".into(),
                severity: "medium".into(),
                category: "eventlogs".into(),
                title: format!("Notable failed logon attempts: {} events", fail_4625_count),
                evidence: format!("{} occurrences of Event ID 4625", fail_4625_count),
                recommendation: "Monitor for escalation. Check if any were followed by successful logons.".into(),
                source: "eventlogs".into(),
            });
        }

        // ── Rule: WMI persistence ──
        let wmi_text = get_text("wmi");
        let wmi_indicators = ["__EventFilter", "CommandLineEventConsumer",
                              "ActiveScriptEventConsumer", "__FilterToConsumerBinding"];
        if !wmi_text.is_empty() && wmi_indicators.iter().any(|i| wmi_text.contains(i)) {
            counter += 1;
            findings.push(Finding {
                id: format!("F-{:03}", counter),
                rule_id: "win.wmi_persistence".into(),
                severity: "high".into(),
                category: "wmi".into(),
                title: "WMI permanent event subscription detected".into(),
                evidence: truncate(&wmi_text, 300),
                recommendation: "WMI event subscriptions are a known persistence mechanism. Verify they are from legitimate software.".into(),
                source: "wmi".into(),
            });
        }

        // ── Rule: External established connections ──
        let net_text = get_text("network");
        if !net_text.is_empty() {
            // Check for non-RFC1918 IPs in established connections
            let mut external_count = 0;
            for line in net_text.lines() {
                let lower = line.to_lowercase();
                if lower.contains("established") || (lower.contains("tcp") && !lower.contains("127.0.0.1")) {
                    // Simple heuristic: if line has an IP that's not private
                    if !line.contains("10.") && !line.contains("192.168.") && !line.contains("172.16.")
                        && !line.contains("172.17.") && !line.contains("172.18.")
                        && !line.contains("172.19.") && !line.contains("172.2")
                        && !line.contains("172.3") && !line.contains("::1")
                        && !line.contains("127.0.0")
                    {
                        // Check if there's actually an IP-like pattern
                        if line.contains(".") && line.chars().any(|c| c.is_ascii_digit()) {
                            external_count += 1;
                        }
                    }
                }
            }
            if external_count > 0 {
                counter += 1;
                findings.push(Finding {
                    id: format!("F-{:03}", counter),
                    rule_id: "win.external_established".into(),
                    severity: "medium".into(),
                    category: "network".into(),
                    title: format!("{} external established connections detected", external_count),
                    evidence: format!("Non-RFC1918 IP connections found in network output"),
                    recommendation: "Verify these connections are to known/expected services. Check for C2 beaconing patterns.".into(),
                    source: "network".into(),
                });
            }
        }

        // ── Rule: Defender disabled ──
        let defender_text = get_text("defender");
        if defender_text.contains("False") &&
            (defender_text.contains("RealTimeProtectionEnabled") || defender_text.contains("DisableRealtimeMonitoring"))
        {
            counter += 1;
            findings.push(Finding {
                id: format!("F-{:03}", counter),
                rule_id: "win.defender_disabled".into(),
                severity: "high".into(),
                category: "defender".into(),
                title: "Windows Defender real-time protection appears disabled".into(),
                evidence: truncate(&defender_text, 300),
                recommendation: "Re-enable Windows Defender immediately. Check Group Policy for tampering.".into(),
                source: "defender".into(),
            });
        }

        // ── Rule: Defender exclusions ──
        if defender_text.contains("ExclusionPath") || defender_text.contains("ExclusionProcess") {
            let has_exclusions = defender_text.lines().any(|l| {
                let lt = l.trim();
                !lt.is_empty() && !lt.starts_with("Exclusion") && !lt.starts_with("---")
                    && (defender_text.contains("ExclusionPath") || defender_text.contains("ExclusionProcess"))
            });
            if has_exclusions {
                counter += 1;
                findings.push(Finding {
                    id: format!("F-{:03}", counter),
                    rule_id: "win.defender_exclusion".into(),
                    severity: "medium".into(),
                    category: "defender".into(),
                    title: "Windows Defender exclusions configured".into(),
                    evidence: truncate(&defender_text, 300),
                    recommendation: "Review exclusions — attackers may add exclusions to bypass detection.".into(),
                    source: "defender".into(),
                });
            }
        }

        // ── Rule: Unsigned drivers ──
        let driver_text = get_text("drivers");
        if driver_text.contains("NotSigned") || driver_text.contains("Unsigned")
            || driver_text.contains("未签名")
        {
            counter += 1;
            findings.push(Finding {
                id: format!("F-{:03}", counter),
                rule_id: "win.unsigned_driver".into(),
                severity: "high".into(),
                category: "drivers".into(),
                title: "Unsigned drivers found (potential rootkit indicator)".into(),
                evidence: truncate(&driver_text, 300),
                recommendation: "Investigate unsigned drivers. Check if they are from known hardware vendors.".into(),
                source: "drivers".into(),
            });
        }

        // ── Rule: PsExec traces ──
        let lateral_text = get_text("lateral");
        if lateral_text.contains("PSEXESVC") {
            counter += 1;
            findings.push(Finding {
                id: format!("F-{:03}", counter),
                rule_id: "win.psexec_service".into(),
                severity: "high".into(),
                category: "lateral".into(),
                title: "PsExec service traces detected".into(),
                evidence: truncate(&lateral_text, 300),
                recommendation: "PsExec indicates remote execution. Verify if this was authorized admin activity.".into(),
                source: "lateral".into(),
            });
        }

        // ── Rule: Suspicious shares ──
        let default_shares = ["C$", "ADMIN$", "IPC$", "PRINT$", "FAX$"];
        if !lateral_text.is_empty() {
            for line in lateral_text.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || default_shares.iter().any(|s| trimmed.contains(s)) {
                    continue;
                }
                // Look for share names in SMB share listings
                if trimmed.contains("SMB Shares") || trimmed.contains("Get-SmbShare") {
                    continue;
                }
            }
        }

        // ── Rule: Web shell indicators ──
        let web_text = get_text("web-logs");
        let web_indicators = ["cmd=", "exec=", "shell=", "upload",
                              ".jsp", ".aspx", ".php"];
        let web_danger = ["cmd", "eval", "base64", "whoami", "powershell"];
        if !web_text.is_empty() {
            for line in web_text.lines() {
                let lower = line.to_lowercase();
                let has_web_ext = web_indicators.iter().any(|i| lower.contains(i));
                let has_danger = web_danger.iter().any(|d| lower.contains(d));
                if has_web_ext && has_danger {
                    counter += 1;
                    findings.push(Finding {
                        id: format!("F-{:03}", counter),
                        rule_id: "web.suspicious_request".into(),
                        severity: "high".into(),
                        category: "web-logs".into(),
                        title: "Possible web shell / command execution in web logs".into(),
                        evidence: truncate(line.trim(), 300),
                        recommendation: "Investigate the web application for compromise. Check for uploaded web shells.".into(),
                        source: "web-logs".into(),
                    });
                }
            }
        }

        // ── Rule: DNS suspicious cache ──
        let dns_indicators = ["ngrok", "frp", "dnslog", "burp", "interactsh",
                              "oast", "duckdns", "no-ip", "dynu", "serveo",
                              "pastebin", "raw.githubusercontent", "telegram",
                              "tor2web", "onion"];
        let dns_text = get_text("dns");
        if !dns_text.is_empty() {
            for line in dns_text.lines() {
                let lower = line.to_lowercase();
                if dns_indicators.iter().any(|i| lower.contains(i)) {
                    counter += 1;
                    findings.push(Finding {
                        id: format!("F-{:03}", counter),
                        rule_id: "win.dns_suspicious_cache".into(),
                        severity: "medium".into(),
                        category: "network".into(),
                        title: "Suspicious DNS cache entry".into(),
                        evidence: truncate(line.trim(), 300),
                        recommendation: "Check if this DNS lookup is from legitimate software or indicates C2/exfiltration.".into(),
                        source: "network".into(),
                    });
                }
            }
        }

        // ── Rule: Hidden accounts ──
        let account_text = get_text("accounts");
        if account_text.contains("\"hidden\":true") || account_text.contains("\"hidden\": true") {
            counter += 1;
            findings.push(Finding {
                id: format!("F-{:03}", counter),
                rule_id: "win.hidden_account".into(),
                severity: "high".into(),
                category: "accounts".into(),
                title: "Hidden user account detected".into(),
                evidence: "Account enumeration found hidden accounts (registry SpecialAccounts or $ suffix)".into(),
                recommendation: "Hidden accounts are a common persistence technique. Investigate and remove if unauthorized.".into(),
                source: "accounts".into(),
            });
        }

        // ── Rule: Unquoted service path ──
        let service_text = get_text("services");
        if !service_text.is_empty() {
            for line in service_text.lines() {
                if line.contains("  ") && line.contains(".exe")
                    && !line.contains("\"") && line.contains(" Auto")
                {
                    counter += 1;
                    findings.push(Finding {
                        id: format!("F-{:03}", counter),
                        rule_id: "win.unquoted_service_path".into(),
                        severity: "medium".into(),
                        category: "services".into(),
                        title: "Unquoted service path detected".into(),
                        evidence: truncate(line.trim(), 300),
                        recommendation: "Unquoted service paths can be exploited for privilege escalation. Quote the path or restrict directory permissions.".into(),
                        source: "services".into(),
                    });
                }
            }
        }

        // ── Causal Chain Correlation ──
        // Extract indicators from each finding for cross-referencing
        let mut finding_indicators: Vec<HashSet<String>> = Vec::new();
        for f in &findings {
            let indicators = extract_indicators(&f.evidence, &f.category, &f.rule_id);
            finding_indicators.push(indicators);
        }

        // Build correlation map: finding index -> set of correlated finding indices
        let mut correlation_map: HashMap<usize, HashSet<usize>> = HashMap::new();
        for i in 0..findings.len() {
            for j in (i + 1)..findings.len() {
                let shared: HashSet<_> = finding_indicators[i]
                    .intersection(&finding_indicators[j])
                    .cloned()
                    .collect();
                if !shared.is_empty() {
                    correlation_map.entry(i).or_default().insert(j);
                    correlation_map.entry(j).or_default().insert(i);
                }
            }
        }

        // Detect known attack chain patterns
        let attack_chains = detect_attack_chains(&findings);

        // ── Summary ──
        let critical = findings.iter().filter(|f| f.severity == "critical").count();
        let high = findings.iter().filter(|f| f.severity == "high").count();
        let medium = findings.iter().filter(|f| f.severity == "medium").count();
        let low = findings.iter().filter(|f| f.severity == "low").count();

        if findings.is_empty() {
            counter += 1;
            findings.push(Finding {
                id: format!("F-{:03}", counter),
                rule_id: "collector.no_hit".into(),
                severity: "pass".into(),
                category: "overall".into(),
                title: "No anomalies detected by rule engine".into(),
                evidence: "All rules passed without matches".into(),
                recommendation: "System appears clean based on automated rules. Manual review recommended for thorough assessment.".into(),
                source: "overall".into(),
            });
        }

        let findings_json: Vec<Value> = findings.iter().enumerate().map(|(idx, f)| {
            let techniques: Vec<Value> = mitre_mapping(&f.rule_id).iter().map(|t| {
                json!({
                    "id": t.id,
                    "name": t.name,
                    "tactic": t.tactic,
                })
            }).collect();
            // Add correlated finding IDs
            let correlated: Vec<String> = correlation_map.get(&idx)
                .map(|set| set.iter().map(|&j| findings[j].id.clone()).collect())
                .unwrap_or_default();
            json!({
                "id": f.id,
                "rule_id": f.rule_id,
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
                "source": f.source,
                "mitre_techniques": techniques,
                "correlated_with": correlated,
            })
        }).collect();

        // Build correlation chains JSON
        let chains_json: Vec<Value> = attack_chains.iter().map(|chain| {
            let finding_ids: Vec<String> = chain.finding_indices.iter()
                .map(|&i| findings[i].id.clone()).collect();
            json!({
                "chain_id": chain.chain_id,
                "name": chain.name,
                "description": chain.description,
                "kill_chain_phase": chain.kill_chain_phase,
                "confidence": chain.confidence,
                "finding_ids": finding_ids,
            })
        }).collect();

        Ok(json!({
            "status": "ok",
            "total_findings": findings.len(),
            "summary": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
            "findings": findings_json,
            "correlation_chains": chains_json,
            "correlation_summary": {
                "total_correlations": correlation_map.values().map(|s| s.len()).sum::<usize>() / 2,
                "chains_detected": attack_chains.len(),
            },
        }))
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

/// Extract correlation indicators from a finding's evidence and metadata.
fn extract_indicators(evidence: &str, category: &str, rule_id: &str) -> HashSet<String> {
    let mut indicators = HashSet::new();
    let lower = evidence.to_lowercase();

    // Extract IP addresses
    let ip_re = regex::Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap();
    for cap in ip_re.captures_iter(evidence) {
        let ip = &cap[1];
        if !ip.starts_with("127.") && !ip.starts_with("0.0.") {
            indicators.insert(format!("ip:{}", ip));
        }
    }

    // Extract process/service names from evidence
    let proc_patterns = ["psexesvc", "cobalt", "meterpreter", "beacon",
                         "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin",
                         "wmic", "powershell", "cmd.exe", "wscript", "cscript"];
    for p in &proc_patterns {
        if lower.contains(p) {
            indicators.insert(format!("proc:{}", p));
        }
    }

    // Extract file paths (normalize to lowercase)
    let path_re = regex::Regex::new(r"([A-Za-z]:\\[^\s,;)]+)").unwrap();
    for cap in path_re.captures_iter(evidence) {
        indicators.insert(format!("path:{}", cap[1].to_lowercase()));
    }

    // Extract account names from relevant categories
    if category == "accounts" || category == "eventlogs" {
        let acct_re = regex::Regex::new(r"(?i)(?:user|account|target)[:\s=]+([A-Za-z0-9_.$]{2,30})").unwrap();
        for cap in acct_re.captures_iter(evidence) {
            let acct = cap[1].to_lowercase();
            if !matches!(acct.as_str(), "system" | "local" | "service") {
                indicators.insert(format!("account:{}", acct));
            }
        }
    }

    // Add rule-based category indicator for chain detection
    indicators.insert(format!("rule:{}", rule_id));

    indicators
}

/// A detected attack chain.
struct AttackChain {
    chain_id: String,
    name: String,
    description: String,
    kill_chain_phase: String,
    confidence: String,
    finding_indices: Vec<usize>,
}

/// Detect known attack chain patterns from findings.
fn detect_attack_chains(findings: &[Finding]) -> Vec<AttackChain> {
    let mut chains = Vec::new();
    let mut chain_counter = 0u32;

    // Build rule_id -> indices map
    let mut rule_indices: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, f) in findings.iter().enumerate() {
        rule_indices.entry(f.rule_id.as_str()).or_default().push(i);
    }

    // Chain 1: Credential Attack → Persistence → Lateral Movement
    let has_bruteforce = rule_indices.contains_key("win.bruteforce_many")
        || rule_indices.contains_key("win.bruteforce_some");
    let has_account_change = rule_indices.contains_key("win.account_change");
    let has_hidden = rule_indices.contains_key("win.hidden_account");
    let has_psexec = rule_indices.contains_key("win.psexec_service");

    if (has_bruteforce || has_account_change) && (has_hidden || has_psexec) {
        chain_counter += 1;
        let mut indices = Vec::new();
        for key in &["win.bruteforce_many", "win.bruteforce_some", "win.account_change", "win.hidden_account", "win.psexec_service"] {
            if let Some(idxs) = rule_indices.get(*key) {
                indices.extend(idxs);
            }
        }
        chains.push(AttackChain {
            chain_id: format!("CH-{:03}", chain_counter),
            name: "Credential Attack → Persistence → Lateral Movement".into(),
            description: "Evidence of brute force or account manipulation combined with persistence mechanisms and lateral movement tools. This pattern suggests an attacker compromised credentials, created backdoor access, and is moving laterally.".into(),
            kill_chain_phase: "Credential Access → Persistence → Lateral Movement".into(),
            confidence: if has_bruteforce && has_psexec { "high".into() } else { "medium".into() },
            finding_indices: indices,
        });
    }

    // Chain 2: Defense Evasion → Execution → C2
    let has_defender_disabled = rule_indices.contains_key("win.defender_disabled");
    let has_defender_exclusion = rule_indices.contains_key("win.defender_exclusion");
    let has_encoded_ps = rule_indices.contains_key("win.encoded_powershell");
    let has_lolbin = rule_indices.contains_key("win.lolbin_exec");
    let has_external = rule_indices.contains_key("win.external_established");
    let has_dns_suspicious = rule_indices.contains_key("win.dns_suspicious_cache");
    let has_log_cleared = rule_indices.contains_key("win.eventlog_cleared");

    if (has_defender_disabled || has_defender_exclusion || has_log_cleared)
        && (has_encoded_ps || has_lolbin)
        && (has_external || has_dns_suspicious)
    {
        chain_counter += 1;
        let mut indices = Vec::new();
        for key in &["win.defender_disabled", "win.defender_exclusion", "win.eventlog_cleared",
                     "win.encoded_powershell", "win.lolbin_exec",
                     "win.external_established", "win.dns_suspicious_cache"] {
            if let Some(idxs) = rule_indices.get(*key) {
                indices.extend(idxs);
            }
        }
        chains.push(AttackChain {
            chain_id: format!("CH-{:03}", chain_counter),
            name: "Defense Evasion → Execution → Command & Control".into(),
            description: "Attacker disabled security tools, executed obfuscated code, and established external communications. This is a classic post-exploitation pattern indicating an active compromise with anti-detection measures.".into(),
            kill_chain_phase: "Defense Evasion → Execution → Command and Control".into(),
            confidence: "high".into(),
            finding_indices: indices,
        });
    }

    // Chain 3: Initial Access → Persistence → Privilege Escalation
    let has_service_install = rule_indices.contains_key("win.service_install");
    let has_suspicious_path = rule_indices.contains_key("win.suspicious_path");
    let has_webshell = rule_indices.contains_key("web.suspicious_request");

    if has_webshell && (has_service_install || has_suspicious_path) {
        chain_counter += 1;
        let mut indices = Vec::new();
        for key in &["web.suspicious_request", "win.service_install", "win.suspicious_path",
                     "win.unsigned_driver", "win.unquoted_service_path"] {
            if let Some(idxs) = rule_indices.get(*key) {
                indices.extend(idxs);
            }
        }
        chains.push(AttackChain {
            chain_id: format!("CH-{:03}", chain_counter),
            name: "Web Exploitation → Persistence → Privilege Escalation".into(),
            description: "Web shell activity combined with service installation or suspicious executables suggests the attacker gained initial access via a web vulnerability, established persistence, and is escalating privileges.".into(),
            kill_chain_phase: "Initial Access → Persistence → Privilege Escalation".into(),
            confidence: "high".into(),
            finding_indices: indices,
        });
    }

    // Chain 4: Suspicious path + service install (potential malware deployment)
    if has_suspicious_path && has_service_install && !has_webshell {
        chain_counter += 1;
        let mut indices = Vec::new();
        if let Some(idxs) = rule_indices.get("win.suspicious_path") {
            indices.extend(idxs);
        }
        if let Some(idxs) = rule_indices.get("win.service_install") {
            indices.extend(idxs);
        }
        chains.push(AttackChain {
            chain_id: format!("CH-{:03}", chain_counter),
            name: "Malware Deployment via Service Installation".into(),
            description: "Executables in suspicious directories combined with service installation events suggest malware was deployed as a Windows service for persistence.".into(),
            kill_chain_phase: "Execution → Persistence".into(),
            confidence: "medium".into(),
            finding_indices: indices,
        });
    }

    // Chain 5: Log cleared + any other findings (evidence tampering)
    if has_log_cleared && findings.len() > 1 {
        chain_counter += 1;
        let mut indices = rule_indices.get("win.eventlog_cleared").cloned().unwrap_or_default();
        // Add all critical/high findings as potentially related
        for (i, f) in findings.iter().enumerate() {
            if (f.severity == "critical" || f.severity == "high")
                && f.rule_id != "win.eventlog_cleared"
                && !indices.contains(&i)
            {
                indices.push(i);
            }
        }
        if indices.len() > 1 {
            chains.push(AttackChain {
                chain_id: format!("CH-{:03}", chain_counter),
                name: "Evidence Tampering with Active Findings".into(),
                description: "Event logs were cleared while other high-severity findings exist. This strongly suggests an attacker (or insider) attempted to cover their tracks while other malicious activity is present.".into(),
                kill_chain_phase: "Defense Evasion".into(),
                confidence: "high".into(),
                finding_indices: indices,
            });
        }
    }

    chains
}
