use async_trait::async_trait;
use serde_json::{json, Value};

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

        let findings_json: Vec<Value> = findings.iter().map(|f| {
            json!({
                "id": f.id,
                "rule_id": f.rule_id,
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
                "source": f.source,
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
