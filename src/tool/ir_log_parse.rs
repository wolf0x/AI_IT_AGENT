use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::fs::File;
use regex::Regex;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

/// Generic log file parser — auto-detects format and extracts structured records.
/// Supports: Linux syslog (RFC3164), Windows Event Log text export, CSV,
/// and generic timestamp-prefixed text logs.
///
/// Ported from RavenEye's syslog-worker.js multi-format parser.
pub struct IrLogParseTool;

// ── Log format detection ────────────────────────────────────────
#[derive(Debug, Clone, Copy)]
enum LogFormat {
    Syslog,         // RFC3164: "Mon DD HH:MM:SS hostname program[pid]: message"
    WindowsText,    // "MM/DD/YYYY HH:MM:SS AM/PM" prefix
    Csv,            // Comma-separated with header
    Generic,        // ISO timestamp or any timestamp prefix
}

fn detect_format(first_line: &str, second_line: Option<&str>) -> LogFormat {
    // CSV: starts with common CSV headers or has consistent comma separation
    if first_line.contains(',') && second_line.map_or(false, |l| {
        let c1 = first_line.matches(',').count();
        let c2 = l.matches(',').count();
        c1 > 2 && c1 == c2
    }) {
        return LogFormat::Csv;
    }

    // Syslog: "Mon DD HH:MM:SS" or "Mon  D HH:MM:SS"
    if Regex::new(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+").unwrap().is_match(first_line) {
        return LogFormat::Syslog;
    }

    // Windows text export: "MM/DD/YYYY HH:MM:SS" or "YYYY/MM/DD HH:MM:SS"
    if Regex::new(r"^\d{1,4}[/\-]\d{1,2}[/\-]\d{1,4}\s+\d{1,2}:\d{2}:\d{2}").unwrap().is_match(first_line) {
        return LogFormat::WindowsText;
    }

    // Generic: ISO timestamp "YYYY-MM-DDTHH:MM:SS" or "YYYY-MM-DD HH:MM:SS"
    if Regex::new(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}").unwrap().is_match(first_line) {
        return LogFormat::Generic;
    }

    LogFormat::Generic
}

// ── Syslog parser ───────────────────────────────────────────────
fn parse_syslog_line(line: &str) -> Option<Value> {
    let re = Regex::new(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)$").unwrap();
    let caps = re.captures(line)?;

    let month = caps.get(1)?.as_str();
    let day = caps.get(2)?.as_str();
    let time = caps.get(3)?.as_str();
    let host = caps.get(4)?.as_str();
    let rest = caps.get(5)?.as_str();

    // Split program[pid]: message
    let (program, message) = if let Some(colon_pos) = rest.find(':') {
        let prog_part = &rest[..colon_pos];
        let msg = rest[colon_pos+1..].trim();
        if let Some(bracket) = prog_part.find('[') {
            (&prog_part[..bracket], msg)
        } else {
            (prog_part, msg)
        }
    } else {
        (rest, "")
    };

    // Classify severity from message content
    let severity = classify_severity(message);

    Some(json!({
        "timestamp": format!("{} {} {}", month, day, time),
        "hostname": host,
        "program": program.trim(),
        "message": message,
        "severity": severity,
    }))
}

// ── Windows text log parser ─────────────────────────────────────
fn parse_windows_text_line(line: &str) -> Option<Value> {
    let re = Regex::new(r"^(\d{1,4}[/\-]\d{1,2}[/\-]\d{1,4}\s+\d{1,2}:\d{2}:\d{2}(?:\s*[APap][Mm])?)\s+(.+)$").unwrap();
    let caps = re.captures(line)?;

    let timestamp = caps.get(1)?.as_str();
    let rest = caps.get(2)?.as_str();

    let severity = classify_severity(rest);

    Some(json!({
        "timestamp": timestamp,
        "message": rest,
        "severity": severity,
    }))
}

// ── CSV parser ──────────────────────────────────────────────────
fn parse_csv_lines(lines: &[String]) -> Vec<Value> {
    if lines.is_empty() { return Vec::new(); }

    let headers: Vec<&str> = lines[0].split(',').map(|s| s.trim().trim_matches('"')).collect();
    let mut records = Vec::new();

    for line in &lines[1..] {
        let values: Vec<&str> = line.split(',').map(|s| s.trim().trim_matches('"')).collect();
        if values.len() != headers.len() { continue; }

        let mut record = serde_json::Map::new();
        for (i, header) in headers.iter().enumerate() {
            record.insert(header.to_string(), json!(values[i]));
        }

        // Try to find severity/level column
        let severity = headers.iter().position(|h| {
            let hl = h.to_lowercase();
            hl == "severity" || hl == "level" || hl == "priority" || hl == "risk"
        }).map(|idx| classify_severity(values[idx]))
          .unwrap_or_else(|| "info".to_string());

        record.insert("severity".to_string(), json!(severity));
        records.push(Value::Object(record));
    }

    records
}

// ── Generic timestamp parser ────────────────────────────────────
fn parse_generic_line(line: &str) -> Option<Value> {
    let re = Regex::new(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*)\s*(.*)$").unwrap();
    let caps = re.captures(line)?;

    let timestamp = caps.get(1)?.as_str();
    let message = caps.get(2).map_or("", |m| m.as_str());

    let severity = classify_severity(message);

    Some(json!({
        "timestamp": timestamp,
        "message": message,
        "severity": severity,
    }))
}

// ── Severity classification ─────────────────────────────────────
fn classify_severity(text: &str) -> String {
    let lower = text.to_lowercase();
    if lower.contains("critical") || lower.contains("crit") || lower.contains("emergency") || lower.contains("emerg") || lower.contains("panic") {
        "critical".to_string()
    } else if lower.contains("error") || lower.contains("err") || lower.contains("fail") || lower.contains("failure") {
        "error".to_string()
    } else if lower.contains("warn") || lower.contains("warning") {
        "warning".to_string()
    } else if lower.contains("debug") || lower.contains("trace") {
        "debug".to_string()
    } else if lower.contains("info") || lower.contains("notice") {
        "info".to_string()
    } else {
        "info".to_string()
    }
}

// ── Security pattern detection ──────────────────────────────────
fn detect_security_patterns(text: &str) -> Vec<String> {
    let mut findings = Vec::new();
    let lower = text.to_lowercase();

    let patterns: Vec<(&str, &str)> = vec![
        ("authentication failure", "AuthFailure"),
        ("failed password", "AuthFailure"),
        ("invalid user", "AuthFailure"),
        ("access denied", "AccessDenied"),
        ("permission denied", "AccessDenied"),
        ("unauthorized", "AccessDenied"),
        ("privilege escalation", "PrivEsc"),
        ("sudo", "SudoUsage"),
        ("su:", "SuUsage"),
        ("root", "RootAccess"),
        ("segfault", "Crash"),
        ("oom-killer", "OOM"),
        ("out of memory", "OOM"),
        ("kernel panic", "KernelPanic"),
        ("malware", "Malware"),
        ("virus", "Malware"),
        ("trojan", "Malware"),
        ("backdoor", "Backdoor"),
        ("exploit", "Exploit"),
        ("buffer overflow", "Exploit"),
        ("shellcode", "Exploit"),
        ("reverse shell", "ReverseShell"),
        ("bind shell", "ReverseShell"),
        ("connection refused", "ConnRefused"),
        ("timeout", "Timeout"),
        ("disk full", "DiskFull"),
        ("no space left", "DiskFull"),
    ];

    for (needle, label) in patterns {
        if lower.contains(needle) && !findings.contains(&label.to_string()) {
            findings.push(label.to_string());
        }
    }

    findings
}

#[async_trait]
impl Tool for IrLogParseTool {
    fn name(&self) -> &str { "ir_log_parse" }

    fn description(&self) -> &str {
        "Generic log file parser with auto-format detection. Supports Linux syslog (RFC3164), \
         Windows Event Log text export, CSV, and generic timestamp-prefixed logs. \
         Auto-classifies severity levels and detects security patterns (auth failures, \
         privilege escalation, malware indicators, crashes, OOM). \
         Returns structured records with statistics and security findings. \
         Handles large files via streaming."
    }

    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the log file"
                },
                "max_records": {
                    "type": "integer",
                    "description": "Maximum records to return (default 500)"
                },
                "severity": {
                    "type": "string",
                    "enum": ["all", "critical", "error", "warning", "info", "debug"],
                    "description": "Minimum severity to include (default 'all')"
                },
                "security_only": {
                    "type": "boolean",
                    "description": "Only return records with security findings (default false)"
                },
                "search": {
                    "type": "string",
                    "description": "Text search filter — only return records containing this text"
                }
            },
            "required": ["file_path"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let file_path = args["file_path"].as_str()
            .ok_or_else(|| -> crate::error::AgentError { "Missing required parameter: file_path".into() })?;

        let max_records = args["max_records"].as_u64().unwrap_or(500) as usize;
        let min_severity = args["severity"].as_str().unwrap_or("all");
        let security_only = args["security_only"].as_bool().unwrap_or(false);
        let search_text = args["search"].as_str().map(|s| s.to_lowercase());

        let file = File::open(file_path)
            .map_err(|e| -> crate::error::AgentError { format!("Cannot open file: {}", e).into() })?;

        let reader = BufReader::new(file);
        let mut lines_iter = reader.lines();

        // Read first two lines for format detection
        let first_line = match lines_iter.next() {
            Some(Ok(l)) => l,
            Some(Err(e)) => return Err(format!("Read error: {}", e).into()),
            None => return Ok(json!({"status": "ok", "file": file_path, "format": "empty", "summary": {"total_lines": 0}, "records": []})),
        };
        let second_line = match lines_iter.next() {
            Some(Ok(l)) => Some(l),
            _ => None,
        };

        let format = detect_format(&first_line, second_line.as_deref());
        let format_name = match format {
            LogFormat::Syslog => "syslog",
            LogFormat::WindowsText => "windows-text",
            LogFormat::Csv => "csv",
            LogFormat::Generic => "generic",
        };

        // Severity filter levels
        let severity_rank = |s: &str| -> u32 {
            match s {
                "critical" => 4,
                "error" => 3,
                "warning" => 2,
                "info" => 1,
                "debug" => 0,
                _ => 1,
            }
        };
        let min_rank = severity_rank(min_severity);

        // Collect all lines for CSV processing
        let mut all_lines: Vec<String> = Vec::new();
        if matches!(format, LogFormat::Csv) {
            all_lines.push(first_line);
            if let Some(l) = second_line { all_lines.push(l); }
            for line in lines_iter.by_ref() {
                match line {
                    Ok(l) => all_lines.push(l),
                    Err(_) => break,
                }
            }
            let records = parse_csv_lines(&all_lines);
            return Ok(json!({
                "status": "ok",
                "file": file_path,
                "format": format_name,
                "summary": {
                    "total_lines": all_lines.len(),
                    "parsed_records": records.len(),
                },
                "records": records.into_iter().take(max_records).collect::<Vec<_>>(),
            }));
        }

        // Non-CSV: process line by line
        let mut total_lines: u64 = 1;
        let mut parsed_records: u64 = 0;
        let mut returned_records: u64 = 0;
        let mut records: Vec<Value> = Vec::new();
        let mut severity_counts: HashMap<String, u64> = HashMap::new();
        let mut security_findings: HashMap<String, u64> = HashMap::new();

        // Process first line
        let process_line = |line: &str, format: LogFormat| -> Option<Value> {
            match format {
                LogFormat::Syslog => parse_syslog_line(line),
                LogFormat::WindowsText => parse_windows_text_line(line),
                LogFormat::Generic => parse_generic_line(line),
                LogFormat::Csv => None,
            }
        };

        let mut handle_record = |record: &mut Value| {
            parsed_records += 1;
            let severity = record["severity"].as_str().unwrap_or("info").to_string();
            *severity_counts.entry(severity.clone()).or_insert(0) += 1;

            // Security pattern detection
            let msg = record["message"].as_str().unwrap_or("").to_string();
            let findings = detect_security_patterns(&msg);
            if !findings.is_empty() {
                record.as_object_mut().unwrap().insert("security".to_string(), json!(findings));
                for f in &findings {
                    *security_findings.entry(f.clone()).or_insert(0) += 1;
                }
            }

            // Apply filters
            if severity_rank(&severity) < min_rank { return; }
            if security_only && findings.is_empty() { return; }
            if let Some(ref search) = search_text {
                let full_text = serde_json::to_string(record).unwrap_or_default().to_lowercase();
                if !full_text.contains(search.as_str()) { return; }
            }

            if records.len() < max_records {
                records.push(record.clone());
                returned_records += 1;
            }
        };

        // Process first two lines
        if let Some(mut rec) = process_line(&first_line, format) {
            handle_record(&mut rec);
        }
        if let Some(ref l) = second_line {
            total_lines += 1;
            if let Some(mut rec) = process_line(l, format) {
                handle_record(&mut rec);
            }
        }

        // Process remaining lines
        for line_result in lines_iter {
            let line = match line_result {
                Ok(l) => l,
                Err(_) => break,
            };
            total_lines += 1;
            if line.trim().is_empty() { continue; }

            if let Some(mut rec) = process_line(&line, format) {
                handle_record(&mut rec);
            }
        }

        let severity_summary: Vec<Value> = severity_counts.into_iter()
            .map(|(sev, count)| json!({"severity": sev, "count": count}))
            .collect();

        let security_summary: Vec<Value> = security_findings.into_iter()
            .map(|(finding, count)| json!({"pattern": finding, "count": count}))
            .collect();

        Ok(json!({
            "status": "ok",
            "file": file_path,
            "format": format_name,
            "summary": {
                "total_lines": total_lines,
                "parsed_records": parsed_records,
                "returned_records": returned_records,
            },
            "severity_summary": severity_summary,
            "security_summary": security_summary,
            "records": records,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_severity_classification() {
        assert_eq!(classify_severity("CRITICAL: system failure"), "critical");
        assert_eq!(classify_severity("ERROR: connection refused"), "error");
        assert_eq!(classify_severity("WARNING: disk space low"), "warning");
        assert_eq!(classify_severity("INFO: service started"), "info");
        assert_eq!(classify_severity("DEBUG: variable dump"), "debug");
    }

    #[test]
    fn test_security_pattern_detection() {
        let findings = detect_security_patterns("Failed password for root from 10.0.0.1");
        assert!(findings.contains(&"AuthFailure".to_string()));

        let findings = detect_security_patterns("sudo: user : command not allowed");
        assert!(findings.contains(&"SudoUsage".to_string()));

        let findings = detect_security_patterns("Out of memory: Kill process");
        assert!(findings.contains(&"OOM".to_string()));

        let findings = detect_security_patterns("normal log message");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_syslog_parsing() {
        let line = "Jul 15 10:15:30 webserver sshd[1234]: Failed password for root from 10.0.0.1";
        let record = parse_syslog_line(line).unwrap();
        assert_eq!(record["hostname"], "webserver");
        assert_eq!(record["program"], "sshd");
        assert!(record["message"].as_str().unwrap().contains("Failed password"));
    }

    #[test]
    fn test_format_detection() {
        assert!(matches!(
            detect_format("Jul 15 10:15:30 host prog: msg", Some("Jul 16 11:00:00 host prog: msg2")),
            LogFormat::Syslog
        ));
        assert!(matches!(
            detect_format("2026-07-15T10:15:30Z some message", None),
            LogFormat::Generic
        ));
    }

    #[test]
    fn test_log_parse_syslog() {
        let content = "Jul 15 10:15:30 webserver sshd[1234]: Failed password for root from 10.0.0.1\n\
                       Jul 15 10:16:00 webserver kernel: Out of memory: Kill process 8901\n\
                       Jul 15 10:17:00 webserver sudo: engineer : TTY=pts/0 ; COMMAND=/bin/ls\n";
        let path = std::env::temp_dir().join("test_syslog.txt");
        let mut f = File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();

        let tool = IrLogParseTool;
        let base = crate::context::ReadonlyContext::new("test".into(), "test".into(), "test".into());
        let cb = crate::context::CallbackContext::new(base);
        let ctx = crate::context::ToolContext::new(cb, "test".into(), ".".into());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(tool.execute(json!({
            "file_path": path.to_string_lossy(),
        }), &ctx)).unwrap();

        assert_eq!(result["status"], "ok");
        assert_eq!(result["format"], "syslog");
        assert!(result["summary"]["parsed_records"].as_u64().unwrap() >= 3);

        // Check security findings
        let security_summary = result["security_summary"].as_array().unwrap();
        let patterns: Vec<&str> = security_summary.iter()
            .map(|v| v["pattern"].as_str().unwrap())
            .collect();
        assert!(patterns.contains(&"AuthFailure"), "Should detect auth failure");

        std::fs::remove_file(&path).ok();
    }
}
