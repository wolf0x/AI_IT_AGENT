use async_trait::async_trait;
use mail_parser::{MessageParser, MimeHeaders};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

/// EML file parser for phishing email analysis.
/// Parses RFC5322 email messages and extracts headers, body, attachments,
/// URLs, and basic phishing indicators.
pub struct IrEmlTool;

#[async_trait]
impl Tool for IrEmlTool {
    fn name(&self) -> &str { "ir_eml" }
    fn description(&self) -> &str {
        "EML email file parser for phishing and malware analysis. \
         Parses .eml / RFC5322 messages and extracts: headers (From, To, CC, Reply-To, \
         Message-ID, Return-Path), body text/HTML, attachments (name, size, content-type), \
         embedded URLs, and basic phishing indicators (display name spoofing, suspicious TLDs, \
         URL/IP mismatches). Use with phishing SKILL for full analysis workflow."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the .eml file to parse"
                },
                "extract_urls": {
                    "type": "boolean",
                    "description": "Extract all URLs from HTML body (default: true)"
                },
                "max_body_chars": {
                    "type": "integer",
                    "description": "Maximum body text characters to return (default: 10000)"
                }
            },
            "required": ["path"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let path = args["path"].as_str().ok_or("Missing 'path' parameter")?;
        let extract_urls = args["extract_urls"].as_bool().unwrap_or(true);
        let max_body = args["max_body_chars"].as_u64().unwrap_or(10000) as usize;

        // Read the EML file
        let raw = fs::read(path)
            .map_err(|e| format!("Failed to read EML file '{}': {}", path, e))?;

        // Parse with mail-parser
        let message = MessageParser::default()
            .parse(&raw)
            .ok_or_else(|| format!("Failed to parse EML file: {}", path))?;

        // ── Extract Headers ──
        let from = extract_address(message.from());
        let to = extract_address_list(message.to());
        let cc = extract_address_list(message.cc());
        let reply_to = extract_address(message.reply_to());
        let return_path = message.header("Return-Path")
            .and_then(|v| v.as_text().map(|s| s.to_string()));
        let subject = message.subject().unwrap_or("").to_string();
        let date = message.date().map(|d| d.to_rfc3339());
        let message_id = message.message_id().map(|s| s.to_string());

        // Extract Received headers for hop analysis
        let mut received_hops = Vec::new();
        if let Some(received) = message.received() {
            let mut hop = json!({});
            if let Some(from_host) = received.from() {
                hop["from"] = json!(from_host.to_string());
            }
            if let Some(by_host) = received.by() {
                hop["by"] = json!(by_host.to_string());
            }
            if let Some(when) = received.date() {
                hop["date"] = json!(when.to_rfc3339());
            }
            received_hops.push(hop);
        }

        // Additional headers for forensic analysis
        let x_mailer = message.header("X-Mailer")
            .and_then(|v| v.as_text().map(|s| s.to_string()));
        let x_originating_ip = message.header("X-Originating-IP")
            .and_then(|v| v.as_text().map(|s| s.to_string()));
        let authentication_results = message.header("Authentication-Results")
            .and_then(|v| v.as_text().map(|s| s.to_string()));
        let dkim_signature = message.header("DKIM-Signature")
            .and_then(|v| v.as_text().map(|s| s.to_string()));

        // ── Extract Body ──
        let body_text = message.body_text(0)
            .map(|s| {
                if s.len() > max_body { format!("{}...", &s[..max_body]) }
                else { s.to_string() }
            });
        let body_html = message.body_html(0)
            .map(|s| {
                if s.len() > max_body { format!("{}...", &s[..max_body]) }
                else { s.to_string() }
            });

        // ── Extract URLs from HTML body ──
        let mut urls: Vec<String> = Vec::new();
        let mut suspicious_urls: Vec<Value> = Vec::new();
        if extract_urls {
            if let Some(ref html) = body_html {
                urls = extract_urls_from_html(html);
                suspicious_urls = analyze_urls_for_phishing(&urls, &from);
            }
            // Also scan plain text body for URLs
            if let Some(ref text) = body_text {
                let text_urls = extract_urls_from_text(text);
                for u in text_urls {
                    if !urls.contains(&u) {
                        urls.push(u);
                    }
                }
            }
        }

        // ── Extract Attachments ──
        let mut attachments = Vec::new();
        for attachment in message.attachments() {
            let ct_str = attachment.content_type()
                .map(|ct| format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or("*")))
                .unwrap_or_default();
            let mut att_info = json!({
                "size": attachment.len(),
                "content_type": ct_str,
            });
            if let Some(name) = attachment.attachment_name() {
                att_info["filename"] = json!(name);
            }
            if let Some(cid) = attachment.content_id() {
                att_info["content_id"] = json!(cid);
            }
            // Check for nested messages
            if let Some(nested) = attachment.message() {
                att_info["is_nested_message"] = json!(true);
                att_info["nested_subject"] = json!(nested.subject().unwrap_or(""));
                att_info["nested_from"] = json!(extract_address(nested.from()));
            }
            // Check for suspicious extensions
            if let Some(name) = attachment.attachment_name() {
                let lower = name.to_lowercase();
                let suspicious_ext = [".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".wsf",
                                      ".ps1", ".hta", ".cpl", ".msi", ".dll", ".com", ".pif"];
                if suspicious_ext.iter().any(|ext| lower.ends_with(ext)) {
                    att_info["suspicious_extension"] = json!(true);
                }
                // Double extension check (e.g., invoice.pdf.exe)
                let parts: Vec<&str> = lower.rsplitn(3, '.').collect();
                if parts.len() >= 3 {
                    let inner = parts[1];
                    let outer = parts[0];
                    let doc_exts = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "png", "gif"];
                    if doc_exts.contains(&inner) && suspicious_ext.contains(&format!(".{}", outer).as_str()) {
                        att_info["double_extension"] = json!(true);
                    }
                }
            }
            attachments.push(att_info);
        }

        // ── Phishing Indicators ──
        let mut indicators = Vec::new();

        // Display name spoofing: From name looks like a known org but email doesn't match
        if let Some(ref from_info) = from {
            if let Some(name) = from_info.get("name").and_then(|v| v.as_str()) {
                if let Some(addr) = from_info.get("email").and_then(|v| v.as_str()) {
                    let name_lower = name.to_lowercase();
                    let addr_lower = addr.to_lowercase();
                    // Check if name contains org-like words but email domain doesn't match
                    let org_keywords = ["microsoft", "google", "apple", "amazon", "paypal",
                                        "bank", "support", "admin", "security", "notification",
                                        "service", "team", "helpdesk"];
                    for keyword in &org_keywords {
                        if name_lower.contains(keyword) && !addr_lower.contains(keyword) {
                            indicators.push(json!({
                                "type": "display_name_spoofing",
                                "severity": "high",
                                "description": format!("From name '{}' contains '{}' but email domain doesn't match", name, keyword),
                            }));
                            break;
                        }
                    }
                }
            }
        }

        // Reply-To mismatch
        if let (Some(ref from_info), Some(ref reply_info)) = (&from, &reply_to) {
            let from_addr = from_info.get("email").and_then(|v| v.as_str()).unwrap_or("");
            let reply_addr = reply_info.get("email").and_then(|v| v.as_str()).unwrap_or("");
            if !from_addr.is_empty() && !reply_addr.is_empty()
                && from_addr.to_lowercase() != reply_addr.to_lowercase()
            {
                indicators.push(json!({
                    "type": "reply_to_mismatch",
                    "severity": "medium",
                    "description": format!("Reply-To ({}) differs from From ({})", reply_addr, from_addr),
                }));
            }
        }

        // Return-Path mismatch
        if let (Some(ref from_info), Some(ref rp)) = (&from, &return_path) {
            let from_addr = from_info.get("email").and_then(|v| v.as_str()).unwrap_or("");
            if !from_addr.is_empty() && !rp.is_empty()
                && from_addr.to_lowercase() != rp.to_lowercase()
                && !rp.contains("<>")
            {
                indicators.push(json!({
                    "type": "return_path_mismatch",
                    "severity": "medium",
                    "description": format!("Return-Path ({}) differs from From ({})", rp, from_addr),
                }));
            }
        }

        // X-Originating-IP present (useful for tracing)
        if let Some(ref ip) = x_originating_ip {
            indicators.push(json!({
                "type": "originating_ip",
                "severity": "info",
                "description": format!("X-Originating-IP: {}", ip.trim_matches(|c| c == '[' || c == ']')),
            }));
        }

        // Suspicious URLs found
        if !suspicious_urls.is_empty() {
            indicators.push(json!({
                "type": "suspicious_urls",
                "severity": "high",
                "count": suspicious_urls.len(),
                "description": format!("{} potentially malicious URLs detected in email body", suspicious_urls.len()),
            }));
        }

        // Suspicious attachments
        let suspicious_atts: Vec<_> = attachments.iter()
            .filter(|a| a.get("suspicious_extension").and_then(|v| v.as_bool()).unwrap_or(false)
                      || a.get("double_extension").and_then(|v| v.as_bool()).unwrap_or(false))
            .collect();
        if !suspicious_atts.is_empty() {
            indicators.push(json!({
                "type": "suspicious_attachment",
                "severity": "critical",
                "count": suspicious_atts.len(),
                "description": format!("{} attachment(s) with suspicious file extensions", suspicious_atts.len()),
            }));
        }

        // Urgency language detection
        if let Some(ref text) = body_text {
            let lower = text.to_lowercase();
            let urgency_words = ["urgent", "immediately", "suspend", "verify your account",
                                 "unauthorized", "compromised", "expire", "24 hours",
                                 "click here", "confirm your", "update your", "action required"];
            let urgency_count = urgency_words.iter().filter(|w| lower.contains(*w)).count();
            if urgency_count >= 3 {
                indicators.push(json!({
                    "type": "urgency_language",
                    "severity": "medium",
                    "triggered_count": urgency_count,
                    "description": format!("Email contains {} urgency/social-engineering indicators", urgency_count),
                }));
            }
        }

        // Overall risk assessment
        let risk_level = if indicators.iter().any(|i| i["severity"] == "critical") {
            "critical"
        } else if indicators.iter().any(|i| i["severity"] == "high") {
            "high"
        } else if indicators.iter().any(|i| i["severity"] == "medium") {
            "medium"
        } else {
            "low"
        };

        Ok(json!({
            "status": "ok",
            "file": path,
            "headers": {
                "from": from,
                "to": to,
                "cc": cc,
                "reply_to": reply_to,
                "return_path": return_path,
                "subject": subject,
                "date": date,
                "message_id": message_id,
                "x_mailer": x_mailer,
                "x_originating_ip": x_originating_ip,
                "dkim_signature": dkim_signature.is_some(),
                "authentication_results": authentication_results,
                "received_hops": received_hops,
            },
            "body": {
                "text": body_text,
                "html": body_html,
            },
            "urls": {
                "total": urls.len(),
                "list": urls,
                "suspicious": suspicious_urls,
            },
            "attachments": {
                "total": attachments.len(),
                "list": attachments,
            },
            "phishing_indicators": {
                "risk_level": risk_level,
                "total_indicators": indicators.len(),
                "indicators": indicators,
            },
        }))
    }
}

/// Extract address info from an optional Address header value.
fn extract_address(addr: Option<&mail_parser::Address>) -> Option<Value> {
    addr.map(|a| match a {
        mail_parser::Address::List(list) if !list.is_empty() => {
            let first = &list[0];
            json!({
                "name": first.name().unwrap_or(""),
                "email": first.address().unwrap_or(""),
            })
        }
        mail_parser::Address::Group(groups) if !groups.is_empty() => {
            let addrs = &groups[0];
            if let Some(first) = addrs.addresses.first() {
                json!({
                    "name": first.name().unwrap_or(""),
                    "email": first.address().unwrap_or(""),
                })
            } else {
                json!({ "group": addrs.name.as_deref().unwrap_or("") })
            }
        }
        _ => json!(null),
    }).and_then(|v| if v.is_null() { None } else { Some(v) })
}

/// Extract a list of addresses from an optional Address header.
fn extract_address_list(addr: Option<&mail_parser::Address>) -> Vec<Value> {
    let mut result = Vec::new();
    if let Some(a) = addr {
        match a {
            mail_parser::Address::List(list) => {
                for a in list {
                    result.push(json!({
                        "name": a.name().unwrap_or(""),
                        "email": a.address().unwrap_or(""),
                    }));
                }
            }
            mail_parser::Address::Group(groups) => {
                for g in groups {
                    for a in &g.addresses {
                        result.push(json!({
                            "name": a.name().unwrap_or(""),
                            "email": a.address().unwrap_or(""),
                            "group": g.name.as_deref().unwrap_or(""),
                        }));
                    }
                }
            }
        }
    }
    result
}

/// Extract URLs from HTML content using simple regex.
fn extract_urls_from_html(html: &str) -> Vec<String> {
    let mut urls = BTreeSet::new();
    let url_re = regex::Regex::new(r#"https?://[^\s"'<>)\]]+"#).unwrap();
    for cap in url_re.find_iter(html) {
        let url = cap.as_str().trim_end_matches(|c: char| c == '.' || c == ',' || c == ';');
        urls.insert(url.to_string());
    }
    urls.into_iter().collect()
}

/// Extract URLs from plain text.
fn extract_urls_from_text(text: &str) -> Vec<String> {
    let mut urls = BTreeSet::new();
    let url_re = regex::Regex::new(r"https?://\S+").unwrap();
    for cap in url_re.find_iter(text) {
        let url = cap.as_str().trim_end_matches(|c: char| c == '.' || c == ',' || c == ')' || c == '\n');
        urls.insert(url.to_string());
    }
    urls.into_iter().collect()
}

/// Analyze URLs for phishing indicators.
fn analyze_urls_for_phishing(urls: &[String], from: &Option<Value>) -> Vec<Value> {
    let mut suspicious = Vec::new();
    let from_domain = from.as_ref()
        .and_then(|f| f.get("email"))
        .and_then(|e| e.as_str())
        .and_then(|e| e.split('@').nth(1))
        .unwrap_or("");

    let suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz",
                           ".pw", ".cc", ".club", ".work", ".date", ".review"];

    for url in urls {
        let mut reasons: Vec<String> = Vec::new();

        // Parse domain from URL
        if let Some(domain) = extract_domain(url) {
            let domain_lower = domain.to_lowercase();

            // Check suspicious TLD
            if suspicious_tlds.iter().any(|tld| domain_lower.ends_with(tld)) {
                reasons.push("suspicious TLD".to_string());
            }

            // Check if URL contains IP address instead of domain
            let ip_re = regex::Regex::new(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap();
            if ip_re.is_match(url) {
                reasons.push("URL uses raw IP address".to_string());
            }

            // Check for URL/brand mismatch (URL domain doesn't match sender domain)
            if !from_domain.is_empty() && !domain_lower.contains(from_domain) && !from_domain.contains(&domain_lower) {
                // Check if URL contains brand-like keywords
                let brands = ["microsoft", "google", "apple", "amazon", "paypal", "bank", "outlook", "office365"];
                if brands.iter().any(|b| domain_lower.contains(b)) && !from_domain.contains(&domain_lower) {
                    reasons.push(format!("URL domain '{}' mimics brand but sender is '{}'", domain_lower, from_domain));
                }
            }

            // Check for homograph-like patterns (multiple subdomains)
            let dot_count = domain_lower.matches('.').count();
            if dot_count >= 3 {
                reasons.push("excessive subdomains (possible homograph)".to_string());
            }

            // Check for @ in URL (URL spoofing)
            if url.contains('@') {
                reasons.push("URL contains @ symbol (possible redirect spoofing)".to_string());
            }
        }

        // Check for URL shorteners
        let shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "shorturl.at"];
        if shorteners.iter().any(|s| url.contains(s)) {
            reasons.push("URL shortener detected".to_string());
        }

        if !reasons.is_empty() {
            suspicious.push(json!({
                "url": url,
                "reasons": reasons,
                "severity": if reasons.iter().any(|r| r.contains("IP address") || r.contains("mimics brand")) { "high" } else { "medium" },
            }));
        }
    }

    suspicious
}

/// Extract domain from a URL string.
fn extract_domain(url: &str) -> Option<String> {
    let url_re = regex::Regex::new(r"https?://([^/:]+)").unwrap();
    url_re.captures(url).map(|c| c[1].to_string())
}
