//! Risk-graded URL safety assessment (phishing / abuse heuristics).
//!
//! Inspired by thClaws' `external_url` / `net_guard`. These are offline
//! heuristics only - they never block retrieval (investigation may need to
//! visit hostile sites), but they annotate a risk level + reasons so the agent
//! and user can decide. Combine with SSRF protection for full coverage.

use std::net::IpAddr;

/// Overall risk of a URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

impl RiskLevel {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
        }
    }
    fn raise(self, other: RiskLevel) -> RiskLevel {
        use RiskLevel::*;
        match (self, other) {
            (High, _) | (_, High) => High,
            (Medium, _) | (_, Medium) => Medium,
            _ => Low,
        }
    }
}

/// Result of assessing a URL.
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct UrlAssessment {
    pub url: String,
    pub host: String,
    pub risk: RiskLevel,
    pub reasons: Vec<String>,
}

/// Free / ephemeral TLDs commonly abused for phishing.
const SUSPICIOUS_TLDS: &[&str] = &[
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".click", ".link",
    ".icu", ".site", ".live", ".club", ".online", ".rest", ".monster",
    ".tokyo", ".cyou", ".zip", ".mov", ".country", ".space",
];

/// High-signal phishing/social-engineering keywords in host or path.
const PHISH_KEYWORDS: &[&str] = &[
    "login", "signin", "sign-in", "verify", "account", "secure", "update",
    "billing", "bank", "paypal", "apple-id", "icloud", "microsoft365",
    "office365", "outlook", "web3", "wallet", "seed", "sync", "auth",
];

/// URL-shortener hosts (need expansion before trusting).
const SHORTENER_HOSTS: &[&str] = &[
    "t.co", "bit.ly", "tinyurl.com", "is.gd", "rb.gy", "cutt.ly", "goo.gl",
    "shorturl.at", "s.id", "ow.ly", "buff.ly", "v.gd",
];

/// Extract the host (without port) from a URL, lowercased. Best effort.
fn host_of(url: &str) -> String {
    let after_scheme = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => url,
    };
    let without_userinfo = match after_scheme.find('@') {
        Some(i) => &after_scheme[i + 1..],
        None => after_scheme,
    };
    let host_port = without_userinfo.split(['/', '?', '#']).next().unwrap_or("");
    let host = host_port.split(':').next().unwrap_or("").trim_matches(|c| c == '[' || c == ']');
    host.to_lowercase()
}

/// Port from a bare authority string (only meaningful when non-default).
fn authority_port(url: &str) -> Option<u16> {
    let after_scheme = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => url,
    };
    let without_userinfo = match after_scheme.find('@') {
        Some(i) => &after_scheme[i + 1..],
        None => after_scheme,
    };
    let host_port = without_userinfo.split(['/', '?', '#']).next().unwrap_or("");
    let is_ipv6 = host_port.starts_with('[');
    if is_ipv6 {
        // [::1]:8080
        if let Some(ri) = host_port.rfind("]:") {
            return host_port[ri + 2..].split(['/', '?', '#']).next().and_then(|p| p.parse().ok());
        }
        return None;
    }
    host_port.split(':').nth(1).and_then(|p| p.parse().ok())
}

/// Assess a URL and return a risk grade plus human-readable reasons.
pub fn assess_url(url: &str) -> UrlAssessment {
    let url = url.trim();
    let host = host_of(url);
    let mut risk = RiskLevel::Low;
    let mut reasons: Vec<String> = Vec::new();

    // 1) IP-literal host hides the real domain.
    if host.parse::<IpAddr>().is_ok() {
        risk = risk.raise(RiskLevel::High);
        reasons.push(format!("Host is an IP literal ({}) instead of a domain name", host));
    }

    // 2) '@' in the authority is a classic "malicious@trusted.com" spoof.
    if let Some(i) = url.find("://") {
        let after = &url[i + 3..];
        if after.find('@').is_some() {
            risk = risk.raise(RiskLevel::High);
            reasons.push("Authority contains '@' (displayed host is not the real host)".to_string());
        }
    }

    // 3) Suspicious / ephemeral TLD.
    if let Some((_, tld)) = host.rsplit_once('.') {
        let tld = format!(".{}", tld.to_lowercase());
        if SUSPICIOUS_TLDS.contains(&tld.as_str()) {
            risk = risk.raise(RiskLevel::Medium);
            reasons.push(format!("Ephemeral or frequently abused TLD '{}'", tld));
        }
    }

    // 4) Excessive label count (obfuscation).
    if host.matches('.').count() >= 4 {
        risk = risk.raise(RiskLevel::Medium);
        reasons.push("Suspiciously deep subdomain nesting".to_string());
    }

    // 5) Shortener (must expand before trusting).
    if SHORTENER_HOSTS.iter().any(|s| host == *s || host.ends_with(&format!(".{}", s))) {
        risk = risk.raise(RiskLevel::Medium);
        reasons.push("URL is a short-link; expand it before trusting".to_string());
    }

    // 6) Phishing keyword density (>=2 in host+path).
    let lower = url.to_lowercase();
    let hits: Vec<&str> = PHISH_KEYWORDS
        .iter()
        .filter(|k| lower.contains(*k))
        .copied()
        .collect();
    if hits.len() >= 2 {
        risk = risk.raise(RiskLevel::Medium);
        reasons.push(format!("Multiple high-signal keywords present: {:?}", &hits[..hits.len().min(4)]));
    }

    // 7) Non-standard port.
    if let Some(port) = authority_port(url) {
        if !matches!(port, 80 | 443 | 8080 | 8443) && port != 0 {
            risk = risk.raise(RiskLevel::Low);
            // keep low; unusual ports by themselves are weak evidence - just note it.
            reasons.push(format!("Non-standard port {:?}", port));
        }
    }

    if reasons.is_empty() {
        reasons.push("No obvious phishing indicators detected offline".to_string());
    }

    UrlAssessment { url: url.to_string(), host, risk, reasons }
}
