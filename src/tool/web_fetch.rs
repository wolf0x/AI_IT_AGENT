use async_trait::async_trait;
use serde_json::{json, Value};
use std::net::{IpAddr, ToSocketAddrs};

use crate::context::ToolContext;
use crate::error::AgentResult;
use crate::tool::Tool;

// ============================================================
// web_fetch — HTTP GET/POST tool for fetching web content
// ============================================================

pub struct WebFetchTool;

#[async_trait]
impl Tool for WebFetchTool {
    fn name(&self) -> &str {
        "web_fetch"
    }

    fn description(&self) -> &str {
        "Fetch content from a URL via HTTP GET or POST. Returns the response body as text. \
         Useful for reading web pages, APIs, downloading data. Supports custom headers and method. \
         SSRF protection blocks private IPs by default; set allow_private=true to bypass. \
         Large responses (>12k chars) are auto-saved to workspace/output/fetch/ and a preview + \
         saved_path is returned — use file_read to read the full content."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to fetch (must start with http:// or https://)"
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "description": "HTTP method (default: GET)"
                },
                "headers": {
                    "type": "object",
                    "description": "Optional HTTP headers as key-value pairs",
                    "additionalProperties": { "type": "string" }
                },
                "body": {
                    "type": "string",
                    "description": "Request body for POST requests"
                },
                "max_length": {
                    "type": "integer",
                    "description": "Maximum response body length in characters (default: context-scaled inline cap)"
                },
                "allow_private": {
                    "type": "boolean",
                    "description": "Bypass SSRF protection and allow private IPs (default: false). Set to true for internal network investigation"
                }
            },
            "required": ["url"]
        })
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn is_concurrency_safe(&self) -> bool {
        true
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value> {
        let url = args["url"]
            .as_str()
            .ok_or_else(|| crate::error::AgentError::tool("web_fetch", "Missing required parameter: url"))?;

        // Validate URL scheme
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(crate::error::AgentError::tool(
                "web_fetch", "URL must start with http:// or https://",
            ));
        }

        // SSRF protection: resolve host and reject non-public IPs
        // Can be bypassed by setting allow_private=true (for internal network investigation)
        let allow_private = args["allow_private"].as_bool().unwrap_or(false);
        if !allow_private {
            if let Some(host) = url.split("://").nth(1).and_then(|s| s.split('/').next()).and_then(|s| s.split(':').next()) {
                if let Ok(addrs) = (host, 0).to_socket_addrs() {
                    for addr in addrs {
                        let ip = addr.ip();
                        if !is_public_ip(ip) {
                            return Err(crate::error::AgentError::tool(
                                "web_fetch",
                                format!("SSRF protection: host '{}' resolves to non-public IP {}. Set allow_private=true to bypass", host, ip),
                            ));
                        }
                    }
                }
            }
        }

        let method = args["method"].as_str().unwrap_or("GET");
        // Context-scaled inline cap (raised with the model's context window when
        // scaling is enabled; bounded by the absolute max_inline_chars cap).
        let inline_limit = ctx.inline_limit(12_000);
        let preview_chars = ctx.inline_limit(8_000);
        let max_length = args["max_length"].as_u64().map(|v| v as usize).unwrap_or(inline_limit);

        // Build client with timeout
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("RustAgent/0.1")
            .build()
            .map_err(|e| crate::error::AgentError::tool("web_fetch", format!("Failed to build HTTP client: {}", e)))?;

        // Build request
        let mut req = match method {
            "POST" => client.post(url),
            _ => client.get(url),
        };

        // Add custom headers
        if let Some(headers) = args["headers"].as_object() {
            for (k, v) in headers {
                if let Some(v_str) = v.as_str() {
                    req = req.header(k.as_str(), v_str);
                }
            }
        }

        // Add body for POST
        if let Some(body) = args["body"].as_str() {
            req = req.body(body.to_string());
        }

        // Execute request
        let response = req
            .send()
            .await
            .map_err(|e| crate::error::AgentError::tool("web_fetch", format!("HTTP request failed: {}", e)))?;

        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        // Read body with length limit (stream with byte cap to avoid OOM)
        let body_bytes = response
            .bytes()
            .await
            .map_err(|e| crate::error::AgentError::tool("web_fetch", format!("Failed to read response body: {}", e)))?;

        // Cap at 10MB to prevent OOM from malicious servers
        let max_bytes = 10 * 1024 * 1024;
        let truncated_bytes = body_bytes.len() > max_bytes;
        let body_slice = if truncated_bytes { &body_bytes[..max_bytes] } else { &body_bytes };

        let body_text = String::from_utf8_lossy(body_slice).to_string();

        // ── Large-response auto-save (prevents context-window truncation) ──
        // Responses above INLINE_LIMIT chars are written to workspace/output/fetch/
        // and the LLM gets a preview + saved_path instead of a truncated inline body.
        let body_chars = body_text.chars().count();
        if body_chars > inline_limit {
            let name = format!(
                "fetch_{}_{}.json",
                ctx.base.base.session_id.get(..8).unwrap_or("sess"),
                chrono::Utc::now().format("%Y%m%d_%H%M%S%3f")
            );
            let dir = std::path::Path::new(&ctx.output_dir()).join("fetch");
            let _ = std::fs::create_dir_all(&dir);
            let path = dir.join(&name);
            match std::fs::write(&path, &body_text) {
                Ok(_) => {
                    let preview: String = body_text.chars().take(preview_chars).collect();
                    return Ok(json!({
                        "status": status,
                        "content_type": content_type,
                        "truncated": true,
                        "body_length": body_chars,
                        "preview": preview,
                        "saved_path": path.to_string_lossy(),
                        "note": "Response exceeded the inline limit; full content saved to saved_path. Use file_read to read it (in chunks if needed) instead of relying on the preview."
                    }));
                }
                Err(e) => {
                    // Fall through to inline truncation if the file cannot be written.
                    tracing::warn!("web_fetch: failed to save large response to {}: {}", path.display(), e);
                }
            }
        }

        let truncated = body_text.len() > max_length;
        let body = if truncated {
            body_text.chars().take(max_length).collect::<String>()
        } else {
            body_text
        };

        Ok(json!({
            "status": status,
            "content_type": content_type,
            "body": body,
            "truncated": truncated || truncated_bytes,
            "body_length": body.len()
        }))
    }
}

/// Check if an IP address is a public (globally routable) address.
/// Rejects loopback, link-local, private, and other non-public ranges.
fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_loopback()
                && !v4.is_private()
                && !v4.is_link_local()
                && !v4.is_multicast()
                && !v4.is_broadcast()
                && !v4.is_unspecified()
                // 169.254.0.0/16 (link-local, includes cloud metadata 169.254.169.254)
                && !(v4.octets()[0] == 169 && v4.octets()[1] == 254)
                // 100.64.0.0/10 (Carrier-grade NAT)
                && !(v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_multicast()
                && !v6.is_unspecified()
                // Reject unique local addresses (fc00::/7)
                && (v6.segments()[0] & 0xfe00) != 0xfc00
                // Reject link-local (fe80::/10)
                && (v6.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}
