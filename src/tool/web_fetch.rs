use async_trait::async_trait;
use serde_json::{json, Value};

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
         Useful for reading web pages, APIs, downloading data. Supports custom headers and method."
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
                    "description": "Maximum response body length in characters (default: 50000)"
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

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let url = args["url"]
            .as_str()
            .ok_or_else(|| crate::error::AgentError::tool("web_fetch", "Missing required parameter: url"))?;

        // Validate URL scheme
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(crate::error::AgentError::tool(
                "web_fetch", "URL must start with http:// or https://",
            ));
        }

        let method = args["method"].as_str().unwrap_or("GET");
        let max_length = args["max_length"].as_u64().unwrap_or(50000) as usize;

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

        // Read body with length limit
        let body_text = response
            .text()
            .await
            .map_err(|e| crate::error::AgentError::tool("web_fetch", format!("Failed to read response body: {}", e)))?;

        let truncated = body_text.len() > max_length;
        let body = if truncated {
            body_text[..max_length].to_string()
        } else {
            body_text
        };

        Ok(json!({
            "status": status,
            "content_type": content_type,
            "body": body,
            "truncated": truncated,
            "body_length": body.len()
        }))
    }
}
