//! Browser CDP tool — Chrome DevTools Protocol browser automation via chromiumoxide.
//!
//! Actions:
//! - `navigate`: Go to a URL
//! - `get_text`: Get page or element text
//! - `click`: Click an element by CSS selector
//! - `type_text`: Type text into an element
//! - `screenshot`: Take a screenshot, save to workspace
//! - `get_url`: Get current page URL
//! - `get_html`: Get page or element HTML
//! - `execute_js`: Execute JavaScript and return result
//! - `find_element`: Find element and return its attributes
//! - `close`: Close the browser session

use async_trait::async_trait;
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::page::{
    CaptureScreenshotFormat, CaptureScreenshotParams,
};
use chromiumoxide::page::Page;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

/// Maximum text length returned to the LLM (to avoid flooding context).
const MAX_TEXT_LEN: usize = 5000;

/// Inner state holding the browser connection.
struct BrowserInner {
    browser: Browser,
    page: Page,
}

/// Shared browser session with lazy initialization.
pub struct BrowserSession {
    inner: Mutex<Option<BrowserInner>>,
    workspace_dir: String,
}

impl BrowserSession {
    pub fn new(workspace_dir: String) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(None),
            workspace_dir,
        })
    }

    /// Get or initialize the browser session. Returns a cloneable Page.
    async fn get_or_init(&self) -> Result<Page, String> {
        let mut guard = self.inner.lock().await;
        if let Some(inner) = guard.as_ref() {
            return Ok(inner.page.clone());
        }

        info!("Browser CDP: launching Chrome (with window)...");

        let config = BrowserConfig::builder()
            .with_head()
            .viewport(chromiumoxide::handler::viewport::Viewport {
                width: 1920,
                height: 1080,
                device_scale_factor: Some(1.0),
                emulating_mobile: false,
                is_landscape: true,
                has_touch: false,
            })
            .build()
            .map_err(|e| format!("Failed to build browser config: {}", e))?;

        let (browser, mut handler) = Browser::launch(config)
            .await
            .map_err(|e| format!("Failed to launch browser: {}", e))?;

        // Spawn the handler task in the background
        tokio::spawn(async move {
            use futures::StreamExt;
            while let Some(_event) = handler.next().await {
                // Events are processed internally by the handler
            }
        });

        let page = browser
            .new_page("about:blank")
            .await
            .map_err(|e| format!("Failed to create page: {}", e))?;

        info!("Browser CDP: Chrome launched successfully");

        *guard = Some(BrowserInner {
            browser,
            page: page.clone(),
        });

        Ok(page)
    }

    /// Close the browser session.
    pub async fn close(&self) -> Result<(), String> {
        let mut guard = self.inner.lock().await;
        if let Some(mut inner) = guard.take() {
            info!("Browser CDP: closing Chrome");
            let _ = inner.browser.close().await;
        }
        Ok(())
    }
}

/// The browser CDP tool — single tool with multiple actions.
pub struct BrowserCdpTool {
    session: Arc<BrowserSession>,
}

impl BrowserCdpTool {
    pub fn new(session: Arc<BrowserSession>) -> Self {
        Self { session }
    }

    fn output_dir(&self) -> PathBuf {
        let dir = PathBuf::from(&self.session.workspace_dir).join("output");
        let _ = std::fs::create_dir_all(&dir);
        dir
    }
}

#[async_trait]
impl Tool for BrowserCdpTool {
    fn name(&self) -> &str { "browser_cdp" }

    fn description(&self) -> &str {
        "Control a Chrome browser via CDP (Chrome DevTools Protocol). \
         Actions:\n\
         - 'navigate': Go to a URL. Provide 'url'.\n\
         - 'get_text': Get page text or element text. Optional 'selector' (CSS).\n\
         - 'click': Click an element. Provide 'selector' (CSS).\n\
         - 'type_text': Type into an element. Provide 'selector' and 'text'.\n\
         - 'screenshot': Take a screenshot. Optional 'path' (defaults to workspace/output/).\n\
         - 'get_url': Get current page URL.\n\
         - 'get_html': Get page or element HTML. Optional 'selector' (CSS).\n\
         - 'execute_js': Run JavaScript. Provide 'js'.\n\
         - 'find_element': Find element by CSS selector. Provide 'selector'.\n\
         - 'close': Close the browser session."
    }

    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { false }
    fn category(&self) -> &str { "write" }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["navigate", "get_text", "click", "type_text", "screenshot",
                             "get_url", "get_html", "execute_js", "find_element", "close"],
                    "description": "Which browser action to perform"
                },
                "url": {
                    "type": "string",
                    "description": "URL to navigate to (for 'navigate' action)"
                },
                "selector": {
                    "type": "string",
                    "description": "CSS selector (for 'click', 'type_text', 'get_text', 'get_html', 'find_element')"
                },
                "text": {
                    "type": "string",
                    "description": "Text to type (for 'type_text' action)"
                },
                "js": {
                    "type": "string",
                    "description": "JavaScript code to execute (for 'execute_js' action)"
                },
                "path": {
                    "type": "string",
                    "description": "File path for screenshot (optional, defaults to workspace/output/)"
                }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let action = args["action"].as_str()
            .ok_or_else(|| "Missing 'action'".to_string())?;

        // Close does not need browser init
        if action == "close" {
            self.session.close().await.map_err(|e| -> crate::error::AgentError { e.into() })?;
            return Ok(json!({
                "success": true,
                "action": "close",
                "message": "Browser session closed"
            }));
        }

        // All other actions need the browser initialized
        let page = self.session.get_or_init().await
            .map_err(|e| -> crate::error::AgentError { e.into() })?;

        match action {
            "navigate" => {
                let url = args["url"].as_str()
                    .ok_or_else(|| "Missing 'url' for navigate".to_string())?;
                page.goto(chromiumoxide::cdp::browser_protocol::page::NavigateParams {
                    url: url.to_string(),
                    referrer: None,
                    transition_type: None,
                    frame_id: None,
                    referrer_policy: None,
                }).await
                    .map_err(|e| format!("Navigate failed: {}", e))?;
                let _ = page.wait_for_navigation().await;
                let title = page.get_title().await
                    .map_err(|e| format!("Get title failed: {}", e))?
                    .unwrap_or_default();
                Ok(json!({
                    "success": true,
                    "action": "navigate",
                    "url": url,
                    "title": title
                }))
            }

            "get_text" => {
                let text = if let Some(selector) = args["selector"].as_str() {
                    let elem = page.find_element(selector)
                        .await
                        .map_err(|e| format!("Element not found '{}': {}", selector, e))?;
                    elem.inner_text().await
                        .map_err(|e| format!("Get text failed: {}", e))?
                        .unwrap_or_default()
                } else {
                    let result = page.evaluate_expression("document.body.innerText")
                        .await
                        .map_err(|e| format!("Evaluate failed: {}", e))?;
                    result.value().and_then(|v| v.as_str().map(String::from))
                        .unwrap_or_default()
                };
                let truncated = text.len() > MAX_TEXT_LEN;
                let brief = if truncated { &text[..MAX_TEXT_LEN] } else { &text };
                Ok(json!({
                    "success": true,
                    "action": "get_text",
                    "text": brief,
                    "truncated": truncated
                }))
            }

            "click" => {
                let selector = args["selector"].as_str()
                    .ok_or_else(|| "Missing 'selector' for click".to_string())?;
                let elem = page.find_element(selector)
                    .await
                    .map_err(|e| format!("Element not found '{}': {}", selector, e))?;
                elem.click().await
                    .map_err(|e| format!("Click failed: {}", e))?;
                let _ = tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                Ok(json!({
                    "success": true,
                    "action": "click",
                    "selector": selector
                }))
            }

            "type_text" => {
                let selector = args["selector"].as_str()
                    .ok_or_else(|| "Missing 'selector' for type_text".to_string())?;
                let text = args["text"].as_str()
                    .ok_or_else(|| "Missing 'text' for type_text".to_string())?;
                let elem = page.find_element(selector)
                    .await
                    .map_err(|e| format!("Element not found '{}': {}", selector, e))?;
                elem.click().await
                    .map_err(|e| format!("Click (focus) failed: {}", e))?;
                elem.type_str(text).await
                    .map_err(|e| format!("Type failed: {}", e))?;
                Ok(json!({
                    "success": true,
                    "action": "type_text",
                    "selector": selector,
                    "typed": text
                }))
            }

            "screenshot" => {
                let filename = format!("screenshot_{}.png",
                    chrono::Local::now().format("%Y%m%d_%H%M%S"));
                // Always save into workspace/output/ — if user provides 'path',
                // only use its file_name component (discard any directory portion).
                let file_name = if let Some(p) = args["path"].as_str() {
                    let pb = PathBuf::from(p);
                    pb.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or(filename)
                } else {
                    filename
                };
                let path = self.output_dir().join(&file_name);
                let params = CaptureScreenshotParams {
                    format: Some(CaptureScreenshotFormat::Png),
                    ..Default::default()
                };
                page.save_screenshot(params, &path)
                    .await
                    .map_err(|e| format!("Screenshot failed: {}", e))?;
                let url = format!("/workspace/output/{}", file_name);
                Ok(json!({
                    "success": true,
                    "action": "screenshot",
                    "url": url
                }))
            }

            "get_url" => {
                let url = page.url().await
                    .map_err(|e| format!("Get URL failed: {}", e))?
                    .unwrap_or_default();
                let title = page.get_title().await
                    .map_err(|e| format!("Get title failed: {}", e))?
                    .unwrap_or_default();
                Ok(json!({
                    "success": true,
                    "action": "get_url",
                    "url": url,
                    "title": title
                }))
            }

            "get_html" => {
                let html = if let Some(selector) = args["selector"].as_str() {
                    let elem = page.find_element(selector)
                        .await
                        .map_err(|e| format!("Element not found '{}': {}", selector, e))?;
                    elem.inner_html().await
                        .map_err(|e| format!("Get HTML failed: {}", e))?
                        .unwrap_or_default()
                } else {
                    page.content().await
                        .map_err(|e| format!("Get content failed: {}", e))?
                };
                let truncated = html.len() > MAX_TEXT_LEN;
                let brief = if truncated { &html[..MAX_TEXT_LEN] } else { &html };
                Ok(json!({
                    "success": true,
                    "action": "get_html",
                    "html": brief,
                    "truncated": truncated
                }))
            }

            "execute_js" => {
                let js = args["js"].as_str()
                    .ok_or_else(|| "Missing 'js' for execute_js".to_string())?;
                let result = page.evaluate_expression(js)
                    .await
                    .map_err(|e| format!("JS execution failed: {}", e))?;
                let value = result.value().cloned().unwrap_or(Value::Null);
                Ok(json!({
                    "success": true,
                    "action": "execute_js",
                    "result": value
                }))
            }

            "find_element" => {
                let selector = args["selector"].as_str()
                    .ok_or_else(|| "Missing 'selector' for find_element".to_string())?;
                let elem = page.find_element(selector)
                    .await
                    .map_err(|e| format!("Element not found '{}': {}", selector, e))?;
                let attrs = elem.attributes().await
                    .map_err(|e| format!("Get attributes failed: {}", e))?;
                let text = elem.inner_text().await
                    .map_err(|e| format!("Get text failed: {}", e))?
                    .unwrap_or_default();
                // attributes() returns flat vec: [name1, val1, name2, val2, ...]
                let mut attr_map = serde_json::Map::new();
                let mut iter = attrs.into_iter();
                while let (Some(k), Some(v)) = (iter.next(), iter.next()) {
                    attr_map.insert(k, Value::String(v));
                }
                let text_brief = if text.len() > 500 { &text[..500] } else { &text };
                Ok(json!({
                    "success": true,
                    "action": "find_element",
                    "selector": selector,
                    "attributes": attr_map,
                    "text": text_brief
                }))
            }

            _ => Err(format!(
                "Unknown action '{}'. Valid: navigate, get_text, click, type_text, \
                 screenshot, get_url, get_html, execute_js, find_element, close",
                action
            ).into())
        }
    }
}
