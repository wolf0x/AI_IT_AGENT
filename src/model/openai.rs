use async_trait::async_trait;
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::config::ModelConfig;
use crate::error::{AgentError, AgentResult};
use crate::model::{
    ChatMessage, FunctionCallDelta, Llm, LlmRequest, LlmResponse,
    LlmResponseStream, ToolCallDelta, ToolDefinition,
};

/// OpenAI-compatible LLM provider.
/// Implements the Llm trait (modeled after ADK-RUST's OpenAIClient).
pub struct OpenAiProvider {
    client: Client,
    models: Vec<ModelConfig>,
}

// --- Internal streaming types ---

#[derive(Debug, Deserialize)]
struct StreamChunk {
    choices: Option<Vec<StreamChoice>>,
    usage: Option<RawUsage>,
}

#[derive(Debug, Deserialize)]
struct RawUsage {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    total_tokens: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct StreamChoice {
    delta: DeltaContent,
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeltaContent {
    #[allow(dead_code)]
    role: Option<String>,
    content: Option<String>,
    reasoning_content: Option<String>,
    tool_calls: Option<Vec<ToolCallChunk>>,
}

#[derive(Debug, Deserialize)]
struct ToolCallChunk {
    index: usize,
    id: Option<String>,
    function: Option<FunctionChunk>,
}

#[derive(Debug, Deserialize)]
struct FunctionChunk {
    name: Option<String>,
    arguments: Option<String>,
}

impl OpenAiProvider {
    pub fn new(models: Vec<ModelConfig>) -> Self {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(180))  // 3 minute timeout for LLM requests
            .build()
            .expect("Failed to create HTTP client");
        Self { client, models }
    }

    fn find_model(&self, name: &str) -> Option<&ModelConfig> {
        self.models.iter().find(|m| m.name == name).or(self.models.first())
    }

    /// Legacy chat_stream method for backward compat (used by agent loop internally).
    /// Sends text deltas through an mpsc channel and returns (content, tool_calls).
    pub async fn chat_stream(
        &self,
        model_name: &str,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
        tx: mpsc::Sender<AgentResult<crate::agent::AgentEvent>>,
        invocation_id: &str,
        author: &str,
    ) -> Result<(String, Vec<ToolCallDelta>), String> {
        let model = self.find_model(model_name).ok_or("No model configured")?;
        let api_key = model.resolved_api_key();
        let url = format!("{}/chat/completions", model.api_base.trim_end_matches('/'));

        let mut body = serde_json::json!({
            "model": model.name,
            "messages": messages,
            "stream": true,
            "temperature": 0.7,
            "max_tokens": 4096,
        });
        if !tools.is_empty() {
            body["tools"] = serde_json::to_value(tools).unwrap();
        }

        let mut req = self.client.post(&url).header("Content-Type", "application/json");
        if !api_key.is_empty() {
            req = req.bearer_auth(&api_key);
        }

        let resp = req.json(&body).send().await
            .map_err(|e| format!("LLM request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_body = resp.text().await.unwrap_or_default();
            return Err(format!("LLM error {}: {}", status, err_body));
        }

        let mut s = resp.bytes_stream();
        let mut full_content = String::new();
        let mut tool_calls_map: Vec<ToolCallAccum> = Vec::new();
        let mut buffer = String::new();

        while let Some(chunk_result) = s.next().await {
            let chunk_bytes = match chunk_result {
                Ok(b) => b,
                Err(e) => { warn!("Stream chunk error: {}", e); break; }
            };
            let text = String::from_utf8_lossy(&chunk_bytes);
            buffer.push_str(&text);

            while let Some(pos) = buffer.find('\n') {
                let line = buffer[..pos].trim().to_string();
                buffer = buffer[pos + 1..].to_string();

                if line.is_empty() || line == "data: [DONE]" { continue; }

                if let Some(data) = line.strip_prefix("data: ") {
                    match serde_json::from_str::<StreamChunk>(data) {
                        Ok(chunk) => {
                            if let Some(choices) = chunk.choices {
                                for choice in choices {
                                    // Handle reasoning_content (thinking phase for DeepSeek V4 etc.)
                                    if let Some(reasoning) = &choice.delta.reasoning_content {
                                        let _ = tx.try_send(
                                            Ok(crate::agent::AgentEvent::thinking(reasoning, invocation_id, author))
                                        );
                                    }
                                    // Handle content (actual response)
                                    if let Some(content) = &choice.delta.content {
                                        if !content.is_empty() {
                                            full_content.push_str(content);
                                            if tx.try_send(
                                                Ok(crate::agent::AgentEvent::text(content, invocation_id, author))
                                            ).is_err() {
                                                tracing::warn!("Failed to send text event: channel full");
                                            }
                                        }
                                    }
                                    if let Some(tcs) = &choice.delta.tool_calls {
                                        for tc in tcs {
                                            let idx = tc.index;
                                            while tool_calls_map.len() <= idx {
                                                tool_calls_map.push(ToolCallAccum::default());
                                            }
                                            if let Some(ref id) = tc.id {
                                                tool_calls_map[idx].id = id.clone();
                                            }
                                            if let Some(ref func) = tc.function {
                                                if let Some(ref name) = func.name {
                                                    tool_calls_map[idx].name.push_str(name);
                                                }
                                                if let Some(ref args) = func.arguments {
                                                    tool_calls_map[idx].arguments.push_str(args);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => { debug!("Failed to parse chunk: {} | data: {}", e, data); }
                    }
                }
            }
        }

        let tool_calls: Vec<ToolCallDelta> = tool_calls_map
            .into_iter()
            .filter(|tc| !tc.id.is_empty())
            .map(|tc| ToolCallDelta {
                id: tc.id,
                call_type: "function".to_string(),
                function: FunctionCallDelta {
                    name: Some(tc.name),
                    arguments: Some(tc.arguments),
                },
            })
            .collect();

        Ok((full_content, tool_calls))
    }
}

#[async_trait]
impl Llm for OpenAiProvider {
    fn name(&self) -> &str { "openai-compatible" }

    async fn generate_content(
        &self,
        request: LlmRequest,
        stream: bool,
    ) -> AgentResult<LlmResponseStream> {
        let model = self.find_model(&request.model)
            .ok_or_else(|| AgentError::model(format!("Model '{}' not found", request.model)))?;
        let api_key = model.resolved_api_key();
        let url = format!("{}/chat/completions", model.api_base.trim_end_matches('/'));

        let mut body = serde_json::json!({
            "model": model.name,
            "messages": request.messages,
            "stream": stream,
        });
        if !request.tools.is_empty() {
            body["tools"] = serde_json::to_value(&request.tools).unwrap();
        }
        if let Some(temp) = request.config.temperature {
            body["temperature"] = serde_json::json!(temp);
        }
        if let Some(max) = request.config.max_tokens {
            body["max_tokens"] = serde_json::json!(max);
        }

        let mut req = self.client.post(&url).header("Content-Type", "application/json");
        if !api_key.is_empty() {
            req = req.bearer_auth(&api_key);
        }

        let resp = req.json(&body).send().await
            .map_err(|e| AgentError::model(format!("Request failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_body = resp.text().await.unwrap_or_default();
            return Err(AgentError::model(format!("{}: {}", status, err_body)));
        }

        if !stream {
            // Non-streaming: read full response
            let text = resp.text().await.map_err(|e| AgentError::model(e.to_string()))?;
            let parsed: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| AgentError::model(format!("Parse: {}", e)))?;

            let content = parsed["choices"][0]["message"]["content"]
                .as_str().map(|s| s.to_string());
            let response = LlmResponse {
                content,
                tool_calls: vec![],
                finish_reason: parsed["choices"][0]["finish_reason"].as_str().map(|s| s.to_string()),
                usage: None,
            };
            return Ok(Box::pin(stream::once(async move { Ok(response) })));
        }

        // Streaming: return a stream that parses SSE chunks
        let byte_stream = resp.bytes_stream();

        let parsed_stream = async_stream::stream! {
            let mut buf = String::new();
            let mut tc_map: Vec<ToolCallAccum> = Vec::new();
            let mut accumulated_content = String::new();
            let mut accumulated_reasoning = String::new();
            let mut finish_reason: Option<String> = None;

            tokio::pin!(byte_stream);
            while let Some(chunk_result) = byte_stream.next().await {
                let chunk_bytes = match chunk_result {
                    Ok(b) => b,
                    Err(e) => {
                        yield Err(AgentError::model(format!("Stream error: {}", e)));
                        return;
                    }
                };
                let text = String::from_utf8_lossy(&chunk_bytes);
                buf.push_str(&text);

                while let Some(pos) = buf.find('\n') {
                    let line = buf[..pos].trim().to_string();
                    buf = buf[pos + 1..].to_string();

                    if line.is_empty() || line == "data: [DONE]" { continue; }

                    if let Some(data) = line.strip_prefix("data: ") {
                        match serde_json::from_str::<StreamChunk>(data) {
                            Ok(chunk) => {
                                if let Some(choices) = chunk.choices {
                                    for choice in choices {
                                        if let Some(fr) = &choice.finish_reason {
                                            finish_reason = Some(fr.clone());
                                        }
                                        // Accumulate reasoning_content (thinking phase)
                                        if let Some(reasoning) = &choice.delta.reasoning_content {
                                            accumulated_reasoning.push_str(reasoning);
                                        }
                                        // Accumulate content (actual response)
                                        if let Some(content) = &choice.delta.content {
                                            accumulated_content.push_str(content);
                                        }
                                        if let Some(tcs) = &choice.delta.tool_calls {
                                            for tc in tcs {
                                                let idx = tc.index;
                                                while tc_map.len() <= idx {
                                                    tc_map.push(ToolCallAccum::default());
                                                }
                                                if let Some(ref id) = tc.id {
                                                    tc_map[idx].id = id.clone();
                                                }
                                                if let Some(ref func) = tc.function {
                                                    if let Some(ref name) = func.name {
                                                        tc_map[idx].name.push_str(name);
                                                    }
                                                    if let Some(ref args) = func.arguments {
                                                        tc_map[idx].arguments.push_str(args);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Err(_) => { /* skip unparseable chunks */ }
                        }
                    }
                }
            }

            // Emit final response with accumulated data
            let tool_calls: Vec<ToolCallDelta> = tc_map
                .into_iter()
                .filter(|tc| !tc.id.is_empty())
                .map(|tc| ToolCallDelta {
                    id: tc.id,
                    call_type: "function".to_string(),
                    function: FunctionCallDelta {
                        name: Some(tc.name),
                        arguments: Some(tc.arguments),
                    },
                })
                .collect();

            yield Ok(LlmResponse {
                content: if accumulated_content.is_empty() { None } else { Some(accumulated_content) },
                tool_calls,
                finish_reason,
                usage: None,
            });
        };

        Ok(Box::pin(parsed_stream))
    }

    fn available_models(&self) -> Vec<String> {
        self.models.iter().map(|m| m.name.clone()).collect()
    }
}

#[derive(Default)]
struct ToolCallAccum {
    id: String,
    name: String,
    arguments: String,
}
