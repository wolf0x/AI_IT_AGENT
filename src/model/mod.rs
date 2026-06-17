#![allow(dead_code)]

pub mod openai;

use async_trait::async_trait;
use futures::Stream;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::pin::Pin;

use crate::error::AgentResult;

// ============================================================
// Chat message types (unchanged from original)
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCallDelta>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallDelta {
    pub id: String,
    #[serde(rename = "type")]
    pub call_type: String,
    pub function: FunctionCallDelta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCallDelta {
    pub name: Option<String>,
    pub arguments: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolDefinition {
    #[serde(rename = "type")]
    pub tool_type: String,
    pub function: FunctionDefinition,
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionDefinition {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

impl ChatMessage {
    pub fn system(content: &str) -> Self {
        Self { role: "system".to_string(), content: Some(content.to_string()), tool_calls: None, tool_call_id: None, name: None }
    }
    pub fn user(content: &str) -> Self {
        Self { role: "user".to_string(), content: Some(content.to_string()), tool_calls: None, tool_call_id: None, name: None }
    }
    pub fn assistant(content: &str) -> Self {
        Self { role: "assistant".to_string(), content: Some(content.to_string()), tool_calls: None, tool_call_id: None, name: None }
    }
    pub fn assistant_with_tool_calls(tool_calls: Vec<ToolCallDelta>) -> Self {
        Self { role: "assistant".to_string(), content: None, tool_calls: Some(tool_calls), tool_call_id: None, name: None }
    }
    pub fn tool_result(tool_call_id: &str, name: &str, content: &str) -> Self {
        Self { role: "tool".to_string(), content: Some(content.to_string()), tool_calls: None, tool_call_id: Some(tool_call_id.to_string()), name: Some(name.to_string()) }
    }
}

// ============================================================
// Llm trait — modeled after ADK-RUST's Llm trait
// ============================================================

/// Request sent to an LLM provider.
/// Modeled after ADK-RUST's LlmRequest.
#[derive(Debug, Clone)]
pub struct LlmRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    pub tools: Vec<ToolDefinition>,
    pub config: GenerateConfig,
}

/// Generation parameters for LLM calls.
/// Modeled after ADK-RUST's GenerateContentConfig.
#[derive(Debug, Clone, Default)]
pub struct GenerateConfig {
    pub temperature: Option<f64>,
    pub max_tokens: Option<u32>,
    pub top_p: Option<f64>,
    pub stop_sequences: Vec<String>,
}

/// Response from an LLM provider.
/// Modeled after ADK-RUST's LlmResponse.
#[derive(Debug, Clone)]
pub struct LlmResponse {
    pub content: Option<String>,
    pub tool_calls: Vec<ToolCallDelta>,
    pub finish_reason: Option<String>,
    pub usage: Option<UsageMetadata>,
}

/// Token usage metadata.
/// Modeled after ADK-RUST's UsageMetadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageMetadata {
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

/// Streaming response chunk from an LLM.
/// Modeled after ADK-RUST's LlmResponseStream.
pub type LlmResponseStream = Pin<Box<dyn Stream<Item = AgentResult<LlmResponse>> + Send>>;

/// LLM provider trait — the core abstraction for language model backends.
/// Modeled after ADK-RUST's `Llm` trait.
///
/// All providers (OpenAI, Gemini, Anthropic, etc.) implement this trait.
#[async_trait]
pub trait Llm: Send + Sync {
    /// Provider/model name.
    fn name(&self) -> &str;

    /// Generate content (streaming or non-streaming).
    /// Returns a stream of LlmResponse chunks.
    async fn generate_content(
        &self,
        request: LlmRequest,
        stream: bool,
    ) -> AgentResult<LlmResponseStream>;

    /// List available model names from this provider.
    fn available_models(&self) -> Vec<String>;
}
