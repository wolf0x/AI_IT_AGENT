/// End-of-session knowledge distillation.
///
/// When a WebSocket session ends, this module extracts valuable knowledge from the
/// conversation and persists it in structured, append-only markdown files under
/// `workspace/knowledge/{category}.md`.
///
/// Categories: facts, decisions, lessons, preferences, skill_hints.
/// Each entry includes metadata (date, session ID, source, confidence) for traceability.

use std::sync::Arc;
use tracing::{info, warn};

use crate::model::openai::OpenAiProvider;
use crate::model::ChatMessage;

/// Minimum number of messages in a session before distillation is attempted.
const MIN_MESSAGES: usize = 4;

/// Maximum characters per message when building the conversation summary for the LLM.
const MAX_MSG_CHARS: usize = 500;

/// Maximum total characters for the conversation summary sent to the LLM.
const MAX_SUMMARY_CHARS: usize = 8000;

/// Valid knowledge categories (also used as filenames).
const CATEGORIES: &[&str] = &["facts", "decisions", "lessons", "preferences", "skill_hints"];

/// A single distilled knowledge entry.
#[derive(Debug, Clone)]
struct DistilledEntry {
    category: String,
    /// Short descriptive title (used as the markdown heading)
    title: String,
    /// What happened / what was done (the core knowledge)
    content: String,
    /// What triggered this knowledge (user report, error, tool usage, etc.)
    trigger: String,
    /// Why it happened / background context (root cause, circumstances)
    context: String,
    /// How this knowledge was derived (session reference)
    source: String,
    /// Confidence level
    confidence: String,
}

/// Distill knowledge from a completed session and append to knowledge files.
///
/// Returns the number of entries written. Skips sessions with fewer than
/// `MIN_MESSAGES` messages.
pub async fn distill_session(
    session_id: &str,
    history: &[ChatMessage],
    provider: Arc<OpenAiProvider>,
    model_name: &str,
    workspace_dir: &str,
) -> Result<usize, String> {
    // Filter to user+assistant messages only (skip tool calls and system messages)
    let relevant: Vec<&ChatMessage> = history
        .iter()
        .filter(|m| m.role == "user" || m.role == "assistant")
        .collect();

    if relevant.len() < MIN_MESSAGES {
        info!("[distill] Session {} has only {} relevant messages, skipping", &session_id[..8.min(session_id.len())], relevant.len());
        return Ok(0);
    }

    // Build a compact conversation summary
    let summary = build_summary(&relevant);

    // Build the distillation prompt
    let messages = build_distillation_messages(&summary);

    // Call LLM (non-streaming, lightweight)
    let response = provider.chat_simple(model_name, &messages).await?;

    // Parse the JSON response
    let entries = parse_distillation_response(&response)?;

    if entries.is_empty() {
        info!("[distill] Session {} produced no knowledge entries", &session_id[..8.min(session_id.len())]);
        return Ok(0);
    }

    // Ensure knowledge directory exists
    let knowledge_dir = std::path::Path::new(workspace_dir).join("knowledge");
    std::fs::create_dir_all(&knowledge_dir)
        .map_err(|e| format!("Failed to create knowledge dir: {}", e))?;

    // Append entries to category files
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    let short_sid = &session_id[..8.min(session_id.len())];
    let mut count = 0;

    for entry in &entries {
        if !CATEGORIES.contains(&entry.category.as_str()) {
            warn!("[distill] Unknown category '{}', skipping entry", entry.category);
            continue;
        }

        let file_path = knowledge_dir.join(format!("{}.md", entry.category));
        let block = format!(
            "\n## {} — {}\n\
             - **Content:** {}\n\
             - **Trigger:** {}\n\
             - **Context:** {}\n\
             - **Source:** {}\n\
             - **Confidence:** {}\n",
            today, entry.title, entry.content, entry.trigger, entry.context, entry.source, entry.confidence
        );

        // Create file with header if it doesn't exist, then append
        if !file_path.exists() {
            let header = format!("# {}\n\nAuto-distilled knowledge entries.\n",
                entry.category.replace('_', " ").to_uppercase());
            let _ = std::fs::write(&file_path, &header);
        }

        match std::fs::OpenOptions::new().append(true).open(&file_path) {
            Ok(mut file) => {
                use std::io::Write;
                if file.write_all(block.as_bytes()).is_ok() {
                    count += 1;
                }
            }
            Err(e) => {
                warn!("[distill] Failed to append to {:?}: {}", file_path, e);
            }
        }
    }

    info!("[distill] Session {} distilled {} entries", short_sid, count);
    Ok(count)
}

/// Build a compact conversation summary from relevant messages.
fn build_summary(messages: &[&ChatMessage]) -> String {
    let mut summary = String::new();
    for msg in messages {
        let role_label = if msg.role == "user" { "User" } else { "Assistant" };
        let text = msg.content_as_text().unwrap_or_default();
        let truncated = if text.len() > MAX_MSG_CHARS {
            format!("{}...", &text[..MAX_MSG_CHARS])
        } else {
            text
        };
        let line = format!("{}: {}\n", role_label, truncated);
        if summary.len() + line.len() > MAX_SUMMARY_CHARS {
            summary.push_str("\n[conversation truncated]\n");
            break;
        }
        summary.push_str(&line);
    }
    summary
}

/// Build the message array for the distillation LLM call.
fn build_distillation_messages(summary: &str) -> Vec<ChatMessage> {
    let system_msg = ChatMessage::system(
        "You are a knowledge extraction assistant. Review the following conversation \
         and extract valuable knowledge worth preserving for future sessions. \
         Focus on: user preferences, environment facts, technical decisions, lessons from errors, \
         and workflow patterns.\n\n\
         For each item, output a JSON object with these fields:\n\
         - \"category\": one of \"facts\", \"decisions\", \"lessons\", \"preferences\", \"skill_hints\"\n\
         - \"title\": short descriptive title (5-10 words, like a heading)\n\
         - \"content\": the core knowledge (1-2 sentences, in the user's language)\n\
         - \"trigger\": what triggered this knowledge (e.g. \"user reported error X\", \"user stated preference\", \"tool failed because...\")\n\
         - \"context\": why it happened / background (root cause, circumstances, 1-2 sentences)\n\
         - \"source\": brief reference (e.g. \"user stated\", \"error occurred\", \"debugging session\")\n\
         - \"confidence\": \"high\", \"medium\", or \"low\"\n\n\
         Rules:\n\
         - Skip trivial exchanges (greetings, simple confirmations).\n\
         - Merge related items into one entry.\n\
         - Output ONLY a valid JSON array. No markdown, no explanation.\n\
         - If nothing is worth preserving, return [].",
    );

    let user_msg = ChatMessage::user(&format!(
        "Extract knowledge from this conversation:\n\n{}", summary
    ));

    vec![system_msg, user_msg]
}

/// Parse the LLM's response into distilled entries.
/// Handles both raw JSON arrays and JSON wrapped in markdown code blocks.
fn parse_distillation_response(response: &str) -> Result<Vec<DistilledEntry>, String> {
    // Try to extract JSON from the response (may be wrapped in ```json ... ```)
    let json_str = extract_json(response);

    let parsed: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| format!("Failed to parse distillation JSON: {} | raw: {}", e, &json_str[..200.min(json_str.len())]))?;

    let arr = parsed.as_array()
        .ok_or("Distillation response is not a JSON array")?;

    let mut entries = Vec::new();
    for item in arr {
        let category = item["category"].as_str().unwrap_or("").to_string();
        let title = item["title"].as_str().unwrap_or("").to_string();
        let content = item["content"].as_str().unwrap_or("").to_string();
        let trigger = item["trigger"].as_str().unwrap_or("").to_string();
        let context = item["context"].as_str().unwrap_or("").to_string();
        let source = item["source"].as_str().unwrap_or("unknown").to_string();
        let confidence = item["confidence"].as_str().unwrap_or("medium").to_string();

        if content.is_empty() {
            continue;
        }

        // Use content as fallback title if title is empty
        let title = if title.is_empty() {
            content.chars().take(50).collect::<String>()
        } else {
            title
        };

        entries.push(DistilledEntry {
            category: if CATEGORIES.contains(&category.as_str()) {
                category
            } else {
                "facts".to_string() // fallback to facts for unknown categories
            },
            title,
            content,
            trigger,
            context,
            source,
            confidence,
        });
    }

    Ok(entries)
}

/// Extract JSON from a string that may contain markdown code blocks.
fn extract_json(text: &str) -> String {
    let trimmed = text.trim();

    // Try direct parse first
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        return trimmed.to_string();
    }

    // Look for ```json ... ``` or ``` ... ```
    if let Some(start) = trimmed.find("```") {
        let after_fence = &trimmed[start + 3..];
        // Skip optional "json" language tag
        let content_start = if after_fence.trim_start().starts_with("json") {
            after_fence.find("json").map(|p| p + 4).unwrap_or(0)
        } else {
            0
        };
        let content = &after_fence[content_start..];
        if let Some(end) = content.find("```") {
            return content[..end].trim().to_string();
        }
        // No closing fence — take everything after the opening
        return content.trim().to_string();
    }

    trimmed.to_string()
}
