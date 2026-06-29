//! Model config persistence — save/load Vec<ModelConfig> to/from JSON.
//! Follows the same pattern as MCP server config persistence (mcp_client.rs).
//! API keys are encrypted at rest using AES-256-GCM.

use std::path::Path;
use tracing::{info, warn, error};

use crate::config::ModelConfig;

/// Save model configs to a JSON file, encrypting api_keys.
pub fn save_configs(configs: &[ModelConfig], path: &Path) {
    let mut configs: Vec<ModelConfig> = configs.to_vec();
    for cfg in &mut configs {
        if let Some(ref key) = cfg.api_key {
            if !key.is_empty() && !crate::crypto::is_encrypted(key) {
                cfg.api_key = Some(crate::crypto::encrypt(key));
            }
        }
    }
    match serde_json::to_string_pretty(&configs) {
        Ok(json_str) => {
            if let Err(e) = std::fs::write(path, json_str) {
                error!("Failed to save model configs: {}", e);
            } else {
                info!("Model configs saved to {} (api keys encrypted)", path.display());
            }
        }
        Err(e) => error!("Failed to serialize model configs: {}", e),
    }
}

/// Load model configs from a JSON file, decrypting api_keys.
pub fn load_configs(path: &Path) -> Vec<ModelConfig> {
    if !path.exists() {
        return Vec::new();
    }
    match std::fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str::<Vec<ModelConfig>>(&content) {
            Ok(mut configs) => {
                for cfg in &mut configs {
                    if let Some(ref key) = cfg.api_key {
                        if !key.is_empty() {
                            cfg.api_key = Some(crate::crypto::decrypt(key));
                        }
                    }
                }
                info!(
                    "Loaded {} persisted model config(s) from {} (api keys decrypted)",
                    configs.len(),
                    path.display()
                );
                configs
            }
            Err(e) => {
                warn!("Failed to parse model configs: {}", e);
                Vec::new()
            }
        },
        Err(e) => {
            warn!("Failed to read model configs: {}", e);
            Vec::new()
        }
    }
}
