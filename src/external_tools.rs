use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Represents a discovered external tool (executable file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalTool {
    /// Tool name (filename without extension)
    pub name: String,
    /// Full path to the executable
    pub path: PathBuf,
    /// Human-readable description
    pub description: String,
    /// Whether this tool is enabled
    pub enabled: bool,
    /// File extension (.exe, .bat, .ps1, .cmd)
    pub extension: String,
}

/// Manages discovery and state of external tools in the Tools directory.
pub struct ExternalToolsManager {
    tools_dir: PathBuf,
    tools: Vec<ExternalTool>,
    state_path: PathBuf,
}

/// Persisted state for external tools (enabled/disabled, custom descriptions).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ToolsState {
    #[serde(default)]
    tools: HashMap<String, ToolStateEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ToolStateEntry {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    description: Option<String>,
}

fn default_true() -> bool { true }

impl ExternalToolsManager {
    pub fn new(tools_dir: PathBuf) -> Self {
        let state_path = tools_dir.join("tools_state.json");
        let mut mgr = Self {
            tools_dir,
            tools: Vec::new(),
            state_path,
        };
        // Ensure tools directory exists
        if !mgr.tools_dir.exists() {
            let _ = std::fs::create_dir_all(&mgr.tools_dir);
        }
        mgr.scan();
        mgr
    }

    /// Scan the Tools directory for executable files.
    pub fn scan(&mut self) {
        self.tools.clear();
        let state = self.load_state();

        if !self.tools_dir.exists() {
            return;
        }

        let entries = match std::fs::read_dir(&self.tools_dir) {
            Ok(e) => e,
            Err(e) => {
                warn!("Failed to read tools dir: {}", e);
                return;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let ext = path.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();

            // Only include known executable types
            if !matches!(ext.as_str(), "exe" | "bat" | "ps1" | "cmd") {
                continue;
            }

            let name = path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();

            // Check for sidecar .json file
            let sidecar_path = path.with_extension("json");
            let (description, custom_desc) = if sidecar_path.exists() {
                match std::fs::read_to_string(&sidecar_path) {
                    Ok(content) => {
                        if let Ok(sidecar) = serde_json::from_str::<serde_json::Value>(&content) {
                            let desc = sidecar["description"].as_str()
                                .or_else(|| sidecar["name"].as_str())
                                .unwrap_or("")
                                .to_string();
                            (desc, true)
                        } else {
                            (Self::auto_description(&name, &ext), false)
                        }
                    }
                    Err(_) => (Self::auto_description(&name, &ext), false),
                }
            } else {
                (Self::auto_description(&name, &ext), false)
            };

            // Apply state overrides
            let (enabled, description) = if let Some(entry) = state.tools.get(&name) {
                let desc = if let Some(ref d) = entry.description {
                    d.clone()
                } else if custom_desc {
                    description
                } else {
                    Self::auto_description(&name, &ext)
                };
                (entry.enabled, desc)
            } else {
                (true, description)
            };

            info!("Discovered tool: {} ({}) enabled={}", name, path.display(), enabled);
            self.tools.push(ExternalTool {
                name,
                path,
                description,
                enabled,
                extension: ext,
            });
        }
    }

    fn auto_description(name: &str, ext: &str) -> String {
        let friendly_name = name.replace('_', " ");
        match ext {
            "exe" => format!("Execute {} tool", friendly_name),
            "bat" => format!("Run {} batch script", friendly_name),
            "ps1" => format!("Run {} PowerShell script", friendly_name),
            "cmd" => format!("Run {} command script", friendly_name),
            _ => format!("Run {} tool", friendly_name),
        }
    }

    /// List all discovered tools.
    pub fn list_tools(&self) -> Vec<serde_json::Value> {
        self.tools.iter().map(|t| {
            serde_json::json!({
                "name": t.name,
                "path": t.path.to_string_lossy(),
                "description": t.description,
                "enabled": t.enabled,
                "extension": t.extension,
            })
        }).collect()
    }

    /// Toggle a tool's enabled state.
    pub fn toggle_tool(&mut self, name: &str) -> Option<bool> {
        let tool = self.tools.iter_mut().find(|t| t.name == name)?;
        tool.enabled = !tool.enabled;
        Some(tool.enabled)
    }

    /// Update a tool's description.
    pub fn update_description(&mut self, name: &str, description: &str) -> bool {
        if let Some(tool) = self.tools.iter_mut().find(|t| t.name == name) {
            tool.description = description.to_string();
            true
        } else {
            false
        }
    }

    /// Get the tools directory path.
    pub fn tools_dir(&self) -> &Path {
        &self.tools_dir
    }

    /// Load persisted state.
    fn load_state(&self) -> ToolsState {
        if !self.state_path.exists() {
            return ToolsState::default();
        }
        match std::fs::read_to_string(&self.state_path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => ToolsState::default(),
        }
    }

    /// Save current state to disk.
    pub fn save_state(&self) {
        let mut state = ToolsState::default();
        for tool in &self.tools {
            state.tools.insert(tool.name.clone(), ToolStateEntry {
                enabled: tool.enabled,
                description: Some(tool.description.clone()),
            });
        }
        match serde_json::to_string_pretty(&state) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.state_path, json) {
                    warn!("Failed to save tools state: {}", e);
                }
            }
            Err(e) => warn!("Failed to serialize tools state: {}", e),
        }
    }

    /// Get enabled tools as Tool trait objects for registration.
    pub fn get_tool_handles(&self) -> Vec<(String, PathBuf)> {
        self.tools.iter()
            .filter(|t| t.enabled)
            .map(|t| (format!("ext_{}", t.name), t.path.clone()))
            .collect()
    }
}
