//! Predefined Sub-Agent definitions (agents.json) + per-agent working directories.
//!
//! A "sub-agent" is a reusable, independently-scoped agent that can be launched
//! from the main session (e.g. "use the Disk Analysis agent to check drive D").
//! Each definition carries its own name, description, system prompt, optional
//! model override and a dedicated working directory under `<workspace>/agents/`.

use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{info, warn};

/// A predefined sub-agent definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubAgentDef {
    pub id: String,
    /// Display/activation name (must be unique).
    pub name: String,
    pub description: String,
    /// The sub-agent's own system prompt (persona / expertise / constraints).
    pub system_prompt: String,
    /// Optional model override; empty = use the caller's model.
    #[serde(default)]
    pub model: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Reservoir path (absolute) where this sub-agent stores its own outputs.
    #[serde(default)]
    pub workdir: String,
}

fn default_true() -> bool { true }

/// A JSON-backed store of sub-agent definitions.
pub struct AgentStore {
    path: String,
    agents: Vec<SubAgentDef>,
    root: String, // <workspace>/agents
}

impl AgentStore {
    /// Open (or create) the store. `workspace_dir` is the RustAgent workspace root.
    pub fn open(workspace_dir: &str) -> Self {
        let root = Path::new(workspace_dir).join("agents");
        let _ = std::fs::create_dir_all(&root);
        let path = Path::new(workspace_dir).join("agents.json").to_string_lossy().into_owned();
        let mut store = Self { path: path.clone(), agents: Vec::new(), root: root.to_string_lossy().into_owned() };
        store.load();
        store
    }

    /// Slugify a name into a safe directory segment.
    fn slug(name: &str) -> String {
        let mut out = String::new();
        for ch in name.trim().chars() {
            if ch.is_ascii_alphanumeric() { out.push(ch.to_ascii_lowercase()); }
            else if ch == '-' || ch == '_' { out.push(ch); }
            else if !out.is_empty() && !out.ends_with('-') { out.push('-'); }
        }
        let out = out.trim_matches('-').to_string();
        if out.is_empty() { "agent".to_string() } else { out }
    }

    fn load(&mut self) {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => match serde_json::from_str::<Vec<SubAgentDef>>(&text) {
                Ok(agents) => {
                    for a in &agents {
                        let _ = self.ensure_workdir(a);
                    }
                    self.agents = agents;
                    info!("AgentStore: loaded {} sub-agent(s) from {}", self.agents.len(), self.path);
                }
                Err(e) => warn!("AgentStore: failed to parse {}: {}", self.path, e),
            },
            Err(_) => info!("AgentStore: no {} yet; will create on first save", self.path),
        }
    }

    fn ensure_workdir(&self, def: &SubAgentDef) -> Result<String, String> {
        let dir = if def.workdir.is_empty() {
            Path::new(&self.root).join(Self::slug(&def.name))
        } else {
            Path::new(&def.workdir).to_path_buf()
        };
        std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create workdir {}: {}", dir.display(), e))?;
        Ok(dir.to_string_lossy().into_owned())
    }

    fn save(&self) {
        if let Ok(text) = serde_json::to_string_pretty(&self.agents) {
            let _ = std::fs::write(&self.path, text);
        }
    }

    pub fn list(&self) -> &[SubAgentDef] { &self.agents }

    pub fn find(&self, name_or_id: &str) -> Option<&SubAgentDef> {
        let q = name_or_id.trim().to_lowercase();
        self.agents.iter().find(|a| a.enabled && (a.name.to_lowercase() == q || a.id == name_or_id))
    }

    /// Create a new sub-agent. Returns the created def or an error.
    pub fn create(
        &mut self,
        name: &str,
        description: &str,
        system_prompt: &str,
        model: &str,
    ) -> Result<SubAgentDef, String> {
        let name = name.trim();
        if name.is_empty() { return Err("name is required".into()); }
        if self.agents.iter().any(|a| a.name.to_lowercase() == name.to_lowercase()) {
            return Err(format!("an agent named '{}' already exists", name));
        }
        if system_prompt.trim().is_empty() {
            return Err("system_prompt is required".into());
        }
        let id = uuid::Uuid::new_v4().to_string();
        let mut def = SubAgentDef {
            id: id.clone(),
            name: name.to_string(),
            description: description.trim().to_string(),
            system_prompt: system_prompt.trim().to_string(),
            model: model.trim().to_string(),
            enabled: true,
            workdir: String::new(),
        };
        def.workdir = self.ensure_workdir(&def)?;
        self.agents.push(def.clone());
        self.save();
        Ok(def)
    }

    /// Update mutable fields of an existing agent by id.
    pub fn update(
        &mut self,
        id: &str,
        name: Option<String>,
        description: Option<String>,
        system_prompt: Option<String>,
        model: Option<String>,
        enabled: Option<bool>,
    ) -> Result<SubAgentDef, String> {
        let idx = self.agents.iter().position(|a| a.id == id)
            .ok_or_else(|| "agent not found".to_string())?;
        if let Some(n) = name {
            let n = n.trim();
            if n.is_empty() { return Err("name cannot be empty".into()); }
            if self.agents.iter().enumerate().any(|(i, a)| i != idx && a.name.to_lowercase() == n.to_lowercase()) {
                return Err(format!("an agent named '{}' already exists", n));
            }
            self.agents[idx].name = n.to_string();
        }
        if let Some(d) = description { self.agents[idx].description = d.trim().to_string(); }
        if let Some(p) = system_prompt {
            if p.trim().is_empty() { return Err("system_prompt cannot be empty".into()); }
            self.agents[idx].system_prompt = p.trim().to_string();
        }
        if let Some(m) = model { self.agents[idx].model = m.trim().to_string(); }
        if let Some(e) = enabled { self.agents[idx].enabled = e; }
        // Refresh workdir if the name changed or it was missing.
        let def = self.agents[idx].clone();
        match self.ensure_workdir(&def) {
            Ok(dir) => self.agents[idx].workdir = dir,
            Err(e) => return Err(e),
        }
        let def = self.agents[idx].clone();
        self.save();
        Ok(def)
    }

    pub fn delete(&mut self, id: &str) -> bool {
        let before = self.agents.len();
        self.agents.retain(|a| a.id != id);
        if self.agents.len() != before { self.save(); true } else { false }
    }

    pub fn toggle(&mut self, id: &str) -> Option<bool> {
        let next = self.agents.iter_mut().find(|a| a.id == id).map(|a| {
            a.enabled = !a.enabled;
            a.enabled
        });
        if next.is_some() { self.save(); }
        next
    }

    /// Workdir lookup by name or id.
    pub fn workdir_of(&self, name_or_id: &str) -> Option<String> {
        self.find(name_or_id).map(|a| a.workdir.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("agent_store_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn create_update_find_delete() {
        let root = tmp_dir();
        let mut store = AgentStore::open(root.to_str().unwrap());
        let a = store.create("Disk Analysis", "analyses disk volumes", "You are a disk analysis expert.", "").unwrap();
        assert!(!a.id.is_empty());
        assert!(a.workdir.contains("agents"));
        assert!(Path::new(&a.workdir).exists());

        // duplicate name rejected
        assert!(store.create("Disk Analysis", "x", "y", "").is_err());

        // update prompt + model
        let upd = store.update(&a.id, None, None, Some("You are a forensic disk analyst.".to_string()), Some("gpt-x".to_string()), None).unwrap();
        assert_eq!(upd.system_prompt, "You are a forensic disk analyst.");
        assert_eq!(upd.model, "gpt-x");

        // find by name (case-insensitive)
        assert!(store.find("disk analysis").is_some());

        // reload persistence
        let mut store2 = AgentStore::open(root.to_str().unwrap());
        assert_eq!(store2.list().len(), 1);

        // toggle + delete
        assert_eq!(store2.toggle(&a.id), Some(false));
        assert!(store2.find("disk analysis").is_none()); // disabled -> not findable
        store2.delete(&a.id);
        let store3 = AgentStore::open(root.to_str().unwrap());
        assert_eq!(store3.list().len(), 0);
    }
}