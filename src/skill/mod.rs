pub mod types;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

use self::types::{SelectionPolicy, Skill, SkillMetadata};
use super::server::NotifyTx;
use super::tool::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;
use async_trait::async_trait;
use serde_json::{json, Value};

pub struct SkillManager {
    skills: Arc<RwLock<Vec<Skill>>>,
    skills_dir: PathBuf,
    state_path: PathBuf,
    notify_tx: Option<NotifyTx>,
}

impl SkillManager {
    pub fn new(skills_dir: &str) -> Self {
        Self::new_with_notify(skills_dir, None)
    }

    pub fn new_with_notify(skills_dir: &str, notify_tx: Option<NotifyTx>) -> Self {
        let dir = PathBuf::from(skills_dir);
        let state_path = dir.join("skills_state.json");
        let mgr = Self {
            skills: Arc::new(RwLock::new(Vec::new())),
            skills_dir: dir,
            state_path,
            notify_tx,
        };
        mgr.reload();
        mgr
    }

    pub fn reload(&self) {
        let mut skills = self.skills.write().unwrap();
        skills.clear();

        if !self.skills_dir.exists() {
            let _ = std::fs::create_dir_all(&self.skills_dir);
            return;
        }

        // Load enabled state
        let state = self.load_state();

        // Scan directory-based skills: skills/*/SKILL.md
        let dir_pattern = format!("{}/*/SKILL.md", self.skills_dir.display());
        for entry in glob::glob(&dir_pattern).ok().into_iter().flatten() {
            match entry {
                Ok(path) => {
                    let skill_dir = path.parent()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default();
                    match parse_skill_file(&path, skill_dir) {
                        Some(mut skill) => {
                            if let Some(enabled) = state.get(&skill.metadata.name) {
                                skill.metadata.enabled = *enabled;
                            }
                            info!("Loaded skill: {} from {} (enabled={})", skill.metadata.name, path.display(), skill.metadata.enabled);
                            skills.push(skill);
                        }
                        None => {
                            warn!("Failed to parse skill file: {}", path.display());
                        }
                    }
                }
                Err(e) => warn!("Glob error: {}", e),
            }
        }
    }

    pub fn list(&self) -> Vec<SkillMetadata> {
        self.skills
            .read()
            .unwrap()
            .iter()
            .map(|s| s.metadata.clone())
            .collect()
    }

    pub fn find_matching(&self, user_message: &str) -> Vec<(String, f32)> {
        self.find_matching_with(user_message, &SelectionPolicy::default())
    }

    /// Score and rank skills by weighted token overlap with the user message.
    ///
    /// Scoring weights (inspired by adk-skill's lexical overlap model):
    /// - Name match:         ×4.0
    /// - Description match:  ×2.5
    /// - Trigger token match: ×2.0
    /// - Body token overlap: ×1.0
    /// - Trigger substring bonus: +10.0 (when a full trigger phrase appears in the message)
    ///
    /// The raw score is normalized by `sqrt(body_token_count)` to prevent
    /// large documents (e.g. 33KB VPS skill) from dominating via sheer token volume.
    pub fn find_matching_with(&self, user_message: &str, policy: &SelectionPolicy) -> Vec<(String, f32)> {
        let skills = self.skills.read().unwrap();
        let query_tokens = Self::tokenize(user_message);
        if query_tokens.is_empty() {
            return Vec::new();
        }

        let mut scored: Vec<(String, f32)> = skills
            .iter()
            .filter(|s| s.metadata.enabled)
            .filter_map(|s| {
                let score = Self::score_skill(s, &query_tokens, user_message);
                if score >= policy.min_score {
                    Some((s.content.clone(), score))
                } else {
                    None
                }
            })
            .collect();

        // Sort by score descending, take top-K
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(policy.top_k);
        scored
    }

    /// Compute weighted relevance score for a single skill against query tokens.
    fn score_skill(skill: &Skill, query_tokens: &[String], message: &str) -> f32 {
        let mut score: f32 = 0.0;
        let msg_lower = message.to_lowercase();

        // Name token overlap (weight: 4.0)
        let name_tokens = Self::tokenize(&skill.metadata.name);
        let name_hits = query_tokens.iter().filter(|t| name_tokens.contains(t)).count();
        score += name_hits as f32 * 4.0;

        // Description token overlap (weight: 2.5)
        let desc_tokens = Self::tokenize(&skill.metadata.description);
        let desc_hits = query_tokens.iter().filter(|t| desc_tokens.contains(t)).count();
        score += desc_hits as f32 * 2.5;

        // Trigger token overlap (weight: 2.0)
        for trigger in &skill.metadata.triggers {
            let trigger_tokens = Self::tokenize(trigger);
            let trigger_hits = query_tokens.iter().filter(|t| trigger_tokens.contains(t)).count();
            score += trigger_hits as f32 * 2.0;
            // Bonus: full trigger phrase appears as substring in the message
            if !trigger.is_empty() && msg_lower.contains(&trigger.to_lowercase()) {
                score += 10.0;
            }
        }

        // Body token overlap (weight: 1.0)
        let body_tokens = Self::tokenize(&skill.content);
        let body_hits = query_tokens.iter().filter(|t| body_tokens.contains(t)).count();
        score += body_hits as f32 * 1.0;

        // Normalize: prevent large documents from dominating
        let body_token_count = body_tokens.len().max(1);
        score / (body_token_count as f32).sqrt()
    }

    /// Tokenize text into lowercase matchable units.
    ///
    /// ASCII words (≥3 chars) are extracted as whole tokens.
    /// CJK characters are emitted individually so that unsegmented
    /// Chinese/Japanese/Korean text still produces meaningful overlap.
    fn tokenize(text: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut current = String::new();

        for ch in text.chars() {
            if ch.is_ascii_alphanumeric() {
                current.push(ch.to_ascii_lowercase());
            } else if !ch.is_ascii() && ch.is_alphanumeric() {
                // CJK and other non-ASCII alphabetic: emit as individual tokens
                if current.len() >= 3 {
                    tokens.push(std::mem::take(&mut current));
                } else {
                    current.clear();
                }
                tokens.push(ch.to_lowercase().to_string());
            } else {
                if current.len() >= 3 {
                    tokens.push(std::mem::take(&mut current));
                } else {
                    current.clear();
                }
            }
        }
        if current.len() >= 3 {
            tokens.push(current);
        }
        tokens
    }

    #[allow(dead_code)]
    pub fn skills_dir(&self) -> &Path {
        self.skills_dir.as_path()
    }

    /// Create a new skill as a directory: skills/{name}/SKILL.md + optional extra files.
    pub fn create_skill(&self, name: &str, description: &str, triggers: &[String], content: &str) -> Result<String, String> {
        self.create_skill_with_files(name, description, triggers, content, None)
    }

    /// Create a skill directory with SKILL.md and optional additional files.
    pub fn create_skill_with_files(
        &self,
        name: &str,
        description: &str,
        triggers: &[String],
        content: &str,
        files: Option<Vec<(String, String)>>,
    ) -> Result<String, String> {
        let dir_name = name.to_lowercase().replace(' ', "_");
        std::fs::create_dir_all(&self.skills_dir)
            .map_err(|e| format!("Failed to create dir: {}", e))?;

        let triggers_yaml: Vec<String> = triggers.iter().map(|t| format!("  - {}", t)).collect();
        let md_content = format!(
            "---\nname: {}\ndescription: {}\ntriggers:\n{}\n---\n\n{}\n",
            name, description, triggers_yaml.join("\n"), content
        );

        // Always create directory: skills/{dir_name}/SKILL.md
        let skill_dir = self.skills_dir.join(&dir_name);
        std::fs::create_dir_all(&skill_dir)
            .map_err(|e| format!("Failed to create skill dir: {}", e))?;
        std::fs::write(skill_dir.join("SKILL.md"), &md_content)
            .map_err(|e| format!("Failed to write SKILL.md: {}", e))?;

        // Write optional extra files
        if let Some(extra_files) = files {
            for (rel_path, file_content) in extra_files {
                let file_path = skill_dir.join(&rel_path);
                if let Some(parent) = file_path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("Failed to create subdirectory: {}", e))?;
                }
                std::fs::write(&file_path, &file_content)
                    .map_err(|e| format!("Failed to write {}: {}", rel_path, e))?;
            }
        }

        self.reload();
        self.notify_skills_changed();
        Ok(dir_name)
    }

    /// Delete a skill by name (removes the skill directory and reloads).
    pub fn delete_skill(&self, name: &str) -> Result<(), String> {
        let skills = self.skills.read().unwrap();
        let skill = skills.iter().find(|s| s.metadata.name == name)
            .ok_or_else(|| format!("Skill '{}' not found", name))?;
        let skill_dir = skill.skill_dir.clone();
        drop(skills);

        // Remove entire skill directory
        std::fs::remove_dir_all(&skill_dir)
            .map_err(|e| format!("Failed to remove skill directory: {}", e))?;
        // Remove from state
        self.remove_from_state(name);
        self.reload();
        self.notify_skills_changed();
        Ok(())
    }

    /// Toggle a skill's enabled state.
    pub fn toggle_skill(&self, name: &str) -> Option<bool> {
        let mut skills = self.skills.write().unwrap();
        let skill = skills.iter_mut().find(|s| s.metadata.name == name)?;
        skill.metadata.enabled = !skill.metadata.enabled;
        let enabled = skill.metadata.enabled;
        drop(skills);
        // Persist
        self.save_state_entry(name, enabled);
        Some(enabled)
    }

    /// Build meta-tools for skill management (install_skill, list_skills, remove_skill)
    pub fn build_meta_tools(&self) -> Vec<Arc<dyn Tool>> {
        let skills_dir = self.skills_dir.clone();
        let skills_ref = self.skills.clone();

        vec![
            Arc::new(InstallSkillTool {
                skills_dir: skills_dir.clone(),
                skills: skills_ref.clone(),
            }) as Arc<dyn Tool>,
            Arc::new(ListSkillsTool {
                skills: skills_ref.clone(),
            }) as Arc<dyn Tool>,
            Arc::new(RemoveSkillTool {
                skills_dir: skills_dir.clone(),
                skills: skills_ref.clone(),
            }) as Arc<dyn Tool>,
        ]
    }

    // --- Notifications ---

    fn notify_skills_changed(&self) {
        if let Some(tx) = &self.notify_tx {
            let count = self.skills.read().map(|s| s.len()).unwrap_or(0);
            let msg = json!({"type": "skills_changed", "count": count}).to_string();
            let _ = tx.send(msg);
        }
    }

    // --- State persistence ---

    fn load_state(&self) -> HashMap<String, bool> {
        if !self.state_path.exists() {
            return HashMap::new();
        }
        match std::fs::read_to_string(&self.state_path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => HashMap::new(),
        }
    }

    fn save_state(&self, state: &HashMap<String, bool>) {
        match serde_json::to_string_pretty(state) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.state_path, json) {
                    warn!("Failed to save skills state: {}", e);
                }
            }
            Err(e) => warn!("Failed to serialize skills state: {}", e),
        }
    }

    fn save_state_entry(&self, name: &str, enabled: bool) {
        let mut state = self.load_state();
        state.insert(name.to_string(), enabled);
        self.save_state(&state);
    }

    fn remove_from_state(&self, name: &str) {
        let mut state = self.load_state();
        state.remove(name);
        self.save_state(&state);
    }
}

fn parse_skill_file(path: &Path, skill_dir: String) -> Option<Skill> {
    let content = std::fs::read_to_string(path).ok()?;
    let (frontmatter, body) = split_frontmatter(&content)?;
    let metadata: SkillMetadata = serde_yaml::from_str(&frontmatter).ok()?;

    Some(Skill {
        metadata,
        content: body.trim().to_string(),
        file_path: path.to_string_lossy().to_string(),
        skill_dir,
    })
}

fn split_frontmatter(content: &str) -> Option<(String, String)> {
    let trimmed = content.trim_start();
    if !trimmed.starts_with("---") {
        return None;
    }
    let rest = &trimmed[3..];
    if let Some(end_pos) = rest.find("\n---") {
        let frontmatter = rest[..end_pos].trim().to_string();
        let body = rest[end_pos + 4..].trim().to_string();
        Some((frontmatter, body))
    } else {
        None
    }
}

// --- Meta Tools ---

struct InstallSkillTool {
    skills_dir: PathBuf,
    skills: Arc<RwLock<Vec<Skill>>>,
}

#[async_trait]
impl Tool for InstallSkillTool {
    fn name(&self) -> &str { "install_skill" }
    fn description(&self) -> &str {
        "Install a new skill as a directory (skills/{name}/SKILL.md). \
         For large skills, write the content to a file first with file_write, then pass 'content_file' \
         (workspace-relative path) instead of inline 'content'. \
         Similarly, use 'source_path' in files[] entries to read additional files from the workspace."
    }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Skill name identifier (also used as directory name, lowercased with spaces→underscores)" },
                "description": { "type": "string", "description": "Skill description for matching and display" },
                "triggers": { "type": "array", "items": { "type": "string" }, "description": "Trigger phrases for skill matching (optional, falls back to description keywords)" },
                "content": { "type": "string", "description": "Skill instructions inline (markdown body of SKILL.md). Use only for small skills; for large ones use content_file." },
                "content_file": { "type": "string", "description": "Workspace-relative path to a file containing the skill instructions (e.g. 'output/my_skill.md'). Alternative to 'content' for large skills." },
                "dir_name": { "type": "string", "description": "Override skill directory name (optional, defaults to lowercased name with spaces→underscores)" },
                "files": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": { "type": "string", "description": "Relative path within skill directory (e.g., 'reference.md', 'templates/report.html')" },
                            "content": { "type": "string", "description": "File content inline (for small files)" },
                            "source_path": { "type": "string", "description": "Workspace-relative path to read file content from (for large files)" }
                        },
                        "required": ["path"]
                    },
                    "description": "Additional files within the skill directory. Provide either 'content' (inline) or 'source_path' (workspace file) for each."
                }
            },
            "required": ["name"]
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value> {
        let name = args["name"].as_str().ok_or_else(|| "Missing 'name'".to_string())?;
        let desc = args["description"].as_str().unwrap_or("");
        let triggers: Vec<String> = args["triggers"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        // Resolve skill body: inline 'content' or read from 'content_file'
        let content = if let Some(inline) = args["content"].as_str() {
            inline.to_string()
        } else if let Some(file_path) = args["content_file"].as_str() {
            let full_path = Path::new(&ctx.working_dir).join(file_path);
            std::fs::read_to_string(&full_path)
                .map_err(|e| format!("Failed to read content_file '{}': {}", full_path.display(), e))?
        } else {
            return Err("Provide either 'content' (inline) or 'content_file' (workspace path) with the skill instructions.".into());
        };

        // Auto-derive directory name from 'name' (or use explicit override)
        let dir_name = args["dir_name"].as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| name.to_lowercase().replace(' ', "_"));

        let triggers_yaml: Vec<String> = triggers.iter().map(|t| format!("  - {}", t)).collect();
        let md_content = format!(
            "---\nname: {}\ndescription: {}\ntriggers:\n{}\n---\n\n{}\n",
            name, desc, triggers_yaml.join("\n"), content
        );

        std::fs::create_dir_all(&self.skills_dir)
            .map_err(|e| format!("Failed to create dir: {}", e))?;

        // Always create directory: skills/{dir_name}/SKILL.md
        let skill_dir = self.skills_dir.join(&dir_name);
        std::fs::create_dir_all(&skill_dir)
            .map_err(|e| format!("Failed to create skill dir: {}", e))?;
        let skill_md = skill_dir.join("SKILL.md");
        std::fs::write(&skill_md, &md_content)
            .map_err(|e| format!("Failed to write SKILL.md: {}", e))?;

        // Write optional extra files (inline content or read from source_path)
        let mut file_count = 0usize;
        if let Some(files_arr) = args["files"].as_array() {
            for item in files_arr {
                let rel_path = item["path"].as_str().ok_or_else(|| "Missing 'path' in files entry".to_string())?;
                let file_content = if let Some(inline) = item["content"].as_str() {
                    inline.to_string()
                } else if let Some(src) = item["source_path"].as_str() {
                    let full_path = Path::new(&ctx.working_dir).join(src);
                    std::fs::read_to_string(&full_path)
                        .map_err(|e| format!("Failed to read source_path '{}': {}", full_path.display(), e))?
                } else {
                    return Err(format!("files[{}]: provide either 'content' or 'source_path'", rel_path).into());
                };
                let file_path = skill_dir.join(rel_path);
                if let Some(parent) = file_path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("Failed to create subdirectory: {}", e))?;
                }
                std::fs::write(&file_path, &file_content)
                    .map_err(|e| format!("Failed to write {}: {}", rel_path, e))?;
                file_count += 1;
            }
        }

        // Reload skills
        let mut skills = self.skills.write().unwrap();
        let dir_str = skill_dir.to_string_lossy().to_string();
        if let Some(skill) = parse_skill_file(&skill_md, dir_str) {
            skills.push(skill);
        }

        Ok(json!({
            "status": "installed",
            "name": name,
            "dir_name": dir_name,
            "skill_dir": skill_dir.to_string_lossy(),
            "files": file_count + 1
        }))
    }
}

struct ListSkillsTool {
    skills: Arc<RwLock<Vec<Skill>>>,
}

#[async_trait]
impl Tool for ListSkillsTool {
    fn name(&self) -> &str { "list_skills" }
    fn description(&self) -> &str { "List all currently installed skills with their names, descriptions, and triggers." }
    fn parameters_schema(&self) -> Value {
        json!({ "type": "object", "properties": {} })
    }
    async fn execute(&self, _args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let skills = self.skills.read().unwrap();
        let list: Vec<Value> = skills
            .iter()
            .map(|s| {
                json!({
                    "name": s.metadata.name,
                    "description": s.metadata.description,
                    "triggers": s.metadata.triggers,
                    "enabled": s.metadata.enabled,
                    "skill_dir": s.skill_dir,
                })
            })
            .collect();
        Ok(json!({ "skills": list, "count": list.len() }))
    }
}

struct RemoveSkillTool {
    #[allow(dead_code)]
    skills_dir: PathBuf,
    skills: Arc<RwLock<Vec<Skill>>>,
}

#[async_trait]
impl Tool for RemoveSkillTool {
    fn name(&self) -> &str { "remove_skill" }
    fn description(&self) -> &str { "Remove an installed skill by name. Removes the skill directory and all its contents." }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Skill name to remove" }
            },
            "required": ["name"]
        })
    }
    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let name = args["name"].as_str().ok_or_else(|| "Missing 'name'".to_string())?;
        let mut skills = self.skills.write().unwrap();
        let name_lower = name.to_lowercase();

        // Try exact match first, then case-insensitive, then by directory name
        let pos = skills.iter().position(|s| s.metadata.name == name)
            .or_else(|| skills.iter().position(|s| s.metadata.name.to_lowercase() == name_lower))
            .or_else(|| {
                let dir_name = name.to_lowercase().replace(' ', "_");
                skills.iter().position(|s| {
                    Path::new(&s.skill_dir).file_name()
                        .map(|n| n.to_string_lossy().to_lowercase() == dir_name)
                        .unwrap_or(false)
                })
            });

        if let Some(pos) = pos {
            let skill_dir = skills[pos].skill_dir.clone();

            // Remove entire skill directory
            let _ = std::fs::remove_dir_all(&skill_dir);
            skills.remove(pos);
            Ok(json!({ "status": "removed", "name": name, "dir": skill_dir }))
        } else {
            let available: Vec<&str> = skills.iter().map(|s| s.metadata.name.as_str()).collect();
            Err(format!("Skill '{}' not found. Available skills: {:?}", name, available).into())
        }
    }
}
