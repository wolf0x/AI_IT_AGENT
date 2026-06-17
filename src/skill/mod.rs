pub mod types;

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

use self::types::{Skill, SkillMetadata};
use super::tool::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;
use async_trait::async_trait;
use serde_json::{json, Value};

pub struct SkillManager {
    skills: Arc<RwLock<Vec<Skill>>>,
    skills_dir: PathBuf,
}

impl SkillManager {
    pub fn new(skills_dir: &str) -> Self {
        let dir = PathBuf::from(skills_dir);
        let mgr = Self {
            skills: Arc::new(RwLock::new(Vec::new())),
            skills_dir: dir,
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

        let pattern = format!("{}/*.md", self.skills_dir.display());
        for entry in glob::glob(&pattern).ok().into_iter().flatten() {
            match entry {
                Ok(path) => match parse_skill_file(&path) {
                    Some(skill) => {
                        info!("Loaded skill: {} from {}", skill.metadata.name, path.display());
                        skills.push(skill);
                    }
                    None => {
                        warn!("Failed to parse skill file: {}", path.display());
                    }
                },
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

    pub fn find_matching(&self, user_message: &str) -> Vec<String> {
        let skills = self.skills.read().unwrap();
        let msg_lower = user_message.to_lowercase();
        skills
            .iter()
            .filter(|s| {
                s.metadata
                    .triggers
                    .iter()
                    .any(|t| msg_lower.contains(&t.to_lowercase()))
            })
            .map(|s| s.content.clone())
            .collect()
    }

    #[allow(dead_code)]
    pub fn skills_dir(&self) -> &Path {
        self.skills_dir.as_path()
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
}

fn parse_skill_file(path: &Path) -> Option<Skill> {
    let content = std::fs::read_to_string(path).ok()?;
    let (frontmatter, body) = split_frontmatter(&content)?;
    let metadata: SkillMetadata = serde_yaml::from_str(&frontmatter).ok()?;

    Some(Skill {
        metadata,
        content: body.trim().to_string(),
        file_path: path.to_string_lossy().to_string(),
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
        "Install a new skill by creating a markdown file with YAML frontmatter (name, description, triggers) and skill instructions as content."
    }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "filename": { "type": "string", "description": "Skill filename (without .md extension)" },
                "name": { "type": "string", "description": "Skill name identifier" },
                "description": { "type": "string", "description": "Skill description" },
                "triggers": { "type": "array", "items": { "type": "string" }, "description": "Trigger phrases" },
                "content": { "type": "string", "description": "Skill instructions (markdown)" }
            },
            "required": ["filename", "name", "description", "triggers", "content"]
        })
    }
    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let filename = args["filename"].as_str().ok_or_else(|| "Missing 'filename'".to_string())?;
        let name = args["name"].as_str().ok_or_else(|| "Missing 'name'".to_string())?;
        let desc = args["description"].as_str().unwrap_or("");
        let triggers: Vec<String> = args["triggers"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let content = args["content"].as_str().ok_or_else(|| "Missing 'content'".to_string())?;

        let triggers_yaml: Vec<String> = triggers.iter().map(|t| format!("  - {}", t)).collect();
        let md_content = format!(
            "---\nname: {}\ndescription: {}\ntriggers:\n{}\n---\n\n{}\n",
            name, desc, triggers_yaml.join("\n"), content
        );

        let path = self.skills_dir.join(format!("{}.md", filename));
        std::fs::create_dir_all(&self.skills_dir)
            .map_err(|e| format!("Failed to create dir: {}", e))?;
        std::fs::write(&path, &md_content).map_err(|e| format!("Failed to write: {}", e))?;

        // Reload skills
        let mut skills = self.skills.write().unwrap();
        if let Some(skill) = parse_skill_file(&path) {
            skills.push(skill);
        }

        Ok(json!({ "status": "installed", "path": path.to_string_lossy(), "name": name }))
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
                    "file": s.file_path,
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
    fn description(&self) -> &str { "Remove an installed skill by name." }
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
        if let Some(pos) = skills.iter().position(|s| s.metadata.name == name) {
            let path = skills[pos].file_path.clone();
            let _ = std::fs::remove_file(&path);
            skills.remove(pos);
            Ok(json!({ "status": "removed", "name": name }))
        } else {
            Err(format!("Skill '{}' not found", name).into())
        }
    }
}
