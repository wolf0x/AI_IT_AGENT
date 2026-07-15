use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillMetadata {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub triggers: Vec<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool { true }

/// Controls skill ranking and filtering during matching.
///
/// Skills are scored via weighted token overlap (name ×4.0, description ×2.5,
/// triggers ×2.0, body ×1.0), normalized by `sqrt(body_tokens)` to prevent
/// large documents from dominating. Only skills scoring >= `min_score` are
/// returned, up to `top_k` results.
#[derive(Debug, Clone)]
pub struct SelectionPolicy {
    pub top_k: usize,
    pub min_score: f32,
}

impl Default for SelectionPolicy {
    fn default() -> Self {
        Self {
            top_k: 3,
            min_score: 0.1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Skill {
    pub metadata: SkillMetadata,
    pub content: String,
    pub file_path: String,
    /// Directory path of the skill (e.g., skills/VulnerabilityPrioritization).
    /// Every skill is a directory containing SKILL.md and optional supporting files.
    pub skill_dir: String,
}
