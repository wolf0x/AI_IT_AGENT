use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

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

/// Skill instruction body.
///
/// Discovery parses only the frontmatter at boot; the markdown body is read
/// lazily from the on-disk SKILL.md on first access and cached thereafter
/// (std::sync::OnceLock). `Eager` is used for in-memory-built skills (tests,
/// programmatic construction) where there is no file to read.
#[derive(Debug, Clone)]
pub enum SkillContent {
    Eager(String),
    Lazy {
        path: PathBuf,
        cell: Arc<OnceLock<String>>,
    },
}

impl SkillContent {
    /// True when this skill's body is lazily loaded from disk.
    pub fn is_lazy(&self) -> bool {
        matches!(self, SkillContent::Lazy { .. })
    }
}

#[derive(Debug, Clone)]
pub struct Skill {
    pub metadata: SkillMetadata,
    /// Skill instruction body (lazy unless built in-memory).
    pub content: SkillContent,
    /// Directory path of the skill (e.g., skills/VulnerabilityPrioritization).
    /// Every skill is a directory containing SKILL.md and optional supporting files.
    pub skill_dir: String,
}
