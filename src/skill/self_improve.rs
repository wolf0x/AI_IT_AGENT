//! Self-improvement loop for skills (default OFF, guarded).
//!
//! When enabled (config `skill_self_improve = true`), the model can propose a
//! patch to a skill via the `improve_skill` tool after a run that under-performed
//! (tool-error spikes, apology markers, empty final answer). Every change is:
//! - version-bumped (frontmatter `version`),
//! - backed up to `<skills>/_audit/<skill>-<ts>.skills.md` (revertible),
//! - gated by a per-skill cooldown (manifest),
//! - refused for human-curated (`curated: true`) skills.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::types::Skill;

/// Cooldown window during which a skill cannot be re-improved.
pub const IMPROVE_COOLDOWN_SECS: u64 = 24 * 3600;

/// Lightweight success assessment over a finished run.
///
/// A run is considered successful only if it produced a non-empty final answer,
/// did not exceed a high tool-error ratio, and shows no strong apology/failure
/// markers. Used to decide whether a self-improvement pass is warranted.
#[allow(dead_code)]
pub fn assess_success(last_text: &str, tool_error_count: usize, tool_total: usize) -> bool {
    let text = last_text.trim();
    if text.is_empty() {
        return false;
    }
    if tool_total > 0 && (tool_error_count as f64 / tool_total as f64) > 0.6 {
        return false;
    }
    let low = text.to_lowercase();
    const FAIL_MARKERS: &[&str] = &[
        "i'm sorry",
        "i am sorry",
        "apologies",
        "i couldn't",
        "i could not",
        "i was unable",
        "i wasn't able",
        "unfortunately",
        "sorry, i",
    ];
    if FAIL_MARKERS.iter().any(|m| low.contains(m)) {
        return false;
    }
    true
}

/// Audit dir is `<skills>/_audit`.
pub fn audit_dir(skills_dir: &Path) -> PathBuf {
    skills_dir.join("_audit")
}

fn manifest_path(skills_dir: &Path) -> PathBuf {
    audit_dir(skills_dir).join("manifest.jsonl")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Copy a skill's on-disk SKILL.md into the audit dir (revertible backup).
pub fn backup_skill(skills_dir: &Path, skill: &Skill) -> std::io::Result<PathBuf> {
    use std::fs;
    let dir = audit_dir(skills_dir);
    fs::create_dir_all(&dir)?;
    let src = Path::new(&skill.skill_dir).join("SKILL.md");
    let dst = dir.join(format!("{}-{}.skills.md", sanitize(&skill.metadata.name), now_unix()));
    fs::copy(&src, &dst)?;
    Ok(dst)
}

/// Last unix time (if any) this skill was improved, from the manifest.
pub fn last_improved_at(skills_dir: &Path, name: &str) -> Option<u64> {
    let data = std::fs::read_to_string(manifest_path(skills_dir)).ok()?;
    let mut last = None;
    for line in data.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if v.get("name").and_then(|n| n.as_str()) == Some(name) {
                if let Some(at) = v.get("at").and_then(|a| a.as_u64()) {
                    last = Some(at);
                }
            }
        }
    }
    last
}

/// Should we allow improving this skill right now?
/// - never for curated (human) skills,
/// - not again within [`IMPROVE_COOLDOWN_SECS`].
/// Cooldown is checked twice for persistence: the _audit manifest (authoritative)
/// and, as a fallback when the manifest entry is missing, the `updated_at` field
/// written into the skill's own frontmatter on the last improvement.
pub fn should_improve(skills_dir: &Path, skill: &Skill, now: u64) -> bool {
    if skill.metadata.curated {
        return false;
    }
    match last_improved_at(skills_dir, &skill.metadata.name) {
        Some(last) => now.saturating_sub(last) >= IMPROVE_COOLDOWN_SECS,
        None => {
            // Fallback double-check: use the frontmatter `updated_at` timestamp.
            let path = Path::new(&skill.skill_dir).join("SKILL.md");
            match frontmatter_updated_at_unix(&path) {
                Some(last) => now.saturating_sub(last) >= IMPROVE_COOLDOWN_SECS,
                None => true,
            }
        }
    }
}

/// Parse a unix-seconds `updated_at:` value from a skill's frontmatter (best effort).
pub fn frontmatter_updated_at_unix(path: &Path) -> Option<u64> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("updated_at:") {
            return rest.trim().parse::<u64>().ok();
        }
    }
    None
}

/// Bump a semantic version string ("1.2.3" -> "1.2.4"). Falls back to
/// appending ".1" for partial versions, or "1.0.0" when empty.
pub fn bump_version(v: &str) -> String {
    let trimmed = v.trim();
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() >= 3 {
        if let Ok(n) = parts[2].parse::<u64>() {
            return format!("{}.{}.{}", parts[0], parts[1], n + 1);
        }
    }
    if trimmed.is_empty() {
        "1.0.0".to_string()
    } else {
        format!("{}.1", trimmed)
    }
}

fn record_improved(skills_dir: &Path, name: &str, at: u64) {
    use std::io::Write;
    let dir = audit_dir(skills_dir);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(manifest_path(skills_dir))
    {
        let name_json = serde_json::to_string(name).unwrap_or_else(|_| "\"?\"".to_string());
        let _ = writeln!(f, "{{\"name\":{},\"at\":{}}}", name_json, at);
    }
}

/// Apply a model-proposed patch to a skill body: bump `version` in frontmatter,
/// replace the instruction body, write to disk, and record the improvement.
/// Returns the new version string.
pub fn apply_patch(skills_dir: &Path, skill: &Skill, new_body: &str) -> Result<String, String> {
    use std::fs;
    let path = Path::new(&skill.skill_dir).join("SKILL.md");
    let content = fs::read_to_string(&path).map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    let (frontmatter, _) = super::split_frontmatter(&content)
        .ok_or_else(|| format!("Invalid frontmatter in {}", path.display()))?;

    let new_version = bump_version(&skill.metadata.version);
    let updated_at = now_unix();

    let mut fm_lines: Vec<String> = Vec::new();
    let mut inserted = false;
    let mut updated = false;
    for l in frontmatter.lines() {
        if l.trim_start().starts_with("version:") {
            fm_lines.push(format!("version: {}", new_version));
            inserted = true;
        } else if l.trim_start().starts_with("updated_at:") {
            fm_lines.push(format!("updated_at: {}", updated_at));
            updated = true;
        } else {
            fm_lines.push(l.to_string());
        }
    }
    if !inserted {
        fm_lines.push(format!("version: {}", new_version));
    }
    if !updated {
        fm_lines.push(format!("updated_at: {}", updated_at));
    }
    let new_fm = fm_lines.join("\n");
    let out = format!("---\n{}\n---\n\n{}\n", new_fm, new_body.trim());
    fs::write(&path, &out).map_err(|e| format!("Failed to write {}: {}", path.display(), e))?;

    record_improved(skills_dir, &skill.metadata.name, now_unix());
    Ok(new_version)
}


// ============================================================================
// Objective validation: record per-version run outcomes and suggest a rollback
// when recent outcomes regress. This is the "objective verification" half of
// the loop - an improvement is only trusted once outcomes show it did not raise
// failures.
// ============================================================================

fn outcomes_path(skills_dir: &Path) -> PathBuf {
    audit_dir(skills_dir).join("outcomes.jsonl")
}

/// Record the outcome of one run that engaged a skill (version-specific).
/// `success` should come from an objective signal (e.g. [`assess_success`] or a
/// tool-error / completion check), not the model's self-report.
#[allow(dead_code)] // public validation API; production run-hook lands separately
pub fn record_outcome(skills_dir: &Path, name: &str, version: &str, success: bool) {
    use std::io::Write;
    let dir = audit_dir(skills_dir);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let name_json = serde_json::to_string(name).unwrap_or_else(|_| "\"?\"".to_string());
    let version_json = serde_json::to_string(version).unwrap_or_else(|_| "\"?\"".to_string());
    let line = format!(
        "{{\"name\":{},\"version\":{},\"success\":{},\"at\":{}}}\n",
        name_json, version_json, if success { "true" } else { "false" }, now_unix()
    );
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(outcomes_path(skills_dir)) {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Aggregate recent outcomes for a skill: (attempts, failures) across the last
/// `window` records for that skill name.
pub fn outcome_stats(skills_dir: &Path, name: &str, window: usize) -> (usize, usize) {
    let data = match std::fs::read_to_string(outcomes_path(skills_dir)) {
        Ok(d) => d,
        Err(_) => return (0, 0),
    };
    let mut attempts = 0usize;
    let mut failures = 0usize;
    for line in data.lines().rev() {
        if attempts >= window {
            break;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if v.get("name").and_then(|n| n.as_str()) == Some(name) {
                attempts += 1;
                if v.get("success").and_then(|s| s.as_bool()) == Some(false) {
                    failures += 1;
                }
            }
        }
    }
    (attempts, failures)
}

/// Suggest rollback when a skill has enough recent outcomes and at least half of
/// them are failures (objective regression signal). Caller surfaces a rollback
/// hint to the user rather than silently reverting.
pub fn should_suggest_rollback(skills_dir: &Path, name: &str, window: usize, failure_ratio: f64) -> bool {
    let (attempts, failures) = outcome_stats(skills_dir, name, window);
    if attempts < 3 {
        return false;
    }
    (failures as f64 / attempts as f64) >= failure_ratio
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skill::types::SkillMetadata;
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rs_si_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn skill(name: &str, version: &str, curated: bool) -> Skill {
        Skill {
            metadata: SkillMetadata {
                name: name.to_string(),
                description: String::new(),
                triggers: vec![],
                enabled: true,
                always: false,
                when_to_use: String::new(),
                version: version.to_string(),
                curated,
            },
            content: crate::skill::SkillContent::Eager(format!("# {}\n", name)),
            skill_dir: String::new(),
        }
    }

    #[test]
    fn assess_success_heuristics() {
        assert!(assess_success("done: all ok", 0, 5));
        assert!(!assess_success("", 0, 1));
        assert!(!assess_success("I'm sorry, I couldn't finish.", 0, 1));
        assert!(!assess_success("partial", 5, 5)); // 100% tool-error ratio
    }

    #[test]
    fn bump_versions() {
        assert_eq!(bump_version("1.2.3"), "1.2.4");
        assert_eq!(bump_version("1.2"), "1.2.1");
        assert_eq!(bump_version(""), "1.0.0");
        assert_eq!(bump_version("2.1.10"), "2.1.11");
    }

    #[test]
    fn curated_refused_and_cooldown() {
        let d = tmp("cooldown");
        let curated = skill("B", "1.0.0", true);
        assert!(!should_improve(&d, &curated, 1000), "curated must be read-only");
        let fresh = skill("C", "1.0.0", false);
        assert!(should_improve(&d, &fresh, 1000), "fresh skill should be improvable");
        record_improved(&d, "C", 1000);
        assert!(!should_improve(&d, &fresh, 1000 + IMPROVE_COOLDOWN_SECS - 1));
        assert!(should_improve(&d, &fresh, 1000 + IMPROVE_COOLDOWN_SECS));

        // Persistent double-check: when the manifest entry is missing but the
        // skill's own frontmatter carries a recent `updated_at`, cooldown holds.
        let skdir = d.join("CFront");
        std::fs::create_dir_all(&skdir).unwrap();
        let recent: u64 = 5;
        std::fs::write(skdir.join("SKILL.md"),
            format!("---\nname: CFront\nversion: 1.0.0\nupdated_at: {}\n---\n\n# B\n", recent)).unwrap();
        let mut cfront = skill("CFront", "1.0.0", false);
        cfront.skill_dir = skdir.to_string_lossy().to_string();
        assert!(!should_improve(&d, &cfront, recent), "frontmatter updated_at should gate");
        assert!(should_improve(&d, &cfront, recent + IMPROVE_COOLDOWN_SECS));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn apply_patch_writes_version_and_manifest() {
        let d = tmp("patch");
        let skdir = d.join("MySkill");
        std::fs::create_dir_all(&skdir).unwrap();
        std::fs::write(skdir.join("SKILL.md"),
            "---\nname: MySkill\ndescription: d\nversion: 1.0.0\n---\n\n# Old body\n").unwrap();
        let mut sk = skill("MySkill", "1.0.0", false);
        sk.skill_dir = skdir.to_string_lossy().to_string();
        let v = apply_patch(&d, &sk, "# New body\nbetter steps").unwrap();
        assert_eq!(v, "1.0.1");
        let content = std::fs::read_to_string(skdir.join("SKILL.md")).unwrap();
        assert!(content.contains("version: 1.0.1"), "version not bumped: {}", content);
        assert!(content.contains("# New body"));
        assert!(!content.contains("# Old body"));
        assert!(last_improved_at(&d, "MySkill").is_some(), "manifest not recorded");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn backup_skill_copies_to_audit() {
        let d = tmp("backup");
        let skdir = d.join("X");
        std::fs::create_dir_all(&skdir).unwrap();
        std::fs::write(skdir.join("SKILL.md"), "# body").unwrap();
        let mut sk = skill("X", "1.0.0", false);
        sk.skill_dir = skdir.to_string_lossy().to_string();
        let b = backup_skill(&d, &sk).unwrap();
        assert!(b.exists());
        assert!(b.to_string_lossy().contains("_audit"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn outcome_recording_and_rollback_suggestion() {
        let d = tmp("outcome");
        // Below the threshold: too few attempts -> no rollback.
        assert!(!should_suggest_rollback(&d, "S", 10, 0.5));
        // 2/3 failures -> rollback suggested.
        record_outcome(&d, "S", "1.0.0", false);
        record_outcome(&d, "S", "1.0.0", true);
        record_outcome(&d, "S", "1.0.1", false);
        assert!(should_suggest_rollback(&d, "S", 10, 0.5));
        // Stats window respected.
        assert_eq!(outcome_stats(&d, "S", 2), (2, 1));
        assert_eq!(outcome_stats(&d, "S", 10), (3, 2));
        // A different skill name never triggers.
        assert!(!should_suggest_rollback(&d, "Other", 10, 0.5));
        let _ = std::fs::remove_dir_all(&d);
    }
}
