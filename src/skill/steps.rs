//! Linear step-contract extraction for skills.
//!
//! Designed to work on ANY SKILL.md, including third-party skills that have no
//! `phases:`/`sop:` frontmatter. We derive an ordered step list from markdown
//! structure (highest-confidence first):
//!   1. `## Phase N:` headings
//!   2. generic `##`/`###` section headings (only if no Phase headings found)
//!   3. top-level `1.` numbered list items (only if no headings found)
//!
//! Returns an empty vec when nothing reliable is found — the skill then behaves
//! exactly as it does today (no step contract, no behavior change).
use crate::skill::types::StepItem;

const MAX_STEPS: usize = 12;
const MAX_STEP_CHARS: usize = 160;

/// Extract a compact, ordered list of steps from a skill body.
pub fn extract_contract(body: &str) -> Vec<StepItem> {
    let text = strip_code_fences(body);
    let mut out: Vec<StepItem> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // 1) Explicit-ish `## Phase N:` headings (highest confidence).
    for cap in heading_phases(&text) {
        push_unique(&mut out, &mut seen, &cap, 1);
    }
    // 2) Generic section headings — only when we found no Phase headings, so a
    //    reference/prose page does not get over-segmented if it happens to use
    //    numbered phases somewhere.
    if out.is_empty() {
        for cap in generic_headings(&text) {
            push_unique(&mut out, &mut seen, &cap, 1);
        }
    }
    // 3) Numbered list items (procedural third-party skills often use these).
    if out.is_empty() {
        for cap in numbered_items(&text) {
            push_unique(&mut out, &mut seen, &cap, 1);
        }
    }

    // A single heading is usually just the page title / noise — require >= 2
    // concrete steps before advertising a contract.
    if out.len() < 2 {
        return Vec::new();
    }
    out.truncate(MAX_STEPS);
    out
}

/// Render the extracted contract as an injectable prompt block, or `None`
/// when there is nothing meaningful to enforce.
pub fn contract_block(steps: &[StepItem]) -> Option<String> {
    if steps.len() < 2 {
        return None;
    }
    let mut s = String::from("\n**Step Contract (follow IN ORDER — do not skip steps):**\n");
    for (i, step) in steps.iter().enumerate() {
        s.push_str(&format!("{}. {}\n", i + 1, step.label));
    }
    s.push_str("Execute these steps in order; report which steps were completed.\n");
    Some(s)
}

/// Strip fenced code blocks so code samples are never mistaken for steps.
fn strip_code_fences(body: &str) -> String {
    let mut out_lines: Vec<&str> = Vec::new();
    let mut in_fence = false;
    for line in body.lines() {
        let t = line.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence {
            out_lines.push(line);
        }
    }
    out_lines.join("\n")
}

fn heading_phases(text: &str) -> Vec<String> {
    let re = regex::Regex::new(r"(?m)^\s*#{2,3}\s+Phase\s+(\d+)\s*[:.\-]?\s*(.*)$").unwrap();
    re.captures_iter(text)
        .map(|c| {
            let num = &c[1];
            let title = c.get(2).map(|m| m.as_str().trim()).unwrap_or("");
            format!("Phase {}: {}", num, title)
        })
        .collect()
}

fn generic_headings(text: &str) -> Vec<String> {
    let re = regex::Regex::new(r"(?m)^\s*(#{2,3})\s+([^#\n].{0,140})$").unwrap();
    re.captures_iter(text)
        .filter_map(|c| {
            let title = c.get(2).map(|m| m.as_str().trim()).unwrap_or("");
            if title.is_empty() || title.eq_ignore_ascii_case("overview") || title.eq_ignore_ascii_case("references") {
                return None;
            }
            Some(title.to_string())
        })
        .collect()
}

fn numbered_items(text: &str) -> Vec<String> {
    let re = regex::Regex::new(r"(?m)^\s*\d+[.)]\s+([^#\n].{0,140})$").unwrap();
    re.captures_iter(text)
        .filter_map(|c| c.get(1).map(|m| m.as_str().trim().to_string()))
        .filter(|s| !s.is_empty())
        .collect()
}

fn push_unique(out: &mut Vec<StepItem>, seen: &mut std::collections::HashSet<String>, cap: &str, _weight: u32) {
    let cleaned = clean_label(cap);
    if cleaned.is_empty() || cleaned.len() > MAX_STEP_CHARS {
        return;
    }
    let key = cleaned.to_lowercase();
    if seen.insert(key) {
        out.push(StepItem { label: cleaned });
    }
}

fn clean_label(s: &str) -> String {
    // Drop markdown: backticks, bold/italic, leading bullets/dashes, links keep text.
    let mut t = s.trim().to_string();
    t = t.replace('`', "");
    t = t.replace("**", "");
    t = t.replace("*", "");
    t = t.trim_start_matches(|c: char| c == '-' || c == '+' || c == '#' || c == ' ').to_string();
    t.truncate(MAX_STEP_CHARS);
    t.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_headings_become_steps() {
        let body = "# Hunt\n\n## Phase 1: Collect\n...\n## Phase 2: Analyze\n...\n## Phase 3: Report\n";
        let steps = extract_contract(body);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].label, "Phase 1: Collect");
        assert_eq!(steps[2].label, "Phase 3: Report");
        assert!(contract_block(&steps).is_some());
    }

    #[test]
    fn generic_headings_fallback() {
        let body = "# Guide\n\n## Setup\n## Collect logs\n## Write report\n";
        let steps = extract_contract(body);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].label, "Setup");
    }

    #[test]
    fn numbered_list_fallback() {
        let body = "# Process\n\n1. Open the file\n2. Run scan\n3. Save results\n";
        let steps = extract_contract(body);
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].label, "Open the file");
    }

    #[test]
    fn code_fences_ignored() {
        let body = "# Tool\n\n```md\n## Phase 1: Fake\n## Phase 2: Fake\n```\n\n## Real step\n## Real step two\n";
        let steps = extract_contract(body);
        assert_eq!(steps.iter().map(|s| s.label.as_str()).collect::<Vec<_>>(), vec!["Real step", "Real step two"]);
    }

    #[test]
    fn single_heading_is_noise() {
        let body = "# Only a title\n\n## A section\n";
        let steps = extract_contract(body);
        assert!(steps.is_empty());
        assert!(contract_block(&steps).is_none());
    }

    #[test]
    fn no_structure_returns_empty() {
        let body = "# Hi\n\nJust some prose with no structure at all.\n";
        assert!(extract_contract(body).is_empty());
    }
}
