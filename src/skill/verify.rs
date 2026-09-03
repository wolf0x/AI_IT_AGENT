//! Lightweight completion verification for skill step contracts.
//!
//! Gives an *objective*, logged adherence number for a skill run by checking
//! the accumulated evidence (the agent's final text + the tool-call names it
//! issued) against the skill's step contract. It is deliberately heuristic and
//! non-destructive: a step counts as evidenced when its normalized label, its
//! `step N` marker, or an explicit "completed N" list bracket appears in the
//! evidence. The result drives a bounded auto-continuation that asks the agent
//! to finish any still-missing steps.
use crate::skill::types::StepItem;

/// Result of verifying one skill run against its step contract.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    /// 1-based step indices whose evidence was found.
    pub completed: Vec<usize>,
    /// 1-based step indices lacking evidence.
    pub missing: Vec<usize>,
    /// Total number of contract steps (>= 2 by construction).
    pub total: usize,
    /// completed / total in [0,1]. 1.0 when there is nothing to verify.
    pub ratio: f64,
}

impl VerifyReport {
    pub fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }
}

/// Verify which contract steps are evidenced as done against `evidence`
/// (accumulated final text + tool-call names from the run).
pub fn verify_completion(contract: &[StepItem], evidence: &str) -> VerifyReport {
    if contract.is_empty() {
        return VerifyReport { completed: Vec::new(), missing: Vec::new(), total: 0, ratio: 1.0 };
    }
    let ev = evidence.trim();
    let mut completed = Vec::new();
    let mut missing = Vec::new();
    for (i, step) in contract.iter().enumerate() {
        let idx = i + 1;
        if step_evidenced(&step.label, idx, ev) {
            completed.push(idx);
        } else {
            missing.push(idx);
        }
    }
    let total = contract.len();
    let ratio = completed.len() as f64 / total as f64;
    VerifyReport { completed, missing, total, ratio }
}

/// A step is evidenced if any of several signals appear in the evidence:
///   1. its normalized label appears verbatim (agents often echo the step),
///   2. a `step N` marker with the step number,
///   3. an explicit "completed N" list that brackets the step number.
fn step_evidenced(label: &str, idx: usize, evidence: &str) -> bool {
    if evidence.is_empty() {
        return false;
    }
    let norm = normalize(label);
    if !norm.is_empty() && contains_norm(evidence, &norm) {
        return true;
    }
    // The trimmed, prefix-stripped label (drops "Step N:" / "Phase N:").
    let trimmed = normalize(trim_prefix(label));
    if !trimmed.is_empty() && trimmed != norm && contains_norm(evidence, &trimmed) {
        return true;
    }
    // "step N" / "Step N:" marker.
    if contains_norm(evidence, &format!("step {}", idx)) {
        return true;
    }
    // Explicit "completed steps N, M" / "completed: N" list.
    if completed_list_contains(evidence, idx) {
        return true;
    }
    false
}

/// Look for a "completed ... <idx> ..." style list (e.g. "completed steps 1, 2",
/// "steps done: 1 2 3", "已完成 1,2,3"). Matches a standalone number token that
/// equals `idx`.
fn completed_list_contains(evidence: &str, idx: usize) -> bool {
    let lower = evidence.to_lowercase();
    let markers = ["completed", "done", "finished", "已完成", "完成", "covered"];
    let mut region = String::new();
    let mut found_marker = false;
    for line in lower.lines() {
        let l = line.trim();
        if l.is_empty() { continue; }
        if markers.iter().any(|m| l.contains(m)) || found_marker {
            region.push(' ');
            region.push_str(l);
            found_marker = true;
        }
    }
    if !found_marker {
        return false;
    }
    // Tokenize: split on non-alphanumeric (keep CJK chars as tokens).
    for token in region.split(|c: char| !(c.is_alphanumeric())) {
        if let Ok(n) = token.trim().parse::<usize>() {
            if n == idx {
                return true;
            }
        }
    }
    false
}

/// Normalize for substring matching: lowercase, ASCII-fold, collapse whitespace.
fn normalize(s: &str) -> String {
    let folded: String = s
        .to_lowercase()
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    folded.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn contains_norm(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() { return false; }
    let h = normalize(haystack);
    h.contains(needle)
}

/// Strips a leading "step N:" / "phase N:" / "step N" prefix from a label.
fn trim_prefix(s: &str) -> &str {
    let t = s.trim();
    let lower = t.to_lowercase();
    for prefix in ["step ", "phase ", "步骤", "阶段"] {
        if lower.starts_with(prefix) {
            // "step N:" or "step N -" etc.
            let rest = &t[prefix.len()..];
            let rest = rest.trim_start_matches(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.', ':', ' ', '-']);
            let rest = rest.trim_start_matches([':', ' ', '-', '.']);
            return rest.trim();
        }
    }
    t
}

/// Build the bounded auto-continuation message for a run that left steps
/// missing: re-run the skill but explicitly focus on the still-uncovered
/// steps, keeping the previous partial output as context. Returns None when
/// nothing is missing (caller should not continue).
pub fn continuation_message(prev_report: &str, missing_labels: &[String]) -> String {
    let mut msg = String::from(
        "You previously ran this skill but the following steps were NOT completed.          Re-run and finish ALL steps in order, and make sure every step below is          fully covered and reflected in your final output:
",
    );
    for (k, label) in missing_labels.iter().enumerate() {
        msg.push_str(&format!("- Step {}: {}
", k + 1, label));
    }
    msg.push_str("
Previous partial output (for context):
");
    let tail = if prev_report.len() > 2000 { &prev_report[prev_report.len() - 2000..] } else { prev_report };
    msg.push_str(tail);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    fn steps(labels: &[&str]) -> Vec<StepItem> {
        labels.iter().map(|l| StepItem { label: l.to_string() }).collect()
    }

    #[test]
    fn empty_contract_is_complete() {
        let r = verify_completion(&[], "");
        assert!(r.is_complete());
        assert_eq!(r.ratio, 1.0);
    }

    #[test]
    fn labels_echoed_in_text_count_as_done() {
        let c = steps(&["collect process list", "scan network connections"]);
        let ev = "collect process list done. step 1 done.";
        let r = verify_completion(&c, ev);
        assert_eq!(r.completed, vec![1]);
        assert_eq!(r.missing, vec![2]);
    }

    #[test]
    fn step_number_marker_counts_as_done() {
        let c = steps(&["first", "second", "third"]);
        let ev = "we completed step 2 and step 3.";
        let r = verify_completion(&c, ev);
        assert_eq!(r.completed, vec![2, 3]);
        assert_eq!(r.missing, vec![1]);
    }

    #[test]
    fn completed_list_counts_as_done() {
        let c = steps(&["one", "two", "three", "four"]);
        let ev = "report: completed steps 1, 2. step 4 done.";
        let r = verify_completion(&c, ev);
        assert_eq!(r.completed, vec![1, 2, 4]);
        assert_eq!(r.missing, vec![3]);
    }

    #[test]
    fn prefix_stripped_label_matches() {
        let c = steps(&["Step 1: collect process list"]);
        let ev = "collect process list";
        let r = verify_completion(&c, ev);
        assert_eq!(r.completed, vec![1]);
    }

    #[test]
    fn no_evidence_means_all_missing() {
        let c = steps(&["aaa bbb", "ccc ddd"]);
        let r = verify_completion(&c, "");
        assert_eq!(r.missing, vec![1, 2]);
        assert_eq!(r.ratio, 0.0);
    }

    #[test]
    fn continuation_message_lists_missing() {
        let m = continuation_message("prev report", &["collect process list".to_string(), "scan net".to_string()]);
        assert!(m.contains("Step 1: collect process list"));
        assert!(m.contains("Step 2: scan net"));
        assert!(m.contains("prev report"));
    }
}
