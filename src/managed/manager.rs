//! Manager — planning role for managed (long-horizon) task execution.
//!
//! The Manager receives only the TaskContract (no growing history) and decides:
//! 1. What subtask the Executor should work on next
//! 2. What success criteria define completion of that subtask
//! 3. What evidence the Auditor should look for
//!
//! This fresh-context approach prevents the context drift that plagues long tasks
//! when using a single accumulating conversation history.

use super::task_contract::{IrPhase, TaskContract};
use crate::model::openai::OpenAiProvider;
use crate::model::ChatMessage;
use crate::skill::types::SkillMetadata;
use std::sync::Arc;

/// Result of a Manager planning round.
#[derive(Debug, Clone)]
pub struct ManagerPlan {
    /// The subtask for the Executor to work on.
    pub subtask: String,
    /// Success criteria — how to know the subtask is done.
    pub success_criteria: String,
    /// Expected evidence — what files/artifacts should be produced.
    pub expected_evidence: String,
    /// Route: what happens after this round.
    pub route: ManagerRoute,
    /// The IR phase the NEXT subtask belongs to (forward-only progression).
    pub phase: Option<IrPhase>,
}

/// What happens after the Executor completes a subtask.
#[derive(Debug, Clone, PartialEq)]
pub enum ManagerRoute {
    /// Continue to next round (more work to do).
    Continue,
    /// Task is complete — generate final summary.
    Done,
    /// Task is blocked — waiting for human input.
    Blocked(String),
    /// Manager output was invalid — retry planning.
    Invalid(String),
}

/// Build the Manager's system prompt.
fn manager_system_prompt() -> String {
    r#"You are the Manager role in a long-horizon incident response task.

Your job is to plan the NEXT subtask for the Executor agent. You receive:
- The original task description
- Current IR phase and verified progress
- Open leads and manager notes

You MUST output a structured plan in the following format:

```
Subtask: <clear, specific description of what the Executor should do next>

Success Criteria: <how to know this subtask is complete>

Expected Evidence: <what files or artifacts should be produced; one file path per line>

Phase: <collection | analysis | attribution | containment | eradication | reporting>

Route: <continue | done | blocked:reason>
```

Rules:
1. Focus on ONE subtask at a time. Do not try to plan the entire remaining workflow.
2. The subtask must be actionable with available tools. See the Tool Reference below for which tools to use for each task type.
3. Success criteria must be objective and verifiable.
4. Route = "continue" if more work remains after this subtask.
5. Route = "done" if the original task is fully complete (all phases done, report generated).
6. Route = "blocked:<reason>" if the task cannot proceed without human input.
7. Base your plan on VERIFIED findings only — do not assume unverified results.
8. If verified findings suggest a critical threat, prioritize containment in the next subtask.
9. Keep the subtask focused — it should be completable in 5-15 tool calls.
10. State the phase the NEXT subtask belongs to. Never regress — the phase must be the same as or later than the current phase.

CRITICAL — Anti-Stagnation Rules:
11. NEVER plan a subtask that is just "summarize findings", "review results", or "analyze what we have". Every subtask MUST require the Executor to run concrete tools and produce concrete artifacts.
12. If Manager Notes show 3+ consecutive rounds with NO new verified findings, you MUST either:
    a. Change strategy significantly (different tools, different targets, broader scope)
    b. Set Route = "blocked:No progress after N rounds, need human guidance" 
13. If the same evidence path failed verification, do NOT retry it — try a different approach or acknowledge the limitation.
14. The Subtask description MUST name at least one concrete tool. Generic descriptions like "investigate further" are not acceptable.

Tool Reference — Use this to pick the RIGHT tool for the job:

  Windows Host Forensics (local machine):
    ir_scan      — Full host collection: processes, network, autoruns, services, events, files, etc.
    ir_process   — List/kill processes on this machine
    ir_network   — Network connections, DNS, firewall, lateral traces
    ir_file      — File forensics: temp dirs, ADS, hashes
    ir_persistence — Autoruns, scheduled tasks, WMI, services, registry hooks
    ir_eventlog  — Structured event log queries (logons, failures, PowerShell, Sysmon)
    ir_driver    — Driver signature analysis
    ir_artifacts — Prefetch, ShimCache, AmCache, UserAssist execution evidence
    ir_account   — Local user/group enumeration
    ir_vss       — Volume Shadow Copy operations
    ir_memdump   — Process memory dumps
    ir_usn       — NTFS USN Journal analysis

  Web Investigation (NOT ir_scan — use these instead):
    web_fetch      — Fetch content from a URL (HTTP GET/POST). Use allow_private=true for internal targets
    ir_weblog_scan — Parse Nginx/Apache access logs for threats (SQLi, XSS, RCE)
    ir_evtx_parse  — Parse EVTX event log files

  File & Malware Analysis:
    malware_scan   — YARA scan files/directories
    malware_deep   — Deep static PE/ELF/Mach-O analysis
    ir_eml         — Parse .eml email files for phishing analysis

  Network & Log Analysis:
    ir_pcap_analyze — Analyze pcap/pcapng captures
    ir_log_parse    — Generic log parser (syslog, CSV, etc.)
    ir_timeline     — Chronological event timeline reconstruction

  Analysis & Reporting:
    ir_analyzer    — Auto-analyze IR scan output for findings
    ir_attackpath  — Build attack path / privilege escalation graph
    ir_case        — Case file tracker
    ir_report      — Generate HTML/PDF incident report

  Linux Remote IR (SSH):
    ir_linux       — 45 detection modules across 13 categories on remote Linux hosts

  General:
    shell_exec     — Execute PowerShell/CMD commands
    sys_eventlog   — Raw Windows Event Log queries
    sys_info       — System information
    sys_process    — General process listing
    sys_service    — Service management

IR Phase Progression:
- Collection → Analysis → Attribution → Containment → Eradication → Reporting → Done
- Do not skip phases. Each phase builds on verified findings from the previous one."#.to_string()
}

/// Build the Manager's user prompt from the TaskContract.
fn manager_user_prompt(contract: &TaskContract) -> String {
    let mut prompt = String::new();

    prompt.push_str(&format!("# Original Task\n{}\n\n", contract.original_task));
    prompt.push_str(&format!("# Scope\n{}\n\n", contract.scope));
    prompt.push_str(&format!("# Current Phase\n{:?}\n\n", contract.phase));
    prompt.push_str(&format!("# Round\n{} of {}\n\n", contract.current_round + 1, contract.max_rounds));

    if !contract.hypothesis.is_empty() {
        prompt.push_str(&format!("# Hypothesis\n{}\n\n", contract.hypothesis));
    }

    if !contract.verified_findings.is_empty() {
        prompt.push_str("# Verified Findings\n");
        for f in &contract.verified_findings {
            prompt.push_str(&format!("- [{}] {} — {}\n", f.severity.to_uppercase(), f.title, f.evidence_summary));
        }
        prompt.push('\n');
    }

    if !contract.verified_actions.is_empty() {
        prompt.push_str("# Verified Actions Taken\n");
        for a in &contract.verified_actions {
            prompt.push_str(&format!("- {} → {}\n", a.description, a.verification));
        }
        prompt.push('\n');
    }

    if !contract.open_leads.is_empty() {
        prompt.push_str("# Open Leads\n");
        for l in &contract.open_leads {
            prompt.push_str(&format!("- [{}] {}: {}\n", l.status, l.description, l.context));
        }
        prompt.push('\n');
    }

    if !contract.manager_notes.is_empty() {
        prompt.push_str("# Manager Notes\n");
        for note in &contract.manager_notes {
            prompt.push_str(&format!("- {}\n", note));
        }
        prompt.push('\n');
    }

    // ── Anti-stagnation hint: show recent round summaries so the Manager
    //    can see if it's been going in circles ──
    let total_findings = contract.verified_findings.len();
    let total_actions = contract.verified_actions.len();
    if contract.current_round > 0 {
        prompt.push_str(&format!(
            "# Progress Summary\n\
             After {} completed rounds: {} verified findings, {} verified actions.\n",
            contract.current_round, total_findings, total_actions
        ));
        // If many rounds but few findings, explicitly warn the Manager
        if contract.current_round >= 3 && total_findings == 0 {
            prompt.push_str(
                "\n⚠️ WARNING: Multiple rounds have completed with ZERO verified findings. \
                 You MUST change strategy significantly in the next subtask — use different tools, \
                 different targets, or broader scope. If the current approach is fundamentally blocked, \
                 set Route = \"blocked:<reason>\".\n\n"
            );
        }
        prompt.push('\n');
    }

    // If user sent a resume message, surface it prominently
    let user_resume_notes: Vec<&String> = contract.manager_notes.iter()
        .filter(|n| n.starts_with("[User Resume]"))
        .collect();
    if !user_resume_notes.is_empty() {
        prompt.push_str("# User Instructions (Resume)\n");
        for note in &user_resume_notes {
            prompt.push_str(&format!("{}\n", note));
        }
        prompt.push_str("\nThe user has provided new instructions. Follow them while continuing the existing task.\n\n");
    }

    prompt.push_str("# Your Task\n");
    prompt.push_str("Plan the NEXT subtask for the Executor. Output the structured plan as specified.\n");
    prompt.push_str("Remember: the Subtask MUST name specific tools to use and produce concrete artifacts.\n");

    prompt
}

/// Parse the Manager's output into a ManagerPlan.
pub fn parse_manager_plan(output: &str) -> ManagerPlan {
    let mut subtask = String::new();
    let mut success_criteria = String::new();
    let mut expected_evidence = String::new();
    let mut route = ManagerRoute::Continue;
    let mut phase: Option<IrPhase> = None;

    let mut current_section = "";

    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("Subtask:") {
            subtask = trimmed.trim_start_matches("Subtask:").trim().to_string();
            current_section = "subtask";
        } else if trimmed.starts_with("Success Criteria:") {
            success_criteria = trimmed.trim_start_matches("Success Criteria:").trim().to_string();
            current_section = "success";
        } else if trimmed.starts_with("Expected Evidence:") {
            expected_evidence = trimmed.trim_start_matches("Expected Evidence:").trim().to_string();
            current_section = "evidence";
        } else if trimmed.starts_with("Phase:") {
            let phase_str = trimmed.trim_start_matches("Phase:").trim().to_lowercase();
            phase = parse_phase(&phase_str);
            current_section = "";
        } else if trimmed.starts_with("Route:") {
            let route_str = trimmed.trim_start_matches("Route:").trim().to_lowercase();
            if route_str == "done" {
                route = ManagerRoute::Done;
            } else if route_str.starts_with("blocked") {
                let reason = route_str.trim_start_matches("blocked").trim_start_matches(':').trim().to_string();
                route = ManagerRoute::Blocked(if reason.is_empty() { "Unknown reason".to_string() } else { reason });
            } else if route_str == "continue" {
                route = ManagerRoute::Continue;
            } else {
                route = ManagerRoute::Invalid(format!("Unknown route: {}", route_str));
            }
            current_section = "";
        } else if !trimmed.is_empty() && current_section == "subtask" {
            subtask.push(' ');
            subtask.push_str(trimmed);
        } else if !trimmed.is_empty() && current_section == "success" {
            success_criteria.push(' ');
            success_criteria.push_str(trimmed);
        } else if !trimmed.is_empty() && current_section == "evidence" {
            // Preserve line breaks so multi-file evidence stays splittable in the runner.
            expected_evidence.push('\n');
            expected_evidence.push_str(trimmed);
        }
    }

    if subtask.is_empty() {
        route = ManagerRoute::Invalid("No subtask specified".to_string());
    }

    ManagerPlan {
        subtask,
        success_criteria,
        expected_evidence,
        route,
        phase,
    }
}

/// Map a Manager phase string to an IrPhase. Returns None for unknown values
/// (callers then leave the current phase unchanged).
fn parse_phase(s: &str) -> Option<IrPhase> {
    match s {
        "collection" => Some(IrPhase::Collection),
        "analysis" => Some(IrPhase::Analysis),
        "attribution" => Some(IrPhase::Attribution),
        "containment" => Some(IrPhase::Containment),
        "eradication" => Some(IrPhase::Eradication),
        "reporting" => Some(IrPhase::Reporting),
        _ => None,
    }
}

/// Run a Manager planning round.
///
/// Calls the LLM with the Manager system prompt and TaskContract as input.
/// Returns a ManagerPlan with the next subtask and route.
pub async fn plan_next(
    provider: &Arc<OpenAiProvider>,
    model: &str,
    contract: &TaskContract,
    skills: &[SkillMetadata],
) -> Result<ManagerPlan, String> {
    let mut system_prompt = manager_system_prompt();

    // Plan A: inject available skills catalog so the Manager can plan subtasks
    // that leverage skills (e.g., "use archify-rs to generate architecture diagram").
    if !skills.is_empty() {
        system_prompt.push_str("\n\n## Available Skills\n");
        system_prompt.push_str(
            "The following skills are available for the Executor. When a subtask \
             matches a skill's purpose, mention the skill name in the subtask description \
             so the Executor can leverage its workflow.\n\n"
        );
        for skill in skills {
            if !skill.enabled { continue; }
            system_prompt.push_str(&format!(
                "- **{}**: {}",
                skill.name, skill.description
            ));
            if !skill.triggers.is_empty() {
                system_prompt.push_str(&format!(
                    " (triggers: {})",
                    skill.triggers.join(", ")
                ));
            }
            system_prompt.push('\n');
        }
    }

    let user_prompt = manager_user_prompt(contract);

    let messages = vec![
        ChatMessage::system(&system_prompt),
        ChatMessage::user(&user_prompt),
    ];

    // Manager uses no tools — pure planning. We don't stream Manager output to the
    // UI, so create a throwaway channel and spawn a drain task to swallow text deltas
    // (same pattern as re-prompt mode in llm_agent.rs). Without the drain task the
    // channel would block once its small buffer fills.
    let (dummy_tx, mut dummy_rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move {
        while dummy_rx.recv().await.is_some() {}
    });

    let (content, _reasoning, _tool_calls, _usage) = provider
        .chat_stream(model, &messages, &[], dummy_tx, &contract.id, "manager")
        .await
        .map_err(|e| format!("Manager LLM call failed: {}", e))?;

    Ok(parse_manager_plan(&content))
}
