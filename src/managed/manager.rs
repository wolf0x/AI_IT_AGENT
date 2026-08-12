//! Manager — planning role for managed (long-horizon) task execution.
//!
//! The Manager receives only the TaskContract (no growing history) and decides:
//! 1. What subtask the Executor should work on next
//! 2. What success criteria define completion of that subtask
//! 3. What evidence the Auditor should look for
//!
//! This fresh-context approach prevents the context drift that plagues long tasks
//! when using a single accumulating conversation history.

use super::task_contract::{IrPhase, TaskContract, TaskDomain};
use crate::model::openai::OpenAiProvider;
use crate::model::ChatMessage;
use crate::model::ToolDefinition;
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
    /// Execution channel: cli / gui / ask (default: cli).
    pub channel: String,
    /// Raw LLM output of the Manager (original reasoning + structured plan).
    /// Persisted to round_dir/plan_raw.md by the runner for audit replay.
    pub raw_output: String,
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
/// Dynamically assemble the Manager system prompt from the task domain and the
/// ACTUAL live tool registry — no hardcoded per-domain tool lists. The Manager gets:
///   - a domain-appropriate role + phase vocabulary,
///   - the real set of available tools (so it picks the right one for the goal),
///   - domain-agnostic planning / anti-stagnation / evidence rules.
fn manager_system_prompt(lang: &str, domain: TaskDomain, tool_defs: &[ToolDefinition]) -> String {
    let (role, phases, focus) = match domain {
        TaskDomain::Ir => (
            "You are the Manager role in a long-horizon incident response task.",
            "collection | analysis | attribution | containment | eradication | reporting",
            "If verified findings suggest a critical threat, prioritize containment in the next subtask.",
        ),
        TaskDomain::Generic => (
            "You are the Manager role in a long-horizon autonomous task agent.",
            "plan | execute | verify",
            "If the task targets a URL/web app/CTF/research problem, plan steps around the ACTUAL target (fetch pages, interact with forms, analyze responses, capture the result). Do NOT redirect to unrelated host/system forensics unless the task asks for it.",
        ),
    };

    // Render the real tool list from the registry, not a hardcoded list.
    let mut tool_ref = String::new();
    if !tool_defs.is_empty() {
        tool_ref.push_str("Tool Reference — pick the RIGHT tool for the job. ONLY these tools actually exist:\n");
        for t in tool_defs {
            let desc: String = t.function.description.chars().take(200).collect();
            tool_ref.push_str(&format!("- `{}` — {}\n", t.function.name, desc));
        }
    } else {
        tool_ref.push_str("Tool Reference — no tool list is available; infer acceptable tools from the task.\n");
    }

    let mut prompt = String::new();
    prompt.push_str(&format!("{}\n\n", role));
    prompt.push_str("Your job is to plan the NEXT subtask for the Executor agent. You receive:\n");
    prompt.push_str("- The original task description\n- Verified progress / outcomes from prior subtasks\n- Open leads and manager notes\n\n");
    prompt.push_str("You MUST output a structured plan in the following format:\n\n```\n");
    prompt.push_str("Subtask: <clear, specific next step>\n\n");
    prompt.push_str("Success Criteria: <how to know this subtask is complete>\n\n");
    prompt.push_str("Expected Evidence: <one artifact file path per line>\n\n");
    prompt.push_str(&format!("Phase: <{}>\n\n", phases));
    prompt.push_str("Route: <continue | done | blocked:reason>\n```\n\n");
    prompt.push_str("Rules:\n");
    prompt.push_str("1. Focus on ONE subtask at a time. Do not plan the whole workflow at once.\n");
    prompt.push_str("2. The subtask must be actionable with the tools listed in Tool Reference below.\n");
    prompt.push_str("3. Success criteria must be objective and verifiable.\n");
    prompt.push_str("4. Route = \"continue\" if more work remains; \"done\" if the original task is fully complete; \"blocked:<reason>\" if human input is required.\n");
    prompt.push_str("5. Base your plan on VERIFIED results only — do not assume unverified outcomes.\n");
    prompt.push_str("6. Keep the subtask focused — completable in 5-15 tool calls.\n");
    prompt.push_str(&format!("7. {}\n", focus));
    prompt.push_str("\nCRITICAL — Anti-Stagnation Rules:\n");
    prompt.push_str("8. NEVER plan a subtask that is only \"summarize\" or \"review results\". Every subtask MUST require the Executor to run concrete tools and produce concrete artifacts.\n");
    prompt.push_str("9. If Manager Notes show 3+ consecutive rounds with NO new verified outcomes, change strategy significantly or set Route = \"blocked:<reason>\".\n");
    prompt.push_str("10. The Subtask MUST name at least one concrete tool.\n");
    prompt.push_str("\nCRITICAL — Evidence Discipline Rules:\n");
    prompt.push_str("11. Only entries recorded as Verified Findings/Outcomes have been independently checked. Treat everything else (prior session context, manager notes) as unverified leads to re-audit.\n");
    prompt.push_str("12. **MANDATORY OUTPUT LOCATION**: ALL artifacts and reports MUST be saved under the `workspace/output/` directory. Expected Evidence paths must be relative to workspace/output/ (e.g. \"output/result.json\").\n");
    prompt.push_str(&format!("\n{}\n", tool_ref));
    prompt.push_str(&format!("\nLANGUAGE: The original task is written in {lang}. Write all free-text fields (Subtask, Success Criteria, Expected Evidence, reason) in {lang}; keep structure and tool names in English.\n"));
    prompt
}

/// Build the Manager's user prompt from the TaskContract.
fn manager_user_prompt(contract: &TaskContract) -> String {
    let mut prompt = String::new();

    prompt.push_str(&format!("# Original Task\n{}\n\n", contract.original_task));
    prompt.push_str(&format!("# Scope\n{}\n\n", contract.scope));
    prompt.push_str(&format!("# Current Phase\n{:?}\n\n", contract.phase));
    prompt.push_str(&format!("# Round\n{} of {}\n\n", contract.current_round + 1, contract.max_rounds));

    // Surface distilled prior-session (Instant) context prominently so the Manager
    // plans Round 1 from prior discoveries instead of redoing completed collection.
    if let Some(ph) = &contract.prior_handoff {
        let ph = ph.trim();
        if !ph.is_empty() {
            prompt.push_str("# Prior Session Context (UNVERIFIED)\n");
            prompt.push_str("Work done earlier this session (Instant mode). Treat as LEADS/hypotheses, NOT verified facts -- re-audit before promoting to verified state. IMPORTANT: DO NOT blindly redo steps already completed here; plan this and later subtasks to CONTINUE from where prior work left off.\n");
            prompt.push_str(ph);
            prompt.push_str("\n\n");
        }
    }
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
        // F2: Manager must NOT see the Executor's raw trajectory. Notes that
        // are "Round N: <executor output summary>" are filtered out — only
        // audit guard feedback, user instructions, and pre-expert context pass.
        let manager_notes: Vec<&String> = contract.manager_notes.iter()
            .filter(|n| {
                !n.starts_with("Round ") || n.starts_with("[Audit Guard]") || n.starts_with("[User Resume]") || n.starts_with("[Pre-Expert")
            })
            .collect();
        if !manager_notes.is_empty() {
            prompt.push_str("# Manager Notes\n");
            for note in manager_notes {
                prompt.push_str(&format!("- {}\n", note));
            }
            prompt.push('\n');
        }
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
    let mut channel = "cli".to_string();

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
        } else if trimmed.starts_with("Channel:") {
            let ch = trimmed.trim_start_matches("Channel:").trim().to_lowercase();
            channel = if ch.starts_with("gui") { "gui".to_string() }
                else if ch.starts_with("ask") { "ask".to_string() }
                else { "cli".to_string() };
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
        channel,
        raw_output: output.to_string(),
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
    tool_defs: &[ToolDefinition],
) -> Result<ManagerPlan, String> {
    let lang = crate::agent::llm_agent::detect_user_language(&contract.original_task);
    let mut system_prompt = manager_system_prompt(&lang, TaskDomain::from_str(&contract.domain), tool_defs);

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
