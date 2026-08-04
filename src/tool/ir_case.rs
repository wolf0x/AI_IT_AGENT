use async_trait::async_trait;
use serde_json::{json, Value};
use std::fs;
use chrono::Utc;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

/// Investigation case file tracker — maintains structured state across
/// an incident response engagement so the agent never loses its place.
pub struct IrCaseTool;

/// Path to the case file directory inside the workspace.
fn case_dir(workspace: &str) -> String {
    format!("{}/output/cases", workspace)
}

/// Load a case file from disk.
fn load_case(workspace: &str, case_id: &str) -> AgentResult<Value> {
    let path = format!("{}/{}.json", case_dir(workspace), case_id);
    let content = fs::read_to_string(&path)
        .map_err(|e| format!("Case '{}' not found: {}", case_id, e))?;
    serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse case file: {}", e).into())
}

/// Save a case file to disk.
fn save_case(workspace: &str, case: &Value) -> AgentResult<String> {
    let dir = case_dir(workspace);
    fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create case directory: {}", e))?;
    let case_id = case["case_id"].as_str().unwrap_or("unknown");
    let path = format!("{}/{}.json", dir, case_id);
    fs::write(&path, serde_json::to_string_pretty(case).unwrap())
        .map_err(|e| format!("Failed to write case file: {}", e))?;
    Ok(path)
}

#[async_trait]
impl Tool for IrCaseTool {
    fn name(&self) -> &str { "ir_case" }
    fn description(&self) -> &str {
        "Investigation case file tracker. Manages structured case state across an IR engagement. \
         Actions: 'init' creates a new case, 'update' adds findings/IOCs/notes, \
         'status' shows current case state, 'list' shows all cases, 'close' marks case resolved. \
         Prevents the agent from losing investigation context across long or multi-session investigations."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { false } // Writes case files
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["init", "update", "status", "list", "close"],
                    "description": "Action to perform"
                },
                "case_id": {
                    "type": "string",
                    "description": "Case identifier (auto-generated on init if omitted)"
                },
                "title": {
                    "type": "string",
                    "description": "Case title (for init)"
                },
                "phase": {
                    "type": "string",
                    "description": "Current investigation phase: collection, analysis, deep_dive, timeline, reporting, closed"
                },
                "findings": {
                    "type": "array",
                    "description": "New findings to add (array of objects with severity, title, evidence)"
                },
                "iocs": {
                    "type": "array",
                    "description": "New IOCs to add (array of strings: IPs, hashes, domains, accounts)"
                },
                "notes": {
                    "type": "string",
                    "description": "Investigation notes to append"
                },
                "tools_called": {
                    "type": "array",
                    "description": "Tools executed in this step (for tracking coverage)"
                },
                "summary": {
                    "type": "string",
                    "description": "Current assessment summary"
                }
            },
            "required": ["action"]
        })
    }

    async fn execute(&self, args: Value, ctx: &ToolContext) -> AgentResult<Value> {
        let action = args["action"].as_str().unwrap_or("status");
        let workspace = &ctx.workspace_dir;

        match action {
            "init" => {
                let now = Utc::now();
                let case_id = args["case_id"].as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("CASE-{}", now.format("%Y%m%d-%H%M%S")));
                let title = args["title"].as_str()
                    .unwrap_or("Untitled Investigation");

                let case = json!({
                    "case_id": case_id,
                    "title": title,
                    "status": "open",
                    "created": now.to_rfc3339(),
                    "updated": now.to_rfc3339(),
                    "phase": "collection",
                    "summary": "",
                    "findings": [],
                    "iocs": [],
                    "notes": [],
                    "tool_log": [],
                    "phase_history": [{
                        "phase": "collection",
                        "entered_at": now.to_rfc3339(),
                    }],
                });

                let path = save_case(workspace, &case)?;
                Ok(json!({
                    "status": "ok",
                    "action": "init",
                    "case_id": case_id,
                    "path": path,
                    "message": format!("Case '{}' initialized: {}", case_id, title),
                }))
            }

            "update" => {
                let case_id = args["case_id"].as_str()
                    .ok_or("case_id required for update action")?;
                let mut case = load_case(workspace, case_id)?;
                let now = Utc::now();

                // Update phase if provided
                if let Some(new_phase) = args["phase"].as_str() {
                    let old_phase = case.get("phase").and_then(|v| v.as_str()).unwrap_or("unknown").to_owned();
                    case["phase"] = json!(new_phase);
                    case["phase_history"].as_array_mut().unwrap().push(json!({
                        "phase": new_phase,
                        "entered_at": now.to_rfc3339(),
                    }));
                    case["notes"].as_array_mut().unwrap().push(json!({
                        "timestamp": now.to_rfc3339(),
                        "type": "phase_change",
                        "content": format!("Phase transition: {} -> {}", old_phase, new_phase),
                    }));
                }

                // Append findings
                if let Some(new_findings) = args["findings"].as_array() {
                    for f in new_findings {
                        case["findings"].as_array_mut().unwrap().push(json!({
                            "added_at": now.to_rfc3339(),
                            "severity": f["severity"].as_str().unwrap_or("unknown"),
                            "title": f["title"].as_str().unwrap_or(""),
                            "evidence": f["evidence"].as_str().unwrap_or(""),
                        }));
                    }
                }

                // Append IOCs (deduplicate)
                if let Some(new_iocs) = args["iocs"].as_array() {
                    let existing: std::collections::HashSet<String> = case["iocs"]
                        .as_array().unwrap_or(&vec![])
                        .iter().filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();
                    for ioc in new_iocs {
                        if let Some(ioc_str) = ioc.as_str() {
                            if !existing.contains(ioc_str) {
                                case["iocs"].as_array_mut().unwrap().push(json!(ioc_str));
                            }
                        }
                    }
                }

                // Append notes
                if let Some(note) = args["notes"].as_str() {
                    if !note.is_empty() {
                        case["notes"].as_array_mut().unwrap().push(json!({
                            "timestamp": now.to_rfc3339(),
                            "type": "note",
                            "content": note,
                        }));
                    }
                }

                // Append tool log
                if let Some(tools) = args["tools_called"].as_array() {
                    for t in tools {
                        case["tool_log"].as_array_mut().unwrap().push(json!({
                            "timestamp": now.to_rfc3339(),
                            "tool": t.as_str().unwrap_or(""),
                        }));
                    }
                }

                // Update summary
                if let Some(summary) = args["summary"].as_str() {
                    case["summary"] = json!(summary);
                }

                case["updated"] = json!(now.to_rfc3339());
                let path = save_case(workspace, &case)?;

                let finding_count = case["findings"].as_array().map(|a| a.len()).unwrap_or(0);
                let ioc_count = case["iocs"].as_array().map(|a| a.len()).unwrap_or(0);
                let tool_count = case["tool_log"].as_array().map(|a| a.len()).unwrap_or(0);

                Ok(json!({
                    "status": "ok",
                    "action": "update",
                    "case_id": case_id,
                    "path": path,
                    "stats": {
                        "findings": finding_count,
                        "iocs": ioc_count,
                        "tools_called": tool_count,
                        "phase": case["phase"].as_str().unwrap_or("unknown"),
                    },
                }))
            }

            "status" => {
                let case_id = args["case_id"].as_str()
                    .ok_or("case_id required for status action")?;
                let case = load_case(workspace, case_id)?;

                let finding_count = case["findings"].as_array().map(|a| a.len()).unwrap_or(0);
                let ioc_count = case["iocs"].as_array().map(|a| a.len()).unwrap_or(0);
                let tool_count = case["tool_log"].as_array().map(|a| a.len()).unwrap_or(0);

                // Severity breakdown
                let findings = case["findings"].as_array().cloned().unwrap_or_default();
                let critical = findings.iter().filter(|f| f["severity"] == "critical").count();
                let high = findings.iter().filter(|f| f["severity"] == "high").count();
                let medium = findings.iter().filter(|f| f["severity"] == "medium").count();

                Ok(json!({
                    "status": "ok",
                    "action": "status",
                    "case": {
                        "case_id": case["case_id"],
                        "title": case["title"],
                        "case_status": case["status"],
                        "phase": case["phase"],
                        "created": case["created"],
                        "updated": case["updated"],
                        "summary": case["summary"],
                    },
                    "stats": {
                        "findings": finding_count,
                        "findings_breakdown": { "critical": critical, "high": high, "medium": medium },
                        "iocs": ioc_count,
                        "tools_called": tool_count,
                        "notes_count": case["notes"].as_array().map(|a| a.len()).unwrap_or(0),
                    },
                    "recent_findings": findings.iter().rev().take(5).collect::<Vec<_>>(),
                    "iocs": case["iocs"],
                    "phase_history": case["phase_history"],
                }))
            }

            "list" => {
                let dir = case_dir(workspace);
                let mut cases = Vec::new();
                if let Ok(entries) = fs::read_dir(&dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().map(|e| e == "json").unwrap_or(false) {
                            if let Ok(content) = fs::read_to_string(&path) {
                                if let Ok(case) = serde_json::from_str::<Value>(&content) {
                                    cases.push(json!({
                                        "case_id": case["case_id"],
                                        "title": case["title"],
                                        "status": case["status"],
                                        "phase": case["phase"],
                                        "created": case["created"],
                                        "updated": case["updated"],
                                    }));
                                }
                            }
                        }
                    }
                }
                // Sort by updated descending
                cases.sort_by(|a, b| {
                    b["updated"].as_str().unwrap_or("").cmp(&a["updated"].as_str().unwrap_or(""))
                });
                Ok(json!({
                    "status": "ok",
                    "action": "list",
                    "cases": cases,
                    "total": cases.len(),
                }))
            }

            "close" => {
                let case_id = args["case_id"].as_str()
                    .ok_or("case_id required for close action")?;
                let mut case = load_case(workspace, case_id)?;
                let now = Utc::now();

                case["status"] = json!("closed");
                case["closed_at"] = json!(now.to_rfc3339());
                if let Some(summary) = args["summary"].as_str() {
                    case["summary"] = json!(summary);
                }
                case["notes"].as_array_mut().unwrap().push(json!({
                    "timestamp": now.to_rfc3339(),
                    "type": "closure",
                    "content": args["notes"].as_str().unwrap_or("Case closed"),
                }));
                case["updated"] = json!(now.to_rfc3339());

                let path = save_case(workspace, &case)?;
                Ok(json!({
                    "status": "ok",
                    "action": "close",
                    "case_id": case_id,
                    "path": path,
                    "message": format!("Case '{}' closed", case_id),
                }))
            }

            _ => Err(format!("Unknown action: {}. Use: init, update, status, list, close", action).into()),
        }
    }
}
