use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

/// Attack path modeling tool — analyzes findings, process trees, and network
/// connections to build a privilege escalation and lateral movement graph.
pub struct IrAttackPathTool;

/// A node in the attack graph.
struct AttackNode {
    id: String,
    node_type: String,  // "entry", "privilege", "lateral", "asset", "c2"
    label: String,
    severity: String,
    evidence: String,
    mitre_technique: String,
}

/// An edge in the attack graph.
struct AttackEdge {
    from: String,
    to: String,
    relationship: String,
    description: String,
}

#[async_trait]
impl Tool for IrAttackPathTool {
    fn name(&self) -> &str { "ir_attackpath" }
    fn description(&self) -> &str {
        "Attack path modeling tool. Analyzes ir_analyzer findings, process data, and network connections \
         to build a privilege escalation and lateral movement attack graph. \
         Identifies how an attacker could progress from initial access to full compromise. \
         Accepts findings JSON (from ir_analyzer) and optional process/network data."
    }
    fn is_builtin(&self) -> bool { true }
    fn is_read_only(&self) -> bool { true }
    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "findings": {
                    "type": "object",
                    "description": "Findings JSON from ir_analyzer (with 'findings' array)"
                },
                "processes": {
                    "type": "string",
                    "description": "Process listing text (from ir_process) for parent-child chain analysis"
                },
                "network": {
                    "type": "string",
                    "description": "Network connections text (from ir_network) for C2 and lateral movement mapping"
                },
                "accounts": {
                    "type": "string",
                    "description": "Account information text (from ir_account) for privilege context"
                }
            },
            "required": ["findings"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let findings_data = &args["findings"];
        let findings_arr = findings_data["findings"].as_array()
            .ok_or("Missing 'findings' array in findings data")?;

        let _process_text = args["processes"].as_str().unwrap_or("");
        let network_text = args["network"].as_str().unwrap_or("");
        let _account_text = args["accounts"].as_str().unwrap_or("");

        let mut nodes: Vec<AttackNode> = Vec::new();
        let mut edges: Vec<AttackEdge> = Vec::new();
        let mut node_counter = 0u32;

        // Track which attack categories are present
        let mut has_initial_access = false;
        let mut has_execution = false;
        let mut has_persistence = false;
        let mut has_privilege_escalation = false;
        let mut has_lateral_movement = false;
        let mut has_c2 = false;
        let mut has_defense_evasion = false;
        let mut has_credential_access = false;

        // Categorize findings into attack graph nodes
        for f in findings_arr {
            let rule_id = f["rule_id"].as_str().unwrap_or("");
            let severity = f["severity"].as_str().unwrap_or("low");
            let evidence = f["evidence"].as_str().unwrap_or("");
            let title = f["title"].as_str().unwrap_or("");
            let category = f["category"].as_str().unwrap_or("");

            // Skip pass/benign findings
            if severity == "pass" { continue; }

            // Determine node type based on rule_id and MITRE mapping
            let (node_type, mitre) = classify_finding(rule_id, category);

            match node_type.as_str() {
                "entry" => { has_initial_access = true; }
                "execution" => { has_execution = true; }
                "persistence" => { has_persistence = true; }
                "privilege" => { has_privilege_escalation = true; }
                "lateral" => { has_lateral_movement = true; }
                "c2" => { has_c2 = true; }
                "evasion" => { has_defense_evasion = true; }
                "credential" => { has_credential_access = true; }
                _ => {}
            }

            node_counter += 1;
            nodes.push(AttackNode {
                id: format!("N{:03}", node_counter),
                node_type,
                label: title.to_string(),
                severity: severity.to_string(),
                evidence: evidence.to_string(),
                mitre_technique: mitre,
            });
        }

        // Extract external IPs from network data for C2 nodes
        let mut external_ips: Vec<String> = Vec::new();
        if !network_text.is_empty() {
            let ip_re = regex::Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").unwrap();
            for line in network_text.lines() {
                let lower = line.to_lowercase();
                if (lower.contains("established") || lower.contains("syn_sent"))
                    && !line.contains("127.0.0") && !line.contains("10.")
                    && !line.contains("192.168.") && !line.contains("172.16.")
                {
                    for cap in ip_re.captures_iter(line) {
                        let ip = cap[1].to_string();
                        if !external_ips.contains(&ip) {
                            external_ips.push(ip);
                        }
                    }
                }
            }
        }

        // Add C2 node if external connections found and not already present
        if !external_ips.is_empty() && !has_c2 {
            node_counter += 1;
            nodes.push(AttackNode {
                id: format!("N{:03}", node_counter),
                node_type: "c2".into(),
                label: format!("External connections to {} IP(s)", external_ips.len()),
                severity: "medium".into(),
                evidence: external_ips.join(", "),
                mitre_technique: "T1071".into(),
            });
            has_c2 = true;
        }

        // Build edges based on attack chain logic
        let nodes_by_type = build_type_index(&nodes);

        // Edge pattern: Entry → Execution
        if has_initial_access && has_execution {
            for from_id in nodes_by_type.get("entry").cloned().unwrap_or_default() {
                for to_id in nodes_by_type.get("execution").cloned().unwrap_or_default() {
                    edges.push(AttackEdge {
                        from: from_id.clone(),
                        to: to_id.clone(),
                        relationship: "leads_to".into(),
                        description: "Initial access vector enables code execution".into(),
                    });
                }
            }
        }

        // Edge pattern: Execution → Persistence
        if has_execution && has_persistence {
            for from_id in nodes_by_type.get("execution").cloned().unwrap_or_default() {
                for to_id in nodes_by_type.get("persistence").cloned().unwrap_or_default() {
                    edges.push(AttackEdge {
                        from: from_id.clone(),
                        to: to_id.clone(),
                        relationship: "establishes".into(),
                        description: "Execution leads to persistence mechanism installation".into(),
                    });
                }
            }
        }

        // Edge pattern: Execution → Privilege Escalation
        if has_execution && has_privilege_escalation {
            for from_id in nodes_by_type.get("execution").cloned().unwrap_or_default() {
                for to_id in nodes_by_type.get("privilege").cloned().unwrap_or_default() {
                    edges.push(AttackEdge {
                        from: from_id.clone(),
                        to: to_id.clone(),
                        relationship: "escalates_via".into(),
                        description: "Process execution enables privilege escalation".into(),
                    });
                }
            }
        }

        // Edge pattern: Credential Access → Lateral Movement
        if has_credential_access && has_lateral_movement {
            for from_id in nodes_by_type.get("credential").cloned().unwrap_or_default() {
                for to_id in nodes_by_type.get("lateral").cloned().unwrap_or_default() {
                    edges.push(AttackEdge {
                        from: from_id.clone(),
                        to: to_id.clone(),
                        relationship: "enables".into(),
                        description: "Compromised credentials enable lateral movement".into(),
                    });
                }
            }
        }

        // Edge pattern: Persistence → C2
        if has_persistence && has_c2 {
            for from_id in nodes_by_type.get("persistence").cloned().unwrap_or_default() {
                for to_id in nodes_by_type.get("c2").cloned().unwrap_or_default() {
                    edges.push(AttackEdge {
                        from: from_id.clone(),
                        to: to_id.clone(),
                        relationship: "communicates_with".into(),
                        description: "Persistent mechanism maintains C2 channel".into(),
                    });
                }
            }
        }

        // Edge pattern: Defense Evasion → (any other node it could be masking)
        if has_defense_evasion {
            let evasion_ids = nodes_by_type.get("evasion").cloned().unwrap_or_default();
            // Connect evasion to the highest-severity non-evasion node
            let target = nodes.iter()
                .filter(|n| n.node_type != "evasion")
                .max_by_key(|n| severity_score(&n.severity))
                .map(|n| n.id.clone());
            if let Some(target_id) = target {
                for from_id in &evasion_ids {
                    edges.push(AttackEdge {
                        from: from_id.clone(),
                        to: target_id.clone(),
                        relationship: "masks".into(),
                        description: "Defense evasion technique used to hide malicious activity".into(),
                    });
                }
            }
        }

        // Edge pattern: Lateral Movement → C2 (pivot)
        if has_lateral_movement && has_c2 {
            for from_id in nodes_by_type.get("lateral").cloned().unwrap_or_default() {
                for to_id in nodes_by_type.get("c2").cloned().unwrap_or_default() {
                    edges.push(AttackEdge {
                        from: from_id.clone(),
                        to: to_id.clone(),
                        relationship: "pivots_to".into(),
                        description: "Lateral movement used to reach additional C2 infrastructure".into(),
                    });
                }
            }
        }

        // If no edges were generated but we have findings, connect them sequentially
        if edges.is_empty() && nodes.len() > 1 {
            for i in 0..nodes.len() - 1 {
                edges.push(AttackEdge {
                    from: nodes[i].id.clone(),
                    to: nodes[i + 1].id.clone(),
                    relationship: "related_to".into(),
                    description: "Findings may be related through common attack chain".into(),
                });
            }
        }

        // Assess overall attack maturity
        let attack_maturity = assess_attack_maturity(
            has_initial_access, has_execution, has_persistence,
            has_privilege_escalation, has_lateral_movement, has_c2,
            has_defense_evasion, has_credential_access,
        );

        // Build JSON output
        let nodes_json: Vec<Value> = nodes.iter().map(|n| {
            json!({
                "id": n.id,
                "type": n.node_type,
                "label": n.label,
                "severity": n.severity,
                "evidence": n.evidence,
                "mitre_technique": n.mitre_technique,
            })
        }).collect();

        let edges_json: Vec<Value> = edges.iter().map(|e| {
            json!({
                "from": e.from,
                "to": e.to,
                "relationship": e.relationship,
                "description": e.description,
            })
        }).collect();

        // Generate human-readable attack narrative
        let narrative = generate_narrative(&nodes, &edges, &attack_maturity);

        Ok(json!({
            "status": "ok",
            "attack_graph": {
                "nodes": nodes_json,
                "edges": edges_json,
            },
            "attack_maturity": {
                "level": attack_maturity.level,
                "description": attack_maturity.description,
                "kill_chain_coverage": attack_maturity.kill_chain_phases,
            },
            "narrative": narrative,
            "summary": {
                "total_nodes": nodes.len(),
                "total_edges": edges.len(),
                "attack_phases_detected": {
                    "initial_access": has_initial_access,
                    "execution": has_execution,
                    "persistence": has_persistence,
                    "privilege_escalation": has_privilege_escalation,
                    "lateral_movement": has_lateral_movement,
                    "c2": has_c2,
                    "defense_evasion": has_defense_evasion,
                    "credential_access": has_credential_access,
                },
                "external_ips": external_ips,
            },
        }))
    }
}

/// Classify a finding into an attack graph node type.
fn classify_finding(rule_id: &str, category: &str) -> (String, String) {
    match rule_id {
        // Initial Access
        "web.suspicious_request" => ("entry".into(), "T1190".into()),
        // Execution
        "win.lolbin_exec" | "win.encoded_powershell" => ("execution".into(), "T1059".into()),
        "win.service_install" => ("execution".into(), "T1569.002".into()),
        // Persistence
        "win.wmi_persistence" => ("persistence".into(), "T1546.003".into()),
        "win.hidden_account" | "win.account_change" => ("persistence".into(), "T1136.001".into()),
        "win.unsigned_driver" => ("persistence".into(), "T1547.006".into()),
        // Privilege Escalation
        "win.unquoted_service_path" => ("privilege".into(), "T1574.009".into()),
        // Lateral Movement
        "win.psexec_service" => ("lateral".into(), "T1570".into()),
        // Command & Control
        "win.external_established" => ("c2".into(), "T1071".into()),
        "win.dns_suspicious_cache" => ("c2".into(), "T1071.004".into()),
        // Defense Evasion
        "win.defender_disabled" | "win.defender_exclusion" => ("evasion".into(), "T1562.001".into()),
        "win.eventlog_cleared" => ("evasion".into(), "T1070.001".into()),
        // Credential Access
        "win.bruteforce_many" | "win.bruteforce_some" => ("credential".into(), "T1110".into()),
        // Fallback: use category
        _ => {
            let node_type = match category {
                "processes" | "tasks" => "execution",
                "network" | "dns" => "c2",
                "accounts" => "persistence",
                "services" | "autoruns" => "persistence",
                "lateral" => "lateral",
                "defender" => "evasion",
                "drivers" => "persistence",
                "web-logs" => "entry",
                _ => "unknown",
            };
            (node_type.into(), String::new())
        }
    }
}

fn severity_score(s: &str) -> u32 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn build_type_index(nodes: &[AttackNode]) -> HashMap<String, Vec<String>> {
    let mut index: HashMap<String, Vec<String>> = HashMap::new();
    for n in nodes {
        index.entry(n.node_type.clone()).or_default().push(n.id.clone());
    }
    index
}

struct AttackMaturity {
    level: String,
    description: String,
    kill_chain_phases: Vec<String>,
}

fn assess_attack_maturity(
    initial_access: bool, execution: bool, persistence: bool,
    priv_esc: bool, lateral: bool, c2: bool,
    evasion: bool, credential: bool,
) -> AttackMaturity {
    let mut phases = Vec::new();
    if initial_access { phases.push("Initial Access"); }
    if execution { phases.push("Execution"); }
    if persistence { phases.push("Persistence"); }
    if priv_esc { phases.push("Privilege Escalation"); }
    if lateral { phases.push("Lateral Movement"); }
    if c2 { phases.push("Command and Control"); }
    if evasion { phases.push("Defense Evasion"); }
    if credential { phases.push("Credential Access"); }

    let score = phases.len();
    let (level, description) = match score {
        0 => ("clean".into(), "No attack indicators detected.".into()),
        1..=2 => ("initial".into(), format!("Early-stage attack detected ({} phases). Attacker has limited foothold. Immediate containment recommended.", score)),
        3..=4 => ("established".into(), format!("Established compromise detected ({} phases). Attacker has achieved persistence and possibly elevated privileges. Full incident response required.", score)),
        5..=6 => ("advanced".into(), format!("Advanced compromise detected ({} phases). Attacker has deep foothold with multiple persistence mechanisms and lateral movement capability. Consider full re-image after evidence preservation.", score)),
        _ => ("critical".into(), format!("Critical compromise — full kill chain present ({} phases). Attacker has initial access, execution, persistence, privilege escalation, lateral movement, and C2. Assume complete system compromise. Isolate immediately and begin forensic imaging before any remediation.", score)),
    };

    AttackMaturity {
        level,
        description,
        kill_chain_phases: phases.into_iter().map(|s| s.to_string()).collect(),
    }
}

fn generate_narrative(nodes: &[AttackNode], edges: &[AttackEdge], maturity: &AttackMaturity) -> String {
    if nodes.is_empty() {
        return "No attack indicators detected. System appears clean.".to_string();
    }

    let mut narrative = String::new();
    narrative.push_str(&format!("Attack Maturity: {} — {}\n\n", maturity.level.to_uppercase(), maturity.description));

    // Group nodes by type for narrative
    let mut by_type: HashMap<&str, Vec<&AttackNode>> = HashMap::new();
    for n in nodes {
        by_type.entry(n.node_type.as_str()).or_default().push(n);
    }

    if let Some(entry_nodes) = by_type.get("entry") {
        narrative.push_str("INITIAL ACCESS: ");
        for n in entry_nodes {
            narrative.push_str(&format!("{} ({}). ", n.label, n.mitre_technique));
        }
        narrative.push('\n');
    }

    if let Some(exec_nodes) = by_type.get("execution") {
        narrative.push_str("EXECUTION: ");
        for n in exec_nodes {
            narrative.push_str(&format!("{} ({}). ", n.label, n.mitre_technique));
        }
        narrative.push('\n');
    }

    if let Some(cred_nodes) = by_type.get("credential") {
        narrative.push_str("CREDENTIAL ACCESS: ");
        for n in cred_nodes {
            narrative.push_str(&format!("{} ({}). ", n.label, n.mitre_technique));
        }
        narrative.push('\n');
    }

    if let Some(persist_nodes) = by_type.get("persistence") {
        narrative.push_str("PERSISTENCE: ");
        for n in persist_nodes {
            narrative.push_str(&format!("{} ({}). ", n.label, n.mitre_technique));
        }
        narrative.push('\n');
    }

    if let Some(priv_nodes) = by_type.get("privilege") {
        narrative.push_str("PRIVILEGE ESCALATION: ");
        for n in priv_nodes {
            narrative.push_str(&format!("{} ({}). ", n.label, n.mitre_technique));
        }
        narrative.push('\n');
    }

    if let Some(lateral_nodes) = by_type.get("lateral") {
        narrative.push_str("LATERAL MOVEMENT: ");
        for n in lateral_nodes {
            narrative.push_str(&format!("{} ({}). ", n.label, n.mitre_technique));
        }
        narrative.push('\n');
    }

    if let Some(c2_nodes) = by_type.get("c2") {
        narrative.push_str("COMMAND & CONTROL: ");
        for n in c2_nodes {
            narrative.push_str(&format!("{} ({}). ", n.label, n.mitre_technique));
        }
        narrative.push('\n');
    }

    if let Some(evasion_nodes) = by_type.get("evasion") {
        narrative.push_str("DEFENSE EVASION: ");
        for n in evasion_nodes {
            narrative.push_str(&format!("{} ({}). ", n.label, n.mitre_technique));
        }
        narrative.push('\n');
    }

    // Edge summary
    if !edges.is_empty() {
        narrative.push_str(&format!("\nATTACK CHAINS ({} connections):\n", edges.len()));
        for e in edges.iter().take(10) {
            let from_label = nodes.iter().find(|n| n.id == e.from).map(|n| n.label.as_str()).unwrap_or(&e.from);
            let to_label = nodes.iter().find(|n| n.id == e.to).map(|n| n.label.as_str()).unwrap_or(&e.to);
            narrative.push_str(&format!("  {} --[{}]--> {}\n    {}\n", from_label, e.relationship, to_label, e.description));
        }
    }

    narrative
}
