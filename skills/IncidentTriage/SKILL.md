---
name: IncidentTriage
description: "Standardized incident triage workflow: parallel collection, rule-based analysis, conditional deep-dive, and structured reporting."
triggers:
  - "triage"
  - "incident"
  - "compromise"
  - "breach"
  - "investigate"
  - "incident response"
  - "IR"
  - "suspicious"
  - "compromised"
enabled: true
---

# Incident Triage Workflow

You are executing a standardized incident triage. Follow these phases IN ORDER. Do not skip phases.

## Phase 1: Parallel Collection

Call ALL of these tools together in a single batch (they will execute in parallel):

```json
{"name": "ir_scan", "arguments": {"category": "all"}}
{"name": "ir_process", "arguments": {"action": "list"}}
{"name": "ir_account", "arguments": {}}
{"name": "ir_persistence", "arguments": {"category": "all"}}
{"name": "ir_network", "arguments": {"category": "all"}}
```

Wait for ALL results before proceeding.

## Phase 2: Rule-Based Analysis

Feed the collected data into the analyzer:

```json
{"name": "ir_analyzer", "arguments": {"data": {
  "processes": "<ir_process output>",
  "network": "<ir_network output>",
  "accounts": "<ir_account output>",
  "autoruns": "<ir_persistence autoruns section>",
  "services": "<ir_scan services section>",
  "eventlogs": "<ir_scan security-events section>",
  "defender": "<ir_scan defender section>",
  "drivers": "<ir_scan drivers section>",
  "wmi": "<ir_scan wmi section>",
  "lateral": "<ir_scan lateral section>"
}}}
```

Review the findings. Note all HIGH and CRITICAL severity items.

## Phase 3: Conditional Deep-Dive

Based on Phase 2 findings, execute ONLY the relevant deep-dive tools:

| Finding | Action |
|---------|--------|
| Suspicious binary / unsigned exe | `malware_deep` with the file path |
| Encoded PowerShell / LOLBin | `ir_eventlog` with log_name=PowerShell, event_id=4104 |
| External C2 connections | `ir_network` with category=connections, then `ir_pcap_analyze` if pcap available |
| Account anomalies | `ir_eventlog` with log_name=Security, event_id=4624,4625,4720 |
| Service/persistence install | `ir_eventlog` with log_name=System, event_id=7045 |
| Web shell indicators | `ir_weblog_scan` with the relevant log path |

If NO high/critical findings: skip to Phase 4.

## Phase 4: Timeline Reconstruction

Call `ir_timeline` to generate a chronological view of events:

```json
{"name": "ir_timeline", "arguments": {"hours": 168, "risk_filter": "medium"}}
```

Use the timeline to identify the attack sequence and initial access vector.

## Phase 5: Report

Generate a structured report:

```json
{"name": "ir_report", "arguments": {
  "findings": "<Phase 2 findings JSON>",
  "timeline": "<Phase 4 timeline>",
  "format": "technical"
}}
```

## Output Format

Present your final assessment as:

1. **Executive Summary** (2-3 sentences: compromised or clean, severity, key finding)
2. **Critical Findings** (bullet list of HIGH/CRITICAL items with evidence)
3. **Attack Timeline** (chronological narrative if compromise confirmed)
4. **MITRE ATT&CK Mapping** (technique IDs from analyzer findings)
5. **Recommended Actions** (containment → eradication → recovery steps)

## Rules

- NEVER skip Phase 1 collection — always gather fresh data
- NEVER fabricate findings — only report what tools return
- If tools return errors, note them and continue with available data
- Keep the report factual — no speculation beyond evidence
