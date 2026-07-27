---
name: FullHunt
description: "Comprehensive threat hunt: full system sweep combining IR collection, malware scanning, log analysis, and persistence auditing for advanced persistent threats."
triggers:
  - "full hunt"
  - "threat hunt"
  - "full scan"
  - "complete assessment"
  - "APT"
  - "advanced persistent"
  - "deep investigation"
  - "full assessment"
enabled: true
---

# Full Threat Hunt Workflow

You are executing a comprehensive threat hunt. This is the most thorough assessment — expect 10-15 minutes of tool execution. Follow ALL phases.

## Phase 1: Full System Collection (Parallel)

Execute ALL collection tools simultaneously:

```json
{"name": "ir_scan", "arguments": {"category": "all", "days": 30}}
{"name": "ir_process", "arguments": {"action": "list"}}
{"name": "ir_account", "arguments": {}}
{"name": "ir_persistence", "arguments": {"category": "all"}}
{"name": "ir_network", "arguments": {"category": "all"}}
{"name": "ir_driver", "arguments": {}}
```

## Phase 2: Filesystem Malware Sweep

Scan common malware staging directories:

```json
{"name": "malware_scan", "arguments": {"paths": [
  "C:\\Windows\\Temp",
  "C:\\Users\\Public",
  "C:\\ProgramData",
  "%APPDATA%",
  "%LOCALAPPDATA%\\Temp"
]}}
```

If any hits → immediately run `malware_deep` on each flagged file.

## Phase 3: Rule-Based Analysis

Feed ALL collected data into the analyzer:

```json
{"name": "ir_analyzer", "arguments": {"data": {
  "processes": "<ir_process output>",
  "network": "<ir_network output>",
  "accounts": "<ir_account output>",
  "autoruns": "<ir_persistence output>",
  "services": "<ir_scan services>",
  "tasks": "<ir_scan tasks>",
  "eventlogs": "<ir_scan security-events + system-events>",
  "defender": "<ir_scan defender>",
  "drivers": "<ir_driver output>",
  "wmi": "<ir_scan wmi>",
  "lateral": "<ir_scan lateral>",
  "dns": "<ir_scan network DNS section>"
}}}
```

## Phase 4: Log Deep-Dive

Query specific high-value event logs:

```json
{"name": "ir_eventlog", "arguments": {"log_name": "Security", "event_id": "4624,4625,4672,4720,4732,1102", "days": 30}}
{"name": "ir_eventlog", "arguments": {"log_name": "PowerShell", "event_id": "4104", "days": 14}}
{"name": "ir_eventlog", "arguments": {"log_name": "System", "event_id": "7045,7036,1001", "days": 14}}
```

Look for:
- Privileged logons (4672) from unusual accounts
- Group membership changes (4732) — especially Administrators
- Service installs (7045) with suspicious paths
- PowerShell script block logging (4104) with encoded commands
- Log clearing (1102) — critical anti-forensics indicator

## Phase 5: Timeline Reconstruction

```json
{"name": "ir_timeline", "arguments": {"hours": 720, "risk_filter": "low"}}
```

Correlate events to identify:
- Initial access point and time
- Privilege escalation events
- Lateral movement indicators
- Data staging / exfiltration windows

## Phase 6: Comprehensive Report

```json
{"name": "ir_report", "arguments": {
  "findings": "<all findings>",
  "timeline": "<Phase 5 output>",
  "format": "technical"
}}
```

## Output Structure

### 1. Threat Assessment Summary
- Overall risk level: CRITICAL / HIGH / MEDIUM / LOW / CLEAN
- Confidence level
- One-paragraph executive summary

### 2. Findings by Severity
- CRITICAL findings (immediate action required)
- HIGH findings (investigate within 24h)
- MEDIUM findings (monitor and verify)

### 3. Attack Narrative (if compromise confirmed)
- Initial Access → Execution → Persistence → Privilege Escalation → Actions on Objectives
- Timeline with timestamps
- Affected systems/accounts

### 4. MITRE ATT&CK Matrix
- Map each finding to technique IDs
- Identify the kill chain coverage

### 5. Indicators of Compromise (IOCs)
- File hashes
- IP addresses / domains
- Registry keys
- Account names
- Service names

### 6. Remediation Plan
- Immediate containment (isolate, disable accounts)
- Eradication (remove persistence, delete malware)
- Recovery (restore from clean backup, reset credentials)
- Lessons learned (how to prevent recurrence)

## Rules

- This is a EXHAUSTIVE hunt — do not skip phases
- Use 30-day lookback for event logs (APTs operate slowly)
- Cross-reference findings across sources (process + network + logs)
- A single CRITICAL finding warrants full escalation
- Document everything — this report may be used for legal/HR actions
- Preserve evidence integrity — do not modify or delete anything
