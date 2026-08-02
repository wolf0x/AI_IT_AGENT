---
name: BYOVDetection
description: "Post-incident BYOVD (Bring Your Own Vulnerable Driver) detection and attribution. Scans loaded drivers, disk files, kernel services, and event logs against the loldrivers.io threat intelligence database to identify exploited vulnerable drivers."
triggers:
  - "byovd"
  - "vulnerable driver"
  - "driver attack"
  - "kernel exploit"
  - "loldrivers"
  - "driver blocklist"
  - "T1068"
  - "bring your own"
  - "driver load attack"
  - "EDR bypass"
  - "AV killer"
enabled: true
---

# BYOVD Post-Incident Detection

You are performing post-incident forensic detection of BYOVD (Bring Your Own Vulnerable Driver) attacks. BYOVD attacks load a known-vulnerable signed driver to gain kernel execution, then abuse it (typically via IOCTL) to terminate security products or escalate privileges. MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation).

## Prerequisites

The detection scripts must be staged in the workspace:
- `tools/byovd_scan.ps1` — main collector (hash matching + service audit + event correlation)
- `tools/byovd_db.json` — loldrivers.io hash database (2185+ entries)
- `tools/driver_triage.ps1` — static PE triage for unknown drivers

If `byovd_db.json` is missing or outdated (>30 days), regenerate it:
```json
{"name": "shell_exec", "arguments": {"command": "python <workspace>/tools/byovd_db_extract.py <workspace>/tools/byovd_db.json", "timeout_secs": 120}}
```

## Step 1: Run Full BYOVD Scan

Execute the collector via external_exec for proper timeout and ExecutionPolicy handling:

```json
{"name": "ext_byovd_scan", "arguments": {"timeout_secs": 180}}
```

If ext_byovd_scan is not registered (script not in tools/), fall back to shell_exec:
```json
{"name": "shell_exec", "arguments": {"command": "powershell -NoProfile -ExecutionPolicy Bypass -File <workspace>/tools/byovd_scan.ps1 -OutputDir <workspace>/output", "timeout_secs": 180}}
```

The scan performs 4 phases:
1. **Loaded driver hash matching** — driverquery enumeration → SHA256 → DB lookup
2. **Non-standard path file scan** — Temp/Downloads/Public/AppData/ProgramData for .sys files
3. **Kernel service registry audit** — HKLM Services Type=1 with non-standard ImagePath
4. **Event 7045 correlation** — kernel driver installs in last 30 days with hash cross-check

## Step 2: Interpret Results

Parse the stdout JSON summary. Key fields:
- `findings_count > 0` → **confirmed BYOVD activity**, proceed to Step 3
- `suspicious_services_count > 0` → services with non-standard paths, investigate even without hash match
- `kernel_driver_installs_30d` → timeline of driver installations

For full details, read the result file:
```json
{"name": "file_read", "arguments": {"path": "<workspace>/output/byovd_result.json"}}
```

## Step 3: Confirmed Hit — Deep Attribution

When a hash match is found, establish the attack timeline:

### 3a. File delivery time
```json
{"name": "ir_usn", "arguments": {"action": "query", "path_filter": "<matched_filename>", "reason_filter": "create"}}
```

### 3b. Service installation event
```json
{"name": "ir_eventlog", "arguments": {"category": "custom", "log_name": "System", "event_ids": "7045,7036,7040", "days": 30}}
```

### 3c. Process context (who loaded it)
```json
{"name": "ir_eventlog", "arguments": {"category": "custom", "log_name": "Security", "event_ids": "4688", "days": 7, "max_events": 500}}
```
Look for: sc.exe create/start commands, or the parent process that dropped the .sys file.

### 3d. Sysmon DriverLoaded (if Sysmon deployed)
```json
{"name": "ir_eventlog", "arguments": {"category": "sysmon", "days": 30}}
```
Event ID 6 (DriverLoaded) shows the exact load time and hash.

### 3e. Shadow copy comparison (was the file present before?)
```json
{"name": "ir_vss", "arguments": {"action": "list"}}
```

## Step 4: Unknown Suspicious Driver — Triage

If `suspicious_services` contains entries WITHOUT hash matches, triage the driver file:

```json
{"name": "shell_exec", "arguments": {"command": "powershell -NoProfile -ExecutionPolicy Bypass -File <workspace>/tools/driver_triage.ps1 -FilePath '<suspicious_driver_path>'", "timeout_secs": 60}}
```

This performs:
- SHA256/MD5 + DB matching
- Authenticode signature validation + expiry check
- PE import table analysis (ZwOpenProcess + ZwTerminateProcess = kill capability)
- Device name string extraction (\Device\, \DosDevices\)
- Risk scoring (critical/high/medium/low)

If risk_level is "high" or "critical" but NOT in the DB → this may be a **new/unknown BYOVD driver**. Report it with full metadata for threat intel submission.

## Step 5: Generate IOC Report

Compile findings into a structured report:

```json
{"name": "ir_report", "arguments": {"format": "markdown"}}
```

The report MUST include:
- **IOC table**: SHA256, MD5, filename, file path, service name, device name
- **Timeline**: file creation → service install → driver load → (abuse) → cleanup attempt
- **MITRE mapping**: T1068 (Privilege Escalation), T1562.001 (Impair Defenses: Disable AV/EDR)
- **Affected driver metadata**: vendor, product, CVE, certificate info
- **Recommendations**: WDAC block rule (by hash), driver blocklist update, HVCI enforcement

## Interpretation Guide

| Finding | Severity | Meaning |
|---------|----------|---------|
| loaded_driver + hash match | CRITICAL | Vulnerable driver is ACTIVE in kernel right now |
| file_scan + hash match | HIGH | Driver file on disk (may be dormant or cleaned) |
| service_registry + hash match | CRITICAL | Service configured to load vulnerable driver |
| event_7045 + hash match | HIGH | Historical evidence of driver installation |
| suspicious_service (no match) | MEDIUM | Non-standard driver path, needs triage |

## False Positive Awareness

- Some legitimate software ships vulnerable drivers (e.g., old GPU utilities, RGB controllers)
- Check: is the driver's parent software still installed? Is the service running?
- A driver in System32\drivers with a valid MS-attestation signature is almost certainly FP
- Focus on: non-standard paths, recently created services, expired certificates
