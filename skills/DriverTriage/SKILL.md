---
name: DriverTriage
description: "Static triage and reverse-engineering-lite analysis of suspicious Windows kernel drivers (.sys). Determines BYOVD process-kill capability via PE import analysis, device interface extraction, signature validation, and loldrivers DB matching. Use when an unknown driver needs risk assessment."
triggers:
  - "driver triage"
  - "analyze driver"
  - "suspicious .sys"
  - "driver analysis"
  - "kernel driver"
  - "driver reverse engineer"
  - "IOCTL analysis"
  - "driver risk"
  - "unknown driver"
  - "driver capability"
enabled: true
---

# Driver Static Triage

You are performing static triage of a suspicious Windows kernel driver (.sys file) to determine if it has BYOVD (Bring Your Own Vulnerable Driver) process-kill capability. This follows the methodology from BlackSnufkin/BYOVD research: import screening → device discovery → IOCTL surface analysis → risk scoring.

## When to Use

- BYOVDetection skill found a suspicious service without a hash match
- User provides a .sys file and asks "is this dangerous?"
- ir_driver flagged an unsigned/non-MS driver in a non-standard location
- Incident response: unknown driver found on a compromised host

## Step 1: Run Automated Triage

```json
{"name": "shell_exec", "arguments": {"command": "powershell -NoProfile -ExecutionPolicy Bypass -File <workspace>/tools/driver_triage.ps1 -FilePath '<target_sys_path>'", "timeout_secs": 60}}
```

The script outputs a JSON report with:
- `db_match` — loldrivers.io lookup (known = true → immediate critical)
- `signature` — Authenticode status, signer, expiry
- `import_analysis` — PE imports with BYOVD-critical flags
- `strings_analysis` — device names (\Device\, \DosDevices\)
- `risk_assessment` — score + level + reasons

## Step 2: Interpret Import Analysis

The KEY indicator from BlackSnufkin's methodology:

**A driver is a potential process-killer if it imports BOTH:**
- `ZwOpenProcess` or `NtOpenProcess` (open target process handle)
- `ZwTerminateProcess` or `NtTerminateProcess` (kill the process)

Additional risk amplifiers:
- `IoCreateDevice` + `IoCreateSymbolicLink` → exposes IOCTL interface to user-mode
- `MmMapLockedPagesSpecifyCache` → physical memory access (RW primitive)
- `KeStackAttachProcess` → process context manipulation (handle stripping)
- `ZwLoadDriver` / `NtLoadDriver` → can load additional drivers
- `ZwWriteVirtualMemory` → code injection capability

## Step 3: Device Interface Analysis

From `strings_analysis.device_names`:
- `\Device\<name>` — the kernel device object
- `\DosDevices\<name>` or `\\.<name>` — user-mode accessible path
- If present: any unprivileged process can open this device and send IOCTLs

Cross-reference with loaded drivers:
```json
{"name": "ir_driver", "arguments": {"category": "loaded"}}
```

Check if the device is currently active. If the driver is loaded AND has kill imports → active threat.

## Step 4: Signature Deep-Dive

If the driver is NOT in the loldrivers DB but has dangerous imports:

### Check certificate validity
- Expired certificate + dangerous imports = high suspicion (legitimate vendors renew)
- Revoked certificate = critical (vendor explicitly disavowed this binary)

### Check signer reputation
```json
{"name": "shell_exec", "arguments": {"command": "powershell -NoProfile -Command \"Get-AuthenticodeSignature '<path>' | Select-Object -ExpandProperty SignerCertificate | Format-List Subject,Issuer,SerialNumber,NotBefore,NotAfter,Thumbprint\"", "timeout_secs": 15}}
```

### Compare Imphash with DB (same-code-family detection)
If the triage script's DB match is negative but imphash matches → same codebase, different build/signing. This indicates a recompiled variant.

## Step 5: Manual RE Guidance (for analyst escalation)

If automated triage is inconclusive but suspicion remains high, document for human reverse engineer:

1. **Entry point**: DriverEntry → look for IoCreateDevice + MajorFunction[IRP_MJ_DEVICE_CONTROL] assignment
2. **IOCTL dispatch**: switch on IoGetCurrentIrpStackLocation→Parameters.DeviceIoControl.IoControlCode
3. **Vulnerable handler**: check if it validates caller privileges before acting on user-supplied PID
4. **Input buffer layout**: typically [padding(4)] [PID(4)] [padding(N)] — document exact offsets

Reference: BlackSnufkin/BYOVD TfSysMon walkthrough demonstrates the full chain:
`DeviceIoControl(\\.\TfSysMon, 0xB4A00404)` → IRP dispatch → IOCTL handler → PID from offset+4 → ZwTerminateProcess

## Step 6: Verdict and Actions

| Risk Level | Action |
|------------|--------|
| critical (score ≥100) | Known BYOVD. Block via WDAC hash rule. Report to loldrivers.io. Hunt for lateral spread. |
| high (score ≥60) | Probable BYOVD capability. Quarantine file. Create WDAC deny rule. Monitor for load attempts. |
| medium (score ≥30) | Suspicious. Restrict via HVCI. Investigate deployment context. |
| low (score <30) | Standard driver. Document and release. |

### WDAC Block Rule Template (for critical/high)
```xml
<Rule ID="ID_RULE_XXX" Type="Hash">
  <Conditions>
    <Condition Key="SHA256" Value="<sha256_hash>" />
  </Conditions>
</Rule>
```

### Microsoft Vulnerable Driver Blocklist
Check if already covered: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules

## Output Format

Always conclude with a structured verdict:
```
DRIVER TRIAGE VERDICT
=====================
File: <path>
SHA256: <hash>
Risk Level: <critical|high|medium|low> (score: <N>)
Known Threat: <yes/no — loldrivers match>
Kill Capability: <yes/no — OpenProcess+TerminateProcess>
Device Exposure: <device names or "none">
Signature: <valid/expired/revoked/unsigned>
Signer: <subject>
Recommendation: <action>
```
