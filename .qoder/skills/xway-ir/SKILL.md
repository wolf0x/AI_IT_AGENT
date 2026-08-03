---
name: xway-ir
description: Linux incident response via native ir_linux tool or Xway script. Use when investigating compromised Linux servers, lateral movement, mining infections, webshells, rootkits, or when the user mentions Linux IR, emergency response, or forensic triage on remote hosts.
---

# Linux IR - Incident Response

RustAgent provides **native Linux IR capabilities** via the `ir_linux` tool, plus the Xway IR script as an alternative.

## Native Tool: ir_linux (Recommended)

The `ir_linux` tool connects to remote Linux hosts via SSH and executes 45 detection modules.

### Usage

```
ir_linux {
    "target": "root@10.0.0.5",
    "modules": "all",           // or "1,2,10" for specific modules
    "auth_method": "key",       // or "password"
    "key_path": "~/.ssh/id_rsa",
    "severity_filter": "all"    // or "critical", "high", "medium"
}
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | ✅ | SSH target: `user@host` or `user@host:port` |
| `modules` | ❌ | Module IDs: `"1,2,10"` or `"all"` (default: all) |
| `auth_method` | ❌ | `"key"` (default) or `"password"` |
| `password` | ❌ | SSH password (if auth_method=password) |
| `key_path` | ❌ | Private key path (default: ~/.ssh/id_rsa) |
| `key_passphrase` | ❌ | Passphrase for encrypted key |
| `timeout_secs` | ❌ | Per-command timeout (default: 30) |
| `severity_filter` | ❌ | Filter: `"all"`, `"critical"`, `"high"`, `"medium"`, `"low"` |

### Output Structure

```json
{
    "status": "ok",
    "target": "root@10.0.0.5:22",
    "scan_duration_secs": 45,
    "modules_executed": 45,
    "risk_score": 76,
    "risk_level": "CRITICAL",
    "summary": {
        "critical": 3,
        "high": 5,
        "medium": 8,
        "low": 12,
        "total": 28
    },
    "lateral_movement": {
        "evidence_count": 4,
        "judgment": "ACTIVE_PIVOT",
        "findings": ["..."]
    },
    "findings": [
        {
            "module_id": 1,
            "module": "process_mining",
            "severity": "CRITICAL",
            "title": "Mining process detected: xmrig",
            "evidence": "root 1234 95.0 ... /tmp/.x11/xmrig",
            "score": 10
        }
    ]
}
```

### Module Categories

| Category | Modules | Detection |
|----------|---------|-----------|
| Process | 1, 31, 32 | Mining, hidden processes, deleted binaries |
| Network | 2, 35 | C2 ports, SSH/DNS/ICMP tunnels |
| Persistence | 3, 19, 21-23, 26 | Cron, systemd, udev, ld.so.preload |
| Rootkit | 4, 29 | LKM, preload backdoors |
| File | 5, 6, 9, 42 | SUID, recent changes, suspicious names |
| Web | 7, 11, 38-40 | Webshell, memory shell, dark links |
| Mining | 8 | Pool connections, config files |
| Lateral | 10, 43-45 | SSH keys, tools, history, logins |
| Auth | 12, 17 | Privilege escalation, suspicious accounts |
| Backdoor | 14-16, 20, 24-25 | LD_PRELOAD, alias, PAM, SSH, Python, kernel |
| BruteForce | 36-37 | SSH, MySQL, FTP, Redis |
| Integrity | 28, 30 | RPM/DEB verification, GPG |
| Config | 13, 27, 33-34, 41 | Container, ptrace, DNS, env, firewall |

## When to Use

- Linux server suspected of compromise (mining, webshell, rootkit)
- Lateral movement investigation (find pivot hosts)
- Emergency response triage before deep forensics
- Security incident scope assessment

## Prerequisites

- SSH access to target Linux host (key-based or password)
- Target runs Linux 2.6+ (CentOS/RHEL/Ubuntu/Debian/Kylin/UOS/Alpine)
- Root/sudo recommended for full coverage

## Risk Scoring

| Score | Level | Action |
|-------|-------|--------|
| ≥ 50 | 🔴 CRITICAL | Immediate isolation + full forensics |
| 30–49 | 🟠 HIGH | Respond within 24h |
| 15–29 | 🟡 MEDIUM | Review within 72h |
| 5–14 | 🟢 LOW | Routine inspection |
| < 5 | ⚪ INFO | No compromise detected |

## Lateral Movement Judgment

| Evidence Count | Judgment | Action |
|----------------|----------|--------|
| 0 | NO_EVIDENCE | Likely initial intrusion, not pivoting |
| 1-2 | SUSPICIOUS | Pull auth.log, check bash_history |
| 3-5 | LIKELY | Prepare isolation, audit connected hosts |
| ≥6 | ACTIVE_PIVOT | 🔴 Isolate immediately, memory dump, disk image |

## Example Workflows

### Quick Triage (Critical Modules Only)

```
ir_linux {
    "target": "root@10.0.0.5",
    "modules": "1,2,3,4,7,8,10",
    "severity_filter": "high"
}
```

### Full Scan

```
ir_linux {
    "target": "admin@192.168.1.100:2222",
    "modules": "all",
    "auth_method": "password",
    "password": "secret"
}
```

### Lateral Movement Focus

```
ir_linux {
    "target": "root@10.0.0.5",
    "modules": "10,43,44,45,36"
}
```

## Alternative: Xway Script

For environments where the native tool isn't suitable, deploy Xway IR script:

```bash
# Clone and deploy
git clone https://github.com/A4n9g7e2l/Xway.git /tmp/Xway
scp -r /tmp/Xway root@<TARGET>:/tmp/
ssh root@<TARGET> "cd /tmp/Xway && sudo bash xway_ir.sh --json-only"

# Retrieve results
scp root@<TARGET>:/tmp/Xway/output/*.jsonl ./evidence/
```

## Post-Scan SOP

1. **ISOLATE** (if score ≥30 or lateral evidence ≥3)
2. **PRESERVE** — memory dump (avml), process list, network state
3. **ANALYZE** — review findings, correlate with SIEM
4. **REMEDIATE** — kill processes, remove persistence, rotate credentials
5. **HARDEN** — disable password auth, deploy fail2ban, enable audit logging

## Limitations

- Read-only tool — does not remediate
- Keyword detection can miss obfuscated malware
- Advanced rootkits may hide from lsmod/proc
- Pair with: chkrootkit, rkhunter, ClamAV for deep analysis
