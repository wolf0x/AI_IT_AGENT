---
name: "PcapAnalysis"
description: "PCAP network traffic analysis workflow: parse packet captures, detect suspicious patterns (C2 beacons, DNS tunneling, port scans, lateral movement), extract IOCs, and generate a visual HTML threat report with AI-powered narrative assessment."
triggers:
  - "pcap"
  - "pcap analysis"
  - "packet capture"
  - "network traffic"
  - "traffic analysis"
  - "网络流量分析"
  - "抓包分析"
  - "流量分析"
  - "pcap report"
  - "network forensics"
  - "网络取证"
  - "C2 detection"
  - "DNS tunnel"
  - "beacon detection"
  - "suspicious traffic"
  - "异常流量"
---

# PCAP Network Traffic Analysis Workflow

You are performing a structured PCAP network traffic analysis for incident response. Follow these phases IN ORDER. Do not skip phases.

## Phase 1: Parse the Capture

Call `ir_pcap_analyze` to extract all structured data from the pcap file:

```json
{"name": "ir_pcap_analyze", "arguments": {"file_path": "<path_to_pcap_file>"}}
```

Review the output carefully. The tool returns:
- `summary`: total packets, bytes, duration, protocol distribution (TCP/UDP/ICMP/other), IPv4/IPv6 counts
- `top_talkers`: top 10 IPs by bytes (ip, packets, bytes)
- `top_ports`: top 15 destination ports by packets (port, service, packets)
- `top_flows`: top 20 flows by bytes (src:port, dst:port, proto, packets, bytes)
- `dns_queries`: top 30 DNS queries by count (name, type, count)
- `http_requests`: top 30 HTTP requests by count (method, host, path, count)
- `suspicious`: up to 200 suspicious port detections (type, detail, src, dst)
- `hourly_distribution`: packet count per hour

## Phase 2: Statistical Anomaly Detection

Analyze the raw data for patterns that the tool's basic detection misses:

### 2a. DNS Tunnel Detection
Examine `dns_queries` for tunneling indicators:
- **Long subdomain names**: Calculate average subdomain character count. Normal DNS queries average <15 chars. If avg >30 chars → likely DNS tunnel
- **High query volume to single domain**: >100 queries to the same base domain in a short period
- **TXT record queries**: DNS tunneling often uses TXT records for data exfiltration
- **Base64-like patterns**: Subdomains containing only alphanumeric chars with length >20

Flag as: `DNS_TUNNEL_SUSPECTED` with evidence.

### 2b. C2 Beacon Detection
Examine `top_flows` for beacon patterns:
- **Persistent connections**: Single flow lasting >1 hour with regular packet intervals
- **Periodic callbacks**: Multiple flows to the same external IP at regular intervals
- **Small consistent payloads**: Flows with similar byte counts (beacon heartbeat)
- **Known C2 ports**: 4444 (Metasploit), 5555, 6666, 8888, 12345, 31337

Flag as: `C2_BEACON_SUSPECTED` with IP, port, and duration.

### 2c. Port Scan Detection
Examine `top_talkers` and `top_flows` for scanning:
- **Single source → many destinations**: One IP connecting to many different IPs on the same port
- **Single source → many ports**: One IP connecting to many different ports on the same destination
- **ICMP sweep**: High ICMP packet count from single source (>50 packets)
- **Short-lived connections**: Flows with 1-3 packets only (SYN scan)

Flag as: `PORT_SCAN_DETECTED` or `ICMP_SWEEP_DETECTED`.

### 2d. Data Exfiltration Indicators
Examine `top_flows` for exfiltration:
- **Large outbound transfers**: Internal IP sending >10MB to single external IP
- **Unusual protocols**: Large transfers over DNS (port 53) or ICMP
- **After-hours activity**: Large transfers during non-business hours (check `hourly_distribution`)
- **Asymmetric flows**: High outbound bytes, low inbound bytes (upload pattern)

Flag as: `DATA_EXFIL_SUSPECTED` with source, destination, and volume.

### 2e. Lateral Movement Indicators
Examine `top_flows` for lateral movement:
- **RDP from external**: Port 3389 connections from external (non-RFC1918) IPs
- **SMB from unexpected sources**: Port 445 connections from unusual internal hosts
- **WinRM/PowerShell Remoting**: Port 5985/5986 connections
- **Sequential internal scanning**: Same source hitting multiple internal IPs on admin ports

Flag as: `LATERAL_MOVEMENT_SUSPECTED`.

## Phase 3: Threat Classification

For each finding from Phase 2, assign a severity and classification:

| Severity | Criteria |
|----------|----------|
| **CRITICAL** | Active C2 channel, confirmed data exfiltration, known malware port with sustained traffic |
| **HIGH** | DNS tunneling, Tor proxy usage, webshell callback, backdoor listener |
| **MEDIUM** | Port scan, ICMP sweep, RDP from external, suspicious HTTP callbacks |
| **LOW** | Unusual port usage with low volume, after-hours normal traffic |

### 3a. Port Risk Assessment
Map each suspicious port to threat category:

| Port | Likely Service | Threat Level |
|------|---------------|--------------|
| 4444 | Metasploit handler | CRITICAL |
| 5555 | ADB/backdoor | HIGH |
| 6666/6667 | IRC (C2 channel) | HIGH |
| 8888 | HTTP-alt/backdoor | MEDIUM |
| 9050/9051 | Tor SOCKS | HIGH |
| 12345 | NetBus backdoor | CRITICAL |
| 27374 | SubSeven backdoor | CRITICAL |
| 31337 | Back Orifice/eleet | CRITICAL |
| 1234 | Stargate backdoor | HIGH |
| 3128 | Squid proxy | MEDIUM |
| 1080 | SOCKS proxy | MEDIUM |

### 3b. Service Name Enhancement
The tool's `port_to_service()` provides basic lookup. Enhance with threat context:
- If port 4444 has sustained traffic → label as "Metasploit C2" not just "unknown"
- If port 9050 has traffic → label as "Tor SOCKS Proxy"
- If port 8080 has POST requests to `/gate.php` or `/cmd` → label as "Webshell Callback"

## Phase 4: IOC Extraction

Compile all IOCs from the analysis into structured categories:

### 4a. Malicious IPs
Extract from:
- `suspicious` entries where dst is external (non-RFC1918, non-reserved)
- `top_talkers` flagged in Phase 2 findings
- `top_flows` with CRITICAL/HIGH classifications

### 4b. Malicious Domains
Extract from:
- `dns_queries` flagged as DNS tunnel targets
- `http_requests` to suspicious hosts
- Base domains from DNS tunnel subdomains

### 4c. Suspicious Ports
List all ports from `suspicious` entries with their threat classification.

### 4d. Suspicious URLs/Paths
Extract from `http_requests`:
- POST requests to unusual paths (`/gate.php`, `/cmd`, `/upload`, `/beacon`)
- Requests to IP addresses instead of domain names
- Requests with encoded parameters (possible C2 protocol)

## Phase 5: AI Threat Narrative

Generate a comprehensive threat assessment narrative that:

### 5a. Executive Summary (2-3 sentences)
State the overall finding: Is the host compromised? What is the attack stage?

### 5b. Attack Timeline
Reconstruct the attack chronology using `hourly_distribution` and flow timing:
- When did suspicious activity begin?
- What was the progression? (recon → access → C2 → exfil → lateral movement)
- When was peak activity?

### 5c. Kill Chain Mapping
Map findings to MITRE ATT&CK:

| Finding | MITRE Technique |
|---------|----------------|
| Port scan / ICMP sweep | T1046 Network Service Discovery |
| C2 beacon | T1071 Application Layer Protocol |
| DNS tunnel | T1071.004 DNS |
| HTTP callback | T1071.001 Web Protocols |
| Data exfiltration | T1048 Exfiltration Over Alternative Protocol |
| Tor usage | T1090 Proxy |
| RDP lateral movement | T1021.001 Remote Desktop Protocol |
| Credential theft (HTTP auth) | T1528 Steal Application Access Token |
| Webshell | T1505.003 Web Shell |

### 5d. Recommended Actions
Provide prioritized remediation steps:
1. **IMMEDIATE**: Isolate compromised hosts, block malicious IPs at firewall
2. **SHORT-TERM**: Sinkhole malicious domains, scan for lateral movement
3. **MEDIUM-TERM**: Review authentication logs, reset potentially compromised credentials
4. **LONG-TERM**: Implement network segmentation, deploy IDS signatures for detected IOCs

## Phase 6: HTML Report Generation

Generate a self-contained HTML report file using the dark glassmorphism theme.

### 6a. Report Structure
The HTML report must include these sections in order:

1. **Header**: Case ID, file name, analyst (RustAgent), generation timestamp
2. **Capture Overview**: 4 stat cards (total packets, duration, unique flows, suspicious events)
3. **Protocol Distribution**: Donut chart (CSS conic-gradient) + hourly bar chart
4. **Top Talkers & Ports**: Two side-by-side tables with risk badges
5. **Suspicious Activity Timeline**: Severity-coded timeline with colored markers
6. **DNS Queries & HTTP Requests**: Two side-by-side tables with risk classification
7. **Top Network Flows**: Full flow table with duration and risk
8. **Indicators of Compromise**: Three cards (Malicious IPs, Domains, Ports) as badge pills
9. **AI Threat Assessment**: Narrative card with executive summary, kill chain, recommendations

### 6b. Theme Specification
Use the dark glassmorphism CSS theme:

```css
:root {
  --bg: #0f1117;
  --surface: #1a1d27;
  --surface2: #22263a;
  --border: rgba(255,255,255,.06);
  --t1: #e8eaed;    /* Primary text */
  --t2: #9aa0a6;    /* Secondary text */
  --t3: #5f6368;    /* Tertiary text */
  --purple: #7c5cfc;  /* Accent */
  --cyan: #13c2c2;    /* IPs, links */
  --green: #34a853;   /* Low/normal */
  --yellow: #fbbc04;  /* Medium */
  --orange: #fa7b17;  /* High */
  --red: #ea4335;     /* Critical */
  --mono: 'Cascadia Code','Fira Code','JetBrains Mono', monospace;
}
```

### 6c. Badge Classes
```css
.badge-critical { background: rgba(234,67,53,.15); color: var(--red); border: 1px solid rgba(234,67,53,.3); }
.badge-high     { background: rgba(250,123,23,.15); color: var(--orange); border: 1px solid rgba(250,123,23,.3); }
.badge-medium   { background: rgba(251,188,4,.15); color: var(--yellow); border: 1px solid rgba(251,188,4,.3); }
.badge-low      { background: rgba(52,168,83,.15); color: var(--green); border: 1px solid rgba(52,168,83,.3); }
.badge-info     { background: rgba(19,194,194,.1); color: var(--cyan); border: 1px solid rgba(19,194,194,.2); }
```

### 6d. IOC Badge Styles
```css
.ioc.ip     { background: rgba(19,194,194,.08); border-color: rgba(19,194,194,.2); color: var(--cyan); }
.ioc.domain { background: rgba(250,123,23,.08); border-color: rgba(250,123,23,.2); color: var(--orange); }
.ioc        { background: rgba(234,67,53,.08); border: 1px solid rgba(234,67,53,.2); color: var(--red); }
```

### 6e. Timeline Styles
```css
.timeline::before { background: linear-gradient(180deg, var(--red), var(--orange), var(--yellow), var(--t3)); }
.tl-item.critical::before { background: var(--red); box-shadow: 0 0 8px rgba(234,67,53,.5); }
.tl-item.high::before     { background: var(--orange); box-shadow: 0 0 8px rgba(250,123,23,.4); }
.tl-item.medium::before   { background: var(--yellow); }
```

### 6f. Output File
Save the report to the output directory:
```
output/pcap_report_<CASE_ID>_<TIMESTAMP>.html
```

Use `shell_exec` to write the file:
```json
{"name": "shell_exec", "arguments": {"command": "Set-Content -Path '<output_path>' -Value '<html_content>' -Encoding UTF8"}}
```

Or use file write if available.

### 6g. Open Report
After generation, open the report in the default browser:
```json
{"name": "shell_exec", "arguments": {"command": "Start-Process '<output_path>'"}}
```

## Phase 7: Summary and Next Steps

After generating the HTML report, provide a text summary to the user:

1. **Verdict**: COMPROMISED / SUSPICIOUS / CLEAN / INCONCLUSIVE
2. **Confidence**: Very High / High / Medium / Low
3. **Key Findings**: Bullet list of the top 3-5 most critical findings
4. **IOCs**: Quick-reference list of malicious IPs, domains, ports
5. **Report Location**: Full path to the generated HTML report
6. **Recommended Next Steps**:
   - If COMPROMISED: Immediate isolation steps
   - If deeper analysis needed: Suggest opening the pcap in PacketLens or Wireshark for byte-level inspection
   - If TLS decryption needed: Guide user to obtain SSLKEYLOGFILE

## Rules

- NEVER modify or delete the original pcap file — it is evidence
- ALWAYS preserve the full IOC list for threat intel sharing
- If the capture contains sensitive data (credentials, PII), note it but do NOT repeat in plain text
- Cross-reference findings across phases — a single suspicious port may be benign, but combined with DNS tunneling and C2 beacon patterns confirms compromise
- The HTML report must be self-contained (no external CSS/JS dependencies)
- Use monospace font for all IPs, ports, domains, and hashes in the report
- If the pcap is very large (>100MB), note that PacketLens or Wireshark may be needed for packet-level inspection
- Document the analysis limitations: `ir_pcap_analyze` provides statistical summary, not byte-level inspection or TLS decryption
