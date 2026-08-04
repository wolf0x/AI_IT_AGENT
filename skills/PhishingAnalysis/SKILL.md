---
name: PhishingAnalysis
description: "Phishing email analysis workflow: parse EML files, extract headers and IOCs, analyze URLs and attachments, check sender reputation, evaluate spoofing indicators, and produce a structured phishing verdict report."
triggers:
  - "phishing"
  - "phishing email"
  - "suspicious email"
  - "email analysis"
  - "eml"
  - "邮件钓鱼"
  - "钓鱼邮件"
  - "邮件分析"
  - "spam"
  - "social engineering"
  - "credential harvesting"
  - "brand spoofing"
  - "email header analysis"
  - "malicious attachment"
  - "BEC"
  - "business email compromise"
enabled: true
---

# Phishing Email Analysis Workflow

You are performing a structured phishing email analysis. Follow these phases IN ORDER. Do not skip phases.

## Phase 1: Parse the Email

Call `ir_eml` to parse the EML file and extract all structured data:

```json
{"name": "ir_eml", "arguments": {"path": "<path_to_eml_file>", "extract_urls": true}}
```

Review the output carefully. Note the `phishing_indicators` section — it already contains automated risk assessment.

## Phase 2: Sender Analysis

Examine the sender information for spoofing:

### 2a. From Address Verification
- Does the **display name** match the **email domain**? (e.g., "Microsoft Support" from `@gmail.com` = spoofed)
- Is the domain a **free email provider** pretending to be a corporate entity?
- Check for **homograph domains** (e.g., `micros0ft.com`, `paypa1.com`, `arnazon.com`)
- Is the domain **newly registered** or known for abuse?

### 2b. Reply-To and Return-Path
- Does `Reply-To` differ from `From`? (common in BEC attacks)
- Does `Return-Path` differ from `From`? (indicates the real sending server)
- Is `X-Originating-IP` present? Note it for geolocation lookup.

### 2c. Authentication Check
- Check `Authentication-Results` header for:
  - `spf=pass/fail/softfail` — did the sending server authorize this domain?
  - `dkim=pass/fail` — was the message signed and verified?
  - `dmarc=pass/fail` — did domain alignment pass?
- If `Authentication-Results` is missing, note it — the email may have bypassed gateway filtering.

### 2d. Received Hop Analysis
- Trace the `received_hops` from bottom (origin) to top (destination)
- Does the first hop's IP match the claimed sender domain?
- Are there unexpected relay servers?

If the sender looks suspicious, use `web_search` to check the sender domain reputation:
```json
{"name": "web_search", "arguments": {"query": "<sender_domain> phishing scam reputation"}}
```

## Phase 3: URL Analysis

Review all URLs extracted by `ir_eml` from the `urls.suspicious` section.

### 3a. URL Destination Verification
For each suspicious URL, use `web_fetch` to check the landing page (if safe to do so):
```json
{"name": "web_fetch", "arguments": {"url": "<suspicious_url>"}}
```

Look for:
- **Credential harvesting pages** — login forms mimicking Microsoft 365, Google, PayPal, banks
- **Malware download pages** — auto-download executables or archives
- **Redirect chains** — URL redirects through multiple domains before landing page
- **Brand impersonation** — logos, language, and layout mimicking legitimate services

### 3b. URL-Display Mismatch
- Does the visible link text differ from the actual URL? (HTML anchor spoofing)
- Does the URL contain `@` symbols? (e.g., `https://legitimate.com@evil.com/path`)
- Are there excessive subdomains? (e.g., `login.microsoft.evil.com`)
- Does the URL use an IP address instead of a domain name?

### 3c. Short URL Expansion
If URL shorteners are detected (bit.ly, tinyurl.com, etc.), resolve them:
```json
{"name": "web_fetch", "arguments": {"url": "<shortened_url>"}}
```
Note the final destination domain.

## Phase 4: Attachment Analysis

Review the `attachments` section from `ir_eml` output.

### 4a. Suspicious Extensions
Flag any attachments with:
- Executable: `.exe`, `.scr`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.wsf`, `.hta`, `.cpl`, `.msi`, `.dll`, `.com`, `.pif`
- Document macros: `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx` (may contain macros)
- Archive files: `.zip`, `.rar`, `.7z` (may contain executables)
- **Double extensions**: `invoice.pdf.exe`, `report.doc.scr`

### 4b. Deep Malware Analysis
If a suspicious attachment is present and saved locally, run deep analysis:
```json
{"name": "malware_deep", "arguments": {"path": "<extracted_attachment_path>"}}
```

### 4c. Nested Messages
If `is_nested_message` is true in any attachment, parse the nested email:
- Check if the nested message contains additional phishing indicators
- Note the nested message's From/To/Subject for the report

## Phase 5: Social Engineering Assessment

Evaluate the email body (from `body.text` and `body.html`) for social engineering tactics:

| Tactic | Indicators |
|--------|-----------|
| **Urgency** | "immediate action required", "your account will be suspended", "within 24 hours" |
| **Authority** | Impersonating CEO, IT department, HR, bank, government agency |
| **Fear** | "unauthorized transaction", "account compromised", "legal action" |
| **Curiosity** | "see attached invoice", "your order confirmation", "payment receipt" |
| **Greed** | "you've won", "refund pending", "tax return" |
| **Trust** | Uses real company logos, correct branding, professional formatting |

Count the urgency indicators detected by `ir_eml` in `phishing_indicators`. If 3+ are triggered, flag as high social engineering risk.

## Phase 6: IOCs and Threat Intel

### 6a. Compile IOCs
From the `ir_eml` output, compile all IOCs into a structured list:
- **Sender email** and domain
- **Reply-To** address (if different)
- **Return-Path** domain
- **X-Originating-IP** (if present)
- **All URLs** (especially suspicious ones)
- **Attachment hashes** (if analyzed with malware_deep)
- **Sender domain** and any redirect domains

### 6b. Threat Intel Lookup
For high-priority IOCs, search threat intelligence:
```json
{"name": "web_search", "arguments": {"query": "<suspicious_domain_or_ip> malware phishing threat intelligence"}}
```

Check if any IOCs match known campaigns (e.g., Check Point, Proofpoint, CISA alerts).

## Phase 7: Verdict and Report

### Verdict Matrix

| Evidence | Verdict |
|----------|---------|
| SPF/DKIM/DMARC all fail + spoofed domain + credential harvesting URL | **PHISHING** (High confidence) |
| Display name spoof + suspicious URL + urgency language | **PHISHING** (High confidence) |
| Suspicious attachment with malicious macros | **MALWARE DELIVERY** (High confidence) |
| SPF fail + suspicious URL but no clear brand spoofing | **LIKELY PHISHING** (Medium confidence) |
| Minor indicators only (e.g., urgency language from legitimate sender) | **SUSPICIOUS** (Low confidence) |
| All authentication passes, no suspicious indicators | **CLEAN** |

### Output Format

Present your final assessment as:

1. **Verdict**: PHISHING / MALWARE DELIVERY / LIKELY PHISHING / SUSPICIOUS / CLEAN
2. **Confidence**: High / Medium / Low
3. **Attack Type**: Credential Harvesting / Malware Delivery / BEC (Business Email Compromise) / Invoice Fraud / Romance Scam / Other
4. **MITRE ATT&CK**:
   - T1566.001 — Phishing: Spearphishing Attachment
   - T1566.002 — Phishing: Spearphishing Link
   - T1566.003 — Phishing: Spearphishing via Service
   - T1598 — Phishing for Information
5. **Executive Summary** (2-3 sentences)
6. **Key Indicators** (bullet list of the strongest evidence)
7. **IOCs** (structured list for threat intel sharing)
   - Sender: email, domain, IP
   - URLs: all suspicious URLs with reasons
   - Attachments: filenames, hashes, content-types
   - Infrastructure: redirect domains, C2 IPs
8. **Recommended Actions**:
   - Block sender domain at email gateway
   - Block suspicious URLs/IPs at web proxy/firewall
   - Search mailbox for other emails from same sender across the organization
   - If attachment was opened: isolate host and run malware scan
   - If credentials were entered: force password reset immediately
   - Report to relevant authorities / anti-phishing working groups

## Rules

- NEVER open or execute email attachments directly — analysis is static only
- NEVER click phishing links from your own machine — use `web_fetch` (isolated) if needed
- ALWAYS preserve the original EML file as evidence
- If the email contains sensitive PII/credentials, note it but do NOT repeat the sensitive data in your response
- Cross-reference findings across all phases — a single indicator may be a false positive, but multiple correlated indicators confirm phishing
- Document everything — this report may be used for security awareness training
