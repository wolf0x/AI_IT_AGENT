---
name: "PhishingAnalysis"
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

If the sender looks suspicious, use threat intel tools to check the sender domain reputation:
```json
{"name": "TB_-_Domain_Analysis", "arguments": {"domain": "<sender_domain>"}}
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

### 3d. 🔴 Password-Protected Page Penetration (CRITICAL — NEW)
**Do NOT stop at HTTP 401/403 or password-protected pages.** A password gate is often used as a trust intermediary to hide the real phishing page behind it.

**When any URL returns 401/403 or a password dialog:**
1. Check if the email body or attachments contain a password
2. If a password is found, attempt to penetrate the gate:
   - Try `web_fetch` with POST body containing the password
   - Or use `browser_cdp` to simulate real browser interaction:
     ```json
     {"name": "browser_cdp", "arguments": {"action": "navigate", "url": "<password_protected_url>"}}
     ```
     Then type the password, submit, and track the redirect chain.
3. **Follow ALL redirects** to the final destination — do not stop at the first 200 OK
4. Analyze the **final** landing page, not the gate page

**If password cannot be penetrated:**
- Mark as "UNVERIFIED PASSWORD GATE → HIGH RISK" in the report
- Explicitly list it in the "Unverified Items" section

### 3e. 🟡 Hosted Platform Subdomain Detection (NEW)
Identify URLs using well-known hosting/building platforms as potential trust intermediaries:

| Platform | Pattern | Risk When... |
|----------|---------|-------------|
| Squarespace | `*.squarespace.com` | + email provides password |
| Wix | `*.wixsite.com` / `*.wix.com` | + commercial email context |
| Notion | `*.notion.site` | + no attachment, link-only |
| WordPress.com | `*.wordpress.com` | + password protected |
| Google Sites | `sites.google.com/*` | + redirects to external domain |
| Canva | `*.canva.com` | + file sharing redirect |

**Detection rule:** If the URL is a subdomain of a known hosting platform AND the email:
- Has no attachments (files shared via link)
- Provides a password in the body
- Has a commercial/business pretext

→ **Mark as HIGH SUSPICION — potential trust chain phishing**

### 3f. 🔴 Trust Chain Analysis (NEW — Phase 3.5)
This is a NEW analysis dimension that maps the trust relationship across all domains in the attack chain.

**Input:** Collect all domains in the chain:
- Sender domain (e.g., `hartsas.gr`)
- URL domain(s) (e.g., `hartsas.squarespace.com`)
- Final destination domain (e.g., `indlesmieux.com`)

**Cross-compare across these dimensions:**

| Dimension | What to check | Risk Signal |
|-----------|--------------|-------------|
| Domain age | Compare ages across the chain | Final domain much younger = 🚩 |
| Registrar | Same or different registrars | Different registrars with privacy proxy = 🚩 |
| Registrant info | Same or different owners | Different owners = 🚩 (trust break) |
| SSL cert dates | Compare cert issuance dates | Final domain cert issued same day as registration = 🚩 |
| Language/region | Geographic mismatch | Sender domain = Greece, final domain = unrelated = 🚩 |
| DNS infrastructure | Same or different providers | Final domain uses Cloudflare to hide origin = 🚩 |

**Weighted scoring for trust chain:**

| Pattern | Score |
|---------|-------|
| Final domain registered < 7 days before email | +3 |
| Final domain uses privacy proxy/WHOIS guard | +2 |
| Final domain hosted on Cloudflare/anti-bot CDN | +1 |
| Intermediate domain is a hosted platform subdomain | +2 |
| Intermediate domain + password gate | +3 |
| Domain registrant country differs from sender domain country | +1 |
| Sender domain age > 5 years BUT final domain < 30 days | +3 |

**Threshold:** Cumulative score ≥ +4 → mark as **PHISHING / LIKELY PHISHING** regardless of email authentication results.

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

### 5a. 🔴 "No Attachment, Link Only" Signal (NEW)
A critical behavioral signal that is often missed:
- Legitimate business emails with file sharing typically use **attachments** OR **known enterprise platforms** (SharePoint, OneDrive, Dropbox, Box)
- If the email is a commercial/business communication AND:
  - Has **no attachments**
  - Links to an **unusual hosting platform** (not enterprise-grade)
  - Provides a **password** in plain text
  - Uses urgency language

→ **Combine this signal with Phase 3.5 trust chain analysis for cumulative scoring**

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
- **🔴 Final destination domain** (after penetrating password gates and following redirects — NEW)

### 6b. Threat Intel Lookup
For high-priority IOCs, search threat intelligence:
```json
{"name": "TB_-_Domain_Analysis", "arguments": {"domain": "<suspicious_domain>"}}
{"name": "VT_-_Domain_Reputation", "arguments": {"domain": "<suspicious_domain>"}}
```

Check if any IOCs match known campaigns (e.g., Check Point, Proofpoint, CISA alerts).

### 6c. 🔴 Trust Chain IOC Mapping (NEW)
Present the full attack chain as a structured IOC map:

```
Sender Domain (hartsas.gr, 2003)
  → Intermediate Platform (hartsas.squarespace.com, password gate)
    → Final Phishing Domain (indlesmieux.com, 2026-07-21)
      → Credential Harvesting Page (fake Microsoft 365 login)
```

For each node in the chain, record:
- Domain name and registration date
- SSL certificate issuance date
- Hosting provider / CDN
- Registrant info (if not privacy-protected)
- Role in the attack chain

## Phase 7: Verdict and Report

### 🔴 REVISED Verdict Matrix — Cumulative Weighted Scoring

**CRITICAL RULE:** Authentication passing (SPF/DKIM/DMARC all pass) does NOT automatically clear an email. It only proves the email originated from the claimed domain. **The content and link chain must be independently evaluated.**

**Weighted scoring system:**

| Evidence | Direction | Weight |
|----------|-----------|--------|
| SPF/DKIM/DMARC all pass | → CLEAN | -3 |
| Sender domain age > 5 years | → CLEAN | -2 |
| Verified company entity with real registration | → CLEAN | -1 |
| No attachments, file shared via link | → SUSPICIOUS | +1 |
| Hosted platform subdomain (Squarespace/Wix/Notion) | → SUSPICIOUS | +2 |
| Password-protected page + password in email body | → SUSPICIOUS | +3 |
| Sender has no prior email history with recipient | → SUSPICIOUS | +1 |
| Commercial email using link instead of attachment | → SUSPICIOUS | +1 |
| Final domain registered < 7 days before email | → MALICIOUS | +3 |
| Final domain uses privacy proxy | → SUSPICIOUS | +2 |
| Final domain hosted on Cloudflare (hiding origin) | → SUSPICIOUS | +1 |
| Trust chain broken (intermediate ≠ final domain owner) | → MALICIOUS | +3 |
| Display name spoofing detected | → MALICIOUS | +3 |
| Credential harvesting page confirmed | → MALICIOUS | +5 |
| SPF/DKIM/DMARC all fail | → MALICIOUS | +3 |
| URL contains @ symbol or IP address | → MALICIOUS | +2 |

**Verdict by cumulative score:**

| Total Score | Verdict |
|-------------|---------|
| ≤ -3 | CLEAN |
| -2 to +2 | SUSPICIOUS (Low confidence) |
| +3 to +5 | LIKELY PHISHING (Medium confidence) |
| +6 to +8 | PHISHING (High confidence) |
| ≥ +9 | PHISHING (Very High confidence) |

**Important:** If the final destination domain is confirmed as a credential harvesting page (fake login form), **override everything** and mark as PHISHING regardless of score.

### 🔴 NEW: Unverified Items Section
BEFORE presenting the final verdict, the report MUST include a section titled **"Unverified Items"** that explicitly lists anything the analysis could not confirm:

| Unverified Item | Why Not Verified | Risk Impact |
|----------------|-----------------|-------------|
| Content behind password gate | Password not provided in email | 🔴 High — could contain phishing page |
| Final redirect destination | Did not follow redirect chain | 🔴 High — could lead to credential harvester |
| Sender's past email history | No historical data available | 🟡 Medium — new sender is higher risk |
| Domain registrant identity | Privacy proxy / WHOIS guard | 🟡 Medium — identity hidden |

**This section serves as a forcing function — if it has entries, the verdict should be more conservative.**

### Output Format

Present your final assessment as:

1. **Verdict**: PHISHING / MALWARE DELIVERY / LIKELY PHISHING / SUSPICIOUS / CLEAN
2. **Confidence**: Very High / High / Medium / Low
3. **Cumulative Score**: [numeric score] (from weighted system)
4. **Attack Type**: Credential Harvesting / Malware Delivery / BEC (Business Email Compromise) / Invoice Fraud / Romance Scam / Multi-Stage Trust Chain Phishing / Other
5. **MITRE ATT&CK**:
   - T1566.001 — Phishing: Spearphishing Attachment
   - T1566.002 — Phishing: Spearphishing Link
   - T1566.003 — Phishing: Spearphishing via Service
   - T1598 — Phishing for Information
6. **Executive Summary** (2-3 sentences)
7. **Key Indicators** (bullet list of the strongest evidence)
8. **🔴 Attack Chain Diagram** (NEW — show the full node-to-node flow):
   ```
   Sender → Intermediate Platform → Password Gate → Final Phishing Page
   ```
9. **🔴 Trust Chain Analysis** (NEW — cross-domain comparison table)
10. **🔴 Unverified Items** (NEW — what could not be checked)
11. **IOCs** (structured list for threat intel sharing)
    - Sender: email, domain, IP
    - URLs: all URLs with roles (initial / intermediate / final)
    - Attachments: filenames, hashes, content-types
    - Infrastructure: redirect domains, CDN providers, C2 IPs
    - Registrant: name, email, phone, address (if exposed)
12. **Recommended Actions**:
    - Block sender domain at email gateway
    - Block suspicious URLs/IPs at web proxy/firewall
    - Search mailbox for other emails from same sender across the organization
    - If attachment was opened: isolate host and run malware scan
    - If credentials were entered: force password reset immediately
    - Report to relevant authorities / anti-phishing working groups
    - 🔴 **NEW: If a legitimate company's email was compromised** → notify them via non-email channel (phone, website contact form)

## Rules

- NEVER open or execute email attachments directly — analysis is static only
- NEVER click phishing links from your own machine — use `web_fetch` (isolated) or `browser_cdp` (sandboxed) if needed
- ALWAYS preserve the original EML file as evidence
- If the email contains sensitive PII/credentials, note it but do NOT repeat the sensitive data in your response
- Cross-reference findings across all phases — a single indicator may be a false positive, but multiple correlated indicators confirm phishing
- Document everything — this report may be used for security awareness training
- 🔴 **CRITICAL: Authentication passes ≠ email is safe.** Always independently evaluate the link chain, especially when password-protected pages or hosted platform subdomains are involved.
- 🔴 **CRITICAL: Always attempt to penetrate password gates.** A password-protected page is a common trust intermediary used to bypass static URL analysis. Do not stop at HTTP 401.
- 🔴 **CRITICAL: If you cannot verify something, say so.** The "Unverified Items" section is mandatory. False certainty is more dangerous than admitting uncertainty.