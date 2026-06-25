---
name: exchange-automation
description: >
  Exchange Online automation for mailbox reporting, archive monitoring, permissions audit (Send As / Full Access),
  and message trace. Use when user asks for Exchange Online PowerShell scripts, CSV exports, mailbox stats,
  archive issues, permission reporting, or message tracing (EOP/EXO).
argument-hint: "[task] [scope] [time range] [output path]"
user-invocable: true
disable-model-invocation: false
---

# Exchange Automation (EXO PowerShell) — Safe-by-default

## Core principles (MUST follow)
- Produce **production-ready** PowerShell: no pseudo-code, no “TODO”, no fake output.
- **Do not assume missing data**. If a field isn’t available, **leave it blank** and state “not available”.
- Prefer **read-only** cmdlets by default. Any destructive action must be explicitly requested and must include safeguards.
- Always output:
  1) a short plan,
  2) prerequisites,
  3) the script(s),
  4) example run commands,
  5) logging notes,
  6) rollback / how-to-undo (when applicable).

## Authentication & connectivity
- Use **ExchangeOnlineManagement (EXO V2)** module and `Connect-ExchangeOnline`.
- If user mentions “runbook”, “automation”, or “scheduled job”, propose Azure-hosted execution to avoid dependency conflicts.

## Tasks supported (choose based on request)
1. Mailbox size + archive status CSV report (user/shared/room).
2. Auto-expanding archive / archive enablement status checks (reporting only).
3. Permissions audit:
   - FullAccess (MailboxPermission)
   - SendAs (RecipientPermission)
   - SendOnBehalf (GrantSendOnBehalfTo on mailbox)
4. Shared mailbox access readiness checks (reporting only).
5. Message trace (Get-MessageTrace + Get-MessageTraceDetail) for specified time range.
6. “Delta monitoring” scripts: compare yesterday vs today report and flag threshold changes.

## Output format rules
- CSV exports must be consistent and stable across runs (fixed header ordering).
- Include `RunId` (GUID), `CollectedAtUtc`, and `Tenant`/`Org` if available; otherwise leave blank.
- Use `-ErrorAction Stop` + try/catch with clear error messages.
- Log to both console and a transcript file.

## Safety gates (MANDATORY)
- If user asks to delete/purge content, remove mail, or modify many objects:
  - require explicit confirmation phrase: "I AUTHORIZE DESTRUCTIVE ACTION"
  - add `-WhatIf` where supported
  - add `-Confirm:$true`
  - scope must be narrow (e.g., specific mailbox + date range)
  - produce a dry-run report first.

## Local resources
- Use scripts and templates stored alongside this skill:
  - [connect-exo.ps1](./scripts/connect-exo.ps1)
  - [export-mailbox-size.ps1](./scripts/export-mailbox-size.ps1)
  - [export-permissions.ps1](./scripts/export-permissions.ps1)
  - [trace-message.ps1](./scripts/trace-message.ps1)
  - [Mailbox size CSV header](./templates/report-mailbox-size.csv.header.txt)
  - [Permissions CSV header](./templates/report-permissions.csv.header.txt)