**[English](#)** | **[中文](README.md)**

# RustAgent

An AI-powered assistant platform for local IT system engineers — focused on system analysis, log investigation, and incident response. Fully local, single-binary deployment with WebSocket gateway, multi-model support, 34+ built-in tools, permission control, persistent memory, and task scheduling. Designed for Windows, ready out of the box.

## Positioning

RustAgent is built specifically for local IT system engineers, addressing the three most time-consuming areas of daily operations: **system status analysis**, **log investigation & root cause tracing**, and **security incident response**.

In traditional workflows, engineers constantly switch between tools — Event Viewer for logs, PowerShell for processes, Registry Editor for configurations, netstat for connections — manually correlating clues across each. RustAgent unifies these capabilities into a single AI Agent: engineers describe symptoms in natural language, the Agent orchestrates the toolchain automatically, collects system state, retrieves relevant logs, correlates anomalies, and delivers structured investigation reports with remediation recommendations.

**Typical Scenarios**:

- **Log Investigation**: *"What errors and warnings are in the system logs from the last 24 hours? Organize them on a timeline."* — The Agent automatically invokes event log tools, filters by severity level, sorts chronologically, and correlates with related process and service states
- **System Analysis**: *"Which processes are consuming excessive resources right now? Check their launch origins."* — The Agent orchestrates process enumeration + resource usage analysis + Autoruns persistence detection to deliver a complete process chain analysis
- **Security Investigation**: *"Check if this machine has any persistence backdoors installed."* — The Agent chains registry auditing, scheduled task enumeration, service enumeration, and Autoruns detection to produce a comprehensive persistence attack surface report
- **Fault Diagnosis**: *"Service XXX failed to start, help me find out why."* — The Agent queries service status, correlates event logs, checks dependent services, and analyzes configuration files to pinpoint the root cause

**Why Fully Local**: Logs, process information, and registry data that IT engineers handle often contain sensitive internal network topology and credential information. RustAgent's AI conversation engine, tool execution, and data storage all run locally. API keys are encrypted with AES-256-GCM at rest. Only LLM inference requests are sent to the cloud model — raw system data never leaves the machine.

A single Rust binary (~28MB) contains the complete AI conversation engine, tool execution layer, WebSocket gateway, and Web Dashboard — no additional runtime or external service dependencies required. Inspired by Google ADK's Agent → LlmAgent → EventStream architecture pattern, implementing a full Agentic Loop within the Rust ecosystem.

## Core Architecture

```
┌─────────────────────────────────────────────────┐
│                  Dashboard SPA                   │
│        (Chat / Skills / MCP / CRON / ...)       │
└──────────────────────┬──────────────────────────┘
                       │ WebSocket / HTTP
┌──────────────────────┴──────────────────────────┐
│              Axum 0.8 Server                     │
│         (REST API + WS Gateway + SSE)           │
├─────────────────────────────────────────────────┤
│  Runner → LlmAgent (Agentic Loop)               │
│    ├── Agent trait → EventStream (9 event types)│
│    ├── CJK-aware token budget history trimming  │
│    ├── Re-prompt detection & self-healing       │
│    └── Truncated JSON repair                    │
├─────────────────────────────────────────────────┤
│  Tool Layer                                      │
│    ├── 34+ Built-in Tools                        │
│    ├── MCP Client (stdio + SSE)                 │
│    ├── Skill Manager (weighted scoring)          │
│    └── External Tools (workspace/tools/)         │
├─────────────────────────────────────────────────┤
│  Infrastructure                                  │
│    ├── Memory (SQLite + FTS5)                    │
│    ├── Permission (category gates + async)       │
│    ├── Scheduler (CRON + interval)               │
│    ├── Checkpoint (crash recovery)               │
│    ├── Crypto (AES-256-GCM)                      │
│    └── Knowledge Distillation                    │
└─────────────────────────────────────────────────┘
```

## Core Capabilities

### Permission System

RustAgent implements a Category-based Gates permission model, rather than a simple allow/deny binary judgment:

- **Five permission categories**: read / write / delete / modify / execute — each tool call declares its required permission category
- **Async user authorization**: When the Agent requests high-privilege operations, it pushes an authorization request to the Dashboard via WebSocket. The user confirms through the UI, and the result is returned via a oneshot channel — the Agent loop waits without blocking
- **Shell dangerous command interception**: ShellExecTool has a built-in blacklist (Remove-Item, del, rm, rmdir, format, erase, etc.) that blocks at the tool execution layer, without relying on LLM judgment
- **Three-layer permission bypass defense**: (1) Hard-reject error messages prevent fallback to alternative tools (2) Permission Denial Rules injected into System Prompt (3) Shell-layer pattern matching as a final safety net

### Memory System

Dual-layer memory architecture balancing real-time retrieval with long-term investigation experience accumulation — insights gathered during each investigation are distilled into reusable knowledge, automatically referenced when similar issues arise:

**SQLite + FTS5 Conversational Memory**
- 4-layer schema evolution: basic conversations → FTS5 full-text index → checkpoints → usage statistics
- CJK bigram tokenization: unicode61 tokenizer optimized for Chinese/Japanese/Korean, with space insertion between single characters to support bigram retrieval
- BM25-ranked full-text search, conversation history auto-cleanup at 3 days / 50 entries
- Separate conversations_fts table to avoid coupling with the main table

**Knowledge Distillation**
- Automatically triggered at session end: detects WebSocket disconnect, minimum 4-message threshold
- LLM extracts structured knowledge entries, written to 5 categorized files under `workspace/knowledge/`: facts / decisions / lessons / preferences / skill_hints
- Append-only design — never modifies existing entries, preventing knowledge pollution
- Each record carries rich metadata: title, trigger, context, source, confidence

**File Memory (MEMORY.md)**
- Personal notes actively maintained by the LLM, automatically injected into System Prompt
- Three categories: user (user profile), memory (environment notes), daily (daily logs)
- Complements SQLite memory: MEMORY.md for high-priority context, SQLite for high-volume historical retrieval

### Scheduler

Built-in lightweight task scheduler supporting periodic inspections and automated monitoring, without relying on system-level cron:

- **CRON expressions**: Standard 5-field (minute hour day month weekday), timezone support
- **Interval syntax**: Natural language style like `every 5m`, `every 2h`
- **JSON persistence**: Task definitions stored in `cron_tasks.json`, survives restarts
- **30-second polling**: Scheduler checks for due tasks every 30 seconds, executes via independent Agent sessions
- **Heartbeat mechanism**: Reads periodic health check checklists from `HEARTBEAT.md`, only notifies users on anomalies, auto-skips when empty

### Tool System

34+ built-in tools designed around IT engineers' core workflows, forming a complete toolchain from routine system checks to deep security analysis:

**File Operations** (5 tools): FileRead / FileWrite / FileDelete / FileModify / FileList — foundational capabilities for log file analysis and configuration file auditing

**System Tools**: ShellExecTool (PowerShell, dangerous command interception) — engineers can drive any system command via natural language, the Agent automatically selects appropriate commands and interprets output. Built-in dangerous command blacklist (Remove-Item, del, rm, rmdir, etc.) prevents accidental data loss

**Incident Response Toolkit** (14 tools, the IT investigation core):

| Tool | Capability | Typical Investigation Use |
|------|-----------|--------------------------|
| Process Analysis | Process tree enumeration, resource usage, command-line args | Identify suspicious processes, miners, fileless attacks |
| Network Connections | TCP/UDP connections, listening ports, associated processes | Detect C2 communication, anomalous outbound, lateral movement |
| Registry Audit | Run/RunOnce, service config, policy keys | Detect persistence backdoors, policy tampering |
| Service Enumeration | Service status, start type, binary paths | Find malware disguised as system services |
| Scheduled Tasks | schtasks enumeration, trigger analysis | Detect timed persistence payloads |
| User Accounts | Local users, group membership, recent logins | Investigate account hijacking, new backdoor accounts |
| Firewall Rules | Inbound/outbound rules, allow/block policies | Analyze network access control, find anomalous allowances |
| Event Logs | System/Security/Application log retrieval | **Log investigation core**: filter by time/level/source, correlate analysis |
| Port Scanning | Local port reachability detection | Verify service exposure, troubleshoot port conflicts |
| Autoruns Persistence | Full persistence location scan | One-click complete attack surface, equivalent to Sysinternals Autoruns |
| Web Log Scan | HTTP log security analysis (SQLi/XSS/RCE/directory traversal/scanners) | Detect web attack traces, anomalous request patterns, attacker IP statistics |
| EVTX Parser | Offline Windows Event Log parsing, 60+ Event ID risk classification | Remote forensics, security event filtering (auth failures/service installs/Sysmon/log clearing) |
| Generic Log Parser | Auto-detect log format (Syslog/CSV/Windows), security pattern matching | Multi-source log aggregation, severity classification, security event detection (27 patterns) |
| PCAP Traffic Analysis | Offline pcap/pcapng parsing, protocol distribution, flow tracking, DNS/HTTP extraction, suspicious port detection | Network traffic forensics, C2 communication discovery, DNS tunneling detection, anomalous connection analysis |

These 14 tools can be automatically orchestrated by the Agent — engineers only need to describe the investigation goal, and the Agent calls multiple tools in logical order, cross-correlates results, and outputs structured reports. For example, when investigating "system is slow after boot", the Agent might execute: Process Analysis (find high-CPU processes) → Network Connections (check for anomalous outbound connections) → Autoruns (trace launch origin) → Event Logs (find related system events in the timeframe).

**Malware Analysis**: Boreal YARA rule scanning (custom rule sets, local file loading) + PE deep analysis (goblin parsing of imports/sections/resources + iced-x86 disassembly of key functions) for static analysis of suspicious files

**Browser Automation**: chromiumoxide CDP isolated browser (no login state, for safe browsing) + user browser control (BSK extension, for operations requiring login state)

**Web Tools**: WebFetch (page content retrieval and analysis) / WebSearch (vulnerability intelligence, CVE information) / ImageSearch / ImageGen

**Productivity Tools**: TodoWrite (investigation task planning and progress tracking), AskUserQuestion (confirm key decisions with engineers during investigations), CronManage (scheduled inspection task management)

**MCP Dynamic Tools**: Connect to external tool servers (e.g., SIEM, CMDB) via MCP protocol, dynamically registered at runtime, extending investigation capability boundaries

**External Tool Discovery**: Executables under `workspace/tools/` are automatically discovered and registered — engineers can incorporate their own analysis scripts into the Agent toolchain

### MCP Integration

Full MCP client implementation based on rmcp v1.8.0:

- **Dual transport**: stdio (subprocess) + SSE/StreamableHTTP (remote services)
- **Dynamic tool registration**: After MCP server connection, its tools are automatically merged into ToolRegistry
- **Encrypted authentication**: AES-256-GCM encrypted auth_token storage, key derived from Windows MachineGuid
- **Multi-server management**: Supports simultaneous connections to multiple MCP servers with a unified tool namespace

### Skill System

Progressive-loading procedural knowledge base, distinct from declarative knowledge:

- **Directory structure**: `skills/{Name}/SKILL.md` + optional reference.md and other attachments
- **Weighted scoring match**: name(×4) + description(×2.5) + triggers(×2) + body(×1), sqrt-normalized
- **CJK-aware tokenization**: Correctly tokenizes mixed Chinese-English content
- **Meta-tool design**: Skills are not pre-loaded into the prompt; activated on-demand via find_matching(), saving tokens
- **Frontmatter convention**: YAML header always uses yaml_quote() to prevent colon-value parsing errors

### Security Features

- **API key encryption**: AES-256-GCM at-rest encryption, key derived from Windows MachineGuid, stored in `models.json`
- **Three-layer permission bypass defense**: Hard-reject error messages → System Prompt rule injection → Shell pattern matching fallback
- **Shell command blacklist**: Destructive commands (rm / del / rmdir / format / erase) blocked at the tool layer
- **Password-authenticated Dashboard**: `.password` file-protected Web interface access control
- **CDP browser isolation**: chromiumoxide runs in an independent Chromium instance with no user login state

### Checkpoint & Crash Recovery

- Persists conversation history to SQLite after each tool round
- Recovers context from the latest checkpoint after unexpected disconnections
- Supports conversation summary compression to reduce historical token usage

### Dashboard

Password-authenticated SPA covering the full Agent lifecycle management:

- **Chat**: Real-time conversation, streaming output, tool call visualization
- **Settings**: Model configuration, Agent parameter tuning
- **Skills**: Skill browsing, creation, editing, deletion
- **MCP**: MCP server management and status monitoring
- **History**: Conversation history search and replay
- **CRON**: Scheduled task management (add, edit, delete, enable/disable)
- **Tools**: Built-in and external tool listing
- **Memory**: Memory content viewing and management
- **Usage**: Token usage analytics charts

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Runtime | Tokio (full features) |
| HTTP/WS | Axum 0.8 |
| LLM Protocol | OpenAI-compatible streaming |
| Database | SQLite (rusqlite bundled) + FTS5 |
| MCP | rmcp v1.8.0 (stdio + SSE) |
| Browser | chromiumoxide (CDP) |
| Encryption | aes-gcm (AES-256-GCM) |
| YARA | boreal (rule scanning) |
| PE Parsing | goblin + iced-x86 (disassembly) |
| Serialization | serde + serde_json + serde_yaml + toml |
| Log Analysis | regex (pattern matching) + evtx (EVTX parsing) |
| Traffic Analysis | pcap-parser (pcap/pcapng offline parsing) |
| Logging | tracing + tracing-subscriber (env-filter) |

## Configuration

Runtime workspace directory: `%USERPROFILE%\.RustAgent\workspace\`

```
workspace/
├── config.toml          # Main config (Server / Agent / Model)
├── models.json          # Model config (API keys encrypted)
├── mcp_servers.json     # MCP server config
├── cron_tasks.json      # Scheduled task definitions
├── .password            # Dashboard access password
├── memory/
│   └── memory.db        # SQLite memory database
├── knowledge/           # Knowledge distillation output (append-only)
├── skills/              # Skill directory
├── tools/               # External tools directory
├── logs/                # JSONL conversation logs
├── static/              # Dashboard static assets
└── output/              # Tool output (screenshots, reports, etc.)
```

## Build & Run

```bash
# Build release binary (~28MB, LTO + strip)
cargo build --release

# Binary output
target/release/rust-agent.exe

# First run automatically creates workspace directory structure
.\target\release\rust-agent.exe
```

Release profile: `opt-level = 3`, `lto = true`, `strip = true` — ensuring minimal binary size and optimal runtime performance.

## Project Structure

```
src/
├── main.rs              # Entry: workspace init, dependency wiring, server start
├── server.rs            # Axum HTTP/WS server, REST API, SSE streaming
├── config.rs            # TOML config loading
├── agent/
│   ├── mod.rs           # Agent trait, EventStream type
│   ├── llm_agent.rs     # LlmAgent: Agentic Loop, tool execution, history trimming
│   └── event.rs         # AgentEvent (9 event types)
├── model/
│   ├── mod.rs           # Llm trait, ChatMessage, ToolDefinition
│   └── openai.rs        # OpenAI-compatible streaming client
├── tool/
│   ├── mod.rs           # Tool trait, ToolRegistry, binary resolution
│   ├── file_ops.rs      # File operations (5 tools)
│   ├── shell_exec.rs    # Shell execution (dangerous command interception)
│   ├── mcp_client.rs    # MCP client manager
│   ├── memory_md.rs     # MEMORY.md read/write
│   ├── cron_manage.rs   # CRON task management
│   ├── todo_update.rs   # Task planning & tracking
│   ├── ir_*.rs          # Incident response tools (14, incl. log + traffic analysis)
│   └── malware_*.rs     # Malware analysis (YARA + PE)
├── permission.rs        # Permission checker (category gates + async auth)
├── memory.rs            # MemoryStore (SQLite + FTS5)
├── distill.rs           # Knowledge distillation engine
├── scheduler.rs         # CRON scheduler
├── heartbeat.rs         # Heartbeat health checks
├── skill/
│   ├── mod.rs           # SkillManager
│   └── types.rs         # SelectionPolicy, weighted scoring
├── crypto.rs            # AES-256-GCM encryption
├── checkpoint.rs        # Conversation checkpoint (crash recovery)
├── runner.rs            # Session management, Agent dispatch
├── context.rs           # Context hierarchy (Readonly → Callback → Tool)
├── callbacks.rs         # Lifecycle hooks
├── error.rs             # Structured errors
├── model_store.rs       # Model config persistence (encrypted API keys)
├── external_tools.rs    # External tool discovery
├── log/                 # JSONL logging
└── web/                 # Static file serving
```

## License

MIT
