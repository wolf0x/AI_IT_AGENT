## RustAgent v0.28.0 — Expert Mode & Long-Horizon Task Architecture

### New Features

**Expert Mode (Managed Mode)**
- Manager-Executor-Auditor three-role separation for long-horizon IR tasks
- TaskContract state persistence (SQLite Schema v5) with crash recovery
- PermissionProfile pre-authorization for unattended containment execution
- Phase progression: Collection → Analysis → Attribution → Containment → Eradication → Reporting
- Forward-only phase advancement guard

**Graded Tool Timeout Policy**
- 4-stage timeout: Immediate (30s) → Standard (300s) → Extended (900s) → Watchdog (24h)
- Liveness watchdog for long-running tools (malware_deep, ir_memdump)
- Progress-based silence detection with auto-abort

**Partial Result Protocol**
- Token-usage-aware early termination for long-running tools

**Web UI Mode Control**
- Instant ⚡ / Expert 🛠 segmented toggle above input bar
- Sidebar status badge (INSTANT/EXPERT) next to Connected indicator
- Settings: global Expert Mode toggle alongside Computer Use
- Expert Mode has independent config parameters (Max Iterations 200, Tool Timeout 600s, etc.)
- Password field Enter-key triggers Connect

### Bug Fixes (P0/P1 from code review)
- TaskContract now receives Executor results (verified findings, manager notes)
- PermissionProfile wired into PermissionChecker pipeline
- Contract persisted on Done/Blocked terminal states
- Manager plan includes Phase field for IR phase progression
- Multi-path evidence verification (split on commas/newlines)
- Hardcoded Executor params replaced with server config values

### Architecture Changes
- 7-layer architecture (added Expert Mode layer)
- 4-layer safety model (added PermissionProfile pre-authorization)
- 40+ built-in tools (added Computer Use, parallel IR collection)
- New config fields: `expert_max_iterations`, `expert_tool_timeout_secs`, `expert_max_tool_retries`, `expert_max_managed_rounds`
- New API endpoint: `POST /api/settings/agent/expert`

### Config Changes
```toml
[agent]
# Instant mode settings (existing)
max_iterations = 100
tool_timeout_secs = 300
max_tool_retries = 2

# Expert mode settings (new)
expert_max_iterations = 200
expert_tool_timeout_secs = 600
expert_max_tool_retries = 3
expert_max_managed_rounds = 50
```

### Files Changed
- `src/managed/runner.rs` — Stateful contract, auditor integration, persist helper
- `src/managed/manager.rs` — Phase field in ManagerPlan, evidence newline preservation
- `src/permission.rs` — PermissionProfile pre-authorization in check()
- `src/context.rs` — preauth_profile field + builder
- `src/runner.rs` — preauth_profile param threading
- `src/config.rs` — Expert mode config fields + save function
- `src/server.rs` — Expert mode dispatch, expert settings endpoint
- `src/agent/llm_agent.rs` — Watchdog timeout fix, preauth threading
- `src/memory.rs` — Schema v5 task_contracts CRUD
- `static/index.html` — Mode toggle UI, Expert settings section
- `src/main.rs` — AppState initialization with new fields
