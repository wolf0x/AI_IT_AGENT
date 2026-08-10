## RustAgent v0.31.0 — Expert HTML Reports & Template Optimization

### New Features

**Expert Mode HTML Reports**
- Completed Expert tasks now generate self-contained HTML reports
- Reports written to `workspace/Expert/` with task-based filenames
- Dark glassmorphism theme matching the UI style
- Includes: task metadata, verified findings, round-by-round details, audit results
- Removed Expert Runs section from Dashboard (replaced by HTML reports)

**USER.md — User Communication Preferences**
- New config file for user-specific communication preferences
- Controls: name/address, tone, language, reply length, format
- Priority: USER.md name > whoami-detected name
- Embedded in binary, extracted on first run (like AGENTS.md/SOUL.md/TOOLS.md)
- Editable via Settings → Config → USER.md tab

### Template Optimization

**AGENTS.md**
- Added USER.md reference and priority rules
- Added Expert mode guidance (when to use Expert vs Instant)
- Added IR workflow guidance (Collection → Analysis → Containment → Reporting)
- Added workspace structure diagram
- Fixed broken JSON code block in heartbeat section

**SOUL.md**
- Added user relationship section (USER.md priority)
- Added professional capabilities (IR expertise)
- Added workspace awareness
- Enhanced continuity section (three-layer memory)
- Added IR safety rules

**TOOLS.md**
- Removed redundant tool documentation (already in system)
- Kept only environment configuration (Windows rules, local paths, output convention)
- Removed incorrect Chrome CDP debugging instructions (tool handles this automatically)

### Bug Fixes & Cleanup

- Fixed 16 compiler warnings (dead code removal, unused imports, field access)
- Removed dead code: `total_entries()`, `get_task_contract()`, `delete_task_contract()` (restored with `#[allow(dead_code)]`)
- Fixed `VerifiedFinding` field access (`detail` → `evidence_summary`)
- Fixed `std::fs::ReadDir` iteration (removed async `.await` in sync context)

### Architecture

- `build.rs`: Added USER.md to embedded workspace files
- `server.rs`: Added USER.md to config files API whitelist
- `managed/runner.rs`: Added `write_expert_report()` function, wired to task completion
- `static/index.html`: Removed Expert Runs section, CSS, and JS function

### Download

- **Windows x64**: `RustAgent-v0.31.0-windows-x64.zip` (12.3 MB)
- Single binary, no installation required
- Extract and run — workspace created automatically on first run
