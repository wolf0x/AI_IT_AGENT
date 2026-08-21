# 🦀 实战构建 RustAgent：从零构建一个 Windows 端侧应急响应 AI Agent

> 架构设计、安全模型与工程实践

---

## 一、背景：为什么需要端侧 IR Agent

应急响应（Incident Response）是一个高度时间敏感的场景。当安全团队发现一台 Windows 主机可能被入侵时，需要在最短时间内完成：

- **采集**：进程、服务、网络连接、持久化项、事件日志、驱动……
- **分析**：YARA 扫描、进程行为评分、持久化枚举、时间线重建
- **报告**：生成结构化报告，包含 IOC 和 MITRE ATT&CK 映射

传统做法是写一堆 PowerShell 脚本，或者用商业 EDR 的取证模块。但这些方案要么需要人工编排，要么需要安装重量级 agent。

> **核心问题**：能不能有一个轻量的、单二进制的、本地运行的 AI Agent，用自然语言驱动整个 IR 流程？

**RustAgent** 就是这个问题的答案。它是一个用 Rust 编写的 Windows 端侧 AI Agent，单二进制 ~34MB，无需安装，启动即用。通过 LLM 驱动的工具调用循环，用自然语言完成从采集到报告的完整 IR 工作流。

---

## 二、整体架构

```
┌─────────────────────────────────────────────────────────┐
│                  Dashboard SPA (HTML/JS)                  │
│     (Chat / Skills / MCP / CRON / Settings)              │
│     Instant ⚡ / Expert 🛠 mode toggle + sidebar badge   │
└────────────────────────┬────────────────────────────────┘
                         │ WebSocket + REST API
┌────────────────────────┴────────────────────────────────┐
│                   Axum 0.8 Server                        │
│            (REST API + WS Gateway + SSE)                  │
├─────────────────────────────────────────────────────────┤
│  Runner → LlmAgent (Agentic Loop)                        │
│    ├── CJK-aware token budget history trimming           │
│    ├── Re-prompt detection & self-healing                │
│    ├── Rabbit hole detection                             │
│    ├── Multi-model fallback                              │
│    └── Truncated JSON repair                             │
├─────────────────────────────────────────────────────────┤
│  Expert Mode (ManagedRunner) — Long-Horizon Tasks        │
│    ├── Manager (plan next subtask, fresh context)        │
│    ├── Executor (existing agent loop, condensed brief)   │
│    ├── Auditor (independent artifact verification)       │
│    ├── TaskContract (SQLite persistence, crash recovery) │
│    └── PermissionProfile (pre-authorization, unattended) │
├─────────────────────────────────────────────────────────┤
│  Safety Layers                                           │
│    ├── Permission System (5-category gates)              │
│    ├── Cross-Category Bypass Detection                   │
│    ├── Command Intent Policy (Block / Audit / Pass)      │
│    └── Graded Tool Timeout (Immediate→Watchdog)          │
├─────────────────────────────────────────────────────────┤
│  Tool Layer (40+ tools)                                  │
│    ├── 15+ IR Tools (parallel execution for collection)  │
│    ├── System Tools (shell_exec/file_*/sys_*)            │
│    ├── Computer Use (screenshot/mouse/keyboard/windows)  │
│    ├── Browser Tools (CDP headless + BrowserSkill)       │
│    ├── MCP Client (stdio + SSE, dynamic registration)    │
│    └── Skill Manager (weighted scoring, progressive)     │
├─────────────────────────────────────────────────────────┤
│  Infrastructure                                          │
│    ├── Memory (SQLite + FTS5)    ├── Scheduler (CRON)   │
│    ├── Checkpoint (crash recovery) ├── Crypto (AES-GCM) │
│    ├── Event Log (JSONL)         ├── YARA (boreal)      │
│    └── Token Usage Tracking      ├── Partial Results    │
└─────────────────────────────────────────────────────────┘
```

RustAgent 的架构分为 **7 层**，每层通过接口或协议解耦：

**① Agent Loop — 核心循环**
问模型 → 检查工具调用 → 执行工具 → 回写结果 → 继续问。一个 while 循环，加上安全阀（max_iterations）和自修复（re-prompt detection）。

**② Model Layer — 模型适配**
OpenAI-compatible 统一接口，支持任意兼容 OpenAI 协议的 Provider（OpenAI、Azure、Ollama、vLLM、DeepSeek……）。流式 SSE 输出。

**③ Tool Layer — 工具系统**
40+ 内置工具 + MCP 动态注册 + 外部工具。每个工具声明 category（read/write/delete/modify/execute），由 Permission System 管控。只读 IR 工具可并行执行（3-4x 加速）。

**④ Safety Layer — 安全纵深**
四层防御：Permission Gates → Cross-Category Bypass Detection → Command Intent Policy → PermissionProfile 预授权（Expert 模式）。即使 LLM 被 prompt injection，也无法绕过 Rust 层面的硬拦截。

**⑤ Expert Mode — 长任务架构**
Manager-Executor-Auditor 三角色分离，TaskContract 状态持久化（SQLite Schema v5），PermissionProfile 预授权无人值守执行，分级超时 + 存活看门狗。

**⑥ Skill Layer — 知识注入**
渐进式加载：不预加载所有 Skill 到 prompt，而是通过加权评分按需注入。CJK 分词支持中英文混合匹配。

**⑦ Infrastructure — 基础设施**
SQLite 记忆、Checkpoint 崩溃恢复、AES-256-GCM 加密、CRON 调度、YARA 扫描、JSONL 事件日志。

---

## 三、Agent Loop（一切的核心）

Agent Loop 的本质是一个 while 循环。下面是简化后的核心逻辑：

```rust
for iteration in 0..max_iter {
    // 1. 调模型（流式）
    let response = provider.chat_stream(&model, &messages, &tools, tx).await?;

    // 2. 提取工具调用
    let tool_calls = extract_tool_calls(response);

    // 3. 没有工具调用 → 结束
    if tool_calls.is_empty() {
        break; // 文本回复即完成
    }

    // 4. 执行工具，回写结果
    for tc in tool_calls {
        let result = execute_tool(tc).await;
        history.push(ChatMessage::tool(tc.name, result));
    }
}
```

### 关键设计决策

#### 为什么要有 max_iterations？

模型可能陷入无限工具循环。上限是安全阀。RustAgent 默认 100 轮，还额外加了 **rabbit hole detection**：如果连续 N 轮（默认 5）都在调工具但没有文本回复，强制要求模型给出总结。

#### Re-prompt 自修复

有些模型（尤其是小模型）会返回「我来帮你查一下」但不实际发出工具调用。RustAgent 检测到这种「意图明确但工具调用缺失」的情况后，会自动注入 re-prompt 要求模型重试，最多 2 次：

```rust
if tool_calls.is_empty() && !has_executed_tools && reprompt_count < 2 {
    // 检测是否提到了工具名或意图短语
    if mentions_tool || has_intent_phrase {
        history.push(ChatMessage::user("Please use the tool call format..."));
        reprompt_count += 1;
        continue;
    }
}
```

#### 文本工具调用提取

不是所有模型都支持原生 function calling。RustAgent 实现了从文本/推理内容中提取 JSON 工具调用的能力：

```rust
// 支持三种格式：
// 1. ```json {"name": "shell_exec", "arguments": {...}} ```
// 2. 内联 JSON 对象 {"name": "...", "arguments": {...}}
// 3. XML 风格 <tool_call>...</tool_call>
```

#### 上下文窗口管理

LLM 有上下文窗口限制。RustAgent 用 **CJK-aware token 估算** + **优先级裁剪**：

| 阶段 | 裁剪目标 | 保留长度 |
|------|---------|---------|
| Phase 1 | 旧工具结果 | 100 字符 |
| Phase 2 | 旧 assistant 回复 | 200 字符 |
| Phase 3 | 旧用户消息 | 100 字符 |
| Phase 4 | 旧工具结果进一步裁剪 | 50 字符 |

最近 6 条消息永远不会被裁剪，保证上下文连贯。

---

## 四、Expert Mode（长任务架构）

短任务（Instant 模式）用单次 Agent Loop 完成。但复杂 IR 任务可能需要数十分钟甚至数小时——单次 Loop 的上下文窗口无法承载，模型会「忘记」早期发现。

**Expert 模式**引入 Manager-Executor-Auditor 三角色分离，解决长任务的上下文漂移和状态丢失问题：

**🧠 Manager（规划者）**
每轮只接收 **TaskContract**（无历史），规划下一个子任务。新鲜上下文，杜绝上下文漂移。Manager 输出结构化计划：Subtask、Success Criteria、Expected Evidence、Phase、Route。

**⚡ Executor（执行者）**
复用现有 Agent Loop，以精炼 brief 为输入。每轮独立上下文，最多 N 次工具调用。Executor 完成后，其输出摘要被记录到 TaskContract 的 manager_notes 中。

**🔍 Auditor（验证者）**
独立验证 Executor 产出：文件是否存在、进程是否已终止、证据是否有效。只有验证通过的发现才进入 TaskContract 的 `verified_findings`。

### TaskContract — 状态合约

TaskContract 是 Expert 模式的核心状态对象，持久化到 SQLite（Schema v5）。包含：

| 字段 | 说明 |
|------|------|
| `phase` | 当前 IR 阶段（Collection → Analysis → Attribution → Containment → Eradication → Reporting → Completed） |
| `verified_findings` | 已验证发现（Auditor 确认的证据） |
| `verified_actions` | 已验证动作（Auditor 确认的 containment/eradication） |
| `open_leads` | 开放线索（待调查的方向） |
| `manager_notes` | Manager 笔记（每轮 Executor 输出摘要，上限 20 条） |

每轮结束后 TaskContract 被持久化到 SQLite。进程崩溃后重启，可从上次状态恢复。

### PermissionProfile — 预授权

长时间无人值守时，containment 动作（杀进程、停服务、删持久化）不能每次都等人工审批。

```rust
// 意图级匹配：只放行特定命令模式
match tool_name {
    "shell_exec" => {
        if cmd.contains("taskkill") || cmd.contains("stop-process") {
            return profile.is_preauthorized(KillProcess);
        }
    }
    "ir_persistence" => { /* remove/delete → RemovePersistence */ }
}
```

### 分级工具超时 + 存活看门狗

| 阶段 | 超时 | 场景 |
|------|------|------|
| Immediate | 30s | 快速查询（进程列表、文件读取） |
| Standard | 300s | 常规工具（YARA 扫描、网络分析） |
| Extended | 900s | 深度分析（malware_deep） |
| Watchdog | 24h | 超长任务（ir_memdump）— 存活看门狗管控 |

Watchdog 阶段：wall-clock 超时设为 24h（实际不触发），真正的中止机制是 **存活看门狗**——如果工具在 N 秒内没有发送任何进度消息，自动中止。

> **Instant vs Expert 配置隔离**：Expert 模式有独立的配置参数（Max Iterations 200、Tool Timeout 600s、Max Retries 3、Max Rounds 50），与 Instant 模式的设置互不干扰。切换模式时自动加载对应配置。

---

## 五、AI 模型适配层

模型适配层的职责只有一句话：**把不同 LLM Provider 的 API 差异统一成一个接口**。

```rust
pub struct OpenAiProvider {
    clients: Vec<ModelClient>,  // 每个模型一个 client
}

// 统一接口：不管背后是 GPT-4o、DeepSeek、Ollama 还是 vLLM
pub async fn chat_stream(
    &self,
    model: &str,
    messages: &[ChatMessage],
    tools: &[ToolDefinition],
    tx: Sender,          // 流式事件推送
) -> Result<(String, Usage, Vec<ToolCall>)>
```

RustAgent 选择了 **OpenAI-compatible** 协议作为统一标准。这意味着任何兼容 OpenAI `/v1/chat/completions` 接口的服务都可以直接接入，无需额外适配。

> **多模型 Fallback**：当主模型连续失败时，自动切换到 fallback 模型重试。这在端侧场景尤为重要——本地 Ollama 可能因为显存不足而失败，fallback 到云端模型保证可用性。

---

## 六、Tool System（Agent 的手和脚）

工具系统让 Agent Loop 可以「做事」。RustAgent 拥有 **40+ 内置工具**，分为以下几类：

| 类别 | 工具 | 说明 |
|------|------|------|
| **Shell 执行** | `shell_exec` | PowerShell / CMD 命令执行，集成 Intent Policy |
| **文件操作** | `file_read/write/delete/list/modify` | 完整文件 CRUD |
| **系统信息** | `sys_info/process/service/eventlog` | 只读系统查询 |
| **IR 工具 (15+)** | `ir_scan/process/persistence/network/eventlog/file/driver/timeline/account/memdump/vss/analyzer/report/eml/pcap` | 专业应急响应工具链 |
| **浏览器** | `browser_cdp` | Headless CDP + 交互式浏览器自动化 |
| **Computer Use** | `cu_screenshot/mouse/keyboard/...` | GUI 桌面自动化 |
| **记忆** | `memory_md` / `todo_update` | 长期记忆 + 任务跟踪 |
| **技能** | `list/install/remove_skill` | 技能的元工具 |
| **MCP** | 动态注册 | Model Context Protocol 外部工具 |

### 工具执行策略

RustAgent 支持三种工具执行策略：

| 策略 | 说明 | 适用场景 |
|------|------|---------|
| **Sequential** | 逐个执行工具调用 | 默认，安全可控 |
| **Parallel** | 所有工具调用并行执行 | IR 采集（3-4x 加速） |
| **Auto** | 智能判断：全是 IR 采集工具 → 并行；否则 → 串行 | 推荐 |

```rust
// Auto 策略的核心逻辑
if strategy == Auto && all_tools_are_ir_collection(tool_calls) {
    // 并行执行所有 IR 采集工具
    let results = join_all(tool_calls.iter().map(|tc| execute_tool(tc))).await;
} else {
    // 串行执行
    for tc in tool_calls {
        let result = execute_tool(tc).await;
    }
}
```

---

## 七、安全模型（四层纵深防御）

> **核心原则**：LLM 是不可信的。即使 system prompt 告诉它「不要做危险操作」，prompt injection 或 jailbreak 仍可能让它尝试执行危险命令。安全必须建立在 **Rust 代码层面**，而不是依赖 LLM 的「自觉」。

### 第一层：Permission Gates（权限门禁）

每个工具声明一个 **permission category**，用户可以在 Dashboard 中控制每个 category 是否允许：

| Category | 默认 | 包含工具 |
|----------|------|---------|
| `read` | ✅ 允许 | `file_read`, `file_list`, `sys_*`, `ir_*`, `browser_cdp(get_*)` |
| `write` | ✅ 允许 | `file_write`, `memory_md`, `todo_update` |
| `delete` | ❌ 需确认 | `file_delete` |
| `modify` | ✅ 允许 | `file_modify`, `sys_process`, `browser_cdp(click/type)` |
| `execute` | ❌ 需确认 | `shell_exec`, `app_launch`, `cu_mouse`, `cu_keyboard` |

当 Agent 请求一个被拒绝的 category 时，系统通过 WebSocket 推送权限请求到 Dashboard，用户点击确认/拒绝后，结果通过 oneshot channel 返回。

### 第二层：Cross-Category Bypass Detection（跨类别绕过检测）

如果用户预授权了 `execute: true`（允许 shell_exec），LLM 可能尝试用 `shell_exec` 执行 `Remove-Item` 来绕过 `delete: false` 的限制。

RustAgent 的对策：对 shell_exec 的命令做 **Intent 分析**，如果命令的语义属于被拒绝的 category，仍然要求确认：

```rust
// shell_exec 预授权了，但命令是 Remove-Item
let intent = parse_intent(command, shell);
match intent.verb {
    Verb::Delete => escalate_to_confirmation(), // 绕过检测！
    Verb::Format => escalate_to_confirmation(),
    _ => // 正常执行
}
```

### 第三层：Command Intent Policy（命令意图策略）

即使所有权限都开放，仍然有一道 **不可绕过的硬拦截**。Intent Policy 对 shell 命令做语义解析，分为三个级别：

| 级别 | 含义 | 示例 |
|------|------|------|
| **Block** | 绝对禁止，不可覆盖 | `Format-Volume`, `Clear-Disk`, `format C:`, `wevtutil cl Security`, `-EncodedCommand` |
| **Audit** | 高风险但合法，记录日志 | `Remove-Item`, `Stop-Service`, `taskkill`, `reg add` |
| **Pass** | 正常操作 | `Get-Process`, `ipconfig`, `netstat` |

```rust
// Block 规则示例：磁盘格式化 — 不可逆，无合法 IR 用途
BlockRule {
    name: "format_volume",
    matches: |intent| intent.verb == Verb::Format,
    explain: |intent| "Format-Volume is an irreversible disk operation",
}
```

> **设计哲学**：Block 规则的准入门槛极高 —— 必须同时满足 (1) 不可逆 (2) 没有合法 IR 用途 (3) 误报概率接近零。只有 Security 日志清除、磁盘格式化、编码命令等极少数操作被 Block。其他高风险操作只 Audit 不 Block。

### 第四层：PermissionProfile 预授权（Expert 模式）

Expert 模式下，`PermissionProfile::ir_containment()` 预授权 containment 类动作（杀进程、停服务、删持久化），使长时间无人值守执行成为可能。预授权采用 **意图级匹配**——不是简单放开整个工具类别，而是精确匹配命令模式（如 `taskkill`、`Stop-Process`）。破坏性操作（格式化磁盘、清除日志）永远不预授权。

---

## 八、Skill System（渐进式知识注入）

把所有知识都塞进 system prompt 会消耗大量 token。RustAgent 的 Skill 系统采用 **渐进式加载**：只在需要时注入相关 Skill。

### 加权评分匹配

```
// 评分权重
name         × 4.0   // 技能名称匹配最重要
description  × 2.5   // 描述匹配次之
triggers     × 2.0   // 触发词匹配
body         × 1.0   // 正文 token 重叠
trigger_substring_bonus = +10.0  // 完整触发短语出现

// 归一化：防止大文档靠 token 数量取胜
final_score = raw_score / sqrt(body_token_count)
```

### CJK 分词

中文不像英文有空格分隔。RustAgent 的分词器对 CJK 字符逐字切分，对 ASCII 字符按词切分，确保中英文混合内容都能正确匹配。

### Slash Command 前端交互

用户可以在聊天框输入 `/` 触发技能选择器弹窗，直接选择要使用的技能。选择后 `/SkillName` 会作为消息前缀发送，加权评分会以 ×4.0 的权重命中技能名称。

---

## 九、Memory System（SQLite + FTS5）

RustAgent 的记忆分两层：

| 层级 | 存储 | 说明 |
|------|------|------|
| **自动记忆** | SQLite + FTS5 | 每轮对话自动持久化，支持全文搜索 |
| **长期记忆** | MEMORY.md | Agent 主动 curate 的精炼记忆 |

### Memory Recall

每轮对话开始时，RustAgent 自动从 SQLite 中检索与当前消息相关的历史记忆，注入到 context 中。Agent 不需要主动调用任何工具就能「记住」之前聊过什么。

```
// 自动注入的记忆格式
[Memory Context]
## 2025-01-15
- 用户要求分析可疑进程 svchost.exe (PID 1234)
- YARA 扫描确认为 Cobalt Strike beacon
- 已完成内存 dump 和时间线重建

## 2025-01-14
- 初始 triage：发现 3 个可疑持久化项
- 注册表 Run key 中有异常条目
```

---

## 十、Server & WebSocket 协议

RustAgent 使用 **Axum 0.8** 作为 Web 框架，同时提供 REST API 和 WebSocket 双通道：

| 通道 | 用途 | 协议 |
|------|------|------|
| **WebSocket** | 实时对话、事件流、权限请求 | JSON 消息 |
| **REST API** | 配置管理、技能管理、MCP 管理、历史查询 | JSON over HTTP |

### WebSocket 事件类型

| 事件 | 方向 | 说明 |
|------|------|------|
| `chat` | Client → Server | 用户发送消息 |
| `text` | Server → Client | Agent 文本输出 |
| `think` | Server → Client | Agent 思考过程（可折叠） |
| `tool_call` | Server → Client | 工具调用开始 |
| `tool_result` | Server → Client | 工具执行结果 |
| `permission_request` | Server → Client | 请求用户授权 |
| `done` | Server → Client | Agent 本轮完成 |
| `error` | Server → Client | 错误信息 |

### REST API 概览

```
// 模型管理
GET  /api/models              // 列出所有模型
GET  /api/providers            // 列出 Provider
POST /api/providers            // 创建 Provider

// 技能管理
GET  /api/skills               // 列出技能
POST /api/skills               // 创建技能
POST /api/skills/{name}/toggle // 启用/禁用

// MCP 管理
GET  /api/mcp                  // 列出 MCP 服务器
POST /api/mcp                  // 添加 MCP 服务器
POST /api/mcp/{name}/restart   // 重启 MCP 连接

// 设置持久化
POST /api/settings/agent       // 保存 Agent 设置到 config.toml
POST /api/settings/agent/expert // 保存 Expert 模式设置
POST /api/settings/computer_use // 切换 Computer Use

// 任务面板
GET  /api/todos                // 获取 TODO 列表（5s 自动刷新）
```

---

## 十一、前端 Dashboard

RustAgent 的前端是一个 **单页应用（SPA）**，嵌入在二进制中（通过 `include_str!`），无需额外部署。

主要页面：

| 页面 | 功能 |
|------|------|
| **Chat** | 对话主界面，Instant ⚡ / Expert 🛠 模式切换，Markdown 渲染、代码高亮 |
| **Skills** | 技能管理：查看、创建、编辑、删除、启用/禁用 |
| **MCP** | MCP 服务器管理：连接状态、工具列表、重启 |
| **CRON** | 定时任务管理：创建、编辑、暂停/恢复 |
| **Settings** | 全局设置：模型选择、权限控制、Agent 参数、Computer Use / Expert Mode 开关 |
| **Dashboard** | 使用统计：Token 消耗、对话历史、模型使用分布 |

> **Expert 模式 UI**：输入框上方分段控制器切换 Instant/Expert，侧边栏状态指示器实时显示当前模式。Expert 模式有独立的配置参数（Max Iterations 200、Tool Timeout 600s 等），切换模式时自动加载对应配置。

---

## 十二、总结

回顾整个项目，RustAgent 的核心设计可以收敛到几个关键判断：

### 1. 安全不可妥协

LLM 是不可信的。所有安全控制必须在 Rust 代码层面实现，不能依赖 prompt 指令。四层纵深防御（Permission → Bypass Detection → Intent Policy → PermissionProfile）确保了即使 LLM 被攻破，也无法执行灾难性操作。

### 2. 端侧优先

单二进制 ~34MB，无需安装，无需网络（除了 LLM API）。所有数据留在本地。这对于 IR 场景至关重要 —— 你不能在被入侵的机器上安装一个需要联网的 agent。

### 3. 渐进式知识注入

不把所有 Skill 都塞进 system prompt。通过加权评分按需注入，节省 token 的同时保证相关知识在需要时可用。

### 4. 工具即能力

Agent 的价值不在于模型多强，而在于它能调用多少有用的工具。40+ 内置工具 + MCP 动态注册 + Computer Use + 并行 IR 采集，让 RustAgent 的能力边界可以无限扩展。

### 5. 记忆是连续性的基础

没有记忆的 Agent 每次对话都是失忆的。SQLite FTS5 自动记忆 + MEMORY.md 长期记忆 + TaskContract 崩溃恢复，让 Agent 能够跨会话、跨崩溃保持上下文。

### 6. Expert Mode — 长任务架构

Manager-Executor-Auditor 三角色分离解决了长任务的上下文漂移问题。TaskContract 状态持久化确保崩溃可恢复。PermissionProfile 预授权使无人值守执行成为可能。分级超时 + 存活看门狗管控超长工具。

---

这个项目距离一个成熟的商用 IR 平台还有很多可以完善的地方 —— 更精确的上下文压缩（LLM 摘要而非裁剪）、插件系统（Lua hooks）、树状会话分支、多 Agent 协作。但作为一个验证「端侧 AI Agent 能否胜任 IR 工作流」的 project，它的核心判断已经被反复验证：

> **理解了 Agent Loop 的构建原理，也就掌握了理解所有 Agent 的一把钥匙。** 客服 Agent 的会话管理、数据分析 Agent 的工具链编排、工作流 Agent 的状态机设计 —— 追根溯源，都是这个循环在不同场景下的变形。

---

*RustAgent — Built with 🦀 by a single developer*
[GitHub](https://github.com/wolf0x/AI_IT_AGENT) · Rust · Axum 0.8 · Tokio · SQLite · chromiumoxide