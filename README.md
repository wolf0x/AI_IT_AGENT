**[English](README.en.md)** | **[中文](#)**

# RustAgent

面向本地 IT 系统工程师的 AI 辅助平台——专注于系统分析、日志调查与事件响应。完全运行在本地，单二进制部署，具备 WebSocket 网关、多模型支持、33+ 内置工具、权限管控、持久记忆与任务调度能力。面向 Windows 环境，开箱即用。

## 项目定位

RustAgent 专为本地 IT 系统工程师设计，解决日常运维中最耗时的三类工作：**系统状态分析**、**日志调查溯源**和**安全事件响应**。

传统方式下，工程师需要在多个工具间反复切换——事件查看器查日志、PowerShell 查进程、注册表编辑器查配置、netstat 查连接——每条线索都需要手动关联和判断。RustAgent 将这些能力统一到一个 AI Agent 中：工程师用自然语言描述问题现象，Agent 自动编排工具链，采集系统状态、检索相关日志、关联分析异常，最终给出结构化的调查结论和处置建议。

**典型场景**：

- **日志调查**：「最近 24 小时系统日志里有哪些错误和警告？按时间线整理出来」——Agent 自动调用事件日志工具，筛选关键级别，按时间排序，关联相关进程和服务状态
- **系统分析**：「当前有哪些异常进程在占用大量资源？检查它们的启动来源」——Agent 编排进程枚举 + 资源占用分析 + Autoruns 持久化检测，给出完整的进程链分析
- **安全排查**：「检查这台机器是否被植入了持久化后门」——Agent 串联注册表审计、计划任务枚举、服务枚举、Autoruns 检测，输出完整的持久化攻击面报告
- **故障定位**：「服务 XXX 启动失败，帮我查原因」——Agent 查询服务状态、关联事件日志、检查依赖服务、分析配置文件，定位根因

**为什么完全本地**：IT 工程师处理的日志、进程信息、注册表数据往往包含敏感的内网拓扑和凭据信息。RustAgent 的 AI 对话引擎、工具执行、数据存储全部在本地完成，API 密钥 AES-256-GCM 加密存储，只有 LLM 推理请求发往云端模型——原始系统数据不出本机。

单个 Rust 编译产物（~28MB）即包含完整的 AI 对话引擎、工具执行层、WebSocket 网关和 Web Dashboard，无需安装额外运行时或外部服务依赖。灵感来源于 Google ADK 的 Agent → LlmAgent → EventStream 架构模式，在 Rust 生态中实现了完整的 Agentic Loop。

## 核心架构

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
│    ├── Agent trait → EventStream (9 种事件)      │
│    ├── CJK-aware token budget 历史裁剪           │
│    ├── Re-prompt 检测与自愈                      │
│    └── Truncated JSON repair                    │
├─────────────────────────────────────────────────┤
│  Tool Layer                                      │
│    ├── 33+ Built-in Tools                        │
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

## 核心能力

### 权限系统

RustAgent 实现了分类门控（Category-based Gates）的权限模型，而非简单的 allow/deny 二元判断：

- **五级权限分类**：read / write / delete / modify / execute，每种工具调用声明所需权限类别
- **异步用户授权**：当 Agent 请求高权限操作时，通过 WebSocket 向 Dashboard 推送授权请求，用户确认后通过 oneshot channel 返回结果，Agent 循环无阻塞等待
- **Shell 危险命令拦截**：ShellExecTool 内置黑名单（Remove-Item、del、rm、rmdir、format、erase 等），在工具执行层直接阻断，不经过 LLM 判断
- **三层权限绕过防御**：(1) 强拒绝错误消息禁止使用替代工具 (2) System Prompt 中注入 Permission Denial Rules (3) Shell 层模式匹配兜底

### 记忆系统

双层记忆架构，兼顾实时检索与长期调查经验积累——Agent 在每次调查中积累的经验会被蒸馏为可复用知识，下次遇到类似问题时自动参考：

**SQLite + FTS5 对话记忆**
- 4 层 Schema 版本演进：基础对话 → FTS5 全文索引 → 检查点 → 用量统计
- CJK bigram 分词：针对中文/日文/韩文优化 unicode61 tokenizer，空格插入单字符以支持 bigram 检索
- BM25 排序的全文搜索，对话历史 3 天/50 条自动清理
- conversations_fts 独立表，避免与主表耦合

**知识蒸馏（Knowledge Distillation）**
- 会话结束时自动触发：检测 WebSocket 断开，最低 4 条消息阈值
- LLM 提取结构化知识条目，写入 `workspace/knowledge/` 下的 5 个分类文件：facts / decisions / lessons / preferences / skill_hints
- Append-only 设计，只增不改，避免知识污染
- 每条记录携带丰富元数据：title、trigger、context、source、confidence

**文件记忆（MEMORY.md）**
- 由 LLM 主动维护的个人笔记，自动注入 System Prompt
- 分为 user（用户画像）、memory（环境笔记）、daily（每日日志）三类
- 与 SQLite 记忆互补：MEMORY.md 用于高优先级上下文，SQLite 用于海量历史检索

### 调度系统

内置轻量级任务调度器，支持定期巡检与自动化监控，无需依赖系统级 cron：

- **CRON 表达式**：标准 5 字段（分 时 日 月 周），支持时区
- **间隔语法**：`every 5m`、`every 2h` 等自然语言风格
- **JSON 持久化**：任务定义存储于 `cron_tasks.json`，重启不丢失
- **30 秒轮询**：调度器每 30 秒检查到期任务，通过独立 Agent 会话执行
- **心跳机制**：从 `HEARTBEAT.md` 读取周期性健康检查清单，仅异常时通知用户，全空则自动跳过

### 工具系统

33+ 内置工具围绕 IT 工程师的核心工作流设计，从日常系统检查到深度安全分析形成完整工具链：

**文件操作**（5 个）：FileRead / FileWrite / FileDelete / FileModify / FileList——日志文件分析、配置文件审查的基础能力

**系统工具**：ShellExecTool（PowerShell，危险命令拦截）——工程师可通过自然语言驱动任意系统命令，Agent 自动选择合适命令并解释输出结果。内置危险命令黑名单（Remove-Item、del、rm、rmdir 等），防止误操作导致数据丢失

**事件响应工具组**（13 个，IT 调查核心）：

| 工具 | 能力 | 典型调查用途 |
|------|------|-------------|
| 进程分析 | 枚举进程树、资源占用、命令行参数 | 识别异常进程、挖矿程序、无文件攻击 |
| 网络连接 | TCP/UDP 连接、监听端口、关联进程 | 发现 C2 通信、异常外连、横向移动 |
| 注册表审计 | Run/RunOnce、服务配置、策略键值 | 检测持久化后门、策略篡改 |
| 服务枚举 | 服务状态、启动类型、二进制路径 | 发现伪装系统服务的恶意程序 |
| 计划任务 | schtasks 枚举、触发器分析 | 检测定时执行的持久化载荷 |
| 用户账户 | 本地用户、组成员、最近登录 | 排查账户劫持、新增后门账户 |
| 防火墙规则 | 入站/出站规则、允许/阻止策略 | 分析网络访问控制、发现异常放行 |
| 事件日志 | System/Security/Application 日志检索 | **日志调查核心**：按时间/级别/来源筛选，关联分析 |
| 端口扫描 | 本地端口可达性检测 | 验证服务暴露面、排查端口冲突 |
| Autoruns 持久化 | 全量持久化位置扫描 | 一键获取完整攻击面，对标 Sysinternals Autoruns |
| Web 日志扫描 | HTTP 日志安全分析（SQLi/XSS/RCE/目录遍历/扫描器） | 检测 Web 攻击痕迹、异常请求模式、攻击源 IP 统计 |
| EVTX 解析 | 离线解析 Windows 事件日志文件，60+ Event ID 风险分类 | 远程取证分析、安全事件筛选（认证失败/服务安装/Sysmon/日志清除等） |
| 通用日志解析 | 自动识别日志格式（Syslog/CSV/Windows），安全模式匹配 | 多源日志聚合分析、严重级别分类、安全事件检测（27 种模式） |

这 13 个工具可被 Agent 自动编排——工程师只需描述调查目标，Agent 会按逻辑顺序调用多个工具，交叉关联结果，输出结构化报告。例如排查「开机后系统变慢」时，Agent 可能依次执行：进程分析（找高 CPU 进程）→ 网络连接（检查该进程是否有异常外连）→ Autoruns（追溯其启动来源）→ 事件日志（查找相关时间段的系统事件）。

**恶意软件分析**：Boreal YARA 规则扫描（支持自定义规则集，本地文件加载）+ PE 深度分析（goblin 解析导入表/节区/资源 + iced-x86 反汇编关键函数），可对可疑文件进行静态分析

**浏览器自动化**：chromiumoxide CDP 隔离浏览器（无登录态，用于安全搜索）+ 用户浏览器控制（BSK 扩展，用于需要登录态的操作）

**Web 工具**：WebFetch（抓取页面内容分析）/ WebSearch（搜索漏洞情报、CVE 信息）/ ImageSearch / ImageGen

**生产力工具**：TodoWrite（调查任务规划与进度跟踪）、AskUserQuestion（调查中向工程师确认关键决策）、CronManage（定时巡检任务调度）

**MCP 动态工具**：通过 MCP 协议接入外部工具服务器（如 SIEM、CMDB 等），运行时动态注册，扩展调查能力边界

**外部工具发现**：`workspace/tools/` 目录下的可执行文件自动发现并注册，工程师可将自有的分析脚本纳入 Agent 工具链

### MCP 集成

基于 rmcp v1.8.0 的完整 MCP 客户端实现：

- **双传输协议**：stdio（子进程）+ SSE/StreamableHTTP（远程服务）
- **动态工具注册**：MCP 服务器连接后，其 tools 自动合并到 ToolRegistry
- **认证加密**：AES-256-GCM 加密存储 auth_token，密钥由 Windows MachineGuid 派生
- **多服务器管理**：支持同时连接多个 MCP 服务器，统一工具命名空间

### 技能系统

渐进式加载的程序性知识库，区别于声明式知识：

- **目录结构**：`skills/{Name}/SKILL.md` + 可选 reference.md 等附件
- **加权评分匹配**：name(×4) + description(×2.5) + triggers(×2) + body(×1)，sqrt 归一化
- **CJK 感知分词**：中英文混合内容正确 tokenize
- **元工具设计**：Skill 不预加载到 prompt，而是通过 find_matching() 按需激活，节省 token
- **Frontmatter 规范**：YAML 头部始终使用 yaml_quote()，防止冒号值解析错误

### 安全特性

- **API 密钥加密**：AES-256-GCM 静态加密，密钥从 Windows MachineGuid 派生，存储于 `models.json`
- **权限绕过三层防御**：错误消息强拒绝 → System Prompt 规则注入 → Shell 模式匹配兜底
- **Shell 命令黑名单**：rm / del / rmdir / format / erase 等破坏性命令在工具层直接阻断
- **密码认证 Dashboard**：`.password` 文件保护的 Web 界面访问控制
- **CDP 浏览器隔离**：chromiumoxide 运行在独立 Chromium 实例中，无用户登录态

### 检查点与崩溃恢复

- 每轮工具调用后持久化对话历史到 SQLite
- 异常断开后可从最近检查点恢复上下文
- 支持会话摘要（summary）压缩，减少历史 token 占用

### Dashboard

密码认证的 SPA 单页应用，功能覆盖 Agent 全生命周期管理：

- **Chat**：实时对话，流式输出，工具调用可视化
- **Settings**：模型配置、Agent 参数调整
- **Skills**：技能浏览、创建、编辑、删除
- **MCP**：MCP 服务器管理与状态监控
- **History**：对话历史检索与回溯
- **CRON**：定时任务管理（增删改查、启停）
- **Tools**：内置工具与外部工具列表
- **Memory**：记忆内容查看与管理
- **Usage**：Token 用量分析图表

## 技术栈

| 组件 | 技术选型 |
|------|----------|
| 运行时 | Tokio (full features) |
| HTTP/WS | Axum 0.8 |
| LLM 协议 | OpenAI-compatible streaming |
| 数据库 | SQLite (rusqlite bundled) + FTS5 |
| MCP | rmcp v1.8.0 (stdio + SSE) |
| 浏览器 | chromiumoxide (CDP) |
| 加密 | aes-gcm (AES-256-GCM) |
| YARA | boreal (规则扫描) |
| PE 解析 | goblin + iced-x86 (反汇编) |
| 序列化 | serde + serde_json + serde_yaml + toml |
| 日志分析 | regex（模式匹配）+ evtx（EVTX 解析） |
| 日志 | tracing + tracing-subscriber (env-filter) |

## 配置

运行时工作目录：`%USERPROFILE%\.RustAgent\workspace\`

```
workspace/
├── config.toml          # 主配置（Server / Agent / Model）
├── models.json          # 模型配置（API Key 加密存储）
├── mcp_servers.json     # MCP 服务器配置
├── cron_tasks.json      # 定时任务定义
├── .password            # Dashboard 访问密码
├── memory/
│   └── memory.db        # SQLite 记忆数据库
├── knowledge/           # 知识蒸馏输出（append-only）
├── skills/              # 技能目录
├── tools/               # 外部工具目录
├── logs/                # JSONL 对话日志
├── static/              # Dashboard 静态资源
└── output/              # 工具输出（截图/报告等）
```

## 构建与运行

```bash
# 编译 release 版本（~28MB，LTO + strip）
cargo build --release

# 二进制产物
target/release/rust-agent.exe

# 首次运行自动创建 workspace 目录结构
.\target\release\rust-agent.exe
```

Release profile 配置：`opt-level = 3`、`lto = true`、`strip = true`，确保最小二进制体积与最优运行性能。

## 项目结构

```
src/
├── main.rs              # 入口：workspace 初始化、依赖装配、启动服务器
├── server.rs            # Axum HTTP/WS 服务器、REST API、SSE 流
├── config.rs            # TOML 配置加载
├── agent/
│   ├── mod.rs           # Agent trait、EventStream 类型
│   ├── llm_agent.rs     # LlmAgent：Agentic Loop、工具执行、历史裁剪
│   └── event.rs         # AgentEvent（9 种事件类型）
├── model/
│   ├── mod.rs           # Llm trait、ChatMessage、ToolDefinition
│   └── openai.rs        # OpenAI-compatible streaming client
├── tool/
│   ├── mod.rs           # Tool trait、ToolRegistry、二进制解析
│   ├── file_ops.rs      # 文件操作 5 工具
│   ├── shell_exec.rs    # Shell 执行（危险命令拦截）
│   ├── mcp_client.rs    # MCP 客户端管理器
│   ├── memory_md.rs     # MEMORY.md 读写
│   ├── cron_manage.rs   # CRON 任务管理
│   ├── todo_update.rs   # 任务规划跟踪
│   ├── ir_*.rs          # 事件响应工具（13 个，含日志分析）
│   └── malware_*.rs     # 恶意软件分析（YARA + PE）
├── permission.rs        # 权限检查器（分类门控 + 异步授权）
├── memory.rs            # MemoryStore（SQLite + FTS5）
├── distill.rs           # 知识蒸馏引擎
├── scheduler.rs         # CRON 调度器
├── heartbeat.rs         # 心跳健康检查
├── skill/
│   ├── mod.rs           # SkillManager
│   └── types.rs         # SelectionPolicy、加权评分
├── crypto.rs            # AES-256-GCM 加密
├── checkpoint.rs        # 对话检查点（崩溃恢复）
├── runner.rs            # 会话管理、Agent 调度
├── context.rs           # 上下文层级（Readonly → Callback → Tool）
├── callbacks.rs         # 生命周期钩子
├── error.rs             # 结构化错误
├── model_store.rs       # 模型配置持久化（加密 API Key）
├── external_tools.rs    # 外部工具发现
├── log/                 # JSONL 日志
└── web/                 # 静态文件服务
```

## License

MIT
