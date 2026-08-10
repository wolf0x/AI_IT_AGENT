TOOLS.md — 本地环境配置

## Windows 执行规则

### 核心规则

1. **所有可执行文件调用必须显式添加 `.exe` 扩展名**  
   ✅ 正确：`python.exe script.py`、`git.exe status`  
   ❌ 错误：`python script.py`（可能触发文件关联或模糊匹配）

2. **若程序不在系统 `%PATH%` 中，必须使用完整绝对路径**  
   可用 `where.exe <命令>` 查询路径（例如 `where.exe python`）

3. **PowerShell 脚本调用统一使用 `powershell.exe -File <脚本路径>`**  
   或使用 `pwsh.exe`（若安装 PowerShell Core）

4. **CMD 内部命令（如 `dir`、`copy`、`del`）无需后缀，但外部工具需遵循规则**

5. **路径含空格时必须加引号**  
   示例：`"C:\Program Files\Git\bin\git.exe"`

### 本地路径（按实际环境修改）

- Git: `"C:\Program Files\Git\bin\git.exe"`
- Python: `"C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python312\python.exe"`
- Node: `"C:\Program Files\nodejs\node.exe"`
- 工作区: `%USERPROFILE%\.RustAgent\workspace`
- 产出物: `%USERPROFILE%\.RustAgent\workspace\output`

### 产出物规范

**所有文件产出必须写入 `output/` 目录**，使用描述性文件名：

- 报告: `output/ir_report_2026-08-07_suspicious_process.html`
- 截图: `output/screenshot_desktop_2026-08-07_143022.png`
- 分析结果: `output/yara_scan_results_2026-08-07.json`

**引用产出物时，使用工具返回的完整路径**（已自动转换为正斜杠格式），不要简化为文件名。

## 本地环境备注

_在此添加你的本地环境特定配置：_

- SSH 主机: （待配置）
- 摄像头名称: （待配置）
- 语音偏好: （待配置）
- 其他: （待配置）
