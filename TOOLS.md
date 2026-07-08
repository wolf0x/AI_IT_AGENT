TOOLS.md — Windows 执行规则

## Chrome CDP 调试
- `browser_cdp` 需要 Chrome 以远程调试模式启动：`chrome.exe --remote-debugging-port=9222`
- 先用 `app_launch` 启动 Chrome + 调试端口，再用 `browser_cdp` 截图或操作

## 核心规则

1. **所有可执行文件调用必须显式添加 `.exe` 扩展名**  
  ✅ 正确：`python.exe script.py`、`git.exe status`  
  ❌ 错误：`python script.py`（可能触发文件关联或模糊匹配）
2. **若程序不在系统 `%PATH%` 中，必须使用完整绝对路径**  
  示例：`C:\Program Files\Git\bin\git.exe`  
  可用 `where.exe <命令>` 查询路径（例如 `where.exe python`）
3. **PowerShell 脚本调用统一使用 `powershell.exe -File <脚本路径>`**  
  或使用 `pwsh.exe`（若安装 PowerShell Core）
4. **CMD 内部命令（如 `dir`、`copy`）无需后缀，但外部工具需遵循规则**

## 常用路径速查（按需添加）
- 用户目录: C:\Users\%USERNAME%
- 下载: C:\Users\%USERNAME%\Downloads
- 系统工具: C:\Windows\System32  
- 临时目录: %TEMP% (环境变量)

## 工具路径示例（视安装位置调整）
- Git: `C:\Program Files\Git\bin\git.exe`
- Python: `C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python312\python.exe`
- Node: `C:\Program Files\nodejs\node.exe`