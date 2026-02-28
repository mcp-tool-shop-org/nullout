<p align="center">
  <a href="README.ja.md">日本語</a> | <a href="README.md">English</a> | <a href="README.es.md">Español</a> | <a href="README.fr.md">Français</a> | <a href="README.hi.md">हिन्दी</a> | <a href="README.it.md">Italiano</a> | <a href="README.pt-BR.md">Português (BR)</a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/mcp-tool-shop-org/brand/main/logos/nullout/readme.png" width="400" alt="NullOut">
</p>

<p align="center">
  <a href="https://github.com/mcp-tool-shop-org/nullout/actions/workflows/ci.yml"><img src="https://github.com/mcp-tool-shop-org/nullout/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/mcp-tool-shop-org/nullout"><img src="https://codecov.io/gh/mcp-tool-shop-org/nullout/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://github.com/mcp-tool-shop-org/nullout/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License"></a>
  <a href="https://mcp-tool-shop-org.github.io/nullout/"><img src="https://img.shields.io/badge/Landing_Page-live-blue" alt="Landing Page"></a>
</p>

一个用于 Windows 系统的 MCP 服务器，用于查找并安全地删除那些“无法删除”的文件。

Windows 系统在 Win32 层级中预留了一些设备名称，例如 `CON`、`PRN`、`AUX`、`NUL`、`COM1`-`COM9` 以及 `LPT1`-`LPT9`。虽然这些名称的文件可以在 NTFS 文件系统中存在（通过 WSL、Linux 工具或底层 API 创建），但通过资源管理器或常规的 shell 命令，这些文件将变得无法重命名、移动或删除。

NullOut 会扫描这些潜在的危险条目，并使用 `\\?\` 扩展路径命名空间安全地删除它们，采用双阶段确认工作流程，专为 MCP 主机设计。

## 工作原理

1. **扫描** 允许访问的目录，查找预留名称冲突、尾随点/空格以及过长的路径。
2. **规划** 清理过程 — NullOut 为每个条目生成一个确认令牌，该令牌与文件的身份（卷序列号 + 文件 ID）相关联。
3. **删除** 使用令牌 — NullOut 在通过扩展命名空间删除文件之前，会重新验证文件是否已更改（TOCTOU 保护）。

## 安全模型

- **仅允许访问的根目录** — 操作仅限于您明确配置的目录。
- **破坏性操作不使用原始路径** — 删除操作仅接受服务器颁发的查找 ID + 确认令牌。
- **deny_all 重解析策略** — 链接、符号链接和挂载点永远不会被遍历或删除。
- **文件身份绑定** — 令牌使用 HMAC 签名，并与卷序列号 + 文件 ID 相关联；扫描和删除之间任何身份更改都会被拒绝。
- **仅删除空目录** — v1 版本拒绝删除非空目录。
- **结构化错误** — 任何失败都会返回一个机器可读的代码，并提供下一步建议。

## MCP 工具

| 工具 | 类型 | 用途 |
|------|------|---------|
| `list_allowed_roots` | 只读 | 显示配置的扫描根目录 |
| `scan_reserved_names` | 只读 | 在根目录中查找潜在的危险条目 |
| `get_finding` | 只读 | 获取某个条目的详细信息 |
| `plan_cleanup` | 只读 | 生成包含确认令牌的删除计划 |
| `delete_entry` | 可破坏 | 删除文件或空目录（需要令牌） |
| `who_is_using` | 只读 | 识别锁定文件的进程（重启管理器） |
| `get_server_info` | 只读 | 服务器元数据、策略和功能 |

## 配置

通过环境变量设置允许访问的根目录：

```
NULLOUT_ROOTS=C:\Users\me\Downloads;C:\temp\cleanup
```

令牌签名密钥（生成一个随机值）：

```
NULLOUT_TOKEN_SECRET=your-random-secret-here
```

## 威胁模型

NullOut 能够防御以下情况：

- **恶意使用** — 删除操作需要服务器颁发的确认令牌；不接受原始路径。
- **路径遍历** — 所有操作都限制在允许访问的根目录中；`..` 类型的路径会被解析并拒绝。
- **重解析点绕过** — 链接、符号链接和挂载点永远不会被遍历或删除（`deny_all`）。
- **TOCTOU 竞争** — 令牌使用 HMAC 与卷序列号 + 文件 ID 相关联；扫描和删除之间任何身份更改都会被拒绝。
- **命名空间技巧** — 破坏性操作使用 `\\?\` 扩展路径前缀，以绕过 Win32 名称解析。
- **已锁定文件** — 重启管理器属性是只读的；NullOut 永远不会终止进程。
- **非空目录** — 策略禁止删除非空目录；只能删除空目录。

**访问的数据：** 文件系统元数据（名称、文件 ID、卷序列号），进程元数据（PID、通过重启管理器获取的应用程序名称）。
**未访问的数据：** 文件内容、网络、凭据、Windows 注册表。
**不收集或发送任何遥测数据。**

## 系统要求

- Windows 10/11
- Python 3.10+

---

由 <a href="https://mcp-tool-shop.github.io/">MCP Tool Shop</a> 构建。
