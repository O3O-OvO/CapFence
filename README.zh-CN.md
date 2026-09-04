# CapFence

[English](README.md) | [简体中文](README.zh-CN.md)

面向 AI Agent Skill 与 MCP Server 的能力差异安全检查工具。

CapFence 对仓库做静态分析，回答一个用于代码审查的实际问题：**这个 Agent、Skill、Server 或构建钩子能够做什么，它的能力是否发生了变化？** 它不会执行被扫描目录中的任何命令。

首个版本刻意保持小而确定：提取能力清单，为高信号风险模式提供源码位置，并与提交到仓库中的基线比较，让 Pull Request 可以按权限变化进行审查。

## 检测内容

| 能力 | 示例 |
| --- | --- |
| `process.execute` | Shell 启动器、子进程 API、提权命令 |
| `filesystem.read` | 敏感路径、外部工作目录、环境文件 |
| `filesystem.write` | 下载后再执行的落地文件 |
| `network.connect` | MCP URL、运行时网络请求、下载脚本 |
| `credential.read` | 注入的密钥环境变量、硬编码令牌 |
| `dynamic.execute` | `eval`、带模板的 Shell 输入、编码命令 |
| `package.lifecycle` | `npx`/`uvx` 运行时包解析、npm 生命周期钩子 |

CapFence 将“能力”与“风险发现”分开处理。正常的 `npx package@1.2.3` 启动会被记录为能力；未固定版本的包、将下载内容直接交给 Shell 执行、嵌入式密钥、远程明文 HTTP MCP 端点或提权操作，则还会产生风险发现。

当前确定性规则包括：

- `CF-EXEC-001`：动态进程或解释器输入
- `CF-EXEC-002`：远程内容直接通过管道交给解释器
- `CF-EXEC-003`：下载文件后执行
- `CF-DYN-001`：执行编码或解码后的内容
- `CF-CRED-001`：敏感文件与出站上传同时出现
- `CF-CRED-002`：活动内容或 MCP 配置中嵌入了凭据材料
- `CF-PKG-001`：未固定版本的运行时包执行
- `CF-PRIV-001`：提权进程或削弱容器权限边界
- `CF-MCP-001`：动态 MCP 命令、动态端点或远程明文 HTTP

## 安装与运行

需要 Node.js 20 或更高版本。

先克隆仓库并构建：

```bash
git clone https://github.com/O3O-OvO/CapFence.git
cd CapFence
corepack enable
pnpm install
pnpm run build

# 扫描一个 Skill、MCP 配置或仓库
node dist/cli.js scan .

# 机器可读输出
node dist/cli.js scan . --format json
node dist/cli.js scan . --format sarif --output capfence.sarif

# GitHub Workflow 注解
node dist/cli.js scan . --format github
```

`npx capfence` 需要在 npm 发布后才能用于任意外部目录；在发布前，请使用本地构建的 `node dist/cli.js`。

支持的输入包括 Markdown Skill/指令文件、JSON/JSONC、YAML、JavaScript/TypeScript、Python、Shell/PowerShell/Command 脚本、`package.json` 与 Dockerfile。Markdown 仅检查显式标注为 Shell 或 PowerShell 的代码块。超过 2 MiB 的文件以及常见依赖/构建目录会被跳过。TOML 和 `.env` 尚未被声明为支持格式，直到有具备结构化解析与可靠定位能力的分析器。

## 能力基线

创建可审查的基线文件，并把它提交到目标仓库：

```bash
node dist/cli.js baseline path/to/project --output capfence.baseline.json
```

之后比较能力变化：

```bash
node dist/cli.js diff path/to/project --baseline capfence.baseline.json
```

能力身份由归一化后的 `kind + scope` 决定，而不是来源文件位置。移动同一个启动器不会产生权限变更；新增主机会显示为 `added`，旧主机会显示为 `removed`；固定主机变为 `dynamic` 会显示为 `widened`。默认情况下，`diff` 与带有 `--baseline` 的 `scan` 在发现新增或扩大的能力时都会失败。需要仅报告而不阻断时，使用 `--allow-changes`。

基线还保存稳定的发现身份。使用 `--fail-on` 时，已存在于基线中的发现不会导致后续扫描失败，除非指定 `--fail-existing`。

导出可用于可视化和 Pull Request 摘要的稳定 JSON 能力图：

```bash
node dist/cli.js graph path/to/project --output capfence.graph.json
# 添加 --baseline 后，能力节点会标注 added、removed 或 widened。
node dist/cli.js graph path/to/project --baseline capfence.baseline.json --output capfence.graph.json
```

## 策略

使用简洁的 YAML 策略拒绝新增能力，并限制网络主机：

```yaml
deny:
  - capability: dynamic.execute
    severity: critical
    reason: 动态执行必须经过明确审查。
  - capability: filesystem.read
    scope: sensitive-path
    severity: high
network:
  allow:
    - api.github.com
    - example.com
```

结合基线执行策略检查：

```bash
node dist/cli.js diff path/to/project \
  --baseline capfence.baseline.json \
  --policy examples/policy.yml \
  --format github \
  --fail-on high
```

策略仅应用于 `added` 与 `widened` 能力。已移除能力会显示在 diff 中，但不会产生策略违规。

## GitHub Actions

CapFence 提供可复用 Composite Action。Action 会为自身的构建和扫描步骤准备 Node 20 与 Corepack/pnpm，并假设使用 GitHub-hosted Ubuntu runner。生产工作流仍应固定到经过审查的提交 SHA，而不是浮动分支名：

```yaml
name: CapFence

on:
  pull_request:

permissions:
  contents: read

jobs:
  capfence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      # 将 <COMMIT_SHA> 替换为经审查的 CapFence 提交 SHA。
      - uses: O3O-OvO/CapFence@<COMMIT_SHA>
        with:
          path: .
          baseline: capfence.baseline.json
          policy: examples/policy.yml
          format: github
          fail-on: high
```

注意：包含演示攻击样例、测试夹具或安全规则源码的仓库不应直接扫描整个根目录。请将 `path` 指向实际要发布的 Skill/MCP 配置目录，或先生成与目标目录匹配的基线。

要上传 SARIF，设置 `format: sarif` 与 `output: capfence.sarif`，然后在下一步使用 `github/codeql-action/upload-sarif` 上传文件。该工作流还需要 `security-events: write` 权限。

退出码：

- `0`：扫描完成，且未命中配置的严重级别、策略违规或能力变更失败条件
- `1`：发现命中 `--fail-on` 的风险、策略违规，或发现新增/扩大能力且未指定 `--allow-changes`
- `2`：CLI 参数、策略、基线无效，或目标无法读取

## 设计边界

CapFence 是静态审查信号，不是沙箱、恶意软件判定器或运行时监控器。它不会解析变量、跨仓库跟踪任意 package script、发起网络请求、读取密钥存储，或证明一个固定主机可信。解析失败会出现在 `analysisLimited` 中，而不会悄悄降级为无限制全文扫描。文本、JSON、SARIF 或 GitHub 注解输出前，证据都会被截断并脱敏。

## 开发

```bash
corepack enable
pnpm install
pnpm run check
pnpm test
pnpm run build
```

项目使用 TypeScript/ESM，扫描过程不需要网络访问。每个新增规则都应在 `tests/fixtures` 中添加专门的安全与风险夹具，并验证发现与安全反例。规则不得执行命令、请求 URL、展开变量或读取密钥存储。

## 许可证

Apache-2.0，见 [LICENSE](LICENSE)。
