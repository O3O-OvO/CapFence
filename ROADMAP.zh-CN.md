# CapFence 演进路线

CapFence 的长期目标是成为 AI Agent Skill 与 MCP Server 的权限变化防火墙：不仅告诉用户“发现了什么”，还要解释能力从哪里来、会触达什么资源，以及一次变更扩大了哪条权限链路。

## 已完成：v0.1.x

- 静态发现 Skill、MCP 配置、脚本、源码和 Dockerfile。
- 提取 7 类能力，检测 9 类确定性风险。
- 支持 baseline、diff、YAML policy、JSON/SARIF/GitHub 输出。
- 提供 GitHub Composite Action、CLI 黑盒测试和双语文档。

## 当前阶段：v0.2 能力图谱

目标是把扫描结果组织为可消费的关系图：

```text
扫描目标 -> 源码文件 -> 能力 -> 风险发现
```

当前已提供：

```bash
node dist/cli.js graph path/to/skill-or-mcp-config
```

输出是稳定排序的 JSON，节点类型包括 `target`、`source`、`capability`、`finding`，边类型包括 `contains`、`declares`、`evidences`。它可以直接作为 PR 摘要、Web 可视化或后续运行时事件关联的输入。

## 后续阶段

### v0.2.x：提高准确度

- 为 JavaScript/TypeScript/Python 引入 AST 和有限变量传播。
- 为 Shell 增加命令分词、多行管道和参数来源分析。
- 支持 TOML、`.env`、Docker Compose 和更多 MCP 配置方言。
- 用真实 Skill/MCP 样本建立误报与漏报回归集。

### v0.3：治理与供应链

- 增加路径、二进制、域名通配和例外过期策略。
- 为 baseline 增加迁移、完整性哈希、审批记录和签名。
- 检查 lockfile、包完整性和 Action 固定 SHA。

### v0.4：运行时与协作

- 增加可选运行时观测，记录网络、文件和子进程事件。
- 对比“声明能力”和“实际能力”。
- 在 SARIF、PR 摘要和评论中展示权限变化路径。
- 提供 npm 正式包、可复现 Action 产物和 provenance。

## 不变的设计边界

CapFence 默认是静态审查工具，不是沙箱、恶意软件判定器或运行时防护。所有更强的语义分析和运行时观测都应保持可解释、可关闭，并在报告中区分“可能能力”和“实际事件”。
