# PR Guardian

> GitHub PR 自动化审查工具 - 双层流水线（确定性规则 + LLM 辅助）

## 概述

PR Guardian 是一个面向 Pull Request 质量守护的 Python 工具，采用**双层流水线**架构：

1. **Deterministic Rule Engine** - 确定性规则引擎，稳定可复现
2. **LLM Review Layer** - LLM 辅助审查，理解上下文

**核心原则**：先硬规则，再 LLM；LLM 只出结构化 JSON 且必须给证据。

## 功能特性

### 内置规则（P0）

| 规则 ID | 名称 | 严重级 | 说明 |
|---------|------|--------|------|
| `security/secrets-scan` | 硬编码密钥扫描 | error | 检测 AWS/GitHub/OpenAI 等密钥泄露 |
| `deps/lockfile-consistency` | Lockfile 一致性 | error | 确保 manifest 与 lockfile 同步 |
| `monorepo/affected-tests` | 受影响测试 | warning | 检查变更是否声明测试 |
| `ci/min-permissions` | 权限最小化 | error | 审查 GitHub Actions 权限 |
| `quality/changelog-breaking` | Breaking Change | error | 检查 breaking change 是否有 changelog |

### 输出通道

- **Check Run** - 用于 gating（error → fail）
- **Review Comments** - 行内批注
- **PR 总结 Comment** - 按 Security/Correctness/CI/Monorepo 分组

### LLM Provider 支持

- OpenAI (GPT-4o)
- GLM (智谱)
- MiniMax
- Kimi (月之暗面)

## 环境要求

- Python 3.11+
- GitHub Personal Access Token

## 安装

```bash
# 克隆仓库
cd pr-guardian

# 安装项目
pip install -e .

# 安装开发依赖（测试、lint）
pip install -e ".[dev]"
```

## 快速开始

### 1. 配置环境变量

```bash
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"
```

### 2. 运行审查

```bash
# 审查 PR
pr-guardian review --repo owner/repo --pr 123

# 模拟运行（不发布结果）
pr-guardian review --repo owner/repo --pr 123 --dry-run

# 禁用 LLM 审查
pr-guardian review --repo owner/repo --pr 123 --no-llm
```

### 3. 配置文件

在项目根目录创建 `.pr-guardian.yml`：

```yaml
mode:
  gate: true            # error 级别阻断合并
  auto_fix: false       # 是否允许自动修复

scope:
  include: ["src/**", "lib/**"]
  exclude: ["vendor/**", "*.generated.*"]

rules:
  enabled:
    - security/secrets-scan
    - deps/lockfile-consistency
    - monorepo/affected-tests
    - ci/min-permissions
    - quality/changelog-breaking
  severity_overrides:
    monorepo/affected-tests: error

llm:
  enabled: true
  provider: openai
  model: gpt-4o
  max_context_tokens: 8000
  budget_usd_per_pr: 0.50
  strategy:
    only_when: ["large_diff", "security_related"]

policy:
  deny_paths: [".github/workflows/**"]
  max_changed_lines_for_autofix: 50
  require_evidence: true
```

## 项目结构

```
pr-guardian/
├── pyproject.toml              # 项目配置
├── .pr-guardian.yml             # 示例配置
├── README.md
├── src/pr_guardian/
│   ├── __init__.py
│   ├── main.py                  # CLI 入口
│   ├── models.py                # 领域模型（Finding, Diff, Policy）
│   ├── diffparse.py             # Diff 解析器
│   ├── github_api.py            # GitHub API 接入
│   ├── policy.py                # 策略配置加载
│   ├── context_builder.py       # 上下文构建 + 脱敏
│   ├── rules/                   # 规则引擎
│   │   ├── base.py              # 规则基类 + 注册表
│   │   ├── secrets_scan.py      # 密钥扫描
│   │   ├── lockfile_consistency.py
│   │   ├── affected_tests.py
│   │   ├── min_permissions.py
│   │   └── changelog_breaking.py
│   ├── llm/                     # LLM 适配层
│   │   ├── schema.py            # Pydantic 输出模型
│   │   ├── prompts.py           # System prompts
│   │   ├── client.py            # 抽象接口
│   │   └── providers/           # Provider 实现
│   │       ├── openai.py
│   │       ├── glm.py
│   │       ├── minimax.py
│   │       └── kimi.py
│   └── report/
│       └── github_reporter.py   # 三通道输出
└── tests/                       # 测试套件（73个测试）
```

## 开发指南

### 运行测试

```bash
# 全部测试
pytest

# 带覆盖率
pytest --cov=src/pr_guardian
```

### 代码质量

```bash
# Lint
ruff check .

# 类型检查
mypy src/pr_guardian
```

### 添加新规则

1. 继承 `Rule` 基类：
```python
from pr_guardian.rules.base import Rule
from pr_guardian.models import Finding, Diff, Policy, Severity

class MyRule(Rule):
    rule_id = "custom/my-rule"
    title = "我的规则"
    default_severity = Severity.WARNING
    
    def execute(self, diff: Diff, policy: Policy) -> list[Finding]:
        # 实现检查逻辑
        return findings
```

2. 在 `rules/__init__.py` 注册：
```python
from pr_guardian.rules.my_rule import MyRule
registry.register(MyRule)
```

## 架构设计

### 双层流水线

```
PR Event
  → github_api 拉取 diff
  → diffparse 解析 hunks + 行号
  → context_builder 裁剪 + 脱敏
  → rules/* 执行硬规则 → Finding[]
  → (可选) llm/* LLM 审查 → Finding[]
  → report/* 输出到 GitHub 三通道
```

### Finding 结构

```json
{
  "id": "security/secrets-scan#1",
  "rule_id": "security/secrets-scan",
  "title": "硬编码 API Key 泄露",
  "severity": "error",
  "message": "在 src/config.py L42 发现疑似 API Key",
  "evidence": [
    { "file": "src/config.py", "line": 42, "snippet": "API_KEY = 'sk-...'" }
  ],
  "tags": ["security", "secrets"],
  "confidence": 0.98,
  "fix": null
}
```

## 许可证

MIT License
