"""PR Guardian 领域模型定义。"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """表示规则发现的严重级别。"""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class Location(BaseModel):
    """表示文件中的定位信息，可映射到 PR 左右侧行。"""

    file: str
    start_line: int | None = None
    end_line: int | None = None
    side: Literal["LEFT", "RIGHT"] | None = None


class Evidence(BaseModel):
    """表示支持规则发现的具体证据片段。"""

    file: str
    line: int
    snippet: str


class FixSuggestion(BaseModel):
    """表示可选的自动修复建议及其替换范围。"""

    description: str
    replacement: str | None = None
    file: str
    line_start: int
    line_end: int


class Finding(BaseModel):
    """表示单条规则在 PR 中发现的问题。"""

    id: str
    rule_id: str
    title: str
    severity: Severity
    message: str
    evidence: list[Evidence]
    tags: list[str]
    confidence: float = Field(ge=0.0, le=1.0)
    fix: FixSuggestion | None = None


class Hunk(BaseModel):
    """表示单个 Diff 块及其行级映射信息。"""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[tuple[str, int | None, int | None]]


class DiffFile(BaseModel):
    """表示 PR 中单个文件的变更内容。"""

    path: str
    status: Literal["added", "removed", "modified", "renamed"]
    patch: str | None = None
    additions: int
    deletions: int
    hunks: list[Hunk]


class Diff(BaseModel):
    """表示 PR 的整体 Diff 结构。"""

    files: list[DiffFile]


class Policy(BaseModel):
    """表示 PR Guardian 的策略配置与执行开关。"""

    gate: bool
    auto_fix: bool
    include: list[str]
    exclude: list[str]
    enabled_rules: list[str]
    severity_overrides: dict[str, Severity]
    allowlist: dict[str, list[str]] = Field(default_factory=dict)
    lockfile_mappings: dict[str, list[str]] = Field(default_factory=dict)
    llm_enabled: bool
    llm_provider: str
    llm_model: str
    llm_max_context_tokens: int
    llm_budget_usd: float
    deny_paths: list[str]
    max_changed_lines_for_autofix: int
    require_evidence: bool


__all__ = [
    "Severity",
    "Location",
    "Evidence",
    "Finding",
    "FixSuggestion",
    "Diff",
    "DiffFile",
    "Hunk",
    "Policy",
]
