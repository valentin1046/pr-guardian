# pyright: reportMissingImports=false, reportUnknownVariableType=false
from __future__ import annotations

from pydantic import BaseModel, Field

from ..models import Evidence, FixSuggestion, Severity


class LLMReviewFinding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    message: str
    evidence: list[Evidence] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    suggested_fix: FixSuggestion | None = None
    tags: list[str] = Field(default_factory=list)


class LLMReviewResult(BaseModel):
    findings: list[LLMReviewFinding] = Field(default_factory=list)
    questions: list[str] | None = None


__all__ = ["LLMReviewFinding", "LLMReviewResult"]
