# pyright: reportMissingImports=false
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any, TypeVar

from pydantic import BaseModel

from pr_guardian.models import Finding

Message = dict[str, Any]
StructuredOutputModel = TypeVar("StructuredOutputModel", bound=BaseModel)


class LLMClient(ABC):
    @abstractmethod
    async def generate_structured(
        self,
        *,
        model: str,
        messages: Sequence[Message],
        schema: type[StructuredOutputModel],
    ) -> tuple[StructuredOutputModel | None, list[Finding]]:
        pass

    @abstractmethod
    def estimate_tokens(self, messages: Sequence[Message]) -> int:
        pass

    @abstractmethod
    async def aclose(self) -> None:
        pass


__all__ = ["LLMClient", "Message", "StructuredOutputModel"]
