from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EmbeddingModelFamily(str, Enum):
    MINILM = "minilm"
    BGE = "bge"
    E5 = "e5"


@dataclass(frozen=True)
class EmbeddingModelConfig:
    model_name: str
    family: EmbeddingModelFamily

    def format_document(self, text: str) -> str:
        if self.family is EmbeddingModelFamily.E5:
            return f"passage: {text}"

        return text

    def format_query(self, query: str) -> str:
        if self.family is EmbeddingModelFamily.E5:
            return f"query: {query}"

        return query