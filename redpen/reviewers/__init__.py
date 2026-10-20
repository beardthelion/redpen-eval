"""Reviewer interface (R9). Real adapters send only request.prompt."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Protocol

from redpen.config import Config, ConfigError, require_configured
from redpen.dataset import Case


@dataclass
class ReviewRequest:
    prompt: str
    case: Case
    side: Literal["vuln", "fixed"]


@dataclass
class ReviewResult:
    text: str
    meta: dict = field(default_factory=dict)


class ReviewerError(Exception):
    def __init__(self, kind: str, message: str, status: int | None = None):
        super().__init__(f"{kind}: {message}")
        self.kind = kind
        self.message = message
        self.status = status  # HTTP status when the error came from a response


class Reviewer(Protocol):
    def review(self, request: ReviewRequest) -> ReviewResult: ...


def make_reviewer(name: str, config: Config) -> Reviewer:
    if name not in config.reviewers:
        raise ConfigError(f"unknown reviewer {name!r}")
    entry = config.reviewers[name]
    require_configured("reviewer", name, entry)
    if entry["adapter"] == "mock":
        from redpen.reviewers.mock import MockReviewer
        return MockReviewer(name, entry)
    if entry["adapter"] == "openai_compat":
        from redpen.reviewers.openai_compat import OpenAICompatReviewer
        return OpenAICompatReviewer(name, entry)
    raise ConfigError(f"reviewer {name!r}: adapter {entry['adapter']!r} is not available")
