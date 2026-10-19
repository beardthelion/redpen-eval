"""Deterministic mock reviewer keyed by case id and side (R19)."""

from __future__ import annotations

from pathlib import Path

from redpen.reviewers import ReviewerError, ReviewRequest, ReviewResult
from redpen.window import Span, split_lines, window_to_original

MOCK_META = {"model": None, "system_fingerprint": None, "finish_reason": None,
             "usage": None, "latency_s": 0.0, "truncated": False}


def _original_line_text(case, line: int) -> str:
    info = case.data["vuln"]
    segments = [Span(s["start"], s["end"]) for s in info["segments"]]
    for i, text in enumerate(split_lines(case.vuln_text), start=1):
        if window_to_original(i, info["header_lines"], segments) == line:
            return text.strip()
    return ""


class MockReviewer:
    def __init__(self, name: str, entry: dict):
        self.name = name
        self.defaults = {"vuln": entry.get("vuln", "hit"), "fixed": entry.get("fixed", "clean")}
        self.overrides = entry.get("overrides") or {}

    def review(self, request: ReviewRequest) -> ReviewResult:
        case, side = request.case, request.side
        mode = self.overrides.get(case.case_id, {}).get(side, self.defaults[side])
        basename = Path(case.data[side]["file"]).name
        cls = case.guard_class
        spans = case.data["vuln"]["expected_spans"]
        if mode == "error":
            raise ReviewerError("http_error", "mock error")
        if mode == "empty":
            text = ""
        elif mode == "hit":
            line = spans[0]["start"]
            text = (f"FINDING: file={basename} line={line} class={cls}\n"
                    f"quote: {_original_line_text(case, line)}")
        elif mode == "partial":
            line = max(s["end"] for s in spans) + 50
            text = f"FINDING: file={basename} line={line} class={cls}"
        elif mode == "miss":
            text = f"FINDING: file={basename} line=1 class=unrelated-issue"
        elif mode == "clean":
            text = "No security vulnerabilities found."
        else:  # fp
            line = case.data["fixed"]["segments"][0]["start"]
            text = f"FINDING: file={basename} line={line} class={cls}"
        return ReviewResult(text=text, meta=dict(MOCK_META))
