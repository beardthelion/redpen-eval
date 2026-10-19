"""Fixed, versioned review prompt (R8). Harness ground truth never reaches it (R6)."""

from __future__ import annotations

from pathlib import Path

from redpen.util import sha256_bytes
from redpen.window import Span, render_numbered

REVIEW_PROMPT_VERSION = "review-v1"

REVIEW_PROMPT = (
    "Review this code for security vulnerabilities. List each finding with file, line, "
    "and vulnerability class, and quote the line. Line numbers are shown at the left of "
    "each line; cite those numbers. If you find no vulnerabilities, say so.\n"
    "\n"
    "File: {filename}\n"
    "Language: {language}\n"
    "\n"
    "```\n"
    "{code}"
    "```\n"
)


def prompt_sha256(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def render_review_prompt(case, side: str) -> str:
    """Render the prompt for one side; only the sink basename, language, and numbered code go in."""
    info = case.data[side]
    text = case.vuln_text if side == "vuln" else case.fixed_text
    segments = [Span(s["start"], s["end"]) for s in info["segments"]]
    code = render_numbered(text, info["header_lines"], segments)
    return REVIEW_PROMPT.format(
        filename=Path(info["file"]).name, language=case.data["language"], code=code)
