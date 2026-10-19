"""Window computation (KTD7): constructs, diff mapping, segments, window text."""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

from redpen.semgrep import run_semgrep

CONSTRUCTS_RULES = Path(__file__).parent / "constructs.yaml"

# Per language: rule ids in enclosing order (first tier with a containing
# construct wins, smallest within the tier), and the comment prefix.
ENCLOSING_ORDER = {
    "go": ["go-func"],
    "python": ["py-def", "py-class"],
    "typescript": ["ts-class", "ts-func"],
    "javascript": ["js-class", "js-func"],
}
COMMENT = {"go": "//", "python": "#", "typescript": "//", "javascript": "//"}

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)


class WindowError(Exception):
    pass


class Span(NamedTuple):
    start: int
    end: int


class Construct(NamedTuple):
    kind: str
    start: int
    end: int


class Hunk(NamedTuple):
    a: int
    b: int
    c: int
    d: int


def _check_language(language: str) -> None:
    if language not in ENCLOSING_ORDER:
        raise WindowError(f"unsupported language: {language}")


def split_lines(text: str) -> list[str]:
    """Split on "\\n" only, keeping line endings; a final unterminated line is kept."""
    parts = text.split("\n")
    lines = [p + "\n" for p in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


def find_constructs(path, language: str) -> list[Construct]:
    _check_language(language)
    run = run_semgrep(CONSTRUCTS_RULES, Path(path))
    if run.errors:
        raise WindowError(f"semgrep errors finding constructs in {path}: {run.errors}")
    kinds = set(ENCLOSING_ORDER[language])
    out = []
    for m in run.matches:
        kind = m.check_id.rsplit(".", 1)[-1]
        if kind in kinds:
            out.append(Construct(kind, m.start_line, m.end_line))
    return sorted(set(out), key=lambda c: (c.start, c.end, c.kind))


def enclosing(span: Span, constructs: list[Construct], language: str) -> Span:
    _check_language(language)
    for kind in ENCLOSING_ORDER[language]:
        containing = [
            c for c in constructs
            if c.kind == kind and c.start <= span.start and span.end <= c.end
        ]
        if containing:
            best = min(containing, key=lambda c: c.end - c.start)
            return Span(best.start, best.end)
    return Span(span.start, span.end)


def parse_diff_u0(text: str) -> list[Hunk]:
    hunks = []
    for m in _HUNK_RE.finditer(text):
        a, b, c, d = m.groups()
        hunks.append(Hunk(int(a), 1 if b is None else int(b), int(c), 1 if d is None else int(d)))
    return hunks


def fix_spans_old(hunks: list[Hunk]) -> list[Span]:
    out = []
    for h in hunks:
        if h.b > 0:
            out.append(Span(h.a, h.a + h.b - 1))
        else:
            out.append(Span(max(h.a, 1), h.a + 1))
    return out


def added_runs_new(hunks: list[Hunk]) -> list[Span]:
    return [Span(h.c, h.c + h.d - 1) for h in hunks if h.d > 0]


def map_old_to_new(line: int, hunks: list[Hunk]) -> int:
    delta = 0
    for h in sorted(hunks, key=lambda h: h.a):
        if h.b == 0:
            if line <= h.a:
                return line + delta
        else:
            if line < h.a:
                return line + delta
            if line <= h.a + h.b - 1:
                if h.d == 0:
                    return h.c
                return min(h.c + (line - h.a), h.c + h.d - 1)
        delta += h.d - h.b
    return line + delta


def _merge(spans: list[Span]) -> list[Span]:
    out: list[Span] = []
    for s in sorted(spans):
        if out and s.start <= out[-1].end + 1:
            out[-1] = Span(out[-1].start, max(out[-1].end, s.end))
        else:
            out.append(Span(s.start, s.end))
    return out


def _with_context(cores: list[Span], n_lines: int, context: int) -> list[Span]:
    return _merge(
        [Span(max(1, c.start - context), min(n_lines, c.end + context)) for c in cores]
    )


def vuln_segments(targets, constructs, language, n_lines, context=3):
    """Return (segments, cores); cores are the merged enclosing ranges before context."""
    cores = _merge([enclosing(t, constructs, language) for t in targets])
    return _with_context(cores, n_lines, context), cores


def fixed_segments(vuln_cores, hunks, fixed_constructs, language, n_lines, context=3):
    cores = []
    for core in vuln_cores:
        mapped = Span(map_old_to_new(core.start, hunks), map_old_to_new(core.end, hunks))
        cores.append(enclosing(mapped, fixed_constructs, language))
    for run in added_runs_new(hunks):
        cores.append(enclosing(run, fixed_constructs, language))
    return _with_context(_merge(cores), n_lines, context)


def _gap(prev: Span, seg: Span) -> Span | None:
    if seg.start > prev.end + 1:
        return Span(prev.end + 1, seg.start - 1)
    return None


def build_window_text(lines: list[str], segments, language: str, header_lines: list[str]) -> str:
    """lines are the original file lines with endings kept (see split_lines)."""
    _check_language(language)
    parts = [h + "\n" for h in header_lines]
    prev = None
    for seg in segments:
        if prev is not None:
            gap = _gap(prev, seg)
            if gap:
                parts.append(f"{COMMENT[language]} ... lines {gap.start}-{gap.end} omitted ...\n")
        parts.extend(lines[seg.start - 1:seg.end])
        prev = seg
    return "".join(parts)


def _layout(segments):
    """Yield ("gap", Span) or ("code", original_line) for each window line after the header."""
    prev = None
    for seg in segments:
        if prev is not None:
            gap = _gap(prev, seg)
            if gap:
                yield "gap", gap
        for n in range(seg.start, seg.end + 1):
            yield "code", n
        prev = seg


def window_to_original(window_line: int, header_line_count: int, segments) -> int | None:
    idx = window_line - header_line_count
    if idx < 1:
        return None
    for i, (kind, value) in enumerate(_layout(segments), start=1):
        if i == idx:
            return value if kind == "code" else None
    return None


def render_numbered(window_text: str, header_line_count: int, segments) -> str:
    body = split_lines(window_text)[header_line_count:]
    out = []
    for line, (kind, value) in zip(body, _layout(segments)):
        if kind == "gap":
            out.append(f"{'':6}  ... (lines {value.start}-{value.end} omitted)\n")
        else:
            out.append(f"{value:>6}  {line.rstrip(chr(10)).rstrip(chr(13))}\n")
    return "".join(out)


def location_selectivity(window_code_original_lines, expected_spans, tolerance=5) -> float:
    """Fraction of window code lines within tolerance of any expected span (KTD9)."""
    lines = list(window_code_original_lines)
    if not lines:
        return 0.0
    spans = [
        (s["start"], s["end"]) if isinstance(s, dict) else (s.start, s.end)
        for s in expected_spans
    ]
    located = sum(
        1 for n in lines if any(a - tolerance <= n <= b + tolerance for a, b in spans)
    )
    return located / len(lines)
