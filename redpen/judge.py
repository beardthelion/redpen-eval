"""LLM judge: strict JSON with tiered enforcement and one repair (R12, KTD10)."""

from __future__ import annotations

import json
import re
import secrets
import threading
from dataclasses import dataclass, field
from typing import Literal, Protocol

from redpen import prompts
from redpen.config import Config, ConfigError, require_configured
from redpen.dataset import Case

TIERS = ("json_schema", "json_object", "prompt")
VERDICT_KEY = {"vuln": "verdict_class_match", "fixed": "reported_patched_vuln"}
MOCK_META = {"model": None, "system_fingerprint": None, "finish_reason": None, "usage": None}


@dataclass
class JudgeRequest:
    case: Case
    side: Literal["vuln", "fixed"]
    numbered_code: str
    review_text: str


@dataclass
class RawCompletion:
    text: str
    meta: dict = field(default_factory=dict)


@dataclass
class JudgeOutcome:
    status: str  # "ok" or "error"
    tier: str | None
    repaired: bool
    raw: str | None
    parsed: dict | None
    error: str | None
    response_meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"status": self.status, "tier": self.tier, "repaired": self.repaired,
                "raw": self.raw, "response_meta": self.response_meta, "parsed": self.parsed,
                "error": self.error}


class TierUnsupported(Exception):
    """Raised by a backend when the endpoint rejects a response_format tier."""


class JudgeBackendError(Exception):
    """Raised by a backend for a transport failure left after its own retries."""


class JudgeBackend(Protocol):
    def complete(self, request: JudgeRequest, messages: list[dict],
                 response_format: dict | None) -> RawCompletion: ...


# ------------------------------------------------------------ parsing

def _first_object(text: str) -> str | None:
    start = text.find("{")
    if start < 0:
        return None
    depth, in_str, esc = 0, False, False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _validate(obj, side: str) -> dict:
    key = VERDICT_KEY[side]
    if not isinstance(obj, dict):
        raise ValueError("output is not a JSON object")
    expected = {key, "cited_ranges", "rationale"}
    if set(obj) != expected:
        raise ValueError(f"keys must be exactly {sorted(expected)}, got {sorted(obj)}")
    if not isinstance(obj[key], bool):
        raise ValueError(f"{key} must be a JSON boolean")
    if not isinstance(obj["rationale"], str):
        raise ValueError("rationale must be a string")
    ranges = obj["cited_ranges"]
    if not isinstance(ranges, list):
        raise ValueError("cited_ranges must be a list")
    for r in ranges:
        if not isinstance(r, dict) or set(r) != {"start", "end"}:
            raise ValueError("each cited range must be an object with exactly start and end")
        if not (_is_int(r["start"]) and _is_int(r["end"])):
            raise ValueError("start and end must be integers")
        if r["start"] < 1 or r["end"] < r["start"]:
            raise ValueError("cited range needs start >= 1 and end >= start")
    return obj


def parse_judge_output(text: str, side: str) -> dict:
    """Strict parse, then the first balanced {...} object, then exact key and type checks."""
    try:
        obj = json.loads(text)
    except ValueError:
        candidate = _first_object(text)
        if candidate is None:
            raise ValueError("no JSON object found in output") from None
        try:
            obj = json.loads(candidate)
        except ValueError as exc:
            raise ValueError(f"invalid JSON: {exc}") from None
    return _validate(obj, side)


# ------------------------------------------------------------ requests

def _schema(side: str) -> dict:
    return prompts.JUDGE_VULN_SCHEMA if side == "vuln" else prompts.JUDGE_FIXED_SCHEMA


def build_messages(request: JudgeRequest, nonce: str) -> list[dict]:
    template = prompts.JUDGE_VULN_PROMPT if request.side == "vuln" else prompts.JUDGE_FIXED_PROMPT
    content = template.format(
        guard_class=request.case.guard_class,
        vuln_description=request.case.data["vuln_description"],
        schema=json.dumps(_schema(request.side), sort_keys=True),
        nonce=nonce, code=request.numbered_code, review=request.review_text)
    return [{"role": "user", "content": content}]


def response_format(tier: str, side: str) -> dict | None:
    if tier == "json_schema":
        return {"type": "json_schema",
                "json_schema": {"name": f"redpen_judge_{side}", "strict": True,
                                "schema": _schema(side)}}
    if tier == "json_object":
        return {"type": "json_object"}
    return None


def judge_side(backend: JudgeBackend, request: JudgeRequest, tier: str) -> JudgeOutcome:
    messages = build_messages(request, secrets.token_hex(8))
    tiers = list(TIERS[TIERS.index(tier):])
    repaired = False
    raw, meta = None, {}

    def call(msgs):
        # Walk down the tiers; TierUnsupported is never counted as the repair.
        while True:
            try:
                return backend.complete(request, msgs, response_format(tiers[0], request.side))
            except TierUnsupported:
                if len(tiers) == 1:
                    raise
                tiers.pop(0)

    try:
        completion = call(messages)
        raw, meta = completion.text, completion.meta
        try:
            parsed = parse_judge_output(raw, request.side)
        except ValueError as exc:
            repaired = True
            repair = prompts.JUDGE_REPAIR_PROMPT.format(
                error=exc, schema=json.dumps(_schema(request.side), sort_keys=True))
            completion = call(messages + [{"role": "assistant", "content": raw},
                                          {"role": "user", "content": repair}])
            raw, meta = completion.text, completion.meta
            parsed = parse_judge_output(raw, request.side)
    except TierUnsupported as exc:
        return JudgeOutcome("error", tiers[0], repaired, raw, None,
                            f"no supported output tier: {exc}", meta)
    except JudgeBackendError as exc:
        return JudgeOutcome("error", tiers[0], repaired, raw, None, f"transport: {exc}", meta)
    except ValueError as exc:
        return JudgeOutcome("error", tiers[0], repaired, raw, None, f"invalid output: {exc}", meta)
    return JudgeOutcome("ok", tiers[0], repaired, raw, parsed, None, meta)


# ------------------------------------------------------------ mock backend

_FINDING_RE = re.compile(r"^FINDING:.*?\bline=(\d+)\b.*?\bclass=(\S+)", re.MULTILINE)


class MockJudgeBackend:
    """Deterministic judge reading the mock reviewer's FINDING lines (R19)."""

    def __init__(self, entry: dict):
        self.malformed = set(entry.get("malformed_cases") or [])
        self.repair = set(entry.get("repair_cases") or [])
        self._seen: set = set()
        self._lock = threading.Lock()

    def complete(self, request: JudgeRequest, messages: list[dict],
                 response_format: dict | None) -> RawCompletion:
        cid = request.case.case_id
        if cid in self.malformed:
            return RawCompletion("not json", dict(MOCK_META))
        if cid in self.repair:
            key = (cid, request.side)
            with self._lock:
                first = key not in self._seen
                self._seen.add(key)
            if first:
                return RawCompletion("not json", dict(MOCK_META))
        cls = request.case.guard_class
        lines = [int(n) for n, c in _FINDING_RE.findall(request.review_text) if c == cls]
        ranges = [{"start": n, "end": n} for n in lines]
        key = VERDICT_KEY[request.side]
        obj = {key: bool(lines), "cited_ranges": ranges,
               "rationale": f"mock: {len(lines)} finding(s) of class {cls}"}
        return RawCompletion(json.dumps(obj), dict(MOCK_META))


def make_judge_backend(name: str, config: Config) -> JudgeBackend:
    if name not in config.judges:
        raise ConfigError(f"unknown judge {name!r}")
    entry = config.judges[name]
    require_configured("judge", name, entry)
    if entry["adapter"] == "mock":
        return MockJudgeBackend(entry)
    raise ConfigError(f"judge {name!r}: adapter {entry['adapter']!r} is not available")
