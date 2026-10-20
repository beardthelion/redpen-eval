"""OpenAI-compatible chat completions adapter for reviewers and the judge (R9, R12, KTD13)."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

import httpx

from redpen.judge import JudgeBackendError, JudgeRequest, RawCompletion, TierUnsupported
from redpen.reviewers import ReviewerError, ReviewRequest, ReviewResult

RETRY_STATUSES = {408, 429}
BODY_SNIPPET = 500


@dataclass
class ChatResult:
    text: str
    meta: dict = field(default_factory=dict)


def _error(kind: str, message: str, key: str, status: int | None = None) -> ReviewerError:
    # Some providers echo the key in error bodies; never let it into a message.
    return ReviewerError(kind, message.replace(key, "<redacted>"), status=status)


def _clip(text: str, key: str) -> str:
    # Redact before truncating, so a cut through an echoed key cannot leave a prefix.
    return text.replace(key, "<redacted>")[:BODY_SNIPPET]


def _snippet(resp: httpx.Response, key: str) -> str:
    return _clip(resp.text, key)


def chat_completion(cfg: dict, messages: list[dict], *, response_format: dict | None = None,
                    transport: httpx.BaseTransport | None = None) -> ChatResult:
    env = cfg["api_key_env"]
    key = os.environ.get(env)
    if not key:
        raise ReviewerError("config", f"env var {env} is not set")
    body = {"model": cfg["model"], "messages": messages}
    if cfg.get("temperature") is not None:
        body["temperature"] = cfg["temperature"]
    if cfg.get("max_tokens") is not None:
        body[cfg.get("max_tokens_param", "max_tokens")] = cfg["max_tokens"]
    if cfg.get("seed") is not None:
        body["seed"] = cfg["seed"]
    stream = cfg.get("stream", False)
    if response_format is not None:
        body["response_format"] = response_format
    if stream:
        # A slow answer arrives as a trickle of chunks, so a proxy that closes
        # long-idle responses never sees the connection go quiet.
        body["stream"] = True
        body["stream_options"] = {"include_usage": True}
    url = cfg["base_url"].rstrip("/") + "/chat/completions"
    max_retries = cfg.get("max_retries", 2)
    backoff = cfg.get("retry_backoff_s", 1.0)

    with httpx.Client(transport=transport, timeout=cfg.get("timeout_s", 120)) as client:
        for attempt in range(max_retries + 1):
            last = attempt == max_retries
            started = time.monotonic()
            try:
                with client.stream("POST", url, json=body,
                                   headers={"Authorization": f"Bearer {key}"}) as resp:
                    status = resp.status_code
                    if status == 200:
                        parsed = _read_stream(resp, key) if stream else _read_json(resp, key)
                        latency = time.monotonic() - started
                        break
                    resp.read()
            except httpx.TimeoutException as exc:
                if last:
                    raise _error("timeout", f"request timed out: {exc}", key) from None
            except httpx.TransportError as exc:
                # Includes a peer that drops the connection mid-response.
                if last:
                    raise _error("http_error", f"transport error: {exc}", key) from None
            else:
                retryable = status in RETRY_STATUSES or status >= 500
                if not retryable or last:
                    kind = "rate_limit" if status == 429 else "http_error"
                    raise _error(kind, f"HTTP {status}: {_snippet(resp, key)}", key, status)
            time.sleep(backoff * 2 ** attempt)

    text, finish, data = parsed
    if finish == "content_filter":
        raise ReviewerError("refusal", "finish_reason content_filter")
    if text is None:
        text = ""
    elif not isinstance(text, str):
        raise _error("http_error", "invalid response body: content is not a string", key)
    meta = {"model": data.get("model"), "system_fingerprint": data.get("system_fingerprint"),
            "finish_reason": finish, "usage": data.get("usage"), "latency_s": round(latency, 3),
            "truncated": finish == "length"}
    return ChatResult(text, meta)


def _read_json(resp: httpx.Response, key: str) -> tuple:
    """(content, finish_reason, response fields) from a non-streamed completion."""
    resp.read()
    try:
        data = resp.json()
        choice = data["choices"][0]
        return choice["message"].get("content"), choice.get("finish_reason"), data
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        raise _error("http_error", f"invalid response body: {_snippet(resp, key)}", key) from None


def _read_stream(resp: httpx.Response, key: str) -> tuple:
    """(content, finish_reason, response fields) assembled from server-sent events."""
    parts, finish, fields, seen = [], None, {}, False
    for line in resp.iter_lines():
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload == "[DONE]":
            break
        try:
            chunk = json.loads(payload)
        except ValueError:
            raise _error("http_error", f"invalid stream chunk: {_clip(payload, key)}", key) from None
        if not isinstance(chunk, dict) or "error" in chunk:
            raise _error("http_error", f"stream error: {_clip(str(chunk), key)}", key)
        for name in ("model", "system_fingerprint", "usage"):
            if chunk.get(name) is not None:
                fields[name] = chunk[name]
        for choice in chunk.get("choices") or []:
            seen = True
            content = (choice.get("delta") or {}).get("content")
            if content is not None:
                if not isinstance(content, str):
                    raise _error("http_error", "invalid response body: content is not a string", key)
                parts.append(content)
            if choice.get("finish_reason") is not None:
                finish = choice["finish_reason"]
    if not seen:
        raise _error("http_error", "invalid response body: stream carried no choices", key)
    return "".join(parts), finish, fields


class OpenAICompatReviewer:
    def __init__(self, name: str, entry: dict, transport: httpx.BaseTransport | None = None):
        self.name = name
        self.entry = entry
        self.transport = transport

    def review(self, request: ReviewRequest) -> ReviewResult:
        # R6: only the rendered prompt goes out; case and side stay local.
        res = chat_completion(self.entry, [{"role": "user", "content": request.prompt}],
                              transport=self.transport)
        return ReviewResult(res.text, res.meta)


class OpenAICompatJudgeBackend:
    def __init__(self, entry: dict, transport: httpx.BaseTransport | None = None):
        self.entry = entry
        self.transport = transport

    def complete(self, request: JudgeRequest, messages: list[dict],
                 response_format: dict | None) -> RawCompletion:
        try:
            res = chat_completion(self.entry, messages, response_format=response_format,
                                  transport=self.transport)
        except ReviewerError as exc:
            if exc.status == 400 and response_format is not None and "response_format" in exc.message:
                raise TierUnsupported(exc.message) from None
            raise JudgeBackendError(str(exc)) from None
        return RawCompletion(res.text, res.meta)
