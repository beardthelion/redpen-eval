"""OpenAI-compatible chat completions adapter for reviewers and the judge (R9, R12, KTD13)."""

from __future__ import annotations

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
    if response_format is not None:
        body["response_format"] = response_format
    url = cfg["base_url"].rstrip("/") + "/chat/completions"
    max_retries = cfg.get("max_retries", 2)
    backoff = cfg.get("retry_backoff_s", 1.0)

    with httpx.Client(transport=transport, timeout=cfg.get("timeout_s", 120)) as client:
        for attempt in range(max_retries + 1):
            last = attempt == max_retries
            started = time.monotonic()
            try:
                resp = client.post(url, json=body, headers={"Authorization": f"Bearer {key}"})
            except httpx.TimeoutException as exc:
                if last:
                    raise _error("timeout", f"request timed out: {exc}", key) from None
            except httpx.HTTPError as exc:
                raise _error("http_error", f"transport error: {exc}", key) from None
            else:
                status = resp.status_code
                if status == 200:
                    latency = time.monotonic() - started
                    break
                retryable = status in RETRY_STATUSES or status >= 500
                if not retryable or last:
                    kind = "rate_limit" if status == 429 else "http_error"
                    raise _error(kind, f"HTTP {status}: {resp.text[:BODY_SNIPPET]}", key, status)
            time.sleep(backoff * 2 ** attempt)

    try:
        data = resp.json()
        choice = data["choices"][0]
        text = choice["message"].get("content") or ""
        finish = choice.get("finish_reason")
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        raise _error("http_error", f"invalid response body: {resp.text[:BODY_SNIPPET]}", key) from None
    if finish == "content_filter":
        raise ReviewerError("refusal", "finish_reason content_filter")
    meta = {"model": data.get("model"), "system_fingerprint": data.get("system_fingerprint"),
            "finish_reason": finish, "usage": data.get("usage"), "latency_s": round(latency, 3),
            "truncated": finish == "length"}
    return ChatResult(text, meta)


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
