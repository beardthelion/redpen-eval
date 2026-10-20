import json

import httpx
import pytest
import yaml

from conftest import make_dataset
from redpen import prompts, runner
from redpen.cli import main
from redpen.config import Config
from redpen.dataset import load_dataset
from redpen.judge import (JudgeBackendError, JudgeRequest, TierUnsupported, judge_side,
                          make_judge_backend)
from redpen.reviewers import ReviewerError, ReviewRequest, make_reviewer
from redpen.reviewers.openai_compat import (OpenAICompatJudgeBackend, OpenAICompatReviewer,
                                            chat_completion)

KEY = "sk-test-SECRET123"
CID = "GHSA-q1w2-e3r4-t5y6"
CVE = "CVE-2026-7777"
DESC = "unsanitized traversal sequence flows into the file opener"
OWNER, NAME = "zorbcorp", "quuxlib"

GOOD_VULN = {"verdict_class_match": True, "cited_ranges": [{"start": 11, "end": 11}],
             "rationale": "same missing guard"}


def entry(**over):
    e = {"adapter": "openai_compat", "base_url": "http://llm.invalid/v1", "model": "test-model",
         "api_key_env": "REDPEN_TEST_KEY", "temperature": 0, "max_tokens": 256, "seed": 7,
         "timeout_s": 5, "max_retries": 2, "retry_backoff_s": 0}
    e.update(over)
    return e


def completion(content="No security vulnerabilities found.", finish_reason="stop", **extra):
    body = {"id": "x", "model": "served-model", "system_fingerprint": "fp_1",
            "choices": [{"index": 0, "finish_reason": finish_reason,
                         "message": {"role": "assistant", "content": content}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}
    body.update(extra)
    return body


class Server:
    """Scripted MockTransport: each item is a response, a callable, or an exception."""

    def __init__(self, *script):
        self.script = list(script)
        self.requests = []
        self.transport = httpx.MockTransport(self.handle)

    def handle(self, request):
        self.requests.append(request)
        item = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        if isinstance(item, Exception):
            raise item
        if callable(item):
            return item(request)
        status, body = item
        if isinstance(body, str):
            return httpx.Response(status, text=body)
        return httpx.Response(status, json=body)

    def bodies(self):
        return [json.loads(r.content) for r in self.requests]


@pytest.fixture
def key(monkeypatch):
    monkeypatch.setenv("REDPEN_TEST_KEY", KEY)


@pytest.fixture
def case(tmp_path):
    root = make_dataset(tmp_path, [{"case_id": CID, "cve": CVE, "description": DESC,
                                    "owner_repo": f"{OWNER}/{NAME}"}])
    return load_dataset(root).cases[0]


MSGS = [{"role": "user", "content": "hello"}]


# ------------------------------------------------------------ chat_completion

def test_happy_returns_text_and_meta(key):
    srv = Server((200, completion("looks fine")))
    res = chat_completion(entry(), MSGS, transport=srv.transport)
    assert res.text == "looks fine"
    assert res.meta["model"] == "served-model"
    assert res.meta["system_fingerprint"] == "fp_1"
    assert res.meta["finish_reason"] == "stop"
    assert res.meta["usage"] == {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    assert res.meta["truncated"] is False
    assert isinstance(res.meta["latency_s"], float)
    (req,) = srv.requests
    assert str(req.url) == "http://llm.invalid/v1/chat/completions"
    assert req.method == "POST"
    assert req.headers["authorization"] == f"Bearer {KEY}"
    body = json.loads(req.content)
    assert body == {"model": "test-model", "messages": MSGS, "temperature": 0,
                    "max_tokens": 256, "seed": 7}


def test_optional_params_omitted_when_absent(key):
    srv = Server((200, completion()))
    cfg = entry(base_url="http://llm.invalid/v1/")
    for k in ("temperature", "max_tokens", "seed"):
        del cfg[k]
    chat_completion(cfg, MSGS, transport=srv.transport)
    assert str(srv.requests[0].url) == "http://llm.invalid/v1/chat/completions"
    assert srv.bodies()[0] == {"model": "test-model", "messages": MSGS}


def test_max_completion_tokens_param(key):
    srv = Server((200, completion()))
    chat_completion(entry(max_tokens_param="max_completion_tokens"), MSGS, transport=srv.transport)
    body = srv.bodies()[0]
    assert body["max_completion_tokens"] == 256
    assert "max_tokens" not in body


def test_response_format_sent_when_given(key):
    srv = Server((200, completion()))
    chat_completion(entry(), MSGS, response_format={"type": "json_object"}, transport=srv.transport)
    assert srv.bodies()[0]["response_format"] == {"type": "json_object"}


def test_meta_never_holds_key_or_headers(key):
    srv = Server((200, completion()))
    res = chat_completion(entry(), MSGS, transport=srv.transport)
    assert set(res.meta) == {"model", "system_fingerprint", "finish_reason", "usage",
                             "latency_s", "truncated"}
    assert KEY not in json.dumps(res.meta)


def test_retry_503_503_200_succeeds(key):
    srv = Server((503, "busy"), (503, "busy"), (200, completion("ok")))
    assert chat_completion(entry(), MSGS, transport=srv.transport).text == "ok"
    assert len(srv.requests) == 3


def test_retry_408_then_200(key):
    srv = Server((408, "slow"), (200, completion("ok")))
    assert chat_completion(entry(), MSGS, transport=srv.transport).text == "ok"
    assert len(srv.requests) == 2


def test_503_exhausted_is_http_error_after_3_requests(key):
    srv = Server((503, "busy"))
    with pytest.raises(ReviewerError) as e:
        chat_completion(entry(max_retries=2), MSGS, transport=srv.transport)
    assert e.value.kind == "http_error"
    assert len(srv.requests) == 3


def test_429_exhausted_is_rate_limit(key):
    srv = Server((429, "slow down"))
    with pytest.raises(ReviewerError) as e:
        chat_completion(entry(), MSGS, transport=srv.transport)
    assert e.value.kind == "rate_limit"
    assert len(srv.requests) == 3


def test_must_not_401_is_not_retried(key):
    srv = Server((401, "bad key"), (200, completion()))
    with pytest.raises(ReviewerError) as e:
        chat_completion(entry(), MSGS, transport=srv.transport)
    assert e.value.kind == "http_error"
    assert len(srv.requests) == 1


def test_must_not_400_is_not_retried(key):
    srv = Server((400, "bad request"), (200, completion()))
    with pytest.raises(ReviewerError) as e:
        chat_completion(entry(), MSGS, transport=srv.transport)
    assert e.value.kind == "http_error"
    assert len(srv.requests) == 1


def test_timeout_after_retries(key):
    srv = Server(httpx.ReadTimeout("slow"))
    with pytest.raises(ReviewerError) as e:
        chat_completion(entry(), MSGS, transport=srv.transport)
    assert e.value.kind == "timeout"
    assert len(srv.requests) == 3


def test_connect_error_is_http_error(key):
    srv = Server(httpx.ConnectError("refused"))
    with pytest.raises(ReviewerError) as e:
        chat_completion(entry(), MSGS, transport=srv.transport)
    assert e.value.kind == "http_error"


def test_invalid_json_body_is_http_error(key):
    srv = Server((200, "<html>gateway</html>"))
    with pytest.raises(ReviewerError) as e:
        chat_completion(entry(), MSGS, transport=srv.transport)
    assert e.value.kind == "http_error"


def test_content_filter_is_refusal(key):
    srv = Server((200, completion("", finish_reason="content_filter")))
    with pytest.raises(ReviewerError) as e:
        chat_completion(entry(), MSGS, transport=srv.transport)
    assert e.value.kind == "refusal"


def test_length_keeps_text_and_flags_truncated(key):
    srv = Server((200, completion("partial answ", finish_reason="length")))
    res = chat_completion(entry(), MSGS, transport=srv.transport)
    assert res.text == "partial answ"
    assert res.meta["truncated"] is True


def test_null_content_is_empty_text(key):
    srv = Server((200, completion(None)))
    assert chat_completion(entry(), MSGS, transport=srv.transport).text == ""


def test_missing_env_var_is_config_without_request(monkeypatch):
    monkeypatch.delenv("REDPEN_TEST_KEY", raising=False)
    srv = Server((200, completion()))
    with pytest.raises(ReviewerError) as e:
        chat_completion(entry(), MSGS, transport=srv.transport)
    assert e.value.kind == "config"
    assert "REDPEN_TEST_KEY" in e.value.message
    assert srv.requests == []


def test_must_not_error_message_never_echoes_key(key):
    srv = Server((401, f"Incorrect API key provided: {KEY}"))
    with pytest.raises(ReviewerError) as e:
        chat_completion(entry(), MSGS, transport=srv.transport)
    assert KEY not in e.value.message
    assert KEY not in str(e.value)


# ------------------------------------------------------------ reviewer

def test_reviewer_sends_only_the_prompt(key, case):
    srv = Server((200, completion("FINDING")))
    rev = OpenAICompatReviewer("oa", entry(), transport=srv.transport)
    prompt = prompts.render_review_prompt(case, "vuln")
    res = rev.review(ReviewRequest(prompt, case, "vuln"))
    assert res.text == "FINDING"
    assert srv.bodies()[0]["messages"] == [{"role": "user", "content": prompt}]


@pytest.mark.parametrize("side", ["vuln", "fixed"])
def test_must_not_ground_truth_in_reviewer_request(key, case, side):
    srv = Server((200, completion()))
    rev = OpenAICompatReviewer("oa", entry(), transport=srv.transport)
    rev.review(ReviewRequest(prompts.render_review_prompt(case, side), case, side))
    raw = srv.requests[0].content.decode("utf-8").lower()
    for needle in (CID, "q1w2", CVE, DESC, OWNER, NAME, "copyright", case.data["rule_sha256"],
                   "a" * 40, "b" * 40):
        assert needle.lower() not in raw, needle


def test_reviewer_empty_content_reaches_runner_as_empty_output(key, case):
    srv = Server((200, completion("")))
    rev = OpenAICompatReviewer("oa", entry(), transport=srv.transport)
    rec = runner._review_side(rev, None, "prompt", case, "vuln")
    assert rec["status"] == "no_answer"
    assert rec["review_error"]["kind"] == "empty_output"
    assert rec["verdict"] == "MISS"


def test_reviewer_refusal_reaches_runner_as_no_answer(key, case):
    srv = Server((200, completion(None, finish_reason="content_filter")))
    rev = OpenAICompatReviewer("oa", entry(), transport=srv.transport)
    rec = runner._review_side(rev, None, "prompt", case, "fixed")
    assert rec["status"] == "no_answer"
    assert rec["review_error"]["kind"] == "refusal"
    assert rec["fixed_clean"] is None


def test_reviewer_missing_key_is_reviewer_error(monkeypatch, case):
    monkeypatch.delenv("REDPEN_TEST_KEY", raising=False)
    srv = Server((200, completion()))
    rev = OpenAICompatReviewer("oa", entry(), transport=srv.transport)
    rec = runner._review_side(rev, None, "prompt", case, "vuln")
    assert rec["status"] == "reviewer_error"
    assert rec["review_error"]["kind"] == "config"
    assert srv.requests == []


def test_make_reviewer_and_backend_build_openai_adapters():
    cfg = Config(reviewers={"oa": entry()}, judges={"llm": entry(structured_output="json_object")},
                 default_judge="llm")
    assert isinstance(make_reviewer("oa", cfg), OpenAICompatReviewer)
    assert isinstance(make_judge_backend("llm", cfg), OpenAICompatJudgeBackend)


# ------------------------------------------------------------ judge backend

def jreq(case, side="vuln"):
    return JudgeRequest(case, side, prompts.numbered_window(case, side),
                        "FINDING: file=handler.go line=11 class=path-traversal")


def test_judge_400_response_format_falls_back_to_json_object(key, case):
    srv = Server((400, {"error": {"message": "response_format json_schema is not supported"}}),
                 (200, completion(json.dumps(GOOD_VULN))))
    out = judge_side(OpenAICompatJudgeBackend(entry(), transport=srv.transport), jreq(case),
                     "json_schema")
    assert out.status == "ok"
    assert out.tier == "json_object"
    assert out.repaired is False
    assert out.parsed == GOOD_VULN
    assert out.response_meta["model"] == "served-model"
    first, second = srv.bodies()
    assert first["response_format"]["type"] == "json_schema"
    assert first["response_format"]["json_schema"]["strict"] is True
    assert second["response_format"] == {"type": "json_object"}


def test_judge_tier_mapping(key, case):
    srv = Server((200, completion(json.dumps(GOOD_VULN))))
    backend = OpenAICompatJudgeBackend(entry(), transport=srv.transport)
    judge_side(backend, jreq(case), "prompt")
    assert "response_format" not in srv.bodies()[0]


def test_must_not_400_without_response_format_is_not_tier_unsupported(key, case):
    srv = Server((400, {"error": {"message": "context length exceeded"}}))
    backend = OpenAICompatJudgeBackend(entry(), transport=srv.transport)
    with pytest.raises(JudgeBackendError):
        backend.complete(jreq(case), MSGS, {"type": "json_object"})


def test_backend_raises_tier_unsupported_on_400_response_format(key, case):
    srv = Server((400, "unknown parameter: response_format"))
    backend = OpenAICompatJudgeBackend(entry(), transport=srv.transport)
    with pytest.raises(TierUnsupported):
        backend.complete(jreq(case), MSGS, {"type": "json_object"})


def test_judge_prose_with_embedded_json_parses(key, case):
    text = "Sure, here is the grade: " + json.dumps(GOOD_VULN) + " Hope it helps."
    srv = Server((200, completion(text)))
    out = judge_side(OpenAICompatJudgeBackend(entry(), transport=srv.transport), jreq(case),
                     "json_schema")
    assert out.status == "ok"
    assert out.parsed == GOOD_VULN
    assert out.repaired is False


def test_judge_prose_without_json_twice_is_judge_error(key, case):
    srv = Server((200, completion("I think it is a match.")))
    out = judge_side(OpenAICompatJudgeBackend(entry(), transport=srv.transport), jreq(case),
                     "json_object")
    assert out.status == "error"
    assert out.repaired is True
    assert len(srv.requests) == 2


def test_judge_transport_error_is_judge_error(key, case):
    srv = Server((503, "down"))
    out = judge_side(OpenAICompatJudgeBackend(entry(), transport=srv.transport), jreq(case),
                     "json_object")
    assert out.status == "error"
    assert out.error.startswith("transport")
    assert len(srv.requests) == 3


def test_judge_missing_key_is_judge_error_without_request(monkeypatch, case):
    monkeypatch.delenv("REDPEN_TEST_KEY", raising=False)
    srv = Server((200, completion(json.dumps(GOOD_VULN))))
    out = judge_side(OpenAICompatJudgeBackend(entry(), transport=srv.transport), jreq(case),
                     "json_object")
    assert out.status == "error"
    assert srv.requests == []


# ------------------------------------------------------------ full run, secrets

def _grade(request):
    """A judge server that grades any request as a vuln-side or fixed-side miss/clean."""
    content = json.loads(request.content)["messages"][0]["content"]
    if "verdict_class_match" in content:
        obj = {"verdict_class_match": False, "cited_ranges": [], "rationale": "no"}
    else:
        obj = {"reported_patched_vuln": False, "cited_ranges": [], "rationale": "no"}
    return httpx.Response(200, json=completion(json.dumps(obj)))


def test_must_not_secret_never_written_full_run(tmp_path, monkeypatch):
    monkeypatch.setenv("REDPEN_TEST_KEY", KEY)
    ds = make_dataset(tmp_path, [{"case_id": "GHSA-aaaa-bbbb-cccc"},
                                 {"case_id": "GHSA-dddd-eeee-ffff"}])
    cfg = {"default_judge": "llm",
           "reviewers": {"oa": entry()},
           "judges": {"llm": entry(model="judge-model", structured_output="json_schema")}}
    cfg_path = tmp_path / "reviewers.yaml"
    cfg_path.write_text(yaml.safe_dump(cfg))

    def reviewer_reply(request):
        assert request.headers["authorization"] == f"Bearer {KEY}"
        if "GHSA" in request.content.decode():
            raise AssertionError("case id leaked")
        # one reviewer request echoes the key in an error body, as some providers do
        if not hasattr(reviewer_reply, "seen"):
            reviewer_reply.seen = True
            return httpx.Response(401, text=f"Incorrect API key provided: {KEY}")
        return httpx.Response(200, json=completion("nothing here"))

    rsrv = Server(reviewer_reply)
    jsrv = Server(_grade)
    monkeypatch.setattr(runner, "make_reviewer",
                        lambda name, config: OpenAICompatReviewer(name, config.reviewers[name],
                                                                  transport=rsrv.transport))
    monkeypatch.setattr(runner, "make_judge_backend",
                        lambda name, config: OpenAICompatJudgeBackend(config.judges[name],
                                                                      transport=jsrv.transport))
    results = tmp_path / "results"
    code = main(["run", "--reviewer", "oa", "--judge", "llm", "--dataset", str(ds),
                 "--config", str(cfg_path), "--results-dir", str(results), "--concurrency", "1"])
    assert code == 1  # one reviewer_error from the 401
    assert len(rsrv.requests) == 4
    assert len(jsrv.requests) == 3
    files = [p for p in results.rglob("*") if p.is_file()]
    assert files
    statuses = []
    for p in files:
        assert KEY not in p.read_text(), p
        if p.parent.name == "cases":
            rec = json.loads(p.read_text())
            statuses += [rec["vuln"]["status"], rec["fixed"]["status"]]
    assert sorted(statuses) == ["reviewer_error", "scored", "scored", "scored"]


def test_must_not_key_prefix_leaks_when_echo_straddles_snippet_cut(key):
    # The key is echoed so that the body snippet cut falls inside it: truncating
    # before redacting would leave a key prefix in the error message.
    from redpen.reviewers.openai_compat import BODY_SNIPPET
    body = "x" * (BODY_SNIPPET - 6) + KEY + " was rejected"
    server = Server((401, body))
    with pytest.raises(ReviewerError) as err:
        chat_completion(entry(), [{"role": "user", "content": "hi"}], transport=server.transport)
    assert KEY[:6] not in err.value.message
    assert "SECRET" not in err.value.message
