import pytest

from conftest import make_dataset
from redpen.config import load_config
from redpen.dataset import load_dataset
from redpen.reviewers import ReviewerError, ReviewRequest, ReviewResult, make_reviewer

A = "GHSA-aaaa-1111-aaaa"
B = "GHSA-bbbb-2222-bbbb"


@pytest.fixture
def cases(tmp_path):
    root = make_dataset(tmp_path, [
        {"case_id": A},
        {"case_id": B, "guard_class": "authz",
         "expected_spans": [{"start": 12, "end": 13, "source": "semgrep"},
                            {"start": 10, "end": 10, "source": "fix_diff"}],
         "fixed_segments": [(5, 7), (9, 14)]},
    ])
    return {c.case_id: c for c in load_dataset(root).cases}


def reviewer(tmp_path, vuln="hit", fixed="clean", overrides="{}"):
    p = tmp_path / "r.yaml"
    p.write_text(
        "default_judge: mock\n"
        "reviewers:\n"
        "  mock:\n"
        "    adapter: mock\n"
        f"    vuln: {vuln}\n"
        f"    fixed: {fixed}\n"
        f"    overrides: {overrides}\n"
        "judges:\n"
        "  mock:\n"
        "    adapter: mock\n"
    )
    return make_reviewer("mock", load_config(p))


def run(r, case, side):
    res = r.review(ReviewRequest(prompt="ignored", case=case, side=side))
    assert isinstance(res, ReviewResult)
    return res.text


def test_hit(tmp_path, cases):
    r = reviewer(tmp_path, vuln="hit")
    assert run(r, cases[A], "vuln") == (
        "FINDING: file=handler.go line=11 class=path-traversal\nquote: data := readFile(path)")
    assert run(r, cases[B], "vuln") == (
        "FINDING: file=handler.go line=12 class=authz\nquote: w.Write(data)")


def test_partial(tmp_path, cases):
    r = reviewer(tmp_path, vuln="partial")
    assert run(r, cases[A], "vuln") == "FINDING: file=handler.go line=61 class=path-traversal"
    assert run(r, cases[B], "vuln") == "FINDING: file=handler.go line=63 class=authz"


def test_miss(tmp_path, cases):
    r = reviewer(tmp_path, vuln="miss")
    assert run(r, cases[A], "vuln") == "FINDING: file=handler.go line=1 class=unrelated-issue"


def test_clean_and_fp(tmp_path, cases):
    assert run(reviewer(tmp_path, fixed="clean"), cases[A], "fixed") == "No security vulnerabilities found."
    r = reviewer(tmp_path, fixed="fp")
    assert run(r, cases[A], "fixed") == "FINDING: file=handler.go line=9 class=path-traversal"
    assert run(r, cases[B], "fixed") == "FINDING: file=handler.go line=5 class=authz"


def test_empty(tmp_path, cases):
    r = reviewer(tmp_path, vuln="empty", fixed="empty")
    assert run(r, cases[A], "vuln") == ""
    assert run(r, cases[A], "fixed") == ""


@pytest.mark.parametrize("side", ["vuln", "fixed"])
def test_error_raises_reviewer_error(tmp_path, cases, side):
    r = reviewer(tmp_path, vuln="error", fixed="error")
    with pytest.raises(ReviewerError) as e:
        run(r, cases[A], side)
    assert e.value.kind == "http_error"
    assert e.value.message == "mock error"


def test_overrides_beat_defaults(tmp_path, cases):
    r = reviewer(tmp_path, overrides="{%s: {vuln: miss}, %s: {fixed: fp}}" % (A, B))
    assert run(r, cases[A], "vuln") == "FINDING: file=handler.go line=1 class=unrelated-issue"
    assert run(r, cases[A], "fixed") == "No security vulnerabilities found."
    assert run(r, cases[B], "vuln").startswith("FINDING: file=handler.go line=12 class=authz")
    assert run(r, cases[B], "fixed") == "FINDING: file=handler.go line=5 class=authz"


def test_deterministic(tmp_path, cases):
    r1 = reviewer(tmp_path)
    r2 = reviewer(tmp_path)
    for side in ("vuln", "fixed"):
        a = r1.review(ReviewRequest(prompt="p", case=cases[B], side=side))
        b = r1.review(ReviewRequest(prompt="p", case=cases[B], side=side))
        c = r2.review(ReviewRequest(prompt="p", case=cases[B], side=side))
        assert a == b == c
