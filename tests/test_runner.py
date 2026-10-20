import json
from pathlib import Path

import pytest
import yaml

from conftest import make_dataset
from redpen.cli import main
from redpen.judge import MockJudgeBackend
from redpen.prompts import judge_prompt_sha256
from redpen.reviewers.mock import MockReviewer

CASES = [
    {"case_id": "GHSA-23vg-4cjm-66q5", "guard_class": "path-traversal"},
    {"case_id": "GHSA-23vx-aaaa-bbbb", "guard_class": "path-traversal"},
    {"case_id": "GHSA-j3hg-cccc-dddd", "guard_class": "input-validation"},
]
ALL_IDS = sorted(c["case_id"] for c in CASES)


def base_config(**mock):
    entry = {"adapter": "mock", "vuln": "hit", "fixed": "clean", "overrides": {}}
    entry.update(mock)
    return {
        "default_judge": "mock",
        "reviewers": {"mock": entry},
        "judges": {"mock": {"adapter": "mock", "malformed_cases": [], "repair_cases": []}},
    }


def write_config(tmp_path, cfg) -> Path:
    path = tmp_path / "reviewers.yaml"
    path.write_text(yaml.safe_dump(cfg))
    return path


@pytest.fixture
def env(tmp_path):
    ds = make_dataset(tmp_path, CASES)
    cfg = write_config(tmp_path, base_config())
    results = tmp_path / "results"
    return ds, cfg, results


def patch_judge(monkeypatch):
    """Stand in a mock judge backend for an openai_compat judge entry (adapter lands in U11)."""
    from redpen import runner
    monkeypatch.setattr(runner, "make_judge_backend",
                        lambda name, config: MockJudgeBackend({"adapter": "mock"}))


def run(ds, cfg, results, *extra):
    argv = ["run", "--reviewer", "mock", "--dataset", str(ds), "--config", str(cfg),
            "--results-dir", str(results), *extra]
    try:
        return main(argv)
    except SystemExit as exc:
        return exc.code


def run_dirs(results: Path) -> list[Path]:
    return sorted(p for p in results.iterdir() if p.is_dir()) if results.exists() else []


def only_run(results: Path) -> Path:
    dirs = run_dirs(results)
    assert len(dirs) == 1
    return dirs[0]


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def test_happy_path_writes_meta_and_case_files(env, capsys):
    ds, cfg, results = env
    assert run(ds, cfg, results) == 0
    rd = only_run(results)
    meta = load(rd / "meta.json")
    assert meta["run_id"] == rd.name
    stamp, name, short = rd.name.rsplit("-", 2)
    assert name == "mock" and len(stamp) == 16 and stamp.endswith("Z")
    assert short == meta["reviewer"]["config_sha256"][:8]
    assert meta["complete"] is True
    assert meta["finished_utc"] is not None
    assert meta["case_ids"] == ALL_IDS
    assert meta["counts"] == {"cases": 3, "done": 3, "reviewer_errors": 0, "judge_errors": 0}
    assert meta["reviewer"]["name"] == "mock" and meta["reviewer"]["adapter"] == "mock"
    assert meta["judge"]["name"] == "mock" and meta["judge"]["adapter"] == "mock"
    assert meta["dataset"]["version"] == "v1"
    manifest = load(ds / "manifest.json")
    assert meta["dataset"]["case_set_sha256"] == manifest["case_set_sha256"]
    assert meta["prompts"]["review_version"] == "review-v1"
    assert len(meta["prompts"]["review_sha256"]) == 64
    assert meta["prompts"]["judge_version"] == "judge-v1"
    assert meta["prompts"]["judge_sha256"] == judge_prompt_sha256()
    assert meta["scoring"] == {"formula": "pair-v1", "location_tolerance": 5,
                               "bootstrap_resamples": 1000, "bootstrap_seed": 0}
    assert meta["harness"]["redpen_version"] == "0.1.0"
    files = sorted(p.stem for p in (rd / "cases").glob("*.json"))
    assert files == ALL_IDS
    rec = load(rd / "cases" / f"{ALL_IDS[0]}.json")
    assert rec["case_id"] == ALL_IDS[0]
    assert rec["vuln"]["status"] == "scored"
    assert rec["vuln"]["review_text"].startswith("FINDING:")
    judge = rec["vuln"]["judge"]
    assert judge["status"] == "ok" and judge["tier"] == "json_schema"
    assert judge["repaired"] is False and judge["error"] is None
    assert judge["parsed"]["verdict_class_match"] is True
    assert judge["parsed"]["cited_ranges"] == [{"start": 11, "end": 11}]
    assert set(judge["response_meta"]) == {"model", "system_fingerprint", "finish_reason", "usage"}
    assert isinstance(judge["raw"], str)
    assert rec["vuln"]["verdict"] == "HIT" and rec["vuln"]["location_match"] is True
    assert rec["fixed"]["status"] == "scored"
    assert rec["fixed"]["review_text"] == "No security vulnerabilities found."
    assert rec["fixed"]["judge"]["parsed"]["reported_patched_vuln"] is False
    assert rec["fixed"]["fixed_clean"] is True and rec["pair_credit"] == 1.0
    out = capsys.readouterr().out
    assert f"run {rd.name}: 3/3 cases, reviewer errors 0, judge errors 0" in out
    assert f"results: {rd}" in out


def test_cases_guard_class_selects_only_that_class(env):
    ds, cfg, results = env
    assert run(ds, cfg, results, "--cases", "input-validation") == 0
    assert load(only_run(results) / "meta.json")["case_ids"] == ["GHSA-j3hg-cccc-dddd"]


def test_cases_short_ids_select_those_cases(env):
    ds, cfg, results = env
    assert run(ds, cfg, results, "--cases", "23vg,j3hg") == 0
    rd = only_run(results)
    assert load(rd / "meta.json")["case_ids"] == ["GHSA-23vg-4cjm-66q5", "GHSA-j3hg-cccc-dddd"]
    assert sorted(p.stem for p in (rd / "cases").glob("*.json")) == [
        "GHSA-23vg-4cjm-66q5", "GHSA-j3hg-cccc-dddd"]


def test_cases_exact_id_and_all(env, tmp_path):
    ds, cfg, results = env
    assert run(ds, cfg, results, "--cases", "GHSA-23vx-aaaa-bbbb") == 0
    assert load(only_run(results) / "meta.json")["case_ids"] == ["GHSA-23vx-aaaa-bbbb"]
    other = tmp_path / "results-all"
    assert run(ds, cfg, other, "--cases", "all") == 0
    assert load(only_run(other) / "meta.json")["case_ids"] == ALL_IDS


def test_must_not_unknown_token_errors_without_run_dir(env, capsys):
    ds, cfg, results = env
    assert run(ds, cfg, results, "--cases", "nosuchthing") == 2
    assert "unknown case or guard class: nosuchthing" in capsys.readouterr().err
    assert run_dirs(results) == []


def test_must_not_unknown_token_mixed_with_valid_errors(env, capsys):
    ds, cfg, results = env
    assert run(ds, cfg, results, "--cases", "j3hg,nosuchthing") == 2
    assert "unknown case or guard class: nosuchthing" in capsys.readouterr().err
    assert run_dirs(results) == []


def test_must_not_ambiguous_short_id_names_both(env, tmp_path, capsys):
    _, cfg, results = env
    ds2 = make_dataset(tmp_path / "amb", [
        {"case_id": "GHSA-abcd-1111-2222"}, {"case_id": "GHSA-abcd-3333-4444"}])
    assert run(ds2, cfg, results, "--cases", "abcd") == 2
    err = capsys.readouterr().err
    assert "GHSA-abcd-1111-2222" in err and "GHSA-abcd-3333-4444" in err
    assert run_dirs(results) == []


def test_reviewer_error_on_one_side(env, tmp_path):
    ds, _, results = env
    cid = "GHSA-j3hg-cccc-dddd"
    cfg = write_config(tmp_path, base_config(overrides={cid: {"vuln": "error"}}))
    assert run(ds, cfg, results) == 1
    rd = only_run(results)
    rec = load(rd / "cases" / f"{cid}.json")
    assert rec["vuln"]["status"] == "reviewer_error"
    assert rec["vuln"]["review_error"]["kind"] == "http_error"
    assert rec["vuln"]["verdict"] is None
    assert rec["fixed"]["status"] == "scored"
    assert rec["pair_credit"] is None
    meta = load(rd / "meta.json")
    assert meta["complete"] is True
    assert meta["counts"]["reviewer_errors"] == 1


def test_must_not_empty_is_no_answer(env, tmp_path):
    ds, _, results = env
    cfg = write_config(tmp_path, base_config(vuln="empty", fixed="empty"))
    assert run(ds, cfg, results) == 0
    rd = only_run(results)
    for cid in ALL_IDS:
        rec = load(rd / "cases" / f"{cid}.json")
        for side in ("vuln", "fixed"):
            assert rec[side]["status"] == "no_answer"
            assert rec[side]["review_error"]["kind"] == "empty_output"
        assert rec["vuln"]["verdict"] == "MISS"
    assert load(rd / "meta.json")["counts"]["reviewer_errors"] == 0


def test_must_not_whitespace_only_is_no_answer(env, monkeypatch):
    from redpen.reviewers import ReviewResult
    ds, cfg, results = env
    monkeypatch.setattr(MockReviewer, "review", lambda self, req: ReviewResult(" \n\t ", {}))
    assert run(ds, cfg, results, "--cases", "j3hg") == 0
    rec = load(only_run(results) / "cases" / "GHSA-j3hg-cccc-dddd.json")
    assert rec["vuln"]["status"] == "no_answer"
    assert rec["vuln"]["review_error"]["kind"] == "empty_output"


def test_must_not_refusal_is_no_answer_not_error(env, monkeypatch):
    from redpen.reviewers import ReviewerError

    def refuse(self, req):
        raise ReviewerError("refusal", "content_filter")

    ds, cfg, results = env
    monkeypatch.setattr(MockReviewer, "review", refuse)
    assert run(ds, cfg, results, "--cases", "j3hg") == 0
    rd = only_run(results)
    rec = load(rd / "cases" / "GHSA-j3hg-cccc-dddd.json")
    for side in ("vuln", "fixed"):
        assert rec[side]["status"] == "no_answer"
        assert rec[side]["review_error"]["kind"] == "refusal"
    assert load(rd / "meta.json")["counts"]["reviewer_errors"] == 0


def counting(monkeypatch):
    calls = []
    original = MockReviewer.review

    def review(self, req):
        calls.append((req.case.case_id, req.side))
        return original(self, req)

    monkeypatch.setattr(MockReviewer, "review", review)
    return calls


def test_resume_reruns_only_missing_case(env, monkeypatch):
    ds, cfg, results = env
    assert run(ds, cfg, results) == 0
    rd = only_run(results)
    gone = "GHSA-23vx-aaaa-bbbb"
    (rd / "cases" / f"{gone}.json").unlink()
    meta = load(rd / "meta.json")
    meta["complete"] = False
    (rd / "meta.json").write_text(json.dumps(meta))
    calls = counting(monkeypatch)
    assert run(ds, cfg, results, "--resume", rd.name) == 0
    assert sorted(calls) == [(gone, "fixed"), (gone, "vuln")]
    meta = load(rd / "meta.json")
    assert meta["complete"] is True
    assert meta["counts"]["done"] == 3
    assert run_dirs(results) == [rd]


def test_resume_reruns_error_cases(env, tmp_path, monkeypatch):
    ds, _, results = env
    cid = "GHSA-j3hg-cccc-dddd"
    cfg = write_config(tmp_path, base_config(overrides={cid: {"vuln": "error"}}))
    assert run(ds, cfg, results) == 1
    rd = only_run(results)
    calls = counting(monkeypatch)
    assert run(ds, cfg, results, "--resume", rd.name) == 1
    assert {c for c, _ in calls} == {cid}


def test_resume_refuses_changed_reviewer_config(env, tmp_path, capsys):
    ds, cfg, results = env
    assert run(ds, cfg, results) == 0
    rd = only_run(results)
    write_config(tmp_path, base_config(fixed="fp"))
    capsys.readouterr()
    assert run(ds, cfg, results, "--resume", rd.name) == 2
    assert "cannot resume: reviewer config changed" in capsys.readouterr().err


def test_resume_refuses_different_cases(env, capsys):
    ds, cfg, results = env
    assert run(ds, cfg, results, "--cases", "j3hg") == 0
    rd = only_run(results)
    assert run(ds, cfg, results, "--resume", rd.name, "--cases", "j3hg") == 0
    capsys.readouterr()
    assert run(ds, cfg, results, "--resume", rd.name, "--cases", "all") == 2
    assert "cannot resume: cases changed" in capsys.readouterr().err


def test_must_not_secret_never_written(env, tmp_path, monkeypatch):
    ds, _, results = env
    monkeypatch.setenv("REDPEN_TEST_KEY", "sk-test-SECRET123")
    cfg_dict = base_config()
    cfg_dict["judges"]["llm"] = {"adapter": "openai_compat", "base_url": "http://judge.invalid",
                                 "model": "judge-model", "api_key_env": "REDPEN_TEST_KEY"}
    cfg = write_config(tmp_path, cfg_dict)
    patch_judge(monkeypatch)
    assert run(ds, cfg, results, "--judge", "llm") == 0
    rd = only_run(results)
    files = [p for p in rd.rglob("*") if p.is_file()]
    assert files
    for p in files:
        assert "sk-test-SECRET123" not in p.read_text()
    assert load(rd / "meta.json")["judge"]["model"] == "judge-model"


def test_same_model_warning(env, tmp_path, monkeypatch, capsys):
    from redpen import runner
    ds, _, results = env
    cfg_dict = base_config()
    shared = {"adapter": "openai_compat", "base_url": "http://x.invalid", "model": "same-model",
              "api_key_env": "REDPEN_TEST_KEY"}
    cfg_dict["reviewers"]["oa"] = dict(shared)
    cfg_dict["judges"]["llm"] = dict(shared)
    cfg = write_config(tmp_path, cfg_dict)
    monkeypatch.setattr(runner, "make_reviewer",
                        lambda name, config: MockReviewer(name, {"adapter": "mock"}))
    patch_judge(monkeypatch)
    argv = ["run", "--reviewer", "oa", "--judge", "llm", "--dataset", str(ds), "--config",
            str(cfg), "--results-dir", str(results), "--cases", "j3hg"]
    assert main(argv) == 0
    assert "warning: reviewer and judge use the same model (same-model)" in capsys.readouterr().err


def test_no_tmp_files_remain(env):
    ds, cfg, results = env
    assert run(ds, cfg, results, "--concurrency", "2") == 0
    rd = only_run(results)
    assert list((rd / "cases").glob("*.tmp")) == []
    assert list(rd.glob("*.tmp")) == []


MIXED = {
    # case id: (vuln mode, fixed mode, vuln status, verdict, fixed status, fixed_clean, pair)
    "GHSA-mx01-0000-0000": ("hit", "clean", "scored", "HIT", "scored", True, 1.0),
    "GHSA-mx02-0000-0000": ("partial", "clean", "scored", "PARTIAL", "scored", True, 0.5),
    "GHSA-mx03-0000-0000": ("miss", "clean", "scored", "MISS", "scored", True, 0.0),
    "GHSA-mx04-0000-0000": ("hit", "fp", "scored", "HIT", "scored", False, 0.0),
    "GHSA-mx05-0000-0000": ("error", "clean", "reviewer_error", None, "scored", True, None),
    "GHSA-mx06-0000-0000": ("empty", "clean", "no_answer", "MISS", "scored", True, 0.0),
    "GHSA-mx07-0000-0000": ("hit", "empty", "scored", "HIT", "no_answer", None, 0.0),
    "GHSA-mx08-0000-0000": ("hit", "error", "scored", "HIT", "reviewer_error", None, None),
    "GHSA-mx09-0000-0000": ("partial", "fp", "scored", "PARTIAL", "scored", False, 0.0),
}
MALFORMED = "GHSA-mx10-0000-0000"
REPAIR = "GHSA-mx11-0000-0000"


def test_mixed_overrides_with_mock_judge(tmp_path):
    ids = sorted([*MIXED, MALFORMED, REPAIR])
    ds = make_dataset(tmp_path, [{"case_id": cid} for cid in ids])
    cfg_dict = base_config(overrides={cid: {"vuln": m[0], "fixed": m[1]}
                                      for cid, m in MIXED.items()})
    cfg_dict["judges"]["mock"] = {"adapter": "mock", "malformed_cases": [MALFORMED],
                                  "repair_cases": [REPAIR]}
    cfg = write_config(tmp_path, cfg_dict)
    results = tmp_path / "results"
    assert run(ds, cfg, results) == 1
    rd = only_run(results)
    for cid, (_, _, v_status, verdict, f_status, clean, pair) in MIXED.items():
        rec = load(rd / "cases" / f"{cid}.json")
        got = (rec["vuln"]["status"], rec["vuln"]["verdict"], rec["fixed"]["status"],
               rec["fixed"]["fixed_clean"], rec["pair_credit"])
        assert got == (v_status, verdict, f_status, clean, pair), cid
        for side in ("vuln", "fixed"):
            if rec[side]["status"] != "scored":
                assert rec[side]["judge"] is None, (cid, side)
        if rec["vuln"]["status"] != "scored":
            assert rec["vuln"]["location_match"] is None
    statuses = {load(p)[s]["status"] for p in (rd / "cases").glob("*.json") for s in ("vuln", "fixed")}
    assert "reviewed" not in statuses

    bad = load(rd / "cases" / f"{MALFORMED}.json")
    for side in ("vuln", "fixed"):
        assert bad[side]["status"] == "judge_error"
        assert bad[side]["judge"]["status"] == "error" and bad[side]["judge"]["error"]
        assert bad[side]["judge"]["parsed"] is None
    assert bad["vuln"]["verdict"] is None and bad["vuln"]["verdict"] != "MISS"
    assert bad["fixed"]["fixed_clean"] is None and bad["pair_credit"] is None

    fixed_up = load(rd / "cases" / f"{REPAIR}.json")
    for side in ("vuln", "fixed"):
        assert fixed_up[side]["status"] == "scored"
        assert fixed_up[side]["judge"]["repaired"] is True
    assert fixed_up["vuln"]["verdict"] == "HIT" and fixed_up["pair_credit"] == 1.0

    meta = load(rd / "meta.json")
    assert meta["counts"]["reviewer_errors"] == 2
    assert meta["counts"]["judge_errors"] == 2


def test_must_not_fixed_empty_is_never_clean(env, tmp_path):
    ds, _, results = env
    cfg = write_config(tmp_path, base_config(fixed="empty"))
    assert run(ds, cfg, results) == 0
    for cid in ALL_IDS:
        rec = load(only_run(results) / "cases" / f"{cid}.json")
        assert rec["fixed"]["status"] == "no_answer"
        assert rec["fixed"]["fixed_clean"] is None
        assert rec["vuln"]["verdict"] == "HIT"
        assert rec["pair_credit"] == 0.0


def test_resume_reruns_judge_error_case(tmp_path, monkeypatch):
    ds = make_dataset(tmp_path, [{"case_id": MALFORMED}])
    cfg_dict = base_config()
    cfg_dict["judges"]["mock"]["malformed_cases"] = [MALFORMED]
    cfg = write_config(tmp_path, cfg_dict)
    results = tmp_path / "results"
    assert run(ds, cfg, results) == 1
    rd = only_run(results)
    calls = counting(monkeypatch)
    assert run(ds, cfg, results, "--resume", rd.name) == 1
    assert sorted(calls) == [(MALFORMED, "fixed"), (MALFORMED, "vuln")]


def test_must_not_openai_judge_unavailable_fails_before_run_dir(env, tmp_path, capsys):
    ds, _, results = env
    cfg_dict = base_config()
    cfg_dict["judges"]["llm"] = {"adapter": "openai_compat", "base_url": "http://judge.invalid",
                                 "model": "judge-model", "api_key_env": "REDPEN_TEST_KEY"}
    cfg = write_config(tmp_path, cfg_dict)
    assert run(ds, cfg, results, "--judge", "llm") == 2
    assert "is not available" in capsys.readouterr().err
    assert run_dirs(results) == []
