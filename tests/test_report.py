import json
import re
from pathlib import Path

import pytest
import yaml

from conftest import load, make_dataset, patch_judge
from redpen.cli import main

CASES = [
    {"case_id": "GHSA-23vg-4cjm-66q5", "guard_class": "path-traversal"},
    {"case_id": "GHSA-23vx-aaaa-bbbb", "guard_class": "path-traversal"},
    {"case_id": "GHSA-j3hg-cccc-dddd", "guard_class": "input-validation"},
]
PT1, PT2, IV = (c["case_id"] for c in CASES)


# ------------------------------------------------------------ helpers

def config(reviewers: dict, judges: dict | None = None) -> dict:
    revs = {}
    for name, opts in reviewers.items():
        entry = {"adapter": "mock", "vuln": "hit", "fixed": "clean", "overrides": {}}
        entry.update(opts)
        revs[name] = entry
    js = {"mock": {"adapter": "mock", "malformed_cases": [], "repair_cases": []}}
    js.update(judges or {})
    return {"default_judge": "mock", "reviewers": revs, "judges": js}


class Env:
    def __init__(self, tmp_path, monkeypatch, cases=CASES, cfg=None):
        self.tmp = tmp_path
        self.mp = monkeypatch
        self.ds = make_dataset(tmp_path, cases)
        self.results = tmp_path / "results"
        self.cfg_path = tmp_path / "reviewers.yaml"
        self.set_config(cfg or config({"mock": {}}))
        self.tick = 0

    def set_config(self, cfg: dict) -> None:
        self.cfg_path.write_text(yaml.safe_dump(cfg))

    def run(self, reviewer, *extra, ds=None) -> Path:
        """Run `redpen run` with a unique, increasing timestamp; return the run dir."""
        from redpen import runner
        self.tick += 1
        stamp = f"20261019T1200{self.tick:02d}Z"
        iso = f"2026-10-19T12:00:{self.tick:02d}Z"
        self.mp.setattr(runner, "utc_stamp", lambda: stamp)
        self.mp.setattr(runner, "utc_now_iso", lambda: iso)
        argv = ["run", "--reviewer", reviewer, "--dataset", str(ds or self.ds), "--config",
                str(self.cfg_path), "--results-dir", str(self.results), *extra]
        code = main(argv)
        assert code in (0, 1)
        (rd,) = [p for p in self.results.iterdir() if p.name.startswith(stamp)]
        return rd

    def report(self, *extra) -> int:
        argv = ["report", "--results-dir", str(self.results), "--dataset", str(self.ds), *extra]
        try:
            return main(argv)
        except SystemExit as exc:
            return exc.code


@pytest.fixture
def env(tmp_path, monkeypatch):
    return Env(tmp_path, monkeypatch)


def save(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2))


def table_rows(out: str) -> dict:
    """Map reviewer name -> list of cells from the leaderboard table."""
    rows = {}
    lines = out.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("rank"))
    header = lines[start]
    cols = [m.start() for m in re.finditer(r"(?:(?<=^)|(?<=  ))\S", header)]
    for line in lines[start + 1:]:
        if not line.strip():
            break
        if set(line.strip()) <= {"-", " "}:
            continue
        cells = [line[a:b].strip() for a, b in zip(cols, cols[1:] + [None])]
        rows[cells[1]] = cells
    return rows


def leaderboard_order(out: str) -> list[str]:
    return list(table_rows(out))


HEADER = ["rank", "reviewer", "model", "pair [95% CI] (n)", "recall [95% CI] (n)",
          "FP rate [95% CI] (n)", "H/P/M", "no answer", "errors (rev/judge)", "label"]
COL = {name: i for i, name in enumerate(HEADER)}


def cell(out: str, reviewer: str, column: str) -> str:
    return table_rows(out)[reviewer][COL[column]]


# ------------------------------------------------------------ statistics

def test_wilson_known_values():
    from redpen.report import wilson
    lo, hi = wilson(5, 10)
    assert lo == pytest.approx(0.2366, abs=1e-4)
    assert hi == pytest.approx(0.7634, abs=1e-4)
    lo, hi = wilson(0, 4)
    assert lo == pytest.approx(0.0, abs=1e-9)
    assert hi == pytest.approx(0.4899, abs=1e-4)
    assert wilson(0, 0) is None


def test_wilson_full_success_is_mirror_of_zero():
    from redpen.report import wilson
    lo, hi = wilson(4, 4)
    assert lo == pytest.approx(0.5101, abs=1e-4)
    assert hi == pytest.approx(1.0, abs=1e-9)


def test_bootstrap_ci():
    from redpen.report import bootstrap_ci
    assert bootstrap_ci([1.0] * 10) == (1.0, 1.0)
    a = bootstrap_ci([0.0, 1.0] * 10)
    b = bootstrap_ci([0.0, 1.0] * 10)
    assert a == b
    assert a[0] < 0.5 < a[1]
    assert bootstrap_ci([]) is None


def test_bootstrap_ci_seed_changes_result():
    from redpen.report import bootstrap_ci
    credits = [i / 29 for i in range(30)]
    assert bootstrap_ci(credits, seed=0) != bootstrap_ci(credits, seed=1)


# ------------------------------------------------------------ leaderboard

def test_perfect_and_mixed_ranked_with_counts_and_classes(env, capsys):
    env.set_config(config({
        "perfect": {},
        "mixed": {"overrides": {PT2: {"vuln": "partial"}, IV: {"fixed": "fp"}}},
    }))
    env.run("mixed")
    env.run("perfect")
    assert env.report() == 0
    out = capsys.readouterr().out
    assert leaderboard_order(out) == ["perfect", "mixed"]
    rows = table_rows(out)
    assert rows["perfect"][COL["rank"]] == "1"
    assert rows["mixed"][COL["rank"]] == "2"
    assert rows["perfect"][COL["pair [95% CI] (n)"]] == "1.00 [1.00, 1.00] (3)"
    assert rows["perfect"][COL["recall [95% CI] (n)"]].startswith("100.0% [")
    assert rows["perfect"][COL["recall [95% CI] (n)"]].endswith("(3)")
    assert rows["perfect"][COL["FP rate [95% CI] (n)"]].startswith("0.0% [0.0%, ")
    assert rows["perfect"][COL["H/P/M"]] == "3/0/0"
    # mixed: credits 1.0, 0.5, 0.0 -> 0.50; recall 2/3; FP 1/3
    assert rows["mixed"][COL["pair [95% CI] (n)"]].startswith("0.50 [")
    assert rows["mixed"][COL["recall [95% CI] (n)"]].startswith("66.7% [")
    assert rows["mixed"][COL["FP rate [95% CI] (n)"]].startswith("33.3% [")
    assert rows["mixed"][COL["H/P/M"]] == "2/1/0"
    assert rows["mixed"][COL["errors (rev/judge)"]] == "0/0"
    assert rows["mixed"][COL["no answer"]] == "0"
    assert rows["mixed"][COL["label"]] == ""
    # per-class table: class rows with k/n per reviewer
    pt = next(line for line in out.splitlines() if line.startswith("path-traversal"))
    iv = next(line for line in out.splitlines() if line.startswith("input-validation"))
    assert pt.split()[1:] == ["2/2", "1/2"]
    assert iv.split()[1:] == ["1/1", "1/1"]


def test_metrics_values(env):
    from redpen.dataset import load_dataset
    from redpen.report import load_run, run_metrics
    env.set_config(config({"mixed": {"overrides": {PT2: {"vuln": "partial"}, IV: {"fixed": "fp"}}}}))
    rd = env.run("mixed")
    classes = sorted({c.guard_class for c in load_dataset(env.ds).cases})
    m = run_metrics(load_run(rd), classes)
    assert (m["recall"]["k"], m["recall"]["n"]) == (2, 3)
    assert (m["fp"]["k"], m["fp"]["n"]) == (1, 3)
    assert m["pair"]["n"] == 3 and m["pair"]["score"] == pytest.approx(0.5)
    assert m["hpm"] == (2, 1, 0)
    assert m["per_class"] == {"input-validation": (1, 1), "path-traversal": (1, 2)}


def test_classes_absent_from_selection_show_dash(env, capsys):
    env.run("mock", "--cases", "input-validation")
    assert env.report() == 0
    out = capsys.readouterr().out
    pt = next(line for line in out.splitlines() if line.startswith("path-traversal"))
    iv = next(line for line in out.splitlines() if line.startswith("input-validation"))
    assert pt.split()[1:] == ["-"]
    assert iv.split()[1:] == ["1/1"]


def test_must_not_fixed_errors_everywhere_is_na_not_zero(env, capsys):
    env.set_config(config({"broken": {"fixed": "error"}}))
    env.run("broken")
    assert env.report() == 0
    out = capsys.readouterr().out
    fp = cell(out, "broken", "FP rate [95% CI] (n)")
    assert fp.startswith("n/a")
    assert "0.0%" not in fp and "0%" not in fp
    assert cell(out, "broken", "errors (rev/judge)") == "3/0"
    assert cell(out, "broken", "pair [95% CI] (n)").startswith("n/a")


def test_must_not_judge_errors_excluded_from_recall_n(env, capsys):
    cfg = config({"mock": {}})
    cfg["judges"]["mock"]["malformed_cases"] = [IV]
    env.set_config(cfg)
    env.run("mock")
    assert env.report() == 0
    out = capsys.readouterr().out
    recall = cell(out, "mock", "recall [95% CI] (n)")
    assert recall.startswith("100.0% [") and recall.endswith("(2)")
    assert cell(out, "mock", "FP rate [95% CI] (n)").endswith("(2)")
    assert cell(out, "mock", "pair [95% CI] (n)").endswith("(2)")
    assert cell(out, "mock", "H/P/M") == "2/0/0"
    assert cell(out, "mock", "errors (rev/judge)") == "0/2"
    assert cell(out, "mock", "label") == "ERRORS"
    assert cell(out, "mock", "rank") == "1"


def test_must_not_empty_vuln_sides_count_as_miss(tmp_path, monkeypatch, capsys):
    cases = [{"case_id": f"GHSA-q{i:03d}-0000-0000", "guard_class": "path-traversal"}
             for i in range(25)]
    quiet = {c["case_id"]: {"vuln": "empty"} for c in cases[:5]}
    env = Env(tmp_path, monkeypatch, cases=cases,
              cfg=config({"quiet": {"overrides": quiet}, "answers": {}}))
    env.run("quiet")
    env.run("answers")
    assert env.report() == 0
    out = capsys.readouterr().out
    assert leaderboard_order(out) == ["answers", "quiet"]
    recall = cell(out, "quiet", "recall [95% CI] (n)")
    assert recall.startswith("80.0% [") and recall.endswith("(25)")
    assert cell(out, "quiet", "H/P/M") == "20/0/5"
    assert cell(out, "quiet", "no answer") == "5"
    assert cell(out, "quiet", "pair [95% CI] (n)").startswith("0.80 [")
    assert cell(out, "quiet", "pair [95% CI] (n)").endswith("(25)")
    assert cell(out, "quiet", "errors (rev/judge)") == "0/0"
    assert cell(out, "quiet", "rank") == "2"


def test_reviewer_error_run_is_unranked_below_ranked(env, capsys):
    env.set_config(config({
        "flaky": {"overrides": {IV: {"vuln": "error"}}},
        "mixed": {"overrides": {PT2: {"vuln": "miss"}}},
    }))
    env.run("flaky")
    env.run("mixed")
    assert env.report() == 0
    out = capsys.readouterr().out
    assert cell(out, "flaky", "pair [95% CI] (n)").startswith("1.00")
    assert leaderboard_order(out) == ["mixed", "flaky"]
    assert cell(out, "mixed", "rank") == "1"
    assert cell(out, "flaky", "rank") == "-"
    assert cell(out, "flaky", "label") == "UNRANKED"
    assert cell(out, "flaky", "errors (rev/judge)") == "1/0"


# ------------------------------------------------------------ comparability

def llm_judge(**extra) -> dict:
    entry = {"adapter": "openai_compat", "base_url": "http://judge.invalid", "model": "judge-a",
             "api_key_env": "REDPEN_TEST_KEY", "temperature": 0}
    entry.update(extra)
    return entry


@pytest.mark.parametrize("j2", [{"model": "judge-b"}, {"temperature": 0.7}])
def test_must_not_different_judge_config_exits_2(env, monkeypatch, capsys, j2):
    patch_judge(monkeypatch)
    env.set_config(config({"r1": {}, "r2": {}}, {"j1": llm_judge(), "j2": llm_judge(**j2)}))
    a = env.run("r1", "--judge", "j1")
    b = env.run("r2", "--judge", "j2")
    assert env.report() == 2
    err = capsys.readouterr().err
    assert "runs are not comparable: judge.config_sha256 differs" in err
    ha = load(a / "meta.json")["judge"]["config_sha256"]
    hb = load(b / "meta.json")["judge"]["config_sha256"]
    assert ha in err and hb in err


def test_same_judge_config_is_comparable(env, monkeypatch, capsys):
    patch_judge(monkeypatch)
    env.set_config(config({"r1": {}, "r2": {}}, {"j1": llm_judge()}))
    env.run("r1", "--judge", "j1")
    env.run("r2", "--judge", "j1")
    assert env.report() == 0
    out = capsys.readouterr().out
    assert sorted(leaderboard_order(out)) == ["r1", "r2"]


def test_served_judge_model_drift_warns_and_continues(env, capsys):
    env.set_config(config({"r1": {}, "r2": {}}))
    for name, served in (("r1", "judge-x-0613"), ("r2", "judge-x-0901")):
        rd = env.run(name)
        for path in (rd / "cases").glob("*.json"):
            rec = load(path)
            for side in ("vuln", "fixed"):
                rec[side]["judge"]["response_meta"]["model"] = served
            save(path, rec)
    assert env.report() == 0
    captured = capsys.readouterr()
    assert "warning: served judge models differ: judge-x-0613, judge-x-0901" in captured.err
    assert sorted(leaderboard_order(captured.out)) == ["r1", "r2"]


def test_same_served_judge_model_does_not_warn(env, capsys):
    env.set_config(config({"r1": {}, "r2": {}}))
    env.run("r1")
    env.run("r2")
    assert env.report() == 0
    assert "served judge models differ" not in capsys.readouterr().err


def test_must_not_different_case_ids_exit_2(env, capsys):
    env.set_config(config({"r1": {}, "r2": {}}))
    env.run("r1", "--cases", "path-traversal")
    env.run("r2")
    assert env.report() == 2
    assert "runs are not comparable: case_ids differs" in capsys.readouterr().err


def test_must_not_different_scoring_exit_2(env, capsys):
    env.set_config(config({"r1": {}, "r2": {}}))
    env.run("r1")
    rd = env.run("r2")
    meta = load(rd / "meta.json")
    meta["scoring"]["formula"] = "pair-v2"
    save(rd / "meta.json", meta)
    assert env.report() == 2
    assert "runs are not comparable: scoring differs" in capsys.readouterr().err


@pytest.mark.parametrize("field", ["review_sha256", "judge_sha256"])
def test_must_not_different_prompt_hash_exit_2(env, capsys, field):
    env.set_config(config({"r1": {}, "r2": {}}))
    env.run("r1")
    rd = env.run("r2")
    meta = load(rd / "meta.json")
    meta["prompts"][field] = "0" * 64
    save(rd / "meta.json", meta)
    assert env.report() == 2
    assert f"runs are not comparable: prompts.{field} differs" in capsys.readouterr().err


# ------------------------------------------------------------ run selection

def make_incomplete(rd: Path, drop: str) -> None:
    (rd / "cases" / f"{drop}.json").unlink()
    meta = load(rd / "meta.json")
    meta["complete"] = False
    meta["finished_utc"] = None
    save(rd / "meta.json", meta)


def test_incomplete_run_ignored_by_default_and_labeled_with_runs(env, capsys):
    env.set_config(config({"r1": {}, "r2": {}}))
    env.run("r1")
    partial = env.run("r2")
    make_incomplete(partial, IV)
    assert env.report() == 0
    out = capsys.readouterr().out
    assert f"ignored incomplete runs: {partial.name}" in out
    assert leaderboard_order(out) == ["r1"]

    assert env.report("--runs", partial.name) == 0
    out = capsys.readouterr().out
    assert leaderboard_order(out) == ["r2"]
    assert cell(out, "r2", "label") == "INCOMPLETE"
    assert cell(out, "r2", "recall [95% CI] (n)").endswith("(2)")
    assert cell(out, "r2", "H/P/M") == "2/0/0"
    assert cell(out, "r2", "pair [95% CI] (n)") == "1.00 [1.00, 1.00] (2)"


def test_incomplete_with_judge_errors_has_both_labels(env, capsys):
    cfg = config({"mock": {}})
    cfg["judges"]["mock"]["malformed_cases"] = [PT1]
    env.set_config(cfg)
    rd = env.run("mock")
    make_incomplete(rd, IV)
    assert env.report("--runs", rd.name) == 0
    label = cell(capsys.readouterr().out, "mock", "label")
    assert "INCOMPLETE" in label and "ERRORS" in label


def test_default_selection_picks_newest_complete_run_per_reviewer(env, capsys):
    env.set_config(config({"mock": {"vuln": "miss"}}))
    old = env.run("mock")
    env.set_config(config({"mock": {}}))
    new = env.run("mock")
    env.set_config(config({"mock": {"vuln": "partial"}}))
    newest = env.run("mock")
    make_incomplete(newest, IV)
    capsys.readouterr()
    assert env.report() == 0
    out = capsys.readouterr().out
    assert leaderboard_order(out) == ["mock"]
    assert cell(out, "mock", "H/P/M") == "3/0/0"
    assert new.name in out and old.name not in out
    assert f"ignored incomplete runs: {newest.name}" in out


def test_no_complete_runs_exit_2(env, capsys):
    env.results.mkdir()
    assert env.report() == 2
    err = capsys.readouterr().err
    assert f"no complete runs in {env.results} for dataset v1" in err


def test_default_selection_skips_other_dataset_runs(env, tmp_path, monkeypatch, capsys):
    other = make_dataset(tmp_path / "other", [{"case_id": "GHSA-zzzz-0000-0000"}])
    env.run("mock", ds=other)
    assert env.report() == 2
    assert "no complete runs" in capsys.readouterr().err


def test_must_not_runs_with_other_case_set_exit_2(env, tmp_path, capsys):
    other = make_dataset(tmp_path / "other", [{"case_id": "GHSA-zzzz-0000-0000"}])
    rd = env.run("mock", ds=other)
    env.run("mock")
    assert env.report("--runs", rd.name) == 2
    err = capsys.readouterr().err
    mine = load(env.ds / "manifest.json")["case_set_sha256"]
    theirs = load(other / "manifest.json")["case_set_sha256"]
    assert rd.name in err and mine in err and theirs in err
    assert "case_set_sha256" in err


def test_must_not_runs_unknown_id_exit_2(env, capsys):
    env.run("mock")
    assert env.report("--runs", "20990101T000000Z-nope-00000000") == 2
    assert "run 20990101T000000Z-nope-00000000 not found" in capsys.readouterr().err


# ------------------------------------------------------------ markdown

def test_markdown_numbers_equal_terminal(env, tmp_path, capsys):
    env.set_config(config({
        "perfect": {},
        "mixed": {"overrides": {PT2: {"vuln": "partial"}, IV: {"fixed": "fp"}}},
    }))
    env.run("perfect")
    env.run("mixed")
    md_path = tmp_path / "board.md"
    assert env.report("--markdown", str(md_path)) == 0
    term = table_rows(capsys.readouterr().out)
    md = md_path.read_text()
    lines = md.splitlines()
    first = next(i for i, line in enumerate(lines) if line.startswith("|"))
    preamble = "\n".join(lines[:first])
    for needle in ("v1", "review-v1", "judge-v1", "pair-v1"):
        assert needle in preamble
    header = [c.strip() for c in lines[first].strip("|").split("|")]
    assert header == HEADER
    assert set(lines[first + 1].replace("|", "").replace(" ", "")) <= {"-", ":"}
    md_rows = {}
    for line in lines[first + 2:]:
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        md_rows[cells[1]] = cells
    assert list(md_rows) == list(term)
    assert md_rows == term
