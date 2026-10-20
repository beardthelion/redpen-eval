"""Run a reviewer over both sides of selected cases, writing resumable results (R7, R10, R11)."""

from __future__ import annotations

import json
import platform
import sys
from concurrent.futures import ThreadPoolExecutor
from importlib.metadata import version as package_version
from pathlib import Path

from redpen.config import load_config
from redpen.dataset import load_dataset
from redpen import scorer
from redpen.judge import JudgeRequest, judge_side, make_judge_backend
from redpen.prompts import (JUDGE_PROMPT_VERSION, REVIEW_PROMPT, REVIEW_PROMPT_VERSION,
                            judge_prompt_sha256, numbered_window, prompt_sha256,
                            render_review_prompt)
from redpen.reviewers import ReviewerError, ReviewRequest, make_reviewer
from redpen.util import atomic_write_json, canonical_json, sha256_bytes, utc_now_iso, utc_stamp

SCORING = {"formula": "pair-v1", "location_tolerance": scorer.LOCATION_TOLERANCE,
           "bootstrap_resamples": 1000, "bootstrap_seed": 0}
ERROR_STATUSES = {"reviewer_error", "judge_error"}
SIDES = ("vuln", "fixed")


class RunError(Exception):
    pass


def select_cases(spec: str, dataset) -> list[str]:
    ids = [c.case_id for c in dataset.cases]
    classes = {c.guard_class for c in dataset.cases}
    selected = set()
    for token in (t.strip() for t in spec.split(",")):
        if token == "all":
            selected.update(ids)
        elif token in classes:
            selected.update(c.case_id for c in dataset.cases if c.guard_class == token)
        elif token in ids:
            selected.add(token)
        else:
            matches = [cid for cid in ids if cid.startswith(f"GHSA-{token}-")]
            if len(matches) > 1:
                raise RunError(f"ambiguous short id {token}: {', '.join(sorted(matches))}")
            if not matches:
                raise RunError(f"unknown case or guard class: {token}")
            selected.add(matches[0])
    return sorted(selected)


def config_sha256(entry: dict) -> str:
    return sha256_bytes(canonical_json(entry))


def _identity(name: str, entry: dict, fields: tuple) -> dict:
    out = {"name": name, "adapter": entry["adapter"]}
    for key in fields:
        out[key] = entry.get(key)
    out["api_key_env"] = entry.get("api_key_env")
    out["config_sha256"] = config_sha256(entry)
    return out


def _review_side(reviewer, judge, tier: str, case, side: str) -> dict:
    rec = {"status": None, "review_text": None, "review_error": None, "response_meta": {},
           "judge": None}
    try:
        result = reviewer.review(ReviewRequest(render_review_prompt(case, side), case, side))
    except ReviewerError as exc:
        status = "no_answer" if exc.kind == "refusal" else "reviewer_error"
        rec.update(status=status, review_error={"kind": exc.kind, "message": exc.message})
    else:
        rec.update(review_text=result.text, response_meta=result.meta)
        if not result.text.strip():
            rec.update(status="no_answer",
                       review_error={"kind": "empty_output", "message": "reviewer returned no text"})
    if side == "vuln":
        rec["location_match"] = None
        rec["verdict"] = "MISS" if rec["status"] == "no_answer" else None
    else:
        rec["fixed_clean"] = None
    if rec["status"] is not None:
        return rec

    outcome = judge_side(judge, JudgeRequest(case, side, numbered_window(case, side),
                                             rec["review_text"]), tier)
    rec["judge"] = outcome.to_dict()
    if outcome.status != "ok":
        rec["status"] = "judge_error"
        return rec
    rec["status"] = "scored"
    if side == "vuln":
        spans = case.data["vuln"]["expected_spans"]
        rec["location_match"] = scorer.located(outcome.parsed["cited_ranges"], spans)
        rec["verdict"] = scorer.vuln_verdict(outcome.parsed, spans)
    else:
        rec["fixed_clean"] = scorer.fixed_clean(outcome.parsed)
    return rec


def _run_case(reviewer, judge, tier: str, case, cases_dir: Path) -> None:
    rec = {"case_id": case.case_id, "guard_class": case.guard_class}
    for side in SIDES:
        rec[side] = _review_side(reviewer, judge, tier, case, side)
    rec["pair_credit"] = scorer.pair_credit(rec["vuln"], rec["fixed"])
    atomic_write_json(cases_dir / f"{case.case_id}.json", rec)


def _count(run_dir: Path, case_ids: list[str]) -> dict:
    counts = {"cases": len(case_ids), "done": 0, "reviewer_errors": 0, "judge_errors": 0}
    for cid in case_ids:
        path = run_dir / "cases" / f"{cid}.json"
        if not path.exists():
            continue
        rec = json.loads(path.read_text())
        counts["done"] += 1
        for side in SIDES:
            status = rec[side]["status"]
            if status == "reviewer_error":
                counts["reviewer_errors"] += 1
            elif status == "judge_error":
                counts["judge_errors"] += 1
    return counts


def _needs_run(path: Path) -> bool:
    if not path.exists():
        return True
    rec = json.loads(path.read_text())
    return any(rec[side]["status"] in ERROR_STATUSES for side in SIDES)


def run(reviewer_name: str, judge_name: str | None, cases_spec: str | None, dataset_path,
        config_path, results_dir, concurrency: int = 4, resume: str | None = None) -> int:
    config = load_config(config_path)
    judge_name = judge_name or config.default_judge
    if reviewer_name not in config.reviewers:
        raise RunError(f"unknown reviewer {reviewer_name!r}")
    if judge_name not in config.judges:
        raise RunError(f"unknown judge {judge_name!r}")
    r_entry, j_entry = config.reviewers[reviewer_name], config.judges[judge_name]
    if (r_entry["adapter"] == j_entry["adapter"] == "openai_compat"
            and r_entry.get("model") == j_entry.get("model")):
        print(f"warning: reviewer and judge use the same model ({r_entry.get('model')})",
              file=sys.stderr)
    reviewer = make_reviewer(reviewer_name, config)
    judge = make_judge_backend(judge_name, config)
    tier = j_entry.get("structured_output", "json_schema")
    dataset = load_dataset(dataset_path)
    if concurrency < 1:
        raise RunError("--concurrency must be at least 1")

    reviewer_id = _identity(reviewer_name, r_entry,
                            ("model", "base_url", "temperature", "max_tokens", "seed"))
    judge_id = _identity(judge_name, j_entry, ("model", "base_url", "temperature", "max_tokens",
                                               "structured_output"))
    prompts = {"review_version": REVIEW_PROMPT_VERSION,
               "review_sha256": prompt_sha256(REVIEW_PROMPT),
               "judge_version": JUDGE_PROMPT_VERSION, "judge_sha256": judge_prompt_sha256()}
    case_set = dataset.manifest["case_set_sha256"]
    results_dir = Path(results_dir)

    if resume:
        run_dir = results_dir / resume
        try:
            meta = json.loads((run_dir / "meta.json").read_text())
        except (OSError, ValueError) as exc:
            raise RunError(f"cannot resume {resume}: {exc}") from exc
        checks = (
            ("reviewer config", (meta["reviewer"]["name"], meta["reviewer"]["config_sha256"]),
             (reviewer_name, reviewer_id["config_sha256"])),
            ("judge config", (meta["judge"]["name"], meta["judge"]["config_sha256"]),
             (judge_name, judge_id["config_sha256"])),
            ("dataset", meta["dataset"]["case_set_sha256"], case_set),
            ("prompts", meta["prompts"], prompts),
        )
        for field, stored, current in checks:
            if stored != current:
                raise RunError(f"cannot resume: {field} changed")
        case_ids = meta["case_ids"]
        if cases_spec is not None and select_cases(cases_spec, dataset) != case_ids:
            raise RunError("cannot resume: cases changed")
    else:
        case_ids = select_cases(cases_spec or "all", dataset)
        run_id = f"{utc_stamp()}-{reviewer_name}-{reviewer_id['config_sha256'][:8]}"
        run_dir = results_dir / run_id
        (run_dir / "cases").mkdir(parents=True, exist_ok=False)
        meta = {
            "run_id": run_id,
            "reviewer": reviewer_id,
            "judge": judge_id,
            "dataset": {"path": str(dataset_path), "version": dataset.manifest["dataset_version"],
                        "case_set_sha256": case_set},
            "case_ids": case_ids,
            "prompts": prompts,
            "scoring": SCORING,
            "harness": {"redpen_version": package_version("redpen"), "python": platform.python_version()},
            "started_utc": utc_now_iso(),
            "finished_utc": None,
            "complete": False,
            "counts": {"cases": len(case_ids), "done": 0, "reviewer_errors": 0, "judge_errors": 0},
        }
        atomic_write_json(run_dir / "meta.json", meta)

    cases_dir = run_dir / "cases"
    by_id = {c.case_id: c for c in dataset.cases}
    todo = [by_id[cid] for cid in case_ids if _needs_run(cases_dir / f"{cid}.json")]
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        for future in [pool.submit(_run_case, reviewer, judge, tier, case, cases_dir) for case in todo]:
            future.result()

    counts = _count(run_dir, case_ids)
    meta["counts"] = counts
    meta["complete"] = counts["done"] == counts["cases"]
    meta["finished_utc"] = utc_now_iso()
    atomic_write_json(run_dir / "meta.json", meta)

    print(f"run {meta['run_id']}: {counts['done']}/{counts['cases']} cases, "
          f"reviewer errors {counts['reviewer_errors']}, judge errors {counts['judge_errors']}")
    print(f"results: {run_dir}")
    if not meta["complete"]:
        return 1
    return 1 if counts["reviewer_errors"] or counts["judge_errors"] else 0
