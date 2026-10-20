"""Aggregate comparable runs into a leaderboard (R14, R15, R16, R17, KTD8, KTD14, KTD16)."""

from __future__ import annotations

import html
import json
import math
import random
import sys
from dataclasses import dataclass
from pathlib import Path

from redpen.dataset import load_dataset
from redpen.util import atomic_write_text, utc_now_iso

COMPARED_FIELDS = (
    ("dataset", "version"), ("dataset", "case_set_sha256"), ("case_ids",),
    ("prompts", "review_sha256"), ("prompts", "judge_sha256"), ("judge", "config_sha256"),
    ("scoring",),
)
HEADER = ["rank", "reviewer", "model", "pair [95% CI] (n)", "recall [95% CI] (n)",
          "FP rate [95% CI] (n)", "H/P/M", "no answer", "errors (rev/judge)", "label"]


class ReportError(Exception):
    pass


@dataclass
class Run:
    run_id: str
    dir: Path
    meta: dict
    cases: list[dict]


# ------------------------------------------------------------ statistics

def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    if n == 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, center - half), min(1.0, center + half)


def bootstrap_ci(credits, resamples: int = 1000, seed: int = 0) -> tuple[float, float] | None:
    if not credits:
        return None
    rng = random.Random(seed)
    n = len(credits)
    means = sorted(sum(rng.choices(credits, k=n)) / n for _ in range(resamples))
    return means[round(0.025 * (resamples - 1))], means[round(0.975 * (resamples - 1))]


# ------------------------------------------------------------ loading and selection

def load_run(run_dir) -> Run:
    run_dir = Path(run_dir)
    meta = json.loads((run_dir / "meta.json").read_text())
    cases = []
    for cid in meta["case_ids"]:
        path = run_dir / "cases" / f"{cid}.json"
        if path.exists():
            cases.append(json.loads(path.read_text()))
    return Run(meta["run_id"], run_dir, meta, cases)


def _dataset_mismatch(meta: dict, manifest: dict) -> str | None:
    for field, want in (("version", manifest["dataset_version"]),
                        ("case_set_sha256", manifest["case_set_sha256"])):
        if meta["dataset"][field] != want:
            return f"dataset.{field} {meta['dataset'][field]} does not match dataset {want}"
    return None


def select_runs(results_dir, manifest: dict, run_ids: list[str] | None) -> tuple[list[Run], list[str]]:
    """Return (selected runs, ignored incomplete run ids)."""
    results_dir = Path(results_dir)
    if run_ids:
        runs = []
        for rid in run_ids:
            if not (results_dir / rid / "meta.json").is_file():
                raise ReportError(f"run {rid} not found in {results_dir}")
            run = load_run(results_dir / rid)
            problem = _dataset_mismatch(run.meta, manifest)
            if problem:
                raise ReportError(f"run {rid}: {problem}")
            runs.append(run)
        return runs, []
    metas = []
    for path in sorted(results_dir.glob("*/meta.json")):
        meta = json.loads(path.read_text())
        if _dataset_mismatch(meta, manifest) is None:
            metas.append((path.parent, meta))
    ignored = sorted(m["run_id"] for _, m in metas if not m["complete"])
    latest = {}
    for run_dir, meta in metas:
        if not meta["complete"]:
            continue
        name = meta["reviewer"]["name"]
        key = (meta["started_utc"], meta["run_id"])
        if name not in latest or key > latest[name][0]:
            latest[name] = (key, run_dir)
    if not latest:
        raise ReportError(f"no complete runs in {results_dir} for dataset {manifest['dataset_version']}")
    return [load_run(run_dir) for _, run_dir in latest.values()], ignored


def _field(meta: dict, path: tuple):
    for key in path:
        meta = meta[key]
    return meta


def check_comparable(runs: list[Run]) -> None:
    first = runs[0]
    for path in COMPARED_FIELDS:
        a = _field(first.meta, path)
        for other in runs[1:]:
            b = _field(other.meta, path)
            if a != b:
                name = ".".join(path)
                raise ReportError(f"runs are not comparable: {name} differs "
                                  f"({first.run_id}: {json.dumps(a)} vs {other.run_id}: {json.dumps(b)})")


def served_judge_models(runs: list[Run]) -> list[str]:
    models = set()
    for run in runs:
        for rec in run.cases:
            for side in ("vuln", "fixed"):
                judge = rec[side].get("judge") or {}
                model = (judge.get("response_meta") or {}).get("model")
                if model:
                    models.add(model)
    return sorted(models)


# ------------------------------------------------------------ metrics

def run_metrics(run: Run, classes: list[str]) -> dict:
    hpm = {"HIT": 0, "PARTIAL": 0, "MISS": 0}
    fp_k = fp_n = no_answer = rev_err = judge_err = 0
    credits = []
    per_class = {}
    for rec in run.cases:
        vuln, fixed = rec["vuln"], rec["fixed"]
        for side in (vuln, fixed):
            no_answer += side["status"] == "no_answer"
            rev_err += side["status"] == "reviewer_error"
            judge_err += side["status"] == "judge_error"
        if vuln["status"] in ("scored", "no_answer"):
            hpm[vuln["verdict"]] += 1
            k, n = per_class.get(rec["guard_class"], (0, 0))
            per_class[rec["guard_class"]] = (k + (vuln["verdict"] == "HIT"), n + 1)
        if fixed["status"] == "scored":
            fp_n += 1
            fp_k += not fixed["fixed_clean"]
        if rec["pair_credit"] is not None:
            credits.append(rec["pair_credit"])
    recall_n = sum(hpm.values())
    scoring = run.meta["scoring"]
    return {
        "run_id": run.run_id,
        "reviewer": run.meta["reviewer"]["name"],
        "model": run.meta["reviewer"].get("model"),
        "complete": run.meta["complete"],
        "recall": {"k": hpm["HIT"], "n": recall_n, "ci": wilson(hpm["HIT"], recall_n)},
        "fp": {"k": fp_k, "n": fp_n, "ci": wilson(fp_k, fp_n)},
        "pair": {"score": sum(credits) / len(credits) if credits else None, "n": len(credits),
                 "ci": bootstrap_ci(credits, scoring["bootstrap_resamples"],
                                    scoring["bootstrap_seed"])},
        "hpm": (hpm["HIT"], hpm["PARTIAL"], hpm["MISS"]),
        "no_answer": no_answer,
        "reviewer_errors": rev_err,
        "judge_errors": judge_err,
        "per_class": {c: per_class[c] for c in classes if c in per_class},
    }


def rank(metrics: list[dict]) -> list[dict]:
    """Sort ranked rows by pair, recall, name; reviewer-error runs go below with rank '-'."""
    def key(m):
        pair = m["pair"]["score"]
        recall = m["recall"]["k"] / m["recall"]["n"] if m["recall"]["n"] else -1.0
        return (-(pair if pair is not None else -1.0), -recall, m["reviewer"], m["run_id"])

    ranked = sorted((m for m in metrics if not m["reviewer_errors"]), key=key)
    unranked = sorted((m for m in metrics if m["reviewer_errors"]), key=key)
    for i, m in enumerate(ranked, start=1):
        m["rank"] = str(i)
    for m in unranked:
        m["rank"] = "-"
    return ranked + unranked


# ------------------------------------------------------------ rendering

def _pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def _rate_cell(stat: dict) -> str:
    if stat["n"] == 0:
        return "n/a (0)"
    lo, hi = stat["ci"]
    return f"{_pct(stat['k'] / stat['n'])} [{_pct(lo)}, {_pct(hi)}] ({stat['n']})"


def _pair_cell(pair: dict) -> str:
    if pair["n"] == 0:
        return "n/a (0)"
    lo, hi = pair["ci"]
    return f"{pair['score']:.2f} [{lo:.2f}, {hi:.2f}] ({pair['n']})"


def _label(m: dict) -> str:
    labels = []
    if not m["complete"]:
        labels.append("INCOMPLETE")
    if m["reviewer_errors"]:
        labels.append("UNRANKED")
    elif m["judge_errors"]:
        labels.append("ERRORS")
    return " ".join(labels)


def leaderboard_cells(m: dict) -> list[str]:
    return [m["rank"], m["reviewer"], m["model"] or "-", _pair_cell(m["pair"]),
            _rate_cell(m["recall"]), _rate_cell(m["fp"]), "/".join(map(str, m["hpm"])),
            str(m["no_answer"]), f"{m['reviewer_errors']}/{m['judge_errors']}", _label(m)]


def _table(header: list[str], rows: list[list[str]]) -> str:
    widths = [max(len(r[i]) for r in [header, *rows]) for i in range(len(header))]
    fmt = lambda r: "  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip()
    lines = [fmt(header), "  ".join("-" * w for w in widths), *(fmt(r) for r in rows)]
    return "\n".join(lines)


def class_cells(metrics: list[dict], classes: list[str]) -> list[list[str]]:
    rows = []
    for c in classes:
        row = [c]
        for m in metrics:
            k, n = m["per_class"].get(c, (0, 0))
            row.append(f"{k}/{n}" if n else "-")
        rows.append(row)
    return rows


def render_terminal(metrics: list[dict], classes: list[str]) -> str:
    board = _table(HEADER, [leaderboard_cells(m) for m in metrics])
    per_class = _table(["guard class", *(m["reviewer"] for m in metrics)],
                       class_cells(metrics, classes))
    return f"{board}\n\nrecall by guard class (HIT/n)\n{per_class}\n"


def render_markdown(metrics: list[dict], meta: dict) -> str:
    p = meta["prompts"]
    intro = (f"Dataset {meta['dataset']['version']}, judge model {meta['judge'].get('model') or '-'} "
             f"({meta['judge']['name']}), prompts {p['review_version']} / {p['judge_version']}, "
             f"formula {meta['scoring']['formula']}.")
    row = lambda cells: "| " + " | ".join(cells) + " |"
    lines = [intro, "", row(HEADER), row(["---"] * len(HEADER)),
             *(row(leaderboard_cells(m)) for m in metrics)]
    return "\n".join(lines) + "\n"


HTML_CSS = """
:root { color-scheme: light dark; --bg: #ffffff; --fg: #1b1b1f; --muted: #5c5f66;
  --line: #d9dce1; --panel: #f4f5f7; --bad: #b42318; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #15171a; --fg: #e6e7ea; --muted: #a0a4ab; --line: #33373d;
    --panel: #1e2125; --bad: #f97066; }
}
body { background: var(--bg); color: var(--fg); margin: 0 auto; max-width: 1200px;
  padding: 16px; font: 14px/1.45 system-ui, sans-serif; }
p.meta { color: var(--muted); }
table { border-collapse: collapse; margin: 8px 0 24px; display: block; overflow-x: auto; }
th, td { border-bottom: 1px solid var(--line); padding: 4px 10px; text-align: left;
  white-space: nowrap; }
details { border: 1px solid var(--line); border-radius: 6px; margin: 6px 0; padding: 4px 10px; }
summary { cursor: pointer; font-family: ui-monospace, monospace; }
.sides { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 12px; }
pre { background: var(--panel); padding: 8px; overflow-x: auto; white-space: pre-wrap;
  word-break: break-word; }
.error { color: var(--bad); }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 2px 10px; }
dt { color: var(--muted); }
dd { margin: 0; }
"""


def _e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _html_table(header: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{_e(h)}</th>" for h in header)
    body = "".join("<tr>" + "".join(f"<td>{_e(c)}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _dl(items: list[tuple[str, str]]) -> str:
    return "<dl>" + "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in items) + "</dl>"


def _side_html(title: str, side: dict) -> str:
    parts = [f"<h4>{_e(title)}</h4>", _dl([("status", side["status"])])]
    err = side.get("review_error")
    if err:
        cls = ' class="error"' if side["status"] == "reviewer_error" else ""
        parts.append(f"<p{cls}>{_e(err['kind'])}: {_e(err['message'])}</p>")
    if side.get("review_text") is not None:
        parts.append(f"<pre>{_e(side['review_text'])}</pre>")
    judge = side.get("judge")
    if judge:
        if judge.get("error"):
            parts.append(f'<p class="error">{_e(side["status"])}: {_e(judge["error"])}</p>')
        parsed = judge.get("parsed")
        if parsed:
            parts.append(f"<p>{_e(parsed.get('rationale'))}</p>")
            parts.append(f"<pre>{_e(json.dumps(parsed, indent=2, sort_keys=True))}</pre>")
    if "verdict" in side:
        parts.append(_dl([("verdict", side["verdict"] or "-"),
                          ("location match", side.get("location_match"))]))
    else:
        parts.append(_dl([("fixed clean", side.get("fixed_clean"))]))
    return "<div>" + "".join(parts) + "</div>"


def _case_html(rec: dict, case: dict) -> str:
    spans = ", ".join(f"{s['start']}-{s['end']} ({s['source']})"
                      for s in case["vuln"]["expected_spans"])
    credit = rec["pair_credit"]
    info = _dl([("guard class", rec["guard_class"]), ("repo", case["repo_url"]),
                ("vulnerability", case["vuln_description"]), ("expected spans", spans),
                ("pair credit", "-" if credit is None else f"{credit:.2f}")])
    verdict = rec["vuln"].get("verdict") or rec["vuln"]["status"]
    return (f"<details><summary>{_e(rec['case_id'])} {_e(verdict)}</summary>{info}"
            f"<div class=\"sides\">{_side_html('vuln side', rec['vuln'])}"
            f"{_side_html('fixed side', rec['fixed'])}</div></details>")


def render_html(metrics: list[dict], runs: list[Run], classes: list[str],
                cases: dict, generated_utc: str) -> str:
    meta = runs[0].meta
    p = meta["prompts"]
    header = (f"Dataset {meta['dataset']['version']}, {len(meta['case_ids'])} cases, "
              f"judge model {meta['judge'].get('model') or '-'} ({meta['judge']['name']}), "
              f"prompts {p['review_version']} / {p['judge_version']}, "
              f"formula {meta['scoring']['formula']}, generated {generated_utc}.")
    by_id = {r.run_id: r for r in runs}
    sections = []
    for m in metrics:
        run = by_id[m["run_id"]]
        details = "".join(_case_html(rec, cases[rec["case_id"]]) for rec in run.cases)
        sections.append(f"<h3>{_e(m['reviewer'])}</h3><p class=\"meta\">run {_e(m['run_id'])}</p>"
                        f"{details}")
    per_class = _html_table(["guard class", *(m["reviewer"] for m in metrics)],
                            class_cells(metrics, classes))
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<title>RedPen leaderboard</title><style>{HTML_CSS}</style></head><body>"
            f"<h1>RedPen leaderboard</h1><p class=\"meta\">{_e(header)}</p>"
            f"{_html_table(HEADER, [leaderboard_cells(m) for m in metrics])}"
            f"<h2>Recall by guard class (HIT/n)</h2>{per_class}"
            f"<h2>Per-case results</h2>{''.join(sections)}</body></html>\n")


# ------------------------------------------------------------ entry point

def report(results_dir, dataset_path, runs_arg: str | None = None,
           markdown_path=None, html_path=None) -> int:
    dataset = load_dataset(dataset_path)
    manifest = dataset.manifest
    run_ids = [r.strip() for r in runs_arg.split(",") if r.strip()] if runs_arg else None
    runs, ignored = select_runs(results_dir, manifest, run_ids)
    if ignored:
        print(f"ignored incomplete runs: {', '.join(ignored)}")
    check_comparable(runs)
    served = served_judge_models(runs)
    if len(served) > 1:
        print(f"warning: served judge models differ: {', '.join(served)}", file=sys.stderr)
    classes = sorted({e["guard_class"] for e in manifest["cases"]})
    metrics = rank([run_metrics(r, classes) for r in runs])
    print(f"runs: {', '.join(m['run_id'] for m in metrics)}")
    print(render_terminal(metrics, classes), end="")
    if markdown_path:
        atomic_write_text(markdown_path, render_markdown(metrics, runs[0].meta))
        print(f"markdown: {markdown_path}")
    if html_path:
        cases = {c.case_id: c.data for c in dataset.cases}
        atomic_write_text(html_path, render_html(metrics, runs, classes, cases, utc_now_iso()))
        print(f"html: {html_path}")
    return 0
