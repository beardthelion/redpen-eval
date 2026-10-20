"""Judge hand-check worksheet and its sign-off check (R18)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from redpen.prompts import numbered_window

PER_RUN = 3
CASE_HEADING = "## Case "
SIGNOFF_HEADING = "## Sign-off"
AGREE = "Agree with harness (yes/no):"
ANSWER_LINES = ["Human verdict (HIT/PARTIAL/MISS):", "Human fixed side (clean/re-reported):",
                AGREE, "Notes:"]
BUCKETS = (
    lambda r: r["vuln"]["verdict"] == "HIT",
    lambda r: r["vuln"]["verdict"] == "MISS",
    lambda r: r["fixed"]["fixed_clean"] is False,
    lambda r: r["vuln"]["verdict"] == "PARTIAL",
)


@dataclass
class SignOff:
    signed: bool
    agree: int
    total: int
    run_ids: list[str]
    judge_sha256: str


# ------------------------------------------------------------ selection

def _eligible(rec: dict) -> bool:
    return rec["vuln"]["status"] == "scored" and rec["fixed"]["status"] == "scored"


def select_cases(runs) -> list[tuple]:
    """Return [(run, case record)] with up to PER_RUN cases per run, in run order."""
    chosen_ids: set[str] = set()
    picked = []
    for run in runs:
        pool = sorted((r for r in run.cases if _eligible(r)), key=lambda r: r["case_id"])
        mine: list[dict] = []

        def take(pred) -> bool:
            for rec in pool:
                if len(mine) < PER_RUN and rec not in mine and pred(rec):
                    mine.append(rec)
                    chosen_ids.add(rec["case_id"])
                    return True
            return False

        fresh = lambda r: r["case_id"] not in chosen_ids
        new_class = lambda r: r["guard_class"] not in {m["guard_class"] for m in mine}
        for bucket in BUCKETS:
            take(lambda r: fresh(r) and new_class(r) and bucket(r))
        while take(lambda r: fresh(r) and new_class(r)):
            pass
        while take(fresh):
            pass
        while take(lambda r: True):
            pass
        picked.extend((run, rec) for rec in mine)
    return picked


# ------------------------------------------------------------ rendering

def _one_line(value) -> str:
    return " ".join(str("-" if value is None else value).split())


def _fence(text) -> str:
    text = "" if text is None else str(text).rstrip("\n")
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    bar = "`" * max(3, longest + 1)
    return f"{bar}\n{text}\n{bar}"


def _json(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True)


def _case_block(n: int, run, rec: dict, case) -> str:
    spans = ", ".join(f"{s['start']}-{s['end']} ({s['source']})"
                      for s in case.data["vuln"]["expected_spans"])
    vuln, fixed = rec["vuln"], rec["fixed"]
    parts = [
        f"## Case {n}: {_one_line(rec['case_id'])} (run {_one_line(run.run_id)})",
        f"Case id: {_one_line(rec['case_id'])}",
        f"Guard class: {_one_line(rec['guard_class'])}",
        "Vulnerability description:", _fence(case.data["vuln_description"]),
        f"Expected spans: {_one_line(spans)}",
        "Numbered vuln window:", _fence(numbered_window(case, "vuln")),
        "Vuln review text:", _fence(vuln["review_text"]),
        "Vuln judge parsed JSON:", _fence(_json(vuln["judge"]["parsed"])),
        f"Harness verdict: {_one_line(vuln['verdict'])}",
        "Fixed review text:", _fence(fixed["review_text"]),
        "Fixed judge parsed JSON:", _fence(_json(fixed["judge"]["parsed"])),
        f"fixed_clean: {json.dumps(fixed['fixed_clean'])}",
        "",
        *ANSWER_LINES,
    ]
    return "\n".join(parts)


def render_worksheet(runs, cases: dict) -> str:
    """cases maps case_id to a dataset Case (for the numbered window and expected spans)."""
    meta = runs[0].meta
    blocks = [_case_block(n, run, rec, cases[rec['case_id']])
              for n, (run, rec) in enumerate(select_cases(runs), start=1)]
    judge = meta["judge"]
    footer = "\n".join([
        SIGNOFF_HEADING,
        f"Run ids: {', '.join(_one_line(r.run_id) for r in runs)}",
        f"Judge model: {_one_line(judge.get('model'))} ({_one_line(judge['name'])})",
        f"Judge prompt sha256: {_one_line(meta['prompts']['judge_sha256'])}",
        "Reviewer:",
        "Date:",
        "Signed-off: no",
    ])
    intro = ("# Judge hand-check worksheet\n\nFor each case, read the fenced fields and fill in "
             "the four answer lines. Then fill Reviewer and Date and set Signed-off to yes.")
    return "\n\n".join([intro, *blocks, footer]) + "\n"


# ------------------------------------------------------------ sign-off

def _value(line: str, label: str) -> str | None:
    return line[len(label):].strip() if line.startswith(label) else None


def check_signoff(path) -> SignOff:
    """Read answer lines after each case heading and the sign-off footer, outside fences."""
    fence = 0
    section = None
    agrees: list[str | None] = []
    footer: dict[str, str] = {}
    labels = {"Run ids:": "run_ids", "Judge prompt sha256:": "judge", "Reviewer:": "reviewer",
              "Date:": "date", "Signed-off:": "signed"}
    for line in Path(path).read_text().splitlines():
        if fence:
            stripped = line.strip()
            if len(stripped) >= fence and set(stripped) == {"`"}:
                fence = 0
            continue
        opener = re.match(r"\s*(`{3,})", line)
        if opener:
            fence = len(opener.group(1))
            continue
        if line.startswith(CASE_HEADING):
            section = "case"
            agrees.append(None)
        elif line.rstrip() == SIGNOFF_HEADING:
            section = "footer"
        elif section == "case":
            value = _value(line, AGREE)
            if value is not None and agrees[-1] is None:
                agrees[-1] = value
        elif section == "footer":
            for label, key in labels.items():
                value = _value(line, label)
                if value is not None and key not in footer:
                    footer[key] = value
    signed = (footer.get("signed", "").lower() == "yes" and bool(footer.get("reviewer"))
              and bool(footer.get("date")))
    run_ids = [r.strip() for r in footer.get("run_ids", "").split(",") if r.strip()]
    return SignOff(signed=signed, agree=sum(a is not None and a.lower() == "yes" for a in agrees),
                   total=len(agrees), run_ids=run_ids, judge_sha256=footer.get("judge", ""))
