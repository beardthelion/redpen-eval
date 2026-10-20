"""Deterministic location check and verdicts (R13, R14, KTD8, KTD9, KTD14)."""

from __future__ import annotations

LOCATION_TOLERANCE = 5
MAX_RANGE_WIDTH = 2 * LOCATION_TOLERANCE + 1
CREDIT = {"HIT": 1.0, "PARTIAL": 0.5, "MISS": 0.0}
ERROR_STATUSES = {"reviewer_error", "judge_error"}


def located(cited_ranges, expected_spans) -> bool:
    """A cited range is located when it is at most 11 lines wide and within 5 lines of a span."""
    for r in cited_ranges:
        if r["end"] - r["start"] + 1 > MAX_RANGE_WIDTH:
            continue
        for s in expected_spans:
            if r["start"] <= s["end"] + LOCATION_TOLERANCE and r["end"] >= s["start"] - LOCATION_TOLERANCE:
                return True
    return False


def vuln_verdict(parsed: dict, expected_spans) -> str:
    if not parsed["verdict_class_match"]:
        return "MISS"
    return "HIT" if located(parsed["cited_ranges"], expected_spans) else "PARTIAL"


def fixed_clean(parsed: dict) -> bool:
    return not parsed["reported_patched_vuln"]


def pair_credit(vuln_side: dict, fixed_side: dict) -> float | None:
    """Null when either side is an error; 0.0 when either side is no_answer; else pair-v1."""
    statuses = {vuln_side["status"], fixed_side["status"]}
    if statuses & ERROR_STATUSES:
        return None
    if "no_answer" in statuses:
        return 0.0
    return CREDIT[vuln_side["verdict"]] * (1.0 if fixed_side["fixed_clean"] else 0.0)
