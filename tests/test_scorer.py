import pytest

from redpen import scorer

SPAN = [{"start": 50, "end": 60, "source": "semgrep"}]


def r(start, end=None):
    return {"start": start, "end": start if end is None else end}


# ------------------------------------------------------------ KTD9 boundaries

def test_tolerance_constant():
    assert scorer.LOCATION_TOLERANCE == 5


@pytest.mark.parametrize("line,expected", [(45, True), (44, False), (65, True), (66, False),
                                           (50, True), (60, True), (55, True)])
def test_single_line_boundary(line, expected):
    assert scorer.located([r(line)], SPAN) is expected


def test_must_not_wide_range_overlapping_span_is_not_located():
    assert scorer.located([r(40, 97)], SPAN) is False


def test_eleven_line_range_is_located():
    assert scorer.located([r(52, 62)], SPAN) is True


def test_must_not_twelve_line_range_inside_tolerance_is_not_located():
    assert scorer.located([r(50, 61)], SPAN) is False


def test_range_just_outside_tolerance_is_not_located():
    assert scorer.located([r(66, 70)], SPAN) is False
    assert scorer.located([r(35, 44)], SPAN) is False


def test_range_touching_tolerance_edge_is_located():
    assert scorer.located([r(65, 70)], SPAN) is True
    assert scorer.located([r(40, 45)], SPAN) is True


def test_any_expected_span_counts():
    spans = SPAN + [{"start": 200, "end": 200, "source": "fix_diff"}]
    assert scorer.located([r(204)], spans) is True
    assert scorer.located([r(206)], spans) is False


def test_empty_citations_not_located():
    assert scorer.located([], SPAN) is False


# ------------------------------------------------------------ verdicts

def vuln(match, ranges):
    return {"verdict_class_match": match, "cited_ranges": ranges, "rationale": "x"}


def test_must_not_thirty_far_single_lines_is_partial():
    ranges = [r(n) for n in range(100, 130)]
    assert len(ranges) == 30
    assert scorer.vuln_verdict(vuln(True, ranges), SPAN) == "PARTIAL"


def test_class_match_located_is_hit():
    assert scorer.vuln_verdict(vuln(True, [r(100), r(55)]), SPAN) == "HIT"


def test_class_match_far_is_partial():
    assert scorer.vuln_verdict(vuln(True, [r(100)]), SPAN) == "PARTIAL"


def test_class_match_no_citation_is_partial():
    assert scorer.vuln_verdict(vuln(True, []), SPAN) == "PARTIAL"


def test_must_not_class_mismatch_on_span_is_miss():
    assert scorer.vuln_verdict(vuln(False, [r(55)]), SPAN) == "MISS"


def test_class_match_wide_range_only_is_partial():
    assert scorer.vuln_verdict(vuln(True, [r(40, 97)]), SPAN) == "PARTIAL"


def test_fixed_clean():
    assert scorer.fixed_clean({"reported_patched_vuln": False, "cited_ranges": [],
                               "rationale": ""}) is True
    assert scorer.fixed_clean({"reported_patched_vuln": True, "cited_ranges": [],
                               "rationale": ""}) is False


# ------------------------------------------------------------ pair credit

def v(status="scored", verdict="HIT"):
    return {"status": status, "verdict": verdict}


def f(status="scored", clean=True):
    return {"status": status, "fixed_clean": clean}


@pytest.mark.parametrize("vs,fs,expected", [
    (v(verdict="HIT"), f(clean=True), 1.0),
    (v(verdict="PARTIAL"), f(clean=True), 0.5),
    (v(verdict="MISS"), f(clean=True), 0.0),
    (v(verdict="HIT"), f(clean=False), 0.0),
    (v(verdict="PARTIAL"), f(clean=False), 0.0),
])
def test_pair_credit_scored(vs, fs, expected):
    assert scorer.pair_credit(vs, fs) == expected


@pytest.mark.parametrize("vs,fs", [
    (v("no_answer", "MISS"), f(clean=True)),
    (v(verdict="HIT"), f("no_answer", None)),
    (v("no_answer", "MISS"), f("no_answer", None)),
    (v("no_answer", None), f(clean=True)),
])
def test_must_not_no_answer_pair_credit_is_zero(vs, fs):
    assert scorer.pair_credit(vs, fs) == 0.0


@pytest.mark.parametrize("vs,fs", [
    (v("reviewer_error", None), f(clean=True)),
    (v(verdict="HIT"), f("reviewer_error", None)),
    (v("judge_error", None), f(clean=True)),
    (v(verdict="HIT"), f("judge_error", None)),
    (v("no_answer", "MISS"), f("reviewer_error", None)),
    (v("judge_error", None), f("no_answer", None)),
])
def test_must_not_error_pair_credit_is_null(vs, fs):
    assert scorer.pair_credit(vs, fs) is None
