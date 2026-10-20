import pytest

from conftest import line_of
from redpen import window
from redpen.semgrep import run_semgrep
from redpen.window import (
    Construct,
    Hunk,
    Span,
    added_runs_new,
    build_window_text,
    enclosing,
    find_constructs,
    fix_spans_old,
    fixed_segments,
    location_selectivity,
    map_old_to_new,
    parse_diff_u0,
    render_numbered,
    split_lines,
    vuln_segments,
    window_to_original,
)


# ---------------------------------------------------------------- constructs

GO_SRC = """\
package main

func plain(a int) {
	x := a
	_ = x
}

func withRet(a int) (int, error) {
	return a, nil
}

type T struct{}

func (t *T) Method(a int) int {
	f := func() int {
		return a // inside-literal
	}
	return f()
}
"""


def test_go_constructs_exact_spans(tmp_path):
    p = tmp_path / "main.go"
    p.write_text(GO_SRC)
    cs = find_constructs(p, "go")
    spans = sorted((c.start, c.end) for c in cs)
    assert spans == [
        (line_of(GO_SRC, "func plain"), line_of(GO_SRC, "_ = x") + 1),
        (line_of(GO_SRC, "func withRet"), line_of(GO_SRC, "return a, nil") + 1),
        (line_of(GO_SRC, "func (t *T)"), line_of(GO_SRC, "return f()") + 1),
    ]
    inner = line_of(GO_SRC, "inside-literal")
    assert enclosing(Span(inner, inner), cs, "go") == Span(
        line_of(GO_SRC, "func (t *T)"), line_of(GO_SRC, "return f()") + 1
    )


PY_SRC = """\
import os

X = 1


class A:
    attr = os.getenv("A")

    @staticmethod
    def m(a):
        y = a
        return y

    async def n(self):
        return 2


def top():
    return 3
"""


def test_python_enclosing_order(tmp_path):
    p = tmp_path / "mod.py"
    p.write_text(PY_SRC)
    cs = find_constructs(p, "python")
    y = line_of(PY_SRC, "y = a")
    assert enclosing(Span(y, y), cs, "python") == Span(
        line_of(PY_SRC, "@staticmethod"), line_of(PY_SRC, "return y")
    )
    r2 = line_of(PY_SRC, "return 2")
    assert enclosing(Span(r2, r2), cs, "python") == Span(
        line_of(PY_SRC, "async def n"), r2
    )
    attr = line_of(PY_SRC, "attr =")
    assert enclosing(Span(attr, attr), cs, "python") == Span(
        line_of(PY_SRC, "class A"), r2
    )
    x = line_of(PY_SRC, "X = 1")
    assert enclosing(Span(x, x), cs, "python") == Span(x, x)


TS_SRC = """\
import { Y } from "./y";

export class X extends Y implements Z {
  private async extractEntry(x: string) {
    const v = x;
    return v;
  }
}

function top(a: number) {
  const q = a;
  return q;
}

const arrow = (a: number) => {
  const r = a;
  return r;
};
"""


def test_typescript_enclosing_order(tmp_path):
    p = tmp_path / "mod.ts"
    p.write_text(TS_SRC)
    cs = find_constructs(p, "typescript")
    v = line_of(TS_SRC, "const v = x")
    assert enclosing(Span(v, v), cs, "typescript") == Span(
        line_of(TS_SRC, "export class X"), line_of(TS_SRC, "return v") + 2
    )
    q = line_of(TS_SRC, "const q = a")
    assert enclosing(Span(q, q), cs, "typescript") == Span(
        line_of(TS_SRC, "function top"), line_of(TS_SRC, "return q") + 1
    )
    r = line_of(TS_SRC, "const r = a")
    assert enclosing(Span(r, r), cs, "typescript") == Span(
        line_of(TS_SRC, "const arrow"), line_of(TS_SRC, "return r") + 1
    )
    imp = line_of(TS_SRC, "import {")
    assert enclosing(Span(imp, imp), cs, "typescript") == Span(imp, imp)


JS_SRC = """\
const z = 1;

function f(a) {
  const b = a;
  return b;
}
"""


def test_javascript_function(tmp_path):
    p = tmp_path / "mod.js"
    p.write_text(JS_SRC)
    cs = find_constructs(p, "javascript")
    b = line_of(JS_SRC, "const b")
    assert enclosing(Span(b, b), cs, "javascript") == Span(3, 6)


def test_must_not_unsupported_language_raises(tmp_path):
    p = tmp_path / "x.rb"
    p.write_text("def f\nend\n")
    with pytest.raises(window.WindowError):
        find_constructs(p, "ruby")


def test_must_not_parse_error_raises_window_error(tmp_path):
    p = tmp_path / "frag.ts"
    p.write_text("private async extractEntry(x) { return x; }\n")
    with pytest.raises(window.WindowError):
        find_constructs(p, "typescript")


def test_enclosing_smallest_containing_wins():
    cs = [Construct("go-func", 1, 100), Construct("go-func", 10, 20)]
    assert enclosing(Span(12, 13), cs, "go") == Span(10, 20)
    # a construct that only partially overlaps does not count
    assert enclosing(Span(18, 25), cs, "go") == Span(1, 100)


def test_enclosing_ts_class_beats_smaller_function():
    cs = [Construct("ts-class", 1, 50), Construct("ts-func", 10, 20)]
    assert enclosing(Span(12, 12), cs, "typescript") == Span(1, 50)


def test_enclosing_python_def_beats_class():
    cs = [Construct("py-class", 1, 50), Construct("py-def", 10, 20)]
    assert enclosing(Span(12, 12), cs, "python") == Span(10, 20)


# ---------------------------------------------------------------- diffs


def test_parse_diff_u0_forms():
    text = (
        "diff --git a/x b/x\n--- a/x\n+++ b/x\n"
        "@@ -10 +10 @@ func x\n-a\n+b\n"
        "@@ -5,0 +6,2 @@\n+c\n+d\n"
        "@@ -20,3 +22,0 @@\n-e\n-f\n-g\n"
    )
    assert parse_diff_u0(text) == [
        Hunk(10, 1, 10, 1),
        Hunk(5, 0, 6, 2),
        Hunk(20, 3, 22, 0),
    ]


def test_fix_spans_old_and_added_runs():
    hunks = [Hunk(5, 0, 6, 2), Hunk(10, 2, 12, 3), Hunk(20, 3, 22, 0), Hunk(0, 0, 1, 1)]
    assert fix_spans_old(hunks) == [Span(5, 6), Span(10, 11), Span(20, 22), Span(1, 1)]
    assert added_runs_new(hunks) == [Span(6, 7), Span(12, 14), Span(1, 1)]


HUNKS = [Hunk(5, 0, 6, 2), Hunk(10, 2, 12, 3), Hunk(20, 3, 22, 0)]


@pytest.mark.parametrize(
    "old,new",
    [
        (3, 3),
        (5, 5),  # insertion is after old line 5
        (6, 8),
        (9, 11),
        (10, 12),  # replacement start
        (11, 13),
        (15, 18),
        (19, 22),
        (20, 22),  # deleted line clamps to c
        (22, 22),
        (23, 23),
        (50, 50),  # after the last hunk
    ],
)
def test_map_old_to_new(old, new):
    assert map_old_to_new(old, HUNKS) == new


def test_map_old_to_new_inside_shrinking_replacement_clamps():
    hunks = [Hunk(10, 4, 10, 2)]
    assert map_old_to_new(13, hunks) == 11
    assert map_old_to_new(14, hunks) == 12


# ---------------------------------------------------------------- segments


def test_vuln_segments_two_distant_functions():
    cs = [Construct("go-func", 10, 20), Construct("go-func", 120, 130)]
    segs, cores = vuln_segments([Span(15, 15), Span(125, 126)], cs, "go", 200)
    assert cores == [Span(10, 20), Span(120, 130)]
    assert segs == [Span(10, 20), Span(120, 130)]


def test_vuln_segments_close_targets_merge():
    segs, cores = vuln_segments([Span(50, 50), Span(54, 54)], [], "go", 200)
    assert segs == [Span(47, 57)]


def test_vuln_segments_touching_after_context_merge():
    # 10+3 = 13 and 17-3 = 14 touch
    segs, _ = vuln_segments([Span(10, 10), Span(17, 17)], [], "go", 200)
    assert segs == [Span(7, 20)]


def test_must_not_vuln_segments_gap_of_one_does_not_merge():
    segs, _ = vuln_segments([Span(10, 10), Span(18, 18)], [], "go", 200)
    assert segs == [Span(7, 13), Span(15, 21)]


def test_vuln_segments_clamp_to_file():
    segs, _ = vuln_segments([Span(1, 2), Span(99, 100)], [], "go", 100)
    assert segs == [Span(1, 5), Span(96, 100)]


def test_fixed_segments_maps_cores_and_adds_new_helper():
    # vuln core 10-20; fix replaces line 15 with 2 lines and inserts a new
    # helper function after old line 40 (new lines 42-47).
    hunks = [Hunk(15, 1, 15, 2), Hunk(40, 0, 42, 6)]
    fixed_cs = [Construct("go-func", 10, 21), Construct("go-func", 42, 47)]
    segs = fixed_segments([Span(10, 20)], hunks, fixed_cs, "go", 100)
    assert segs == [Span(10, 21), Span(42, 47)]


def test_must_not_fixed_segments_without_added_runs_has_no_extra_segment():
    hunks = [Hunk(15, 1, 15, 0)]
    fixed_cs = [Construct("go-func", 10, 19), Construct("go-func", 42, 47)]
    segs = fixed_segments([Span(10, 20)], hunks, fixed_cs, "go", 100)
    assert segs == [Span(10, 19)]


# ------------------------------------------- construct targets get no context

GO_PREV_SRC = """\
package main

func isAllowed(s string) bool {
	if s == "" {
		return true
	}
	return false
}

func (h *ValidationHandler) Handle(s string) error {
	x := s // target
	_ = x
	return nil
}
"""

GO_FUNC_RULE = """\
rules:
  - id: any-func
    languages: [go]
    severity: WARNING
    message: r
    pattern: |
      func ($R $T) $F(...) $RET { ... }
"""

TS_PREV_SRC = """\
import { a } from "./a";

function helper(x: number) {
  if (x > 1) {
    return x;
  }
  return 0;
}
function target(y: string) {
  const z = y; // target
  return z;
}
"""

TS_FUNC_RULE = """\
rules:
  - id: any-func
    languages: [typescript]
    severity: WARNING
    message: r
    pattern: |
      function $F(...) { ... }
"""


def _window_parses(tmp_path, src, segs, language, name, rule_text, header):
    text = build_window_text(split_lines(src), segs, language, header)
    target = tmp_path / name
    target.write_text(text)
    rule = tmp_path / "rule.yaml"
    rule.write_text(rule_text)
    return run_semgrep(rule, target)


def test_go_construct_target_gets_no_context_and_window_parses(tmp_path):
    p = tmp_path / "src.go"
    p.write_text(GO_PREV_SRC)
    n = len(split_lines(GO_PREV_SRC))
    t = line_of(GO_PREV_SRC, "// target")
    func = line_of(GO_PREV_SRC, "func (h *ValidationHandler)")
    end = line_of(GO_PREV_SRC, "return nil") + 1
    segs, cores = vuln_segments([Span(t, t)], find_constructs(p, "go"), "go", n)
    assert cores == [Span(func, end)]
    assert segs == [Span(func, end)]
    run = _window_parses(tmp_path, GO_PREV_SRC, segs, "go", "win.go", GO_FUNC_RULE, ["// h"])
    assert run.errors == []
    assert run.fires is True


def test_ts_construct_target_gets_no_context_and_window_parses(tmp_path):
    p = tmp_path / "src.ts"
    p.write_text(TS_PREV_SRC)
    n = len(split_lines(TS_PREV_SRC))
    t = line_of(TS_PREV_SRC, "// target")
    func = line_of(TS_PREV_SRC, "function target")
    end = line_of(TS_PREV_SRC, "return z") + 1
    segs, _ = vuln_segments([Span(t, t)], find_constructs(p, "typescript"), "typescript", n)
    assert segs == [Span(func, end)]
    run = _window_parses(tmp_path, TS_PREV_SRC, segs, "typescript", "win.ts", TS_FUNC_RULE, ["// h"])
    assert run.errors == []
    assert run.fires is True


GO_BARE_SRC = """\
package main

var a = 1
var b = 2
var c = 3
var target = 4
var d = 5
var e = 6
var f = 7
var g = 8
"""


def test_bare_range_target_still_gets_context(tmp_path):
    p = tmp_path / "src.go"
    p.write_text(GO_BARE_SRC)
    n = len(split_lines(GO_BARE_SRC))
    t = line_of(GO_BARE_SRC, "var target")
    segs, cores = vuln_segments([Span(t, t)], find_constructs(p, "go"), "go", n)
    assert cores == [Span(t, t)]
    assert segs == [Span(t - 3, t + 3)]


GO_BARE_NEAR_FUNC_SRC = """\
package main

func before() bool {
	if true {
		return true
	}
	return false
}
var target = 4
func after() int {
	if true {
		return 1
	}
	return 0
}
"""

GO_VAR_RULE = """\
rules:
  - id: target-var
    languages: [go]
    severity: WARNING
    message: r
    pattern: var target = 4
"""


def test_must_not_bare_range_context_cuts_into_a_construct(tmp_path):
    p = tmp_path / "src.go"
    p.write_text(GO_BARE_NEAR_FUNC_SRC)
    n = len(split_lines(GO_BARE_NEAR_FUNC_SRC))
    t = line_of(GO_BARE_NEAR_FUNC_SRC, "var target")
    segs, _ = vuln_segments([Span(t, t)], find_constructs(p, "go"), "go", n)
    assert segs == [Span(t, t)]
    run = _window_parses(tmp_path, GO_BARE_NEAR_FUNC_SRC, segs, "go", "win.go", GO_VAR_RULE, ["// h"])
    assert run.errors == []
    assert run.fires is True


def test_bare_range_context_keeps_whole_constructs():
    # a construct lying entirely inside the context stays; a partial one is cut off
    cs = [Construct("go-func", 1, 6), Construct("go-func", 8, 9), Construct("go-func", 13, 20)]
    segs, _ = vuln_segments([Span(11, 11)], cs, "go", 30)
    assert segs == [Span(8, 12)]


def test_fixed_segments_bare_mapped_core_gets_context():
    hunks = [Hunk(15, 1, 15, 1)]
    segs = fixed_segments([Span(15, 15)], hunks, [], "go", 100)
    assert segs == [Span(12, 18)]


# ---------------------------------------------------------------- window text

ORIG = "".join(f"line{i}\n" for i in range(1, 31))


def test_build_window_text_and_mapping():
    lines = split_lines(ORIG)
    segs = [Span(2, 4), Span(10, 11)]
    header = ["// h1", "// h2"]
    text = build_window_text(lines, segs, "go", header)
    assert text == (
        "// h1\n// h2\nline2\nline3\nline4\n"
        "// ... lines 5-9 omitted ...\nline10\nline11\n"
    )
    assert window_to_original(1, 2, segs) is None
    assert window_to_original(2, 2, segs) is None
    assert window_to_original(3, 2, segs) == 2
    assert window_to_original(5, 2, segs) == 4
    assert window_to_original(6, 2, segs) is None  # gap line
    assert window_to_original(7, 2, segs) == 10
    assert window_to_original(8, 2, segs) == 11
    assert window_to_original(9, 2, segs) is None


def test_build_window_text_python_gap_and_trailing_newline():
    lines = split_lines("a\nb\nc\nd\ne")  # no trailing newline
    text = build_window_text(lines, [Span(1, 1), Span(4, 5)], "python", ["# h"])
    assert text == "# h\na\n# ... lines 2-3 omitted ...\nd\ne"


def test_render_numbered():
    lines = split_lines(ORIG)
    segs = [Span(2, 3), Span(10, 10)]
    text = build_window_text(lines, segs, "go", ["// SECRET-HEADER"])
    out = render_numbered(text, 1, segs)
    assert "SECRET-HEADER" not in out
    assert out == (
        "     2  line2\n"
        "     3  line3\n"
        "        ... (lines 4-9 omitted)\n"
        "    10  line10\n"
    )


PY_WINDOW_SRC = """\
class Svc:
    def first(self, a):
        b = a + 1
        return b

    def middle(self):
        return 0

    def middle2(self):
        return 0

    def last(self, c):
        d = c * 2
        return d
"""

PY_RULE = """\
rules:
  - id: any-return
    languages: [python]
    severity: WARNING
    message: r
    pattern: return $X
"""


def test_python_window_with_indented_methods_parses(tmp_path):
    lines = split_lines(PY_WINDOW_SRC)
    segs = [Span(2, 4), Span(12, 14)]
    text = build_window_text(lines, segs, "python", ["# header one", "# header two"])
    target = tmp_path / "win.py"
    target.write_text(text)
    rule = tmp_path / "rule.yaml"
    rule.write_text(PY_RULE)
    run = run_semgrep(rule, target)
    assert run.errors == []
    assert run.fires is True


# ---------------------------------------------------------------- selectivity


def test_location_selectivity_whole_window_span():
    code = list(range(40, 80))
    assert location_selectivity(code, [Span(40, 79)]) == 1.0


def test_location_selectivity_single_line_in_40_line_window():
    code = list(range(40, 80))
    sel = location_selectivity(code, [Span(60, 60)])
    assert 0.2 <= sel <= 0.35
    assert sel == 11 / 40


def test_must_not_location_selectivity_excludes_line_beyond_tolerance():
    assert location_selectivity([10, 15, 16], [Span(10, 10)]) == 2 / 3
    assert location_selectivity([4, 16], [{"start": 10, "end": 10}]) == 0.0


def test_location_selectivity_empty_window():
    assert location_selectivity([], [Span(1, 1)]) == 0.0
