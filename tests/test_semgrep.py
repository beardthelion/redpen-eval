import subprocess

import pytest

from redpen import semgrep
from redpen.semgrep import Match, SemgrepError, SemgrepRun, run_semgrep

GO_RULE = """\
rules:
  - id: find-exec
    languages: [go]
    severity: WARNING
    message: exec call
    pattern: exec.Command($X)
"""

GO_MATCH = """\
package main

import "os/exec"

func run(x string) {
	cmd := exec.Command(x)
	_ = cmd
}
"""

GO_NO_MATCH = """\
package main

func run(x string) {
	_ = x
}
"""

TS_RULE = """\
rules:
  - id: find-extract
    languages: [typescript]
    severity: WARNING
    message: extractEntry
    pattern: |
      async extractEntry(...) { ... }
"""


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return p


def test_run_semgrep_fires_with_exact_lines(tmp_path):
    rule = _write(tmp_path, "rule.yaml", GO_RULE)
    target = _write(tmp_path, "main.go", GO_MATCH)
    run = run_semgrep(rule, target)
    assert run.errors == []
    assert len(run.matches) == 1
    m = run.matches[0]
    assert (m.start_line, m.end_line) == (6, 6)
    assert m.check_id.endswith("find-exec")
    # semgrep 1.177.0 OSS JSON omits extra.metavars; the field stays a dict
    assert isinstance(m.metavars, dict)
    assert run.fires is True
    assert run.silent is False


def test_run_semgrep_silent_on_non_matching_file(tmp_path):
    rule = _write(tmp_path, "rule.yaml", GO_RULE)
    target = _write(tmp_path, "main.go", GO_NO_MATCH)
    run = run_semgrep(rule, target)
    assert run.matches == []
    assert run.silent is True
    assert run.fires is False


def test_must_not_bare_ts_method_fragment_is_neither_fires_nor_silent(tmp_path):
    rule = _write(tmp_path, "rule.yaml", TS_RULE)
    target = _write(
        tmp_path, "frag.ts", "private async extractEntry(x) { return x; }\n"
    )
    run = run_semgrep(rule, target)
    assert run.errors != []
    assert run.fires is False
    assert run.silent is False


def test_must_not_fires_false_when_errors_present_even_with_matches():
    run = SemgrepRun(
        matches=[Match(start_line=1, end_line=2, check_id="r", metavars={})],
        errors=[{"level": "warn", "type": "PartialParsing"}],
    )
    assert run.fires is False
    assert run.silent is False


def test_must_not_nonexistent_rule_raises(tmp_path):
    target = _write(tmp_path, "main.go", GO_NO_MATCH)
    with pytest.raises(SemgrepError):
        run_semgrep(tmp_path / "missing.yaml", target)


def _fake_run(returncode=0, stdout="{}"):
    def fake(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], returncode, stdout, "")

    return fake


def test_must_not_unexpected_return_code_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(semgrep.subprocess, "run", _fake_run(2, '{"results": [], "errors": []}'))
    with pytest.raises(SemgrepError):
        run_semgrep(tmp_path / "r.yaml", tmp_path / "t.go")


def test_must_not_invalid_json_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(semgrep.subprocess, "run", _fake_run(0, "not json"))
    with pytest.raises(SemgrepError):
        run_semgrep(tmp_path / "r.yaml", tmp_path / "t.go")


def test_must_not_timeout_raises(tmp_path, monkeypatch):
    def fake(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs.get("timeout"))

    monkeypatch.setattr(semgrep.subprocess, "run", fake)
    with pytest.raises(SemgrepError):
        run_semgrep(tmp_path / "r.yaml", tmp_path / "t.go", timeout_s=1)


def test_return_code_1_is_accepted(tmp_path, monkeypatch):
    monkeypatch.setattr(semgrep.subprocess, "run", _fake_run(1, '{"results": [], "errors": []}'))
    run = run_semgrep(tmp_path / "r.yaml", tmp_path / "t.go")
    assert run.silent is True


def test_errors_kept_verbatim(tmp_path, monkeypatch):
    err = {"level": "warn", "type": ["PartialParsing", []], "message": "m"}
    payload = '{"results": [], "errors": [%s]}' % __import__("json").dumps(err)
    monkeypatch.setattr(semgrep.subprocess, "run", _fake_run(0, payload))
    run = run_semgrep(tmp_path / "r.yaml", tmp_path / "t.go")
    assert run.errors == [err]
