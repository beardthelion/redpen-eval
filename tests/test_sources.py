import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import commit_files, git, make_rule, make_sweep, make_upstream_repo
from redpen import sources
from redpen.sources import SourceError

GHSA = "GHSA-aaaa-bbbb-cccc"
RULE = make_rule(GHSA, "go", "    pattern: io.Copy($D, $R.Body)\n")


def _sweep_case(**kw):
    c = {"ghsa": GHSA, "rule": RULE, "vuln_ref": "a" * 40, "fixed_ref": "b" * 40,
         "sink_path": "pkg/handler.go"}
    c.update(kw)
    return c


# ------------------------------------------------------------ read_corpus

def test_read_corpus_reads_refs_and_sink(tmp_path):
    sweep = make_sweep(tmp_path, [_sweep_case()])
    cases = sources.read_corpus(sweep)
    assert len(cases) == 1
    cc = cases[0]
    assert cc.ghsa == GHSA
    assert cc.error is None
    assert cc.vuln_ref == "a" * 40 and cc.fixed_ref == "b" * 40
    assert cc.sink_path == "pkg/handler.go"
    assert cc.rule["languages"] == ["go"]
    assert cc.rule_bytes == RULE.encode()
    commit, remote = sources.corpus_identity(sweep)
    assert commit == git(sweep, "rev-parse", "HEAD")
    assert remote is None


def test_read_corpus_sorted(tmp_path):
    other = "GHSA-0000-0000-0000"
    sweep = make_sweep(tmp_path, [
        _sweep_case(),
        _sweep_case(ghsa=other, rule=make_rule(other, "go", "    pattern: x()\n")),
    ])
    assert [c.ghsa for c in sources.read_corpus(sweep)] == [other, GHSA]


def test_must_not_two_distinct_sink_paths_is_case_failure(tmp_path):
    sweep = make_sweep(tmp_path, [_sweep_case(sink_paths=["a.go", "b.go"])])
    (cc,) = sources.read_corpus(sweep)
    assert cc.error is not None and "sink" in cc.error


def test_same_sink_path_twice_is_fine(tmp_path):
    sweep = make_sweep(tmp_path, [_sweep_case(sink_paths=["a.go", "a.go"])])
    (cc,) = sources.read_corpus(sweep)
    assert cc.error is None and cc.sink_path == "a.go"


def test_must_not_unverified_result_is_case_failure(tmp_path):
    sweep = make_sweep(tmp_path, [_sweep_case(result="not_verified")])
    (cc,) = sources.read_corpus(sweep)
    assert cc.error is not None and "verified" in cc.error


def test_must_not_ghsa_mismatch_is_case_failure(tmp_path):
    sweep = make_sweep(tmp_path, [_sweep_case(rule=make_rule("GHSA-zzzz-zzzz-zzzz", "go", "    pattern: x()\n"))])
    (cc,) = sources.read_corpus(sweep)
    assert cc.error is not None and "ghsa_id" in cc.error


def test_must_not_dirty_sweep_raises(tmp_path):
    sweep = make_sweep(tmp_path, [_sweep_case()])
    (sweep / "rules" / "verified" / f"{GHSA}.yaml").write_text(RULE + "# edit\n")
    with pytest.raises(SourceError, match="uncommitted"):
        sources.read_corpus(sweep)


def test_must_not_untracked_evidence_is_dirty(tmp_path):
    sweep = make_sweep(tmp_path, [_sweep_case()])
    (sweep / "evidence" / GHSA / "extra.json").write_text("{}")
    with pytest.raises(SourceError, match="uncommitted"):
        sources.read_corpus(sweep)


def test_dirty_outside_corpus_dirs_is_ignored(tmp_path):
    sweep = make_sweep(tmp_path, [_sweep_case()])
    (sweep / "notes.txt").write_text("scratch")
    assert len(sources.read_corpus(sweep)) == 1


# ------------------------------------------------------------ gh calls

def test_gh_retries_with_backoff_then_succeeds(monkeypatch):
    attempts = []
    sleeps = []

    def fake_run(cmd, **kw):
        attempts.append(cmd)
        if len(attempts) < 3:
            return subprocess.CompletedProcess(cmd, 1, "", "HTTP 502")
        return subprocess.CompletedProcess(cmd, 0, '{"published_at": "2026-01-02T00:00:00Z", '
                                           '"cve_id": "CVE-1", "source_code_location": '
                                           '"https://github.com/o/r"}', "")

    monkeypatch.setattr(sources.shutil, "which", lambda name: "/usr/bin/gh")
    monkeypatch.setattr(sources.subprocess, "run", fake_run)
    monkeypatch.setattr(sources.time, "sleep", sleeps.append)
    adv = sources.fetch_advisory(GHSA)
    assert adv == {"repo_url": "https://github.com/o/r", "published_at": "2026-01-02T00:00:00Z",
                   "cve_id": "CVE-1"}
    assert sleeps == [2, 4]
    assert attempts[0][:3] == ["/usr/bin/gh", "api", f"/advisories/{GHSA}"]


def test_must_not_gh_gives_up_after_three_retries(monkeypatch):
    sleeps = []
    monkeypatch.setattr(sources.shutil, "which", lambda name: "/usr/bin/gh")
    monkeypatch.setattr(sources.subprocess, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "boom"))
    monkeypatch.setattr(sources.time, "sleep", sleeps.append)
    with pytest.raises(SourceError, match="boom"):
        sources.fetch_license_spdx("o", "r")
    assert sleeps == [2, 4, 8]


def test_must_not_missing_gh_raises_immediately(monkeypatch):
    sleeps = []
    monkeypatch.setattr(sources.shutil, "which", lambda name: None)
    monkeypatch.setattr(sources.time, "sleep", sleeps.append)
    with pytest.raises(SourceError, match="gh"):
        sources.fetch_advisory(GHSA)
    assert sleeps == []


def test_license_spdx_reads_spdx_id_and_null(monkeypatch):
    monkeypatch.setattr(sources.shutil, "which", lambda name: "/usr/bin/gh")
    out = {"x": '{"license": {"spdx_id": "MIT"}}'}
    monkeypatch.setattr(sources.subprocess, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, out["x"], ""))
    assert sources.fetch_license_spdx("o", "r") == "MIT"
    out["x"] = '{"license": null}'
    assert sources.fetch_license_spdx("o", "r") is None


# ------------------------------------------------------------ upstream git

def test_repo_slug():
    assert sources.repo_slug("https://github.com/getkin/kin-openapi") == ("getkin", "kin-openapi")
    assert sources.repo_slug("https://github.com/o/r.git/") == ("o", "r")
    assert sources.repo_slug("file:///tmp/x/upstream/acme/widget") == ("acme", "widget")


def test_ensure_commits_fetches_and_reads(tmp_path):
    url, v, f = make_upstream_repo(tmp_path, {"a.go": "package a\n"}, {"a.go": "package a\n// fixed\n"},
                                   "MIT License\nCopyright (c) Acme\n")
    cache = tmp_path / "cache"
    repo = sources.ensure_commits(url, f, v, cache)
    assert repo == cache / "acme__widget"
    assert sources.git_show(repo, v, "a.go") == b"package a\n"
    assert sources.git_show(repo, f, "a.go") == b"package a\n// fixed\n"
    assert sources.license_files(repo, f) == ["LICENSE"]
    assert "@@ -1,0 +2 @@" in sources.diff_u0(repo, v, f, "a.go")
    assert sources.commit_date(repo, f).startswith("20")


def test_cache_reuse_without_upstream(tmp_path):
    url, v, f = make_upstream_repo(tmp_path, {"a.go": "package a\n"}, {"a.go": "package b\n"}, None)
    cache = tmp_path / "cache"
    sources.ensure_commits(url, f, v, cache)
    shutil.rmtree(tmp_path / "upstream")
    repo = sources.ensure_commits(url, f, v, cache)
    assert sources.git_show(repo, f, "a.go") == b"package b\n"


def test_must_not_missing_file_raises(tmp_path):
    url, v, f = make_upstream_repo(tmp_path, {"a.go": "package a\n"}, {"a.go": "package b\n"}, None)
    repo = sources.ensure_commits(url, f, v, tmp_path / "cache")
    with pytest.raises(SourceError):
        sources.git_show(repo, f, "missing.go")
    assert sources.license_files(repo, f) == []


def test_license_file_name_matching(tmp_path):
    url, v, f = make_upstream_repo(tmp_path, {"a.go": "x\n"}, {
        "LICENSE.txt": "l", "COPYING": "c", "licence.md": "m", "LICENSES/x": "no",
        "LICENSE-APACHE": "no", "sub/LICENSE": "no"}, None)
    repo = sources.ensure_commits(url, f, v, tmp_path / "cache")
    assert sources.license_files(repo, f) == ["COPYING", "LICENSE.txt", "licence.md"]


def test_must_not_first_parent_mismatch(tmp_path):
    url, a, b = make_upstream_repo(tmp_path, {"a.go": "1\n"}, {"a.go": "2\n"}, None)
    c = commit_files(Path(url[len("file://"):]), {"a.go": "3\n"})
    with pytest.raises(SourceError, match="vuln_ref is not the first parent of fixed_ref"):
        sources.ensure_commits(url, c, a, tmp_path / "cache")


def test_shared_commits_survive_second_pass(tmp_path):
    """A-B-C: case 1 is (A, B), case 2 is (B, C); a second pass over the same
    cache must still verify case 1 after B became a shallow boundary."""
    url, a, b = make_upstream_repo(tmp_path, {"a.go": "1\n"}, {"a.go": "2\n"}, None)
    c = commit_files(Path(url[len("file://"):]), {"a.go": "3\n"})
    cache = tmp_path / "cache"
    for _ in range(2):
        sources.ensure_commits(url, b, a, cache)
        sources.ensure_commits(url, c, b, cache)
