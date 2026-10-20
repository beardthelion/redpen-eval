import json
import socket
import subprocess
from pathlib import Path

import pytest


def _blocked(*args, **kwargs):
    raise RuntimeError("network access in tests")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def line_of(src, needle):
    """1-based line number of the only line containing needle."""
    hits = [i + 1 for i, line in enumerate(src.split("\n")) if needle in line]
    assert len(hits) == 1, (needle, hits)
    return hits[0]


def patch_judge(monkeypatch):
    """Use the mock judge backend for openai_compat judge entries."""
    from redpen import runner
    from redpen.judge import MockJudgeBackend
    monkeypatch.setattr(runner, "make_judge_backend",
                        lambda name, config: MockJudgeBackend({"adapter": "mock"}))


# ------------------------------------------------------------ git fixtures

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"]


def git(cwd, *args) -> str:
    proc = subprocess.run(
        [*GIT, *args], cwd=cwd, check=True, capture_output=True, text=True
    )
    return proc.stdout.strip()


def _write_files(root: Path, files: dict) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def commit_files(repo_dir, files: dict, message: str = "change") -> str:
    """Write files over the work tree of repo_dir, commit, return the new sha."""
    repo_dir = Path(repo_dir)
    _write_files(repo_dir, files)
    git(repo_dir, "add", "-A")
    git(repo_dir, "commit", "-q", "-m", message)
    return git(repo_dir, "rev-parse", "HEAD")


def make_upstream_repo(tmp_path, vuln_files: dict, fixed_files: dict,
                       license_text: str | None, owner_repo: str = "acme/widget"):
    """Create an upstream repo with a vuln commit and a fixed child commit.

    Returns (file:// url, vuln_sha, fixed_sha). The repo lives at
    <tmp_path>/upstream/<owner>/<repo> so the url ends in owner/repo.
    """
    repo_dir = Path(tmp_path) / "upstream" / owner_repo
    repo_dir.mkdir(parents=True)
    git(repo_dir, "init", "-q")
    git(repo_dir, "config", "uploadpack.allowAnySHA1InWant", "true")
    files = dict(vuln_files)
    if license_text is not None:
        files["LICENSE"] = license_text
    vuln_sha = commit_files(repo_dir, files, "vuln")
    fixed_sha = commit_files(repo_dir, fixed_files, "fix")
    return f"file://{repo_dir}", vuln_sha, fixed_sha


def make_rule(ghsa, language, body, ecosystem="go", guard_class="input-validation",
              cve="CVE-2026-0001", message="untrusted input reaches a sink"):
    """Rule file text; body is the indented YAML for the pattern keys."""
    return (
        "rules:\n"
        f"  - id: {ghsa.lower()}\n"
        f"    languages: [{language}]\n"
        "    severity: ERROR\n"
        f"    message: {message}\n"
        "    metadata:\n"
        f"      ghsa_id: {ghsa}\n"
        f"      cve: {cve}\n"
        f"      ecosystem: {ecosystem}\n"
        f"      guard_class: {guard_class}\n"
        f"{body}"
    )


def make_sweep(tmp_path, cases: list[dict]) -> Path:
    """Write a committed sweep dir with rules/verified and evidence.

    Each case: ghsa, rule (text), vuln_ref, fixed_ref, sink_path or sink_paths,
    optional result (default "verified").
    """
    sweep = Path(tmp_path) / "sweep"
    (sweep / "rules" / "verified").mkdir(parents=True)
    for c in cases:
        ghsa = c["ghsa"]
        (sweep / "rules" / "verified" / f"{ghsa}.yaml").write_text(c["rule"])
        sinks = c.get("sink_paths") or [c["sink_path"]]
        verdict = {
            "result": c.get("result", "verified"),
            "runs": {
                "vuln": {
                    "ref": c["vuln_ref"],
                    "sink_matched_paths": [f"/tmp/sweep-co/{ghsa}-vuln/{s}" for s in sinks],
                },
                "fixed": {"ref": c["fixed_ref"], "sink_matched_paths": []},
            },
        }
        ev = sweep / "evidence" / ghsa
        ev.mkdir(parents=True)
        (ev / "verdict.json").write_text(json.dumps(verdict, indent=2))
    git(sweep, "init", "-q")
    git(sweep, "add", "-A")
    git(sweep, "commit", "-q", "-m", "corpus")
    return sweep


def patch_github(monkeypatch, advisories: dict, licenses: dict):
    """advisories: {ghsa: {repo_url, published_at, cve_id}}; licenses: {"owner/repo": spdx}."""
    from redpen import sources

    calls = []

    def fake_advisory(ghsa):
        calls.append(("advisory", ghsa))
        if ghsa not in advisories:
            raise sources.SourceError(f"no advisory {ghsa}")
        return dict(advisories[ghsa])

    def fake_license(owner, repo):
        calls.append(("license", owner, repo))
        return licenses.get(f"{owner}/{repo}")

    monkeypatch.setattr(sources, "fetch_advisory", fake_advisory)
    monkeypatch.setattr(sources, "fetch_license_spdx", fake_license)
    return calls


# ------------------------------------------------------------ fixture datasets

DEFAULT_VULN_SOURCE = (
    "package handler\n"
    "\n"
    'import "net/http"\n'
    "\n"
    "func helper() int {\n"
    "\treturn 1\n"
    "}\n"
    "\n"
    "func Serve(w http.ResponseWriter, r *http.Request) {\n"
    '\tpath := r.URL.Query().Get("path")\n'
    "\tdata := readFile(path)\n"
    "\tw.Write(data)\n"
    "}\n"
    "\n"
    "func other() {\n"
    "}\n"
)

DEFAULT_FIXED_SOURCE = (
    "package handler\n"
    "\n"
    'import "net/http"\n'
    "\n"
    "func helper() int {\n"
    "\treturn 1\n"
    "}\n"
    "\n"
    "func Serve(w http.ResponseWriter, r *http.Request) {\n"
    '\tpath := r.URL.Query().Get("path")\n'
    '\tif strings.Contains(path, "..") { return }\n'
    "\tdata := readFile(path)\n"
    "\tw.Write(data)\n"
    "}\n"
    "\n"
    "func other() {\n"
    "}\n"
)

DEFAULT_LICENSE_TEXT = (
    "MIT License\n\n"
    "Copyright (c) 2026 Acmecorp Widget Authors\n\n"
    "Permission is hereby granted, free of charge, to any person obtaining a copy\n"
)


def make_dataset(tmp_path, cases: list[dict]) -> Path:
    """Write a schema-valid dataset at <tmp_path>/dataset/v1 without running semgrep.

    Each case dict needs case_id; optional keys: language, ecosystem, guard_class,
    cve, description, owner_repo, basename, vuln_source, fixed_source,
    vuln_segments, fixed_segments ([(start, end)]), expected_spans
    ([{"start", "end", "source"}]), license_spdx. Returns the dataset root,
    which redpen.dataset.load_dataset accepts.
    """
    from redpen import dataset as ds
    from redpen import window
    from redpen.window import Span

    root = Path(tmp_path) / "dataset" / "v1"
    (root / "cases").mkdir(parents=True)
    entries = []
    for spec in cases:
        cid = spec["case_id"]
        language = spec.get("language", "go")
        owner_repo = spec.get("owner_repo", "acmecorp/widgetlib")
        owner, name = owner_repo.split("/")
        repo_url = f"https://github.com/{owner_repo}"
        basename = spec.get("basename", "handler.go")
        spdx = spec.get("license_spdx", "MIT")
        vuln_src = spec.get("vuln_source", DEFAULT_VULN_SOURCE)
        fixed_src = spec.get("fixed_source", DEFAULT_FIXED_SOURCE)
        seg_v = [Span(*s) for s in spec.get("vuln_segments", [(1, 1), (9, 13)])]
        seg_f = [Span(*s) for s in spec.get("fixed_segments", [(9, 14)])]
        expected = spec.get("expected_spans", [
            {"start": 11, "end": 11, "source": "semgrep"},
            {"start": 10, "end": 10, "source": "fix_diff"},
        ])
        description = spec.get("description", "untrusted path reaches readFile")
        vuln_ref, fixed_ref = "a" * 40, "b" * 40
        license_dir = f"licenses/{owner}__{name}"
        notice = "Copyright (c) 2026 Acmecorp Widget Authors"
        lic = root / license_dir
        lic.mkdir(parents=True, exist_ok=True)
        (lic / "LICENSE").write_text(DEFAULT_LICENSE_TEXT)

        sink_path = f"internal/server/{basename}"
        head_v = ds._header(language, repo_url, vuln_ref, sink_path, "2026-10-19", spdx,
                            license_dir, ["LICENSE"], notice)
        head_f = ds._header(language, repo_url, fixed_ref, sink_path, "2026-10-19", spdx,
                            license_dir, ["LICENSE"], notice)
        vuln_lines = window.split_lines(vuln_src)
        fixed_lines = window.split_lines(fixed_src)

        case_dir = root / "cases" / cid
        (case_dir / "vuln").mkdir(parents=True)
        (case_dir / "fixed").mkdir(parents=True)
        rule_text = (
            "rules:\n"
            f"  - id: {cid.lower()}\n"
            f"    languages: [{language}]\n"
            "    severity: ERROR\n"
            f"    message: {description}\n"
            "    pattern: readFile(...)\n"
        )
        (case_dir / "rule.yaml").write_text(rule_text)
        (case_dir / "vuln" / basename).write_text(
            window.build_window_text(vuln_lines, seg_v, language, head_v))
        (case_dir / "fixed" / basename).write_text(
            window.build_window_text(fixed_lines, seg_f, language, head_f))
        case = {
            "schema_version": 1,
            "case_id": cid,
            "ecosystem": spec.get("ecosystem", "go"),
            "language": language,
            "guard_class": spec.get("guard_class", "path-traversal"),
            "cve": spec.get("cve", "CVE-2026-4242"),
            "vuln_description": description,
            "cve_published_at": "2026-01-02T00:00:00Z",
            "fix_commit_date": "2026-01-01T00:00:00Z",
            "repo_url": repo_url,
            "vuln_ref": vuln_ref,
            "fixed_ref": fixed_ref,
            "sink_path": sink_path,
            "rule_file": "rule.yaml",
            "rule_sha256": ds.sha256_bytes(rule_text.encode("utf-8")),
            "window_mode": "trimmed",
            "vuln": {
                "file": f"vuln/{basename}",
                "header_lines": len(head_v),
                "segments": [{"start": s.start, "end": s.end} for s in seg_v],
                "original_line_count": len(vuln_lines),
                "expected_spans": expected,
                "semgrep_match_count": 1,
                "location_selectivity": window.location_selectivity(
                    [n for s in seg_v for n in range(s.start, s.end + 1)], expected),
            },
            "fixed": {
                "file": f"fixed/{basename}",
                "header_lines": len(head_f),
                "segments": [{"start": s.start, "end": s.end} for s in seg_f],
                "original_line_count": len(fixed_lines),
            },
            "license_spdx": spdx,
            "license_dir": license_dir,
            "copyright_notice": notice,
            "copyright_source": "license_file",
            "semgrep_warnings": [],
        }
        (case_dir / "case.json").write_text(json.dumps(case, indent=2, sort_keys=True) + "\n")
        entries.append({
            "case_id": cid,
            "guard_class": case["guard_class"],
            "ecosystem": case["ecosystem"],
            "language": language,
            "rule_sha256": case["rule_sha256"],
            "window_mode": "trimmed",
            "license_spdx": spdx,
            "vuln_ref": vuln_ref,
            "fixed_ref": fixed_ref,
            "vuln_segments": case["vuln"]["segments"],
            "fixed_segments": case["fixed"]["segments"],
            "case_sha256": ds.case_sha256(case_dir, case),
        })
    entries.sort(key=lambda e: e["case_id"])
    manifest = {
        "schema_version": 1,
        "dataset_version": "v1",
        "built_utc": "2026-10-19T00:00:00Z",
        "redpen_version": "0.1.0",
        "corpus": {"remote_url": None, "commit": "c" * 40},
        "semgrep_version": "1.177.0",
        "window_policy": {"version": "window-v1", "context_lines": 3},
        "case_count": len(entries),
        "cases": entries,
        "case_set_sha256": ds.case_set_sha256(entries),
    }
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return root
