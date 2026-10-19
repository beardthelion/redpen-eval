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
