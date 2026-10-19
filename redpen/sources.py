"""Inputs to the dataset build: the sweep corpus, GitHub metadata, upstream git cache."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml

# Used only when the GitHub API reports NOASSERTION or no license.
LICENSE_SPDX_OVERRIDES = {"GHSA-cv23-7vc5-jfh7": "BSD-2-Clause"}

GH_BACKOFF_S = (2, 4, 8)
LICENSE_FILE_RE = re.compile(r"(?i)^(licen[cs]e|copying)(\.[a-z0-9]+)?$")


class SourceError(Exception):
    pass


@dataclass
class CorpusCase:
    ghsa: str
    rule_path: Path
    rule_bytes: bytes = b""
    rule: dict | None = None
    vuln_ref: str | None = None
    fixed_ref: str | None = None
    sink_path: str | None = None
    error: str | None = None


def _run(cmd, cwd=None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True)


def _git(repo, *args) -> bytes:
    proc = _run(["git", "-C", str(repo), *args])
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", "replace").strip()
        raise SourceError(f"git {' '.join(args)} failed: {msg}")
    return proc.stdout


def _git_ok(repo, *args) -> bool:
    return _run(["git", "-C", str(repo), *args]).returncode == 0


# ------------------------------------------------------------ corpus

def corpus_identity(sweep_dir) -> tuple[str, str | None]:
    """(HEAD commit, origin remote url or None) of the sweep checkout."""
    commit = _git(sweep_dir, "rev-parse", "HEAD").decode().strip()
    proc = _run(["git", "-C", str(sweep_dir), "remote", "get-url", "origin"])
    remote = proc.stdout.decode().strip() if proc.returncode == 0 else None
    return commit, remote or None


def _read_case(sweep: Path, rule_path: Path) -> CorpusCase:
    ghsa = rule_path.stem
    cc = CorpusCase(ghsa=ghsa, rule_path=rule_path)
    try:
        cc.rule_bytes = rule_path.read_bytes()
        cc.rule = yaml.safe_load(cc.rule_bytes)["rules"][0]
        meta_ghsa = (cc.rule.get("metadata") or {}).get("ghsa_id")
        if meta_ghsa != ghsa:
            raise SourceError(f"metadata.ghsa_id {meta_ghsa!r} does not match file stem {ghsa}")
        verdict = json.loads((sweep / "evidence" / ghsa / "verdict.json").read_text())
        if verdict.get("result") != "verified":
            raise SourceError(f"evidence result is {verdict.get('result')!r}, not verified")
        runs = verdict["runs"]
        cc.vuln_ref = runs["vuln"]["ref"]
        cc.fixed_ref = runs["fixed"]["ref"]
        marker = f"{ghsa}-vuln/"
        paths = set()
        for p in runs["vuln"]["sink_matched_paths"]:
            if marker not in p:
                raise SourceError(f"sink path {p!r} lacks {marker!r}")
            paths.add(p.split(marker, 1)[1])
        if len(paths) != 1:
            raise SourceError(f"expected exactly one sink path, got {sorted(paths)}")
        cc.sink_path = paths.pop()
    except Exception as e:  # any malformed input is a case failure, not a crash
        cc.error = str(e) if isinstance(e, SourceError) else f"{type(e).__name__}: {e}"
    return cc


def read_corpus(sweep_dir) -> list[CorpusCase]:
    sweep = Path(sweep_dir)
    status = _git(sweep, "status", "--porcelain", "--", "rules/verified", "evidence")
    if status.strip():
        raise SourceError(f"sweep dir {sweep} has uncommitted changes under rules/verified or evidence")
    rules = sorted((sweep / "rules" / "verified").glob("*.yaml"))
    return [_read_case(sweep, p) for p in rules]


# ------------------------------------------------------------ GitHub

def gh_api(path: str) -> dict:
    gh = shutil.which("gh")
    if gh is None:
        raise SourceError("gh not found on PATH")
    cmd = [gh, "api", path]
    last = ""
    for attempt in range(len(GH_BACKOFF_S) + 1):
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode == 0:
            return json.loads(proc.stdout)
        last = proc.stderr.strip()
        if attempt < len(GH_BACKOFF_S):
            time.sleep(GH_BACKOFF_S[attempt])
    raise SourceError(f"gh api {path} failed: {last}")


def fetch_advisory(ghsa: str) -> dict:
    data = gh_api(f"/advisories/{ghsa}")
    return {
        "repo_url": data["source_code_location"],
        "published_at": data["published_at"],
        "cve_id": data.get("cve_id"),
    }


def fetch_license_spdx(owner: str, repo: str) -> str | None:
    data = gh_api(f"repos/{owner}/{repo}")
    lic = data.get("license") or {}
    return lic.get("spdx_id")


# ------------------------------------------------------------ upstream git cache

def repo_slug(repo_url: str) -> tuple[str, str]:
    parts = [p for p in urlparse(repo_url).path.split("/") if p]
    if len(parts) < 2:
        raise SourceError(f"cannot derive owner/repo from {repo_url!r}")
    owner, repo = parts[-2], parts[-1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return owner, repo


def _has_commit(repo: Path, ref: str) -> bool:
    return repo.is_dir() and _git_ok(repo, "cat-file", "-e", f"{ref}^{{commit}}")


def first_parent(repo: Path, ref: str) -> str | None:
    """First `parent` header of the commit object. Not `rev-parse <ref>^1`: that
    stops resolving once a later depth-2 fetch marks this commit shallow."""
    for line in _git(repo, "cat-file", "-p", ref).decode("utf-8", "replace").splitlines():
        if not line:
            break
        if line.startswith("parent "):
            return line.split(" ", 1)[1].strip()
    return None


def ensure_commits(repo_url: str, fixed_ref: str, vuln_ref: str, cache_dir) -> Path:
    owner, name = repo_slug(repo_url)
    repo = Path(cache_dir) / f"{owner}__{name}"
    if not (_has_commit(repo, fixed_ref) and _has_commit(repo, vuln_ref)):
        repo.mkdir(parents=True, exist_ok=True)
        if not (repo / ".git").exists():
            _git(repo, "init", "-q")
        if not _git_ok(repo, "remote", "get-url", "origin"):
            _git(repo, "remote", "add", "origin", repo_url)
        _git(repo, "fetch", "-q", "--depth", "2", "origin", fixed_ref)
    if first_parent(repo, fixed_ref) != vuln_ref:
        raise SourceError("vuln_ref is not the first parent of fixed_ref")
    return repo


def git_show(repo, ref: str, path: str) -> bytes:
    return _git(repo, "show", f"{ref}:{path}")


def license_files(repo, ref: str) -> list[str]:
    out = _git(repo, "ls-tree", ref).decode("utf-8", "replace")
    names = []
    for line in out.splitlines():
        meta, name = line.split("\t", 1)
        if meta.split()[1] == "blob" and LICENSE_FILE_RE.match(name):
            names.append(name)
    return sorted(names)


def commit_date(repo, ref: str) -> str:
    return _git(repo, "show", "-s", "--format=%cI", ref).decode().strip()


def diff_u0(repo, vuln_ref: str, fixed_ref: str, path: str) -> str:
    return _git(repo, "diff", "-U0", vuln_ref, fixed_ref, "--", path).decode("utf-8", "replace")
