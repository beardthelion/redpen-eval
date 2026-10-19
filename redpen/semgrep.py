"""Run semgrep on one target and parse its JSON output."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from redpen.util import semgrep_bin


class SemgrepError(Exception):
    pass


@dataclass
class Match:
    start_line: int
    end_line: int
    check_id: str
    metavars: dict


@dataclass
class SemgrepRun:
    matches: list[Match] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)

    @property
    def fires(self) -> bool:
        return not self.errors and len(self.matches) > 0

    @property
    def silent(self) -> bool:
        return not self.errors and len(self.matches) == 0


def run_semgrep(rule_path: Path, target: Path, timeout_s: int = 300) -> SemgrepRun:
    binary = semgrep_bin()
    if binary is None:
        raise SemgrepError("semgrep not found")
    cmd = [
        binary, "scan", "--config", str(rule_path), "--json", "--quiet",
        "--disable-version-check", "--metrics", "off", "--no-git-ignore", str(target),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired as e:
        raise SemgrepError(f"semgrep timed out after {timeout_s}s on {target}") from e
    if proc.returncode not in (0, 1):
        raise SemgrepError(
            f"semgrep exited {proc.returncode} on {target}: {proc.stderr.strip()[-2000:]}"
        )
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise SemgrepError(f"semgrep returned invalid JSON on {target}") from e
    matches = [
        Match(
            start_line=r["start"]["line"],
            end_line=r["end"]["line"],
            check_id=r["check_id"],
            metavars=r.get("extra", {}).get("metavars", {}),
        )
        for r in data.get("results", [])
    ]
    return SemgrepRun(matches=matches, errors=list(data.get("errors", [])))
