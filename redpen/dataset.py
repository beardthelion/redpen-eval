"""Build a versioned dataset of semgrep-verified source windows, and load it back."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from importlib.metadata import version as package_version
from pathlib import Path

from redpen import sources, window
from redpen.semgrep import SemgrepRun, run_semgrep
from redpen.util import atomic_write_bytes, semgrep_bin, sha256_bytes, utc_now_iso
from redpen.window import Construct, Span

# KTD18: per-case allowlist of accepted warn-level PartialParsing errors.
ACCEPTED_PARSE_WARNINGS = {"GHSA-pw5q-rjx4-7f7p": "Go 1.26 new(expr) syntax at lines 287 and 289"}

SCHEMA_VERSION = 1
CONTEXT_LINES = 3
WINDOW_POLICY = {"version": "window-v1", "context_lines": CONTEXT_LINES}
VERSION_RE = re.compile(r"^v[0-9]+$")
COPYRIGHT_RE = re.compile(r"(?i)\bcopyright\b")


class DatasetError(Exception):
    pass


class CaseFailure(Exception):
    pass


@dataclass
class Case:
    case_id: str
    dir: Path
    data: dict
    vuln_text: str
    fixed_text: str
    rule_text: str

    @property
    def guard_class(self) -> str:
        return self.data["guard_class"]


@dataclass
class Dataset:
    manifest: dict
    cases: list[Case]


@dataclass
class BuildReport:
    out: Path
    built: list[str] = field(default_factory=list)
    failures: list[tuple[str, str]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.built) + len(self.failures)


# ------------------------------------------------------------ KTD18 error filter

def _error_type(err: dict):
    t = err.get("type")
    return t[0] if isinstance(t, list) and t else t


def _split_errors(run: SemgrepRun, case_id: str) -> tuple[list[dict], list[dict]]:
    """(blocking errors, accepted warnings) for this case."""
    if case_id not in ACCEPTED_PARSE_WARNINGS:
        return list(run.errors), []
    blocking, accepted = [], []
    for e in run.errors:
        if e.get("level") == "warn" and _error_type(e) == "PartialParsing":
            accepted.append(e)
        else:
            blocking.append(e)
    return blocking, accepted


def fires(run: SemgrepRun, case_id: str) -> bool:
    blocking, _ = _split_errors(run, case_id)
    return not blocking and len(run.matches) > 0


def silent(run: SemgrepRun, case_id: str) -> bool:
    blocking, _ = _split_errors(run, case_id)
    return not blocking and len(run.matches) == 0


def _side_problem(side: str, run: SemgrepRun, case_id: str, want: str) -> str | None:
    blocking, _ = _split_errors(run, case_id)
    if blocking:
        return f"{side} side: semgrep errors: {_describe_errors(blocking)}"
    if want == "fires" and not run.matches:
        return f"{side} side: rule does not fire"
    if want == "silent" and run.matches:
        return f"{side} side: rule fires {len(run.matches)} time(s), expected silent"
    return None


def _describe_errors(errors: list[dict]) -> str:
    return "; ".join(f"{e.get('level')} {_error_type(e)}: {str(e.get('message', ''))[:200]}" for e in errors)


def _warning_records(side: str, run: SemgrepRun, case_id: str) -> list[dict]:
    _, accepted = _split_errors(run, case_id)
    out = []
    for e in accepted:
        t = e.get("type")
        spans = t[1] if isinstance(t, list) and len(t) > 1 else []
        lines = [[s["start"]["line"], s["end"]["line"]] for s in spans]
        out.append({"side": side, "level": e["level"], "type": "PartialParsing", "window_lines": lines})
    return out


def _constructs(path: Path, language: str, case_id: str) -> list[Construct]:
    """window.find_constructs, but tolerating KTD18-accepted warnings for listed cases."""
    if case_id not in ACCEPTED_PARSE_WARNINGS:
        return window.find_constructs(path, language)
    run = run_semgrep(window.CONSTRUCTS_RULES, path)
    blocking, _ = _split_errors(run, case_id)
    if blocking:
        raise CaseFailure(f"semgrep errors finding constructs: {_describe_errors(blocking)}")
    kinds = set(window.ENCLOSING_ORDER[language])
    found = {
        Construct(m.check_id.rsplit(".", 1)[-1], m.start_line, m.end_line)
        for m in run.matches
        if m.check_id.rsplit(".", 1)[-1] in kinds
    }
    return sorted(found, key=lambda c: (c.start, c.end, c.kind))


# ------------------------------------------------------------ build helpers

def _clean_copyright(line: str) -> str:
    s = line.strip()
    s = re.sub(r"^(//+|#+|/\*+|\*+|--|;+)\s*", "", s)
    s = re.sub(r"\s*\*+/\s*$", "", s)
    return s.strip()


def _copyright(sink_text: str, license_texts: list[str], owner: str, repo: str) -> tuple[str, str]:
    for line in sink_text.splitlines()[:40]:
        if COPYRIGHT_RE.search(line):
            return _clean_copyright(line), "sink_file"
    for text in license_texts:
        for line in text.splitlines():
            if COPYRIGHT_RE.search(line):
                return _clean_copyright(line), "license_file"
    return f"Copyright the {owner}/{repo} contributors", "fallback"


def _header(language, repo_url, ref, sink_path, build_date, spdx, license_dir, license_names, notice):
    c = window.COMMENT[language]
    lines = [
        f"{c} Source: {repo_url}",
        f"{c} Ref: {ref} Path: {sink_path}",
        f"{c} Excerpted and modified from {repo_url}@{ref} on {build_date}",
        f"{c} License: {spdx}, see {', '.join(f'{license_dir}/{n}' for n in license_names)}",
        f"{c} {notice}",
    ]
    if spdx.startswith("AGPL-3.0"):
        lines.append(f"{c} This excerpt is released under the GNU Affero General Public License v3.0.")
    return lines


def _decode(data: bytes, what: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise CaseFailure(f"{what} is not UTF-8: {e}") from e


def _spans(segments) -> list[dict]:
    return [{"start": s.start, "end": s.end} for s in segments]


def _code_lines(segments) -> list[int]:
    return [n for s in segments for n in range(s.start, s.end + 1)]


def semgrep_version() -> str:
    binary = semgrep_bin()
    if binary is None:
        raise DatasetError("semgrep not found")
    proc = subprocess.run([binary, "--version", "--disable-version-check"], capture_output=True, text=True)
    if proc.returncode != 0:
        raise DatasetError(f"semgrep --version failed: {proc.stderr.strip()}")
    return proc.stdout.strip().splitlines()[-1].strip()


def build_case(cc: sources.CorpusCase, staging: Path, cache_dir: Path, build_date: str) -> dict:
    """Build one case into staging/cases/<id>; return its manifest entry. Raises on failure."""
    if cc.error:
        raise CaseFailure(cc.error)
    case_id = cc.ghsa
    rule = cc.rule
    language = (rule.get("languages") or [None])[0]
    if language not in window.ENCLOSING_ORDER:
        raise CaseFailure(f"unsupported language: {language}")
    meta = rule.get("metadata") or {}

    adv = sources.fetch_advisory(case_id)
    repo_url = adv["repo_url"]
    owner, name = sources.repo_slug(repo_url)
    repo = sources.ensure_commits(repo_url, cc.fixed_ref, cc.vuln_ref, cache_dir)

    spdx = sources.fetch_license_spdx(owner, name)
    if spdx in (None, "NOASSERTION"):
        spdx = sources.LICENSE_SPDX_OVERRIDES.get(case_id)
    if not spdx or spdx == "NOASSERTION":
        raise CaseFailure(f"unknown license for {owner}/{name}")
    lic_names = sources.license_files(repo, cc.fixed_ref)
    if not lic_names:
        raise CaseFailure(f"no top-level license file in {owner}/{name} at fixed_ref")
    lic_bytes = {n: sources.git_show(repo, cc.fixed_ref, n) for n in lic_names}

    vuln_src = _decode(sources.git_show(repo, cc.vuln_ref, cc.sink_path), "vuln sink file")
    fixed_src = _decode(sources.git_show(repo, cc.fixed_ref, cc.sink_path), "fixed sink file")
    vuln_lines = window.split_lines(vuln_src)
    fixed_lines = window.split_lines(fixed_src)
    basename = Path(cc.sink_path).name

    case_dir = staging / "cases" / case_id
    (case_dir / "vuln").mkdir(parents=True)
    (case_dir / "fixed").mkdir(parents=True)
    rule_path = case_dir / "rule.yaml"
    atomic_write_bytes(rule_path, cc.rule_bytes)

    with tempfile.TemporaryDirectory(prefix="redpen-src-") as tmp:
        whole_v_path = Path(tmp) / "vuln" / basename
        whole_f_path = Path(tmp) / "fixed" / basename
        whole_v_path.parent.mkdir()
        whole_f_path.parent.mkdir()
        whole_v_path.write_bytes(vuln_src.encode("utf-8"))
        whole_f_path.write_bytes(fixed_src.encode("utf-8"))

        whole_v = run_semgrep(rule_path, whole_v_path)
        whole_f = run_semgrep(rule_path, whole_f_path)
        problems = [p for p in (_side_problem("vuln", whole_v, case_id, "fires"),
                                _side_problem("fixed", whole_f, case_id, "silent")) if p]
        if problems:
            raise CaseFailure("whole file: " + "; ".join(problems))

        hunks = window.parse_diff_u0(sources.diff_u0(repo, cc.vuln_ref, cc.fixed_ref, cc.sink_path))
        semgrep_spans = sorted({Span(m.start_line, m.end_line) for m in whole_v.matches})
        fix_spans = sorted(set(window.fix_spans_old(hunks)))
        expected = (
            [{"start": s.start, "end": s.end, "source": "semgrep"} for s in semgrep_spans]
            + [{"start": s.start, "end": s.end, "source": "fix_diff"} for s in fix_spans]
        )
        targets = semgrep_spans + fix_spans
        seg_v, cores = window.vuln_segments(
            targets, _constructs(whole_v_path, language, case_id), language, len(vuln_lines), CONTEXT_LINES)
        seg_f = window.fixed_segments(
            cores, hunks, _constructs(whole_f_path, language, case_id), language, len(fixed_lines),
            CONTEXT_LINES)

    lic_texts = [b.decode("utf-8", "replace") for b in lic_bytes.values()]
    notice, notice_source = _copyright(vuln_src, lic_texts, owner, name)
    license_dir = f"licenses/{owner}__{name}"
    head_v = _header(language, repo_url, cc.vuln_ref, cc.sink_path, build_date, spdx, license_dir,
                     lic_names, notice)
    head_f = _header(language, repo_url, cc.fixed_ref, cc.sink_path, build_date, spdx, license_dir,
                     lic_names, notice)
    win_v_path = case_dir / "vuln" / basename
    win_f_path = case_dir / "fixed" / basename

    def write_and_check(sv, sf):
        atomic_write_bytes(win_v_path, window.build_window_text(vuln_lines, sv, language, head_v).encode("utf-8"))
        atomic_write_bytes(win_f_path, window.build_window_text(fixed_lines, sf, language, head_f).encode("utf-8"))
        rv = run_semgrep(rule_path, win_v_path)
        rf = run_semgrep(rule_path, win_f_path)
        probs = [p for p in (_side_problem("vuln", rv, case_id, "fires"),
                             _side_problem("fixed", rf, case_id, "silent")) if p]
        return rv, rf, probs

    window_mode = "trimmed"
    fallback = None
    win_v, win_f, probs = write_and_check(seg_v, seg_f)
    if probs:
        window_mode = "whole_file"
        fallback = "; ".join(probs)
        seg_v = [Span(1, len(vuln_lines))]
        seg_f = [Span(1, len(fixed_lines))]
        win_v, win_f, probs = write_and_check(seg_v, seg_f)
        if probs:
            raise CaseFailure("whole-file window: " + "; ".join(probs))

    lic_out = staging / license_dir
    lic_out.mkdir(parents=True, exist_ok=True)
    for n, data in lic_bytes.items():
        atomic_write_bytes(lic_out / n, data)

    warnings = _warning_records("vuln", win_v, case_id) + _warning_records("fixed", win_f, case_id)
    case = {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "ecosystem": meta.get("ecosystem"),
        "language": language,
        "guard_class": meta.get("guard_class"),
        "cve": meta.get("cve") or adv.get("cve_id"),
        "vuln_description": rule.get("message"),
        "cve_published_at": adv["published_at"],
        "fix_commit_date": sources.commit_date(repo, cc.fixed_ref),
        "repo_url": repo_url,
        "vuln_ref": cc.vuln_ref,
        "fixed_ref": cc.fixed_ref,
        "sink_path": cc.sink_path,
        "rule_file": "rule.yaml",
        "rule_sha256": sha256_bytes(cc.rule_bytes),
        "window_mode": window_mode,
        "vuln": {
            "file": f"vuln/{basename}",
            "header_lines": len(head_v),
            "segments": _spans(seg_v),
            "original_line_count": len(vuln_lines),
            "expected_spans": expected,
            "semgrep_match_count": len(whole_v.matches),
            "location_selectivity": window.location_selectivity(_code_lines(seg_v), expected),
        },
        "fixed": {
            "file": f"fixed/{basename}",
            "header_lines": len(head_f),
            "segments": _spans(seg_f),
            "original_line_count": len(fixed_lines),
        },
        "license_spdx": spdx,
        "license_dir": license_dir,
        "copyright_notice": notice,
        "copyright_source": notice_source,
        "semgrep_warnings": warnings,
    }
    for key in ("ecosystem", "guard_class", "vuln_description"):
        if not case[key]:
            raise CaseFailure(f"rule is missing {key}")
    case_bytes = (json.dumps(case, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    atomic_write_bytes(case_dir / "case.json", case_bytes)
    return {
        "case_id": case_id,
        "guard_class": case["guard_class"],
        "ecosystem": case["ecosystem"],
        "language": language,
        "rule_sha256": case["rule_sha256"],
        "window_mode": window_mode,
        "license_spdx": spdx,
        "vuln_ref": cc.vuln_ref,
        "fixed_ref": cc.fixed_ref,
        "vuln_segments": case["vuln"]["segments"],
        "fixed_segments": case["fixed"]["segments"],
        "case_sha256": case_sha256(case_dir, case),
        "_vuln_lines": sum(s.end - s.start + 1 for s in seg_v),
        "_fixed_lines": sum(s.end - s.start + 1 for s in seg_f),
        "_fallback": fallback,
    }


def case_sha256(case_dir: Path, case: dict) -> str:
    parts = [
        (case_dir / "case.json").read_bytes(),
        (case_dir / case["rule_file"]).read_bytes(),
        (case_dir / case["vuln"]["file"]).read_bytes(),
        (case_dir / case["fixed"]["file"]).read_bytes(),
    ]
    return sha256_bytes(b"".join(parts))


def case_set_sha256(entries: list[dict]) -> str:
    lines = "".join(f"{e['case_id']} {e['case_sha256']}\n" for e in sorted(entries, key=lambda e: e["case_id"]))
    return sha256_bytes(lines.encode("utf-8"))


def build_dataset(sweep_dir, out, cache_dir, force: bool = False, log=print) -> BuildReport:
    out = Path(out)
    if not VERSION_RE.match(out.name):
        raise DatasetError(f"dataset version {out.name!r} must match ^v[0-9]+$")
    if out.exists() and not force:
        raise DatasetError(f"{out} exists; pass --force to overwrite")
    cases = sources.read_corpus(sweep_dir)
    if not cases:
        raise DatasetError(f"no rules found under {sweep_dir}/rules/verified")
    commit, remote = sources.corpus_identity(sweep_dir)
    version = semgrep_version()
    build_date = utc_now_iso()[:10]

    report = BuildReport(out=out)
    staging = out.parent / f"{out.name}.staging-{os.getpid()}"
    out.parent.mkdir(parents=True, exist_ok=True)
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir()
    try:
        entries = []
        for cc in cases:
            try:
                entry = build_case(cc, staging, Path(cache_dir), build_date)
            except Exception as e:
                shutil.rmtree(staging / "cases" / cc.ghsa, ignore_errors=True)
                report.failures.append((cc.ghsa, str(e)))
                log(f"FAIL {cc.ghsa}: {e}")
                continue
            vl, fl = entry.pop("_vuln_lines"), entry.pop("_fixed_lines")
            fallback = entry.pop("_fallback")
            entries.append(entry)
            report.built.append(cc.ghsa)
            line = f"ok   {cc.ghsa} window={entry['window_mode']} vuln_lines={vl} fixed_lines={fl}"
            if fallback is not None:
                line += f" fallback={json.dumps(fallback, ensure_ascii=False)}"
            log(line)
        if report.failures:
            shutil.rmtree(staging)
            return report
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "dataset_version": out.name,
            "built_utc": utc_now_iso(),
            "redpen_version": package_version("redpen"),
            "corpus": {"remote_url": remote, "commit": commit},
            "semgrep_version": version,
            "window_policy": WINDOW_POLICY,
            "case_count": len(entries),
            "cases": entries,
            "case_set_sha256": case_set_sha256(entries),
        }
        atomic_write_bytes(staging / "manifest.json",
                           (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        old = None
        if out.exists():
            old = out.parent / f"{out.name}.old-{os.getpid()}"
            os.rename(out, old)
        os.rename(staging, out)
        if old is not None:
            shutil.rmtree(old)
        return report
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


# ------------------------------------------------------------ loader

def load_dataset(path) -> Dataset:
    root = Path(path)
    try:
        manifest = json.loads((root / "manifest.json").read_text())
    except (OSError, ValueError) as e:
        raise DatasetError(f"cannot read manifest in {root}: {e}") from e
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise DatasetError(f"unsupported manifest schema_version {manifest.get('schema_version')!r}")
    entries = manifest.get("cases") or []
    if manifest.get("case_count") != len(entries):
        raise DatasetError("manifest case_count does not match its case list")
    on_disk = {p.name for p in (root / "cases").iterdir() if p.is_dir()} if (root / "cases").is_dir() else set()
    listed = {e["case_id"] for e in entries}
    if on_disk != listed:
        raise DatasetError(f"case directories {sorted(on_disk ^ listed)} do not match the manifest")
    cases = []
    for e in entries:
        cid = e["case_id"]
        case_dir = root / "cases" / cid
        try:
            data = json.loads((case_dir / "case.json").read_text())
            if data.get("case_id") != cid:
                raise DatasetError(f"{cid}: case.json case_id is {data.get('case_id')!r}")
            actual = case_sha256(case_dir, data)
            vuln_text = (case_dir / data["vuln"]["file"]).read_text()
            fixed_text = (case_dir / data["fixed"]["file"]).read_text()
            rule_text = (case_dir / data["rule_file"]).read_text()
        except DatasetError:
            raise
        except (OSError, ValueError, KeyError) as exc:
            raise DatasetError(f"{cid}: {exc}") from exc
        if actual != e.get("case_sha256"):
            raise DatasetError(f"{cid}: case_sha256 mismatch (files changed after the build)")
        cases.append(Case(cid, case_dir, data, vuln_text, fixed_text, rule_text))
    if case_set_sha256(entries) != manifest.get("case_set_sha256"):
        raise DatasetError("case_set_sha256 mismatch")
    return Dataset(manifest=manifest, cases=cases)
