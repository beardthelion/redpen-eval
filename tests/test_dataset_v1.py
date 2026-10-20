"""Offline re-verification of the committed dataset/v1 (U4).

Skips when dataset/v1 has not been built. When it exists, every assertion
here must hold; a corrupted dataset fails rather than skips.
"""

import json
import shutil
from collections import Counter
from pathlib import Path

import pytest

from redpen import dataset as ds
from redpen.semgrep import run_semgrep

ROOT = Path(__file__).resolve().parent.parent / "dataset" / "v1"
MANIFEST = ROOT / "manifest.json"

pytestmark = pytest.mark.skipif(not MANIFEST.exists(), reason="dataset/v1 not built")

CORPUS_COMMIT = "c5bd9ad219fed12b982e445708b7afbb413b6bd8"
GUARD_CLASSES = {
    "input-validation": 6,
    "auth-check": 5,
    "allowlist-denylist": 4,
    "escaping-encoding": 4,
    "type-range-check": 3,
    "size-cap": 2,
    "symlink-toctou-check": 1,
}
ECOSYSTEMS = {"go": 15, "npm": 6, "pip": 4}
AGPL_CASES = {"GHSA-j3hg-9rp3-5hw9", "GHSA-xv7q-fvmc-jx96"}
AGPL_LINE_TEXT = "This excerpt is released under the GNU Affero General Public License v3.0."


def _case_ids() -> list[str]:
    if not MANIFEST.exists():
        return []
    return [e["case_id"] for e in json.loads(MANIFEST.read_text())["cases"]]


def semgrep_problems(case: ds.Case) -> list[str]:
    """Re-run the committed rule on both windows; return every ground-truth violation.

    Uses the builder's KTD18-aware fires/silent, so only the allowlisted case
    may carry warn-level PartialParsing errors and any other error fails.
    """
    rule = case.dir / case.data["rule_file"]
    problems = []
    for side, want in (("vuln", "fires"), ("fixed", "silent")):
        run = run_semgrep(rule, case.dir / case.data[side]["file"])
        ok = ds.fires(run, case.case_id) if want == "fires" else ds.silent(run, case.case_id)
        if not ok:
            problems.append(
                f"{case.case_id} {side} side: expected {want}, got {len(run.matches)} match(es), "
                f"errors={ds._describe_errors(run.errors) or 'none'}"
            )
    return problems


@pytest.fixture(scope="module")
def loaded():
    return ds.load_dataset(ROOT)


def test_manifest_shape(loaded):
    m = loaded.manifest
    assert m["case_count"] == 25
    assert len(loaded.cases) == 25
    assert m["corpus"]["commit"] == CORPUS_COMMIT
    assert dict(Counter(e["guard_class"] for e in m["cases"])) == GUARD_CLASSES
    assert dict(Counter(e["ecosystem"] for e in m["cases"])) == ECOSYSTEMS
    for case in loaded.cases:
        assert case.data["guard_class"] in GUARD_CLASSES
        assert case.data["ecosystem"] in ECOSYSTEMS


def test_agpl_notice_only_on_agpl_cases(loaded):
    agpl_by_license = {c.case_id for c in loaded.cases if c.data["license_spdx"].startswith("AGPL-3.0")}
    assert agpl_by_license == AGPL_CASES
    for case in loaded.cases:
        for side, text in (("vuln", case.vuln_text), ("fixed", case.fixed_text)):
            header = text.splitlines()[: case.data[side]["header_lines"]]
            has_line = any(line.rstrip().endswith(AGPL_LINE_TEXT) for line in header)
            if case.case_id in AGPL_CASES:
                assert has_line, f"{case.case_id} {side}: AGPL notice missing from header"
            else:
                assert AGPL_LINE_TEXT not in text, f"{case.case_id} {side}: unexpected AGPL notice"


def test_license_dirs_populated(loaded):
    for case in loaded.cases:
        d = ROOT / case.data["license_dir"]
        assert d.is_dir(), f"{case.case_id}: {d} missing"
        assert any(p.is_file() for p in d.iterdir()), f"{case.case_id}: {d} is empty"


def test_accepted_warnings_only_where_allowlisted(loaded):
    for case in loaded.cases:
        if case.case_id not in ds.ACCEPTED_PARSE_WARNINGS:
            assert case.data["semgrep_warnings"] == [], case.case_id


@pytest.mark.parametrize("case_id", _case_ids())
def test_semgrep_ground_truth(loaded, case_id):
    case = next(c for c in loaded.cases if c.case_id == case_id)
    assert semgrep_problems(case) == []


# ------------------------------------------------------------ must-not


def _copy(tmp_path) -> Path:
    dst = tmp_path / "v1"
    shutil.copytree(ROOT, dst)
    return dst


def _pick_case(root: Path) -> dict:
    """A case outside the KTD18 allowlist, first by id."""
    m = json.loads((root / "manifest.json").read_text())
    return next(e for e in sorted(m["cases"], key=lambda e: e["case_id"])
                if e["case_id"] not in ds.ACCEPTED_PARSE_WARNINGS)


def test_appended_byte_in_fixed_window_fails_load(tmp_path):
    root = _copy(tmp_path)
    cid = _pick_case(root)["case_id"]
    case_dir = root / "cases" / cid
    data = json.loads((case_dir / "case.json").read_text())
    with open(case_dir / data["fixed"]["file"], "ab") as f:
        f.write(b"\n")
    with pytest.raises(ds.DatasetError, match=cid):
        ds.load_dataset(root)


def test_fixed_replaced_by_vuln_is_caught_by_semgrep_recheck(tmp_path):
    root = _copy(tmp_path)
    cid = _pick_case(root)["case_id"]
    case_dir = root / "cases" / cid
    data = json.loads((case_dir / "case.json").read_text())
    shutil.copyfile(case_dir / data["vuln"]["file"], case_dir / data["fixed"]["file"])

    manifest = json.loads((root / "manifest.json").read_text())
    for e in manifest["cases"]:
        if e["case_id"] == cid:
            e["case_sha256"] = ds.case_sha256(case_dir, data)
    manifest["case_set_sha256"] = ds.case_set_sha256(manifest["cases"])
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    loaded = ds.load_dataset(root)  # hashes are consistent, so only semgrep can catch it
    case = next(c for c in loaded.cases if c.case_id == cid)
    problems = semgrep_problems(case)
    assert len(problems) == 1
    assert problems[0].startswith(f"{cid} fixed side: expected silent")
