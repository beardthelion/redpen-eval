import contextlib
import io
import json
import shutil
from pathlib import Path

import pytest

from conftest import commit_files, line_of, make_rule, make_sweep, make_upstream_repo, patch_github
from redpen import cli, dataset, sources
from redpen.dataset import DatasetError
from redpen.semgrep import Match, SemgrepRun, run_semgrep
from redpen.util import sha256_bytes

MIT = "MIT License\n\nCopyright (c) 2023 Extractor Devs\n\nPermission is hereby granted...\n"
NO_COPYRIGHT_LICENSE = "Permission to use this software is granted to all.\n"
AGPL = "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007\n"

CASE_KEYS = {
    "schema_version", "case_id", "ecosystem", "language", "guard_class", "cve",
    "vuln_description", "cve_published_at", "fix_commit_date", "repo_url", "vuln_ref",
    "fixed_ref", "sink_path", "rule_file", "rule_sha256", "window_mode", "vuln", "fixed",
    "license_spdx", "license_dir", "copyright_notice", "copyright_source", "semgrep_warnings",
}
VULN_KEYS = {"file", "header_lines", "segments", "original_line_count", "expected_spans",
             "semgrep_match_count", "location_selectivity"}
FIXED_KEYS = {"file", "header_lines", "segments", "original_line_count"}
MANIFEST_KEYS = {"schema_version", "dataset_version", "built_utc", "redpen_version", "corpus",
                 "semgrep_version", "window_policy", "case_count", "cases", "case_set_sha256"}
MANIFEST_CASE_KEYS = {"case_id", "guard_class", "ecosystem", "language", "rule_sha256",
                      "window_mode", "license_spdx", "vuln_ref", "fixed_ref", "vuln_segments",
                      "fixed_segments", "case_sha256"}


# ------------------------------------------------------------ fixture sources

GO_UPLOAD_BODY = "".join(f'\t_ = r.Header.Get("X-H{i}")\n' for i in range(18))
GO_UPLOAD_TAIL = "".join(f'\t_ = r.Header.Get("X-T{i}")\n' for i in range(17))
GO_VULN = (
    "// Copyright 2024 Acme Widget Authors\n"
    "package handler\n"
    "\n"
    "import (\n"
    '\t"bytes"\n'
    '\t"io"\n'
    '\t"net/http"\n'
    ")\n"
    "\n"
    "func allowed(s string) bool {\n"
    "\tif s == \"\" {\n"
    "\t\treturn true\n"
    "\t}\n"
    "\treturn false\n"
    "}\n"
    "\n"
    "func Upload(w http.ResponseWriter, r *http.Request) {\n"
    "\tvar buf bytes.Buffer\n"
    + GO_UPLOAD_BODY +
    "\tio.Copy(&buf, r.Body)\n"
    + GO_UPLOAD_TAIL +
    "\tw.Write(buf.Bytes())\n"
    "}\n"
    + "".join(f"// pad {i}\n" for i in range(40)) +
    "func filler() {\n\tprintln(\"far away\")\n}\n"
)
GO_FIXED = GO_VULN.replace("io.Copy(&buf, r.Body)", "io.Copy(&buf, http.MaxBytesReader(w, r.Body, 1<<20))")
GO_RULE_BODY = (
    "    patterns:\n"
    "      - pattern-inside: |\n"
    "          func $F($W http.ResponseWriter, $R *http.Request) { ... }\n"
    "      - pattern: io.Copy($D, $R.Body)\n"
)

PY_VULN = (
    "import yaml\n"
    "\n"
    "\n"
    "class Loader:\n"
    "    def __init__(self):\n"
    "        self.a = 1\n"
    "        self.b = 2\n"
    "        self.c = 3\n"
    "        self.d = 4\n"
    "\n"
    "    def load(self, x):\n"
    "        data = x.strip()\n"
    "        return yaml.load(data)\n"
)
PY_FIXED = PY_VULN.replace("yaml.load(data)", "yaml.safe_load(data)")
PY_RULE_BODY = "    pattern: yaml.load(...)\n"

TS_VULN = (
    'import * as path from "path";\n'
    "\n"
    "export class Extractor extends Base {\n"
    "  private root: string;\n"
    "\n"
    "  constructor(root: string) {\n"
    "    super();\n"
    "    this.root = root;\n"
    "  }\n"
    "\n"
    "  private async extractEntry(name: string, data: Buffer) {\n"
    "    const dest = path.join(this.root, name);\n"
    "    await write(dest, data);\n"
    "  }\n"
    "}\n"
    + "".join(f"// pad {i}\n" for i in range(12)) +
    "export function unrelated() {\n  return 1;\n}\n"
)
TS_FIXED = TS_VULN.replace(
    "    const dest = path.join(this.root, name);\n",
    "    const dest = path.join(this.root, name);\n"
    "    if (!isContainedPath(this.root, dest)) {\n"
    '      throw new Error("bad path");\n'
    "    }\n",
)
TS_RULE_BODY = (
    "    patterns:\n"
    "      - pattern: |\n"
    "          private async extractEntry(...) { ... }\n"
    "      - pattern-not-regex: (?s)isContainedPath\n"
)
TS_FRAGMENT = (
    "  private async extractEntry(name: string, data: Buffer) {\n"
    "    const dest = path.join(this.root, name);\n"
    "    if (!isContainedPath(this.root, dest)) {\n"
    '      throw new Error("bad path");\n'
    "    }\n"
    "  }\n"
)

JS_VULN = (
    "// helpers\n"
    "function render(el, s) {\n"
    "  const x = s.trim();\n"
    "  el.innerHTML = x;\n"
    "  return el;\n"
    "}\n"
    + "".join(f"// pad {i}\n" for i in range(12)) +
    "function far() {\n  return 2;\n}\n"
)
JS_FIXED = JS_VULN.replace("el.innerHTML = x;", "el.textContent = x;")
JS_RULE_BODY = (
    "    pattern: |\n"
    "      function $F(...) { ... $EL.innerHTML = $S; ... }\n"
)

PICKLE_VULN = (
    "import json\n"
    "import pickle\n"
    + "".join(f"# pad {i}\n" for i in range(10)) +
    "\n"
    "def decode(data):\n"
    "    return pickle.loads(data)\n"
)
PICKLE_FIXED = PICKLE_VULN.replace("pickle.loads(data)", "json.loads(data)")
PICKLE_RULE_BODY = (
    "    patterns:\n"
    "      - pattern-inside: |\n"
    "          import pickle\n"
    "          ...\n"
    "      - pattern: pickle.loads(...)\n"
)

GO_WARN_VULN = (
    "package handler\n"
    "\n"
    "import (\n"
    '\t"io"\n'
    '\t"net/http"\n'
    ")\n"
    "\n"
    "func Upload(w http.ResponseWriter, r *http.Request) {\n"
    "\ttype A[T any] = []T\n"
    "\tio.Copy(w, r.Body)\n"
    "}\n"
)
GO_WARN_FIXED = GO_WARN_VULN.replace("io.Copy(w, r.Body)", "io.Copy(w, http.MaxBytesReader(w, r.Body, 1<<20))")

ADV_DATE = "2026-03-04T05:06:07Z"


class World:
    """Fixture upstream repos plus a sweep and a patched gh."""

    def __init__(self, tmp_path, monkeypatch):
        self.tmp = Path(tmp_path)
        self.monkeypatch = monkeypatch
        self.cases = []
        self.advisories = {}
        self.licenses = {}

    def add(self, ghsa, language, rule_body, sink_path, vuln_src, fixed_src, license_text,
            spdx="MIT", owner_repo=None, ecosystem="go", refs=None, **case_kw):
        owner_repo = owner_repo or f"acme/{ghsa.lower()}"
        if refs is None:
            url, v, f = make_upstream_repo(self.tmp, {sink_path: vuln_src}, {sink_path: fixed_src},
                                           license_text, owner_repo=owner_repo)
        else:
            url, v, f = refs
        self.cases.append({"ghsa": ghsa, "rule": make_rule(ghsa, language, rule_body, ecosystem=ecosystem),
                           "vuln_ref": v, "fixed_ref": f, "sink_path": sink_path, **case_kw})
        self.advisories[ghsa] = {"repo_url": url, "published_at": ADV_DATE, "cve_id": "CVE-2026-0001"}
        self.licenses[owner_repo] = spdx
        return url, v, f

    def sweep(self):
        patch_github(self.monkeypatch, self.advisories, self.licenses)
        return make_sweep(self.tmp, self.cases)


def build(sweep, out, cache, *extra):
    return cli.main(["build-dataset", "--sweep-dir", str(sweep), "--out", str(out),
                     "--cache-dir", str(cache), *extra])


GO_ID = "GHSA-0go0-0000-0000"
PY_ID = "GHSA-1py0-0000-0000"
TS_ID = "GHSA-2ts0-0000-0000"
JS_ID = "GHSA-3js0-0000-0000"
PK_ID = "GHSA-4pk0-0000-0000"


@pytest.fixture(scope="module")
def happy(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("happy")
    with pytest.MonkeyPatch.context() as mp:
        w = World(tmp, mp)
        w.add(GO_ID, "go", GO_RULE_BODY, "pkg/handler.go", GO_VULN, GO_FIXED, MIT)
        w.add(PY_ID, "python", PY_RULE_BODY, "app/loader.py", PY_VULN, PY_FIXED, MIT, ecosystem="pip")
        w.add(TS_ID, "typescript", TS_RULE_BODY, "src/extract.ts", TS_VULN, TS_FIXED, MIT, ecosystem="npm")
        w.add(JS_ID, "javascript", JS_RULE_BODY, "lib/render.js", JS_VULN, JS_FIXED,
              NO_COPYRIGHT_LICENSE, spdx="ISC", ecosystem="npm")
        w.add(PK_ID, "python", PICKLE_RULE_BODY, "codec.py", PICKLE_VULN, PICKLE_FIXED, AGPL,
              spdx="AGPL-3.0-only", ecosystem="pip")
        sweep = w.sweep()
        out = tmp / "dataset" / "v1"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = build(sweep, out, tmp / "cache")
    assert rc == 0, buf.getvalue()
    return {"out": out, "sweep": sweep, "stdout": buf.getvalue()}


def case_json(out, cid):
    return json.loads((out / "cases" / cid / "case.json").read_text())


def window(out, cid, side):
    c = case_json(out, cid)
    return (out / "cases" / cid / c[side]["file"]).read_text()


# ------------------------------------------------------------ happy paths

def test_go_happy_path(happy):
    out = happy["out"]
    c = case_json(out, GO_ID)
    assert c["window_mode"] == "trimmed"
    start = line_of(GO_VULN, "func Upload")
    end = line_of(GO_VULN, "w.Write(buf.Bytes())") + 1
    assert c["vuln"]["segments"] == [{"start": start, "end": end}]
    assert "return false" not in window(out, GO_ID, "vuln")
    filler = line_of(GO_VULN, "func filler")
    assert all(s["end"] < filler for s in c["vuln"]["segments"])
    sink = line_of(GO_VULN, "io.Copy(&buf, r.Body)")
    assert {"start": sink, "end": sink, "source": "semgrep"} in c["vuln"]["expected_spans"]
    assert {"start": sink, "end": sink, "source": "fix_diff"} in c["vuln"]["expected_spans"]
    assert c["vuln"]["semgrep_match_count"] == 1
    assert c["vuln"]["file"] == "vuln/handler.go" and c["fixed"]["file"] == "fixed/handler.go"
    assert "far away" not in window(out, GO_ID, "vuln")
    # committed windows re-check
    rule = out / "cases" / GO_ID / "rule.yaml"
    assert run_semgrep(rule, out / "cases" / GO_ID / "vuln" / "handler.go").fires
    assert run_semgrep(rule, out / "cases" / GO_ID / "fixed" / "handler.go").silent


def test_location_selectivity_single_line_span_in_40_line_window(happy):
    c = case_json(happy["out"], GO_ID)
    code_lines = sum(s["end"] - s["start"] + 1 for s in c["vuln"]["segments"])
    assert code_lines == 40
    assert 0.2 <= c["vuln"]["location_selectivity"] <= 0.35


def test_location_selectivity_whole_window_span_is_one(happy):
    c = case_json(happy["out"], JS_ID)
    assert c["vuln"]["location_selectivity"] == 1.0


def test_python_happy_path_indented_method(happy):
    out = happy["out"]
    c = case_json(happy["out"], PY_ID)
    assert c["window_mode"] == "trimmed"
    start = line_of(PY_VULN, "def load")
    assert c["vuln"]["segments"] == [{"start": start, "end": c["vuln"]["original_line_count"]}]
    text = window(out, PY_ID, "vuln")
    assert "class Loader" not in text
    assert "    def load(self, x):\n" in text


def test_typescript_happy_path_window_is_class(happy):
    out = happy["out"]
    c = case_json(out, TS_ID)
    assert c["window_mode"] == "trimmed"
    cls = line_of(TS_VULN, "export class Extractor")
    cls_end = 15
    assert c["vuln"]["segments"] == [{"start": cls, "end": cls_end}]
    fcls_end = line_of(TS_FIXED, "export class") + 15
    assert c["fixed"]["segments"] == [{"start": cls, "end": fcls_end}]
    assert "unrelated" not in window(out, TS_ID, "vuln")
    assert "constructor(root" in window(out, TS_ID, "vuln")
    assert cls == 3


def test_javascript_happy_path_window_is_function(happy):
    out = happy["out"]
    c = case_json(out, JS_ID)
    assert c["window_mode"] == "trimmed"
    assert c["vuln"]["segments"] == [{"start": 2, "end": 6}]
    assert "function far" not in window(out, JS_ID, "vuln")


def test_whole_file_fallback(happy):
    c = case_json(happy["out"], PK_ID)
    assert c["window_mode"] == "whole_file"
    n_v = len(PICKLE_VULN.splitlines())
    n_f = len(PICKLE_FIXED.splitlines())
    assert c["vuln"]["segments"] == [{"start": 1, "end": n_v}]
    assert c["fixed"]["segments"] == [{"start": 1, "end": n_f}]
    (line,) = [l for l in happy["stdout"].splitlines() if l.startswith(f"ok   {PK_ID} ")]
    assert line == (f"ok   {PK_ID} window=whole_file vuln_lines={n_v} fixed_lines={n_f} "
                    'fallback="vuln side: rule does not fire"')


def test_must_not_trimmed_case_prints_no_fallback(happy):
    lines = [l for l in happy["stdout"].splitlines() if l.startswith("ok   ")]
    assert len(lines) == 5
    for cid in (GO_ID, PY_ID, TS_ID, JS_ID):
        (line,) = [l for l in lines if l.startswith(f"ok   {cid} ")]
        assert " window=trimmed " in line and "fallback=" not in line


def test_manifest_lists_cases_sorted(happy):
    m = json.loads((happy["out"] / "manifest.json").read_text())
    assert [c["case_id"] for c in m["cases"]] == [GO_ID, PY_ID, TS_ID, JS_ID, PK_ID]


# ------------------------------------------------------------ attribution

def test_attribution_headers(happy):
    out = happy["out"]
    agpl = case_json(out, PK_ID)
    mit = case_json(out, GO_ID)
    for c, cid in ((agpl, PK_ID), (mit, GO_ID)):
        for side in ("vuln", "fixed"):
            text = window(out, cid, side)
            head = text.splitlines()[: c[side]["header_lines"]]
            ref = c[f"{side}_ref"]
            prefix = "#" if c["language"] == "python" else "//"
            assert all(h.startswith(prefix) for h in head)
            joined = "\n".join(head)
            assert c["repo_url"] in joined
            assert ref in joined
            assert c["sink_path"] in joined
            assert f"Excerpted and modified from {c['repo_url']}@{ref} on " in joined
            assert c["license_spdx"] in joined
            assert c["license_dir"] in joined
            assert c["copyright_notice"] in joined
            agpl_line = "released under the GNU Affero General Public License v3.0"
            if cid == PK_ID:
                assert agpl_line in joined
            else:
                assert agpl_line not in joined
    assert agpl["license_spdx"] == "AGPL-3.0-only"


def test_license_files_copied_verbatim(happy):
    out = happy["out"]
    c = case_json(out, PK_ID)
    assert (out / c["license_dir"] / "LICENSE").read_text() == AGPL
    assert c["license_dir"] == f"licenses/acme__{PK_ID.lower()}"


def test_copyright_sources(happy):
    out = happy["out"]
    go = case_json(out, GO_ID)
    assert go["copyright_source"] == "sink_file"
    assert go["copyright_notice"] == "Copyright 2024 Acme Widget Authors"
    ts = case_json(out, TS_ID)
    assert ts["copyright_source"] == "license_file"
    assert ts["copyright_notice"] == "Copyright (c) 2023 Extractor Devs"
    js = case_json(out, JS_ID)
    assert js["copyright_source"] == "fallback"
    assert js["copyright_notice"] == f"Copyright the acme/{JS_ID.lower()} contributors"


# ------------------------------------------------------------ schema and loader

def test_case_and_manifest_schema(happy):
    out = happy["out"]
    m = json.loads((out / "manifest.json").read_text())
    assert set(m) == MANIFEST_KEYS
    assert m["schema_version"] == 1 and m["dataset_version"] == "v1"
    assert m["case_count"] == 5
    assert m["corpus"]["commit"] and len(m["corpus"]["commit"]) == 40
    assert m["corpus"]["remote_url"] is None
    assert m["semgrep_version"] == "1.177.0"
    assert m["window_policy"] == {"version": "window-v1", "context_lines": 3}
    for entry in m["cases"]:
        assert set(entry) == MANIFEST_CASE_KEYS
        c = case_json(out, entry["case_id"])
        assert set(c) == CASE_KEYS
        assert set(c["vuln"]) == VULN_KEYS
        assert set(c["fixed"]) == FIXED_KEYS
        assert c["schema_version"] == 1
        assert c["rule_file"] == "rule.yaml"
        assert c["semgrep_warnings"] == []
        assert c["cve_published_at"] == ADV_DATE
        assert c["fix_commit_date"].startswith("20")
        assert c["cve"] == "CVE-2026-0001"
        assert c["vuln_description"] == "untrusted input reaches a sink"
        rule_bytes = (out / "cases" / c["case_id"] / "rule.yaml").read_bytes()
        assert c["rule_sha256"] == sha256_bytes(rule_bytes) == entry["rule_sha256"]
        assert entry["vuln_segments"] == c["vuln"]["segments"]
        assert entry["fixed_segments"] == c["fixed"]["segments"]
        assert entry["window_mode"] == c["window_mode"]
        assert len(c["vuln_ref"]) == 40 and len(c["fixed_ref"]) == 40
    assert case_json(out, GO_ID)["ecosystem"] == "go"
    assert case_json(out, TS_ID)["language"] == "typescript"


def test_load_dataset_round_trips(happy):
    ds = dataset.load_dataset(happy["out"])
    assert ds.manifest["case_count"] == 5
    assert [c.case_id for c in ds.cases] == [GO_ID, PY_ID, TS_ID, JS_ID, PK_ID]
    go = ds.cases[0]
    assert go.guard_class == "input-validation"
    assert go.data == case_json(happy["out"], GO_ID)
    assert go.vuln_text == window(happy["out"], GO_ID, "vuln")
    assert go.fixed_text == window(happy["out"], GO_ID, "fixed")


def test_must_not_load_dataset_detects_edited_window(happy, tmp_path):
    copy = tmp_path / "v1"
    shutil.copytree(happy["out"], copy)
    p = copy / "cases" / JS_ID / "fixed" / "render.js"
    p.write_text(p.read_text() + "// edit\n")
    with pytest.raises(DatasetError, match=JS_ID):
        dataset.load_dataset(copy)


def test_must_not_load_dataset_detects_case_set_hash_change(happy, tmp_path):
    copy = tmp_path / "v1"
    shutil.copytree(happy["out"], copy)
    m = json.loads((copy / "manifest.json").read_text())
    m["case_set_sha256"] = "0" * 64
    (copy / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(DatasetError, match="case_set_sha256"):
        dataset.load_dataset(copy)


# ------------------------------------------------------------ all-or-nothing

def _good_js(w, ghsa):
    w.add(ghsa, "javascript", JS_RULE_BODY, "lib/render.js", JS_VULN, JS_FIXED, MIT, ecosystem="npm")


def test_must_not_partial_build_writes_nothing(tmp_path, monkeypatch, capsys):
    w = World(tmp_path, monkeypatch)
    _good_js(w, "GHSA-good-0000-0001")
    w.add("GHSA-good-0000-0002", "python", PY_RULE_BODY, "app/loader.py", PY_VULN, PY_FIXED, MIT)
    _good_js(w, "GHSA-good-0000-0003")
    # bad 1: rule does not fire on vuln
    w.add("GHSA-bad0-0000-0001", "javascript", "    pattern: eval(...)\n", "lib/render.js",
          JS_VULN, JS_FIXED, MIT)
    # bad 2: fixed file is a bare TS class-method fragment (parse error)
    w.add("GHSA-bad0-0000-0002", "typescript", TS_RULE_BODY, "src/extract.ts",
          TS_VULN, TS_FRAGMENT, MIT)
    sweep = w.sweep()
    out = tmp_path / "ds" / "v1"
    rc = build(sweep, out, tmp_path / "cache")
    text = capsys.readouterr().out
    assert rc == 1
    lines = text.splitlines()
    for g in ("GHSA-good-0000-0001", "GHSA-good-0000-0002", "GHSA-good-0000-0003"):
        assert any(l.startswith(f"ok   {g} window=trimmed vuln_lines=") and " fixed_lines=" in l
                   for l in lines), text
    bad1 = [l for l in lines if l.startswith("FAIL GHSA-bad0-0000-0001: ")]
    bad2 = [l for l in lines if l.startswith("FAIL GHSA-bad0-0000-0002: ")]
    assert len(bad1) == 1 and "vuln side: rule does not fire" in bad1[0]
    assert len(bad2) == 1 and "fixed side: semgrep errors" in bad2[0]
    assert lines[-1] == f"build failed: 2 of 5 cases failed; {out} not written"
    assert not out.exists()
    assert list(out.parent.glob("*.staging-*")) == []


def test_must_not_parse_error_is_never_silent(tmp_path):
    rule = tmp_path / "r.yaml"
    rule.write_text(make_rule("GHSA-bad0-0000-0002", "typescript", TS_RULE_BODY))
    target = tmp_path / "extract.ts"
    target.write_text(TS_FRAGMENT)
    run = run_semgrep(rule, target)
    assert run.errors
    assert dataset.silent(run, "GHSA-bad0-0000-0002") is False
    assert dataset.fires(run, "GHSA-bad0-0000-0002") is False


# ------------------------------------------------------------ KTD18 allowlist filter

def _run(errors, matches=0):
    return SemgrepRun(matches=[Match(1, 1, "r", {}) for _ in range(matches)], errors=errors)


WARN = {"level": "warn", "type": ["PartialParsing", [{"start": {"line": 9}, "end": {"line": 9}}]],
        "message": "partial"}


def test_allowlist_accepts_warn_partial_parsing_for_listed_case(monkeypatch):
    monkeypatch.setattr(dataset, "ACCEPTED_PARSE_WARNINGS", {"GHSA-x": "why"})
    assert dataset.fires(_run([WARN], 1), "GHSA-x") is True
    assert dataset.silent(_run([WARN], 0), "GHSA-x") is True
    assert dataset.fires(_run([dict(WARN, type="PartialParsing")], 1), "GHSA-x") is True


@pytest.mark.parametrize("err", [
    dict(WARN, level="error"),
    dict(WARN, type=["Syntax error", []]),
    dict(WARN, type="Timeout"),
    {"level": "warn"},
])
def test_must_not_allowlist_rejects_other_errors(monkeypatch, err):
    monkeypatch.setattr(dataset, "ACCEPTED_PARSE_WARNINGS", {"GHSA-x": "why"})
    assert dataset.fires(_run([err], 1), "GHSA-x") is False
    assert dataset.silent(_run([err], 0), "GHSA-x") is False


def test_must_not_allowlist_rejects_unlisted_case(monkeypatch):
    monkeypatch.setattr(dataset, "ACCEPTED_PARSE_WARNINGS", {"GHSA-x": "why"})
    assert dataset.fires(_run([WARN], 1), "GHSA-y") is False
    assert dataset.silent(_run([WARN], 0), "GHSA-y") is False


def test_default_allowlist_is_pw5q_only():
    assert set(dataset.ACCEPTED_PARSE_WARNINGS) == {"GHSA-pw5q-rjx4-7f7p"}


WARN_ID = "GHSA-warn-0000-0000"
WARN_RULE = "    pattern: io.Copy($W, $R.Body)\n"


def test_accepted_warning_builds_with_warnings_recorded(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(dataset, "ACCEPTED_PARSE_WARNINGS", {WARN_ID: "generic alias in func"})
    w = World(tmp_path, monkeypatch)
    w.add(WARN_ID, "go", WARN_RULE, "h.go", GO_WARN_VULN, GO_WARN_FIXED, MIT)
    out = tmp_path / "ds" / "v1"
    rc = build(w.sweep(), out, tmp_path / "cache")
    assert rc == 0, capsys.readouterr().out
    c = case_json(out, WARN_ID)
    assert c["semgrep_warnings"]
    assert all(x["type"] == "PartialParsing" and x["level"] == "warn" for x in c["semgrep_warnings"])
    assert {x["side"] for x in c["semgrep_warnings"]} == {"vuln", "fixed"}
    dataset.load_dataset(out)


def test_must_not_unlisted_warning_fails(tmp_path, monkeypatch, capsys):
    w = World(tmp_path, monkeypatch)
    w.add(WARN_ID, "go", WARN_RULE, "h.go", GO_WARN_VULN, GO_WARN_FIXED, MIT)
    out = tmp_path / "ds" / "v1"
    rc = build(w.sweep(), out, tmp_path / "cache")
    text = capsys.readouterr().out
    assert rc == 1
    (fail,) = [l for l in text.splitlines() if l.startswith(f"FAIL {WARN_ID}: ")]
    assert "vuln side: semgrep errors" in fail and "PartialParsing" in fail
    assert not out.exists()


# ------------------------------------------------------------ cache and shared commits

def test_cache_reuse_after_upstream_deleted(tmp_path, monkeypatch, capsys):
    w = World(tmp_path, monkeypatch)
    _good_js(w, JS_ID)
    sweep = w.sweep()
    out = tmp_path / "ds" / "v1"
    cache = tmp_path / "cache"
    assert build(sweep, out, cache) == 0
    shutil.rmtree(tmp_path / "upstream")
    assert build(sweep, out, cache, "--force") == 0
    assert capsys.readouterr().out.splitlines()[-1] == f"built 1 cases into {out}"
    dataset.load_dataset(out)


SHARED_A = "function render(el, s) {\n  el.innerHTML = s;\n}\n"
SHARED_B = "function render(el, s) {\n  el.textContent = s;\n  eval(s);\n}\n"
SHARED_C = "function render(el, s) {\n  el.textContent = s;\n}\n"


def test_shared_commits_build_twice(tmp_path, monkeypatch, capsys):
    url, a, b = make_upstream_repo(tmp_path, {"r.js": SHARED_A}, {"r.js": SHARED_B}, MIT,
                                   owner_repo="acme/shared")
    c = commit_files(Path(url[len("file://"):]), {"r.js": SHARED_C})
    w = World(tmp_path, monkeypatch)
    w.add("GHSA-1111-0000-0000", "javascript", "    pattern: $EL.innerHTML = $S\n", "r.js",
          None, None, None, owner_repo="acme/shared", refs=(url, a, b))
    w.add("GHSA-2222-0000-0000", "javascript", "    pattern: eval(...)\n", "r.js",
          None, None, None, owner_repo="acme/shared", refs=(url, b, c))
    sweep = w.sweep()
    out = tmp_path / "ds" / "v1"
    cache = tmp_path / "cache"
    assert build(sweep, out, cache) == 0, capsys.readouterr().out
    assert build(sweep, out, cache, "--force") == 0, capsys.readouterr().out


# ------------------------------------------------------------ failures

def _single_failure(tmp_path, monkeypatch, capsys, **add_kw):
    w = World(tmp_path, monkeypatch)
    args = dict(ghsa=JS_ID, language="javascript", rule_body=JS_RULE_BODY, sink_path="lib/render.js",
                vuln_src=JS_VULN, fixed_src=JS_FIXED, license_text=MIT)
    args.update(add_kw)
    w.add(**args)
    out = tmp_path / "ds" / "v1"
    rc = build(w.sweep(), out, tmp_path / "cache")
    text = capsys.readouterr().out
    assert rc == 1, text
    assert not out.exists()
    (fail,) = [l for l in text.splitlines() if l.startswith(f"FAIL {JS_ID}: ")]
    return fail


def test_must_not_first_parent_mismatch(tmp_path, monkeypatch, capsys):
    url, a, b = make_upstream_repo(tmp_path, {"lib/render.js": JS_VULN}, {"lib/render.js": JS_VULN + "\n"},
                                   MIT, owner_repo="acme/skip")
    c = commit_files(Path(url[len("file://"):]), {"lib/render.js": JS_FIXED})
    fail = _single_failure(tmp_path, monkeypatch, capsys, owner_repo="acme/skip", refs=(url, a, c))
    assert "vuln_ref is not the first parent of fixed_ref" in fail


def test_must_not_two_sink_paths(tmp_path, monkeypatch, capsys):
    fail = _single_failure(tmp_path, monkeypatch, capsys, sink_paths=["lib/render.js", "lib/other.js"])
    assert "sink" in fail


def test_must_not_no_license_file(tmp_path, monkeypatch, capsys):
    fail = _single_failure(tmp_path, monkeypatch, capsys, license_text=None)
    assert "license" in fail


def test_must_not_unsupported_language(tmp_path, monkeypatch, capsys):
    fail = _single_failure(tmp_path, monkeypatch, capsys, language="ruby",
                           rule_body="    pattern: eval(...)\n")
    assert "unsupported language" in fail and "ruby" in fail


def test_must_not_unknown_spdx_without_override(tmp_path, monkeypatch, capsys):
    fail = _single_failure(tmp_path, monkeypatch, capsys, spdx="NOASSERTION")
    assert "license" in fail


def test_spdx_override_applies_on_noassertion(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sources, "LICENSE_SPDX_OVERRIDES", {JS_ID: "BSD-2-Clause"})
    w = World(tmp_path, monkeypatch)
    w.add(JS_ID, "javascript", JS_RULE_BODY, "lib/render.js", JS_VULN, JS_FIXED, MIT, spdx=None)
    out = tmp_path / "ds" / "v1"
    assert build(w.sweep(), out, tmp_path / "cache") == 0, capsys.readouterr().out
    assert case_json(out, JS_ID)["license_spdx"] == "BSD-2-Clause"


def test_must_not_existing_out_without_force(tmp_path, monkeypatch, capsys):
    w = World(tmp_path, monkeypatch)
    _good_js(w, JS_ID)
    sweep = w.sweep()
    out = tmp_path / "ds" / "v1"
    out.mkdir(parents=True)
    (out / "keep.txt").write_text("mine")
    rc = build(sweep, out, tmp_path / "cache")
    err = capsys.readouterr().err
    assert rc == 2
    assert f"redpen: build-dataset failed: {out} exists; pass --force to overwrite" in err
    assert [p.name for p in out.iterdir()] == ["keep.txt"]
    assert (out / "keep.txt").read_text() == "mine"


def test_must_not_dirty_sweep_exits_before_network(tmp_path, monkeypatch, capsys):
    w = World(tmp_path, monkeypatch)
    _good_js(w, JS_ID)
    sweep = w.sweep()
    calls = patch_github(monkeypatch, w.advisories, w.licenses)
    fetched = []
    monkeypatch.setattr(sources, "ensure_commits", lambda *a, **k: fetched.append(a))
    (sweep / "rules" / "verified" / f"{JS_ID}.yaml").write_text("rules: []\n")
    out = tmp_path / "ds" / "v1"
    rc = build(sweep, out, tmp_path / "cache")
    assert rc == 2
    assert "uncommitted" in capsys.readouterr().err
    assert calls == [] and fetched == []
    assert not out.exists()


def test_must_not_bad_version_name(tmp_path, monkeypatch, capsys):
    w = World(tmp_path, monkeypatch)
    _good_js(w, JS_ID)
    rc = build(w.sweep(), tmp_path / "ds" / "latest", tmp_path / "cache")
    assert rc == 2
    assert "v[0-9]" in capsys.readouterr().err


def test_must_not_missing_sweep_dir(monkeypatch, capsys):
    monkeypatch.delenv("REDPEN_SWEEP_DIR", raising=False)
    assert cli.main(["build-dataset"]) == 2
    assert "redpen: build-dataset failed: --sweep-dir is required" in capsys.readouterr().err


def test_env_defaults_for_sweep_and_cache(tmp_path, monkeypatch):
    seen = {}

    def fake_build(sweep_dir, out, cache_dir, force=False):
        seen.update(sweep=sweep_dir, out=out, cache=cache_dir, force=force)
        return dataset.BuildReport(out=out, built=["x"])

    monkeypatch.setattr(dataset, "build_dataset", fake_build)
    monkeypatch.setenv("REDPEN_SWEEP_DIR", "/s")
    monkeypatch.setenv("REDPEN_CACHE_DIR", "/c")
    assert cli.main(["build-dataset"]) == 0
    assert seen == {"sweep": "/s", "out": Path("dataset/v1"), "cache": "/c", "force": False}
    monkeypatch.delenv("REDPEN_CACHE_DIR")
    cli.main(["build-dataset", "--force"])
    assert seen["cache"] == str(Path.home() / ".cache" / "redpen" / "repos") and seen["force"] is True
