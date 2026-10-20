import hashlib

import pytest

from conftest import DEFAULT_LICENSE_TEXT, make_dataset
from redpen import prompts
from redpen.dataset import load_dataset
from redpen.window import Span, render_numbered

CID = "GHSA-q1w2-e3r4-t5y6"
AGPL_ID = "GHSA-z9x8-c7v6-b5n4"


@pytest.fixture
def ds(tmp_path):
    root = make_dataset(tmp_path, [
        {"case_id": CID},
        {"case_id": AGPL_ID, "license_spdx": "AGPL-3.0-only", "cve": "CVE-2026-9999",
         "description": "archive entry name escapes the target directory",
         "owner_repo": "zorbcorp/quuxserver"},
    ])
    return {c.case_id: c for c in load_dataset(root).cases}


def test_prompt_contains_numbered_code_and_basename(ds):
    case = ds[CID]
    text = prompts.render_review_prompt(case, "vuln")
    numbered = render_numbered(case.vuln_text, case.data["vuln"]["header_lines"], [Span(1, 1), Span(9, 13)])
    assert numbered in text
    assert "    11  \tdata := readFile(path)\n" in text
    assert "... (lines 2-8 omitted)" in text
    assert "File: handler.go\n" in text
    assert "Language: go\n" in text
    assert text.startswith("Review this code for security vulnerabilities.")
    assert "cite those numbers" in text


def test_fixed_prompt_uses_fixed_window(ds):
    text = prompts.render_review_prompt(ds[CID], "fixed")
    assert '    11  \tif strings.Contains(path, "..") { return }\n' in text
    assert "    14  }\n" in text
    assert "omitted" not in text


@pytest.mark.parametrize("cid", [CID, AGPL_ID])
@pytest.mark.parametrize("side", ["vuln", "fixed"])
def test_must_not_prompt_leaks_ground_truth(ds, cid, side):
    case = ds[cid]
    text = prompts.render_review_prompt(case, side)
    d = case.data
    owner, name = d["repo_url"].rsplit("/", 2)[-2:]
    forbidden = [
        cid, cid.lower(), d["cve"], d["vuln_description"], owner, name, d["repo_url"],
        "Excerpted", "Source:", "License:", "Ref:", d["copyright_notice"], d["license_dir"],
        "Affero", DEFAULT_LICENSE_TEXT.splitlines()[0], "Permission is hereby granted",
        d["vuln_ref"], d["fixed_ref"], d["sink_path"], case.rule_text.splitlines()[1].strip(),
        d["guard_class"],
    ]
    for s in forbidden:
        assert s not in text, f"prompt leaks {s!r}"


def test_prompt_version_and_hash_are_stable(ds):
    assert prompts.REVIEW_PROMPT_VERSION == "review-v1"
    h = prompts.prompt_sha256(prompts.REVIEW_PROMPT)
    assert h == prompts.prompt_sha256(prompts.REVIEW_PROMPT)
    assert h == hashlib.sha256(prompts.REVIEW_PROMPT.encode("utf-8")).hexdigest()
    a = prompts.render_review_prompt(ds[CID], "vuln")
    b = prompts.render_review_prompt(ds[CID], "vuln")
    assert a == b


def test_numbered_window_matches_render_numbered(ds):
    case = ds[CID]
    expected = render_numbered(case.vuln_text, case.data["vuln"]["header_lines"],
                               [Span(1, 1), Span(9, 13)])
    assert prompts.numbered_window(case, "vuln") == expected


def test_judge_version_and_schemas():
    assert prompts.JUDGE_PROMPT_VERSION == "judge-v1"
    assert set(prompts.JUDGE_VULN_SCHEMA["properties"]) == {
        "verdict_class_match", "cited_ranges", "rationale"}
    assert set(prompts.JUDGE_FIXED_SCHEMA["properties"]) == {
        "reported_patched_vuln", "cited_ranges", "rationale"}
    for schema in (prompts.JUDGE_VULN_SCHEMA, prompts.JUDGE_FIXED_SCHEMA):
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == set(schema["properties"])


@pytest.mark.parametrize("name", ["JUDGE_VULN_PROMPT", "JUDGE_FIXED_PROMPT", "JUDGE_REPAIR_PROMPT"])
def test_judge_sha256_covers_each_template(monkeypatch, name):
    before = prompts.judge_prompt_sha256()
    monkeypatch.setattr(prompts, name, getattr(prompts, name) + " ")
    assert prompts.judge_prompt_sha256() != before


@pytest.mark.parametrize("name", ["JUDGE_VULN_SCHEMA", "JUDGE_FIXED_SCHEMA"])
def test_judge_sha256_covers_each_schema(monkeypatch, name):
    before = prompts.judge_prompt_sha256()
    monkeypatch.setattr(prompts, name, dict(getattr(prompts, name), title="changed"))
    assert prompts.judge_prompt_sha256() != before


@pytest.mark.parametrize("name", ["JUDGE_VULN_PROMPT", "JUDGE_FIXED_PROMPT"])
def test_judge_templates_carry_nonce_delimiters(name):
    text = getattr(prompts, name)
    for tag in ("<code-{nonce}>", "</code-{nonce}>", "<review-{nonce}>", "</review-{nonce}>"):
        assert tag in text
    assert "{guard_class}" in text and "{vuln_description}" in text
