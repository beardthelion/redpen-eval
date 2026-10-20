import json
import re

from test_report import IV, PT1, PT2, config, env, load, save, table_rows  # noqa: F401 (env is a fixture)

XSS = "<script>alert(1)</script>"
IMG = "<img src=x onerror=alert(1)>"


def html_report(env, tmp_path, *extra) -> str:
    out = tmp_path / "board.html"
    assert env.report("--html", str(out), *extra) == 0
    return out.read_text()


def poison(rd, case_id: str) -> None:
    path = rd / "cases" / f"{case_id}.json"
    rec = load(path)
    rec["vuln"]["review_text"] = XSS
    rec["vuln"]["judge"]["parsed"]["rationale"] = IMG
    rec["fixed"]["review_text"] = "if a < b && c > d { \"x\" }"
    save(path, rec)


# ------------------------------------------------------------ escaping

def test_must_not_review_text_is_escaped_and_no_script_tag(env, tmp_path):
    rd = env.run("mock")
    poison(rd, IV)
    page = html_report(env, tmp_path)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "<script" not in page.lower()
    assert "<img" not in page.lower()
    assert "&lt;img src=x onerror=alert(1)&gt;" in page
    assert "if a &lt; b &amp;&amp; c &gt; d { &quot;x&quot; }" in page


def test_must_not_reviewer_name_is_escaped(env, tmp_path):
    env.set_config(config({'r"<b>': {}}))
    env.run('r"<b>')
    page = html_report(env, tmp_path)
    assert "r&quot;&lt;b&gt;" in page
    assert "<b>" not in page


# ------------------------------------------------------------ no external resources

def test_must_not_external_urls_other_than_repo_url_text(env, tmp_path):
    env.set_config(config({"r1": {}, "r2": {"overrides": {IV: {"vuln": "error"}}}}))
    env.run("r1")
    env.run("r2")
    page = html_report(env, tmp_path)
    repo_urls = {json.loads((env.ds / "cases" / c / "case.json").read_text())["repo_url"]
                 for c in (PT1, PT2, IV)}
    found = re.findall(r"https?://[^\s\"'<>]*", page)
    assert found, "repo_url text values should appear in the drill-down"
    assert set(found) <= repo_urls
    lowered = page.lower()
    for marker in ("src=", "href=", "url(", "@import", "<link", "<iframe", "<object"):
        assert marker not in lowered, marker


def test_single_file_shape(env, tmp_path):
    env.run("mock")
    page = html_report(env, tmp_path)
    assert page.lower().startswith("<!doctype html>")
    assert "<style>" in page
    assert "prefers-color-scheme: dark" in page
    assert "<script" not in page.lower()


# ------------------------------------------------------------ content matches terminal

def test_names_and_pair_scores_match_terminal(env, tmp_path, capsys):
    env.set_config(config({
        "perfect": {},
        "mixed": {"overrides": {PT2: {"vuln": "partial"}, IV: {"fixed": "fp"}}},
    }))
    env.run("mixed")
    env.run("perfect")
    page = html_report(env, tmp_path)
    rows = table_rows(capsys.readouterr().out)
    assert set(rows) == {"perfect", "mixed"}
    for name, cells in rows.items():
        assert f">{name}<" in page
        for value in cells[3:6]:
            assert f">{value}<" in page, value
    # ranked order is the same as the terminal
    assert page.index(">perfect<") < page.index(">mixed<")
    # per-class table
    assert ">path-traversal<" in page and ">1/2<" in page and ">2/2<" in page


def test_header_line(env, tmp_path):
    rd = env.run("mock")
    meta = load(rd / "meta.json")
    page = html_report(env, tmp_path)
    for text in ("v1", "3 cases", meta["prompts"]["review_version"],
                 meta["prompts"]["judge_version"], meta["scoring"]["formula"]):
        assert text in page, text


def test_drill_down_per_case(env, tmp_path):
    env.set_config(config({"r1": {}, "r2": {}}))
    env.run("r1")
    rd = env.run("r2")
    poison(rd, PT1)
    page = html_report(env, tmp_path)
    assert page.count("<details") == 6
    for cid in (PT1, PT2, IV):
        assert cid in page
    assert "untrusted path reaches readFile" in page
    assert "11-11" in page and "10-10" in page
    assert "<pre>&lt;script&gt;" in page
    assert "HIT" in page
    assert "&quot;verdict_class_match&quot;: true" in page
    assert "pair credit" in page


# ------------------------------------------------------------ error sides

def test_reviewer_error_side_shows_kind(env, tmp_path):
    env.set_config(config({"flaky": {"overrides": {IV: {"vuln": "error"}}}}))
    env.run("flaky")
    page = html_report(env, tmp_path)
    block = page[page.index(f"<summary>{IV}"):]
    block = block[:block.index("</details>")]
    assert "reviewer_error" in block
    assert "http_error" in block
    assert "mock error" in block


def test_judge_error_side_shows_kind(env, tmp_path):
    cfg = config({"mock": {}})
    cfg["judges"]["mock"]["malformed_cases"] = [IV]
    env.set_config(cfg)
    env.run("mock")
    page = html_report(env, tmp_path)
    block = page[page.index(f"<summary>{IV}"):]
    block = block[:block.index("</details>")]
    assert block.count("judge_error") >= 2
    assert "invalid output" in block


def test_terminal_output_unchanged_and_path_printed(env, tmp_path, capsys):
    env.run("mock")
    capsys.readouterr()
    assert env.report() == 0
    plain = capsys.readouterr().out
    html_report(env, tmp_path)
    with_html = capsys.readouterr().out
    assert with_html.startswith(plain)
    assert f"html: {tmp_path / 'board.html'}" in with_html

