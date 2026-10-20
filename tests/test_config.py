from pathlib import Path

import pytest

from redpen.config import ConfigError, load_config
from redpen.reviewers import make_reviewer
from redpen.reviewers.mock import MockReviewer

REPO = Path(__file__).resolve().parent.parent

VALID = """\
default_judge: mock
reviewers:
  mock:
    adapter: mock
    vuln: hit
    fixed: clean
    overrides: {}
  real:
    adapter: openai_compat
    base_url: http://localhost:8000/v1
    model: some-model
    api_key_env: REDPEN_REAL_KEY
    temperature: 0
    max_tokens: 2048
judges:
  mock:
    adapter: mock
    malformed_cases: []
    repair_cases: []
  llm:
    adapter: openai_compat
    base_url: http://localhost:8000/v1
    model: judge-model
    api_key_env: REDPEN_JUDGE_KEY
    structured_output: json_schema
"""


def write(tmp_path, text):
    p = tmp_path / "reviewers.yaml"
    p.write_text(text)
    return p


def test_repo_reviewers_yaml_loads():
    cfg = load_config(REPO / "reviewers.yaml")
    assert set(cfg.reviewers) == {"mock", "reviewer-a", "reviewer-b"}
    assert set(cfg.judges) == {"mock", "llm"}
    assert cfg.default_judge == "mock"
    for entry in (cfg.reviewers["reviewer-a"], cfg.reviewers["reviewer-b"], cfg.judges["llm"]):
        assert entry["base_url"] == "https://api.aimlapi.com/v1"
        assert entry["api_key_env"] == "AIMLAPI_API_KEY"
        assert entry.get("seed", 1) >= 1  # aimlapi rejects seed 0


def test_valid_file_loads(tmp_path):
    cfg = load_config(write(tmp_path, VALID))
    assert cfg.reviewers["real"]["model"] == "some-model"
    assert cfg.judges["llm"]["structured_output"] == "json_schema"


@pytest.mark.parametrize("old,new,key", [
    ("default_judge: mock\n", "default_judge: mock\nextra_top: 1\n", "extra_top"),
    ("    fixed: clean\n", "    fixed: clean\n    colour: red\n", "colour"),
    ("    model: some-model\n", "    model: some-model\n    modle: x\n", "modle"),
    ("    repair_cases: []\n", "    repair_cases: []\n    flaky: true\n", "flaky"),
    ("    overrides: {}\n", "    overrides: {GHSA-x: {vuln: hit, side: x}}\n", "side"),
])
def test_must_not_unknown_key_loads(tmp_path, old, new, key):
    with pytest.raises(ConfigError, match=key):
        load_config(write(tmp_path, VALID.replace(old, new)))


@pytest.mark.parametrize("old,new", [
    ("    api_key_env: REDPEN_REAL_KEY\n", "    api_key_env: REDPEN_REAL_KEY\n    api_key: sk-secret\n"),
    ("    api_key_env: REDPEN_REAL_KEY\n", "    api_key: sk-secret\n"),
    ("    api_key_env: REDPEN_JUDGE_KEY\n", "    api_key_env: REDPEN_JUDGE_KEY\n    api_key: sk-secret\n"),
    ("    adapter: mock\n    vuln: hit\n", "    adapter: mock\n    api_key: sk-secret\n    vuln: hit\n"),
])
def test_must_not_inline_api_key(tmp_path, old, new):
    with pytest.raises(ConfigError, match="inline keys are not allowed; use api_key_env") as e:
        load_config(write(tmp_path, VALID.replace(old, new, 1)))
    assert "sk-secret" not in str(e.value)


@pytest.mark.parametrize("key", ["model", "base_url", "api_key_env"])
def test_must_not_openai_compat_missing_required(tmp_path, key):
    lines = [ln for ln in VALID.splitlines(keepends=True)
             if not (ln.startswith(f"    {key}:") and ("some-model" in ln or "REAL" in ln or "8000" in ln))]
    text = "".join(lines)
    # drops the key from reviewer "real" (for base_url, from judge "llm" too)
    with pytest.raises(ConfigError, match=key):
        load_config(write(tmp_path, text))


@pytest.mark.parametrize("old,new,match", [
    ("    adapter: mock\n    vuln: hit\n", "    adapter: magic\n    vuln: hit\n", "magic"),
    ("    vuln: hit\n", "    vuln: clean\n", "vuln"),
    ("    fixed: clean\n", "    fixed: hit\n", "fixed"),
    ("default_judge: mock\n", "default_judge: nobody\n", "nobody"),
    ("    structured_output: json_schema\n", "    structured_output: xml\n", "structured_output"),
    ("    max_tokens: 2048\n", "    max_tokens: 2048\n    stream: yes please\n", "stream"),
])
def test_must_not_invalid_values(tmp_path, old, new, match):
    with pytest.raises(ConfigError, match=match):
        load_config(write(tmp_path, VALID.replace(old, new, 1)))


def test_stream_flag_loads(tmp_path):
    cfg = load_config(write(tmp_path, VALID.replace("    max_tokens: 2048\n", "    max_tokens: 2048\n    stream: true\n", 1)))
    assert cfg.reviewers["real"]["stream"] is True


def test_must_not_missing_file(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.yaml")


def test_change_me_loads_but_make_reviewer_refuses(tmp_path):
    text = (REPO / "reviewers.yaml").read_text().replace("https://api.aimlapi.com/v1", "CHANGE-ME")
    cfg = load_config(write(tmp_path, text))
    with pytest.raises(ConfigError, match=r"reviewer 'reviewer-a' is not configured \(CHANGE-ME\)"):
        make_reviewer("reviewer-a", cfg)


def test_make_reviewer_mock_and_unknown(tmp_path):
    cfg = load_config(write(tmp_path, VALID))
    assert isinstance(make_reviewer("mock", cfg), MockReviewer)
    with pytest.raises(ConfigError, match="ghost"):
        make_reviewer("ghost", cfg)
