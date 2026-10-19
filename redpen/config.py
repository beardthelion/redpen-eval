"""Load and validate reviewers.yaml."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

CHANGE_ME = "CHANGE-ME"

OPENAI_KEYS = {"adapter", "base_url", "model", "api_key_env", "temperature", "max_tokens",
               "max_tokens_param", "seed", "timeout_s", "max_retries", "retry_backoff_s"}
OPENAI_REQUIRED = ("base_url", "model", "api_key_env")
MOCK_REVIEWER_KEYS = {"adapter", "vuln", "fixed", "overrides"}
MOCK_JUDGE_KEYS = {"adapter", "malformed_cases", "repair_cases"}
VULN_MODES = {"hit", "partial", "miss", "empty", "error"}
FIXED_MODES = {"clean", "fp", "empty", "error"}
STRUCTURED_OUTPUT = {"json_schema", "json_object", "prompt"}
MAX_TOKENS_PARAMS = {"max_tokens", "max_completion_tokens"}
TOP_KEYS = {"default_judge", "reviewers", "judges"}


class ConfigError(Exception):
    pass


@dataclass
class Config:
    reviewers: dict
    judges: dict
    default_judge: str


def _reject_inline_keys(obj, where: str) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "api_key":
                raise ConfigError(f"{where}: inline keys are not allowed; use api_key_env")
            _reject_inline_keys(v, f"{where}.{k}")
    elif isinstance(obj, list):
        for v in obj:
            _reject_inline_keys(v, where)


def _check_keys(entry: dict, allowed: set, where: str) -> None:
    unknown = sorted(set(entry) - allowed)
    if unknown:
        raise ConfigError(f"{where}: unknown key {unknown[0]!r}")


def _check_mode(value, allowed: set, where: str) -> None:
    if value not in allowed:
        raise ConfigError(f"{where}: {value!r} is not one of {sorted(allowed)}")


def _check_openai(entry: dict, allowed: set, where: str) -> None:
    _check_keys(entry, allowed, where)
    for key in OPENAI_REQUIRED:
        if not entry.get(key):
            raise ConfigError(f"{where}: openai_compat requires {key!r}")
    if "max_tokens_param" in entry:
        _check_mode(entry["max_tokens_param"], MAX_TOKENS_PARAMS, f"{where}.max_tokens_param")
    if "structured_output" in entry:
        _check_mode(entry["structured_output"], STRUCTURED_OUTPUT, f"{where}.structured_output")


def _check_reviewer(name: str, entry: dict) -> None:
    where = f"reviewers.{name}"
    adapter = entry.get("adapter")
    if adapter == "mock":
        _check_keys(entry, MOCK_REVIEWER_KEYS, where)
        _check_mode(entry.get("vuln", "hit"), VULN_MODES, f"{where}.vuln")
        _check_mode(entry.get("fixed", "clean"), FIXED_MODES, f"{where}.fixed")
        overrides = entry.get("overrides") or {}
        if not isinstance(overrides, dict):
            raise ConfigError(f"{where}.overrides must be a mapping")
        for cid, o in overrides.items():
            w = f"{where}.overrides.{cid}"
            if not isinstance(o, dict):
                raise ConfigError(f"{w} must be a mapping")
            _check_keys(o, {"vuln", "fixed"}, w)
            if "vuln" in o:
                _check_mode(o["vuln"], VULN_MODES, f"{w}.vuln")
            if "fixed" in o:
                _check_mode(o["fixed"], FIXED_MODES, f"{w}.fixed")
    elif adapter == "openai_compat":
        _check_openai(entry, OPENAI_KEYS, where)
    else:
        raise ConfigError(f"{where}: unknown adapter {adapter!r}")


def _check_judge(name: str, entry: dict) -> None:
    where = f"judges.{name}"
    adapter = entry.get("adapter")
    if adapter == "mock":
        _check_keys(entry, MOCK_JUDGE_KEYS, where)
        for key in ("malformed_cases", "repair_cases"):
            if not isinstance(entry.get(key, []), list):
                raise ConfigError(f"{where}.{key} must be a list")
    elif adapter == "openai_compat":
        _check_openai(entry, OPENAI_KEYS | {"structured_output"}, where)
    else:
        raise ConfigError(f"{where}: unknown adapter {adapter!r}")


def _section(raw: dict, key: str) -> dict:
    section = raw.get(key) or {}
    if not isinstance(section, dict):
        raise ConfigError(f"{key} must be a mapping")
    for name, entry in section.items():
        if not isinstance(entry, dict):
            raise ConfigError(f"{key}.{name} must be a mapping")
    return section


def load_config(path) -> Config:
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError) as e:
        raise ConfigError(f"cannot read {path}: {e}") from e
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    _reject_inline_keys(raw, path.name)
    _check_keys(raw, TOP_KEYS, path.name)
    reviewers = _section(raw, "reviewers")
    judges = _section(raw, "judges")
    for name, entry in reviewers.items():
        _check_reviewer(name, entry)
    for name, entry in judges.items():
        _check_judge(name, entry)
    default_judge = raw.get("default_judge")
    if default_judge not in judges:
        raise ConfigError(f"default_judge {default_judge!r} is not a configured judge")
    return Config(reviewers=reviewers, judges=judges, default_judge=default_judge)


def require_configured(kind: str, name: str, entry: dict) -> None:
    """Refuse an entry that still holds a CHANGE-ME placeholder."""
    if any(v == CHANGE_ME for v in entry.values()):
        raise ConfigError(f"{kind} '{name}' is not configured ({CHANGE_ME})")
