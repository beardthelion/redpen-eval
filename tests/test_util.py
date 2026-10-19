import json
import os
import socket
import sys

import pytest

from redpen import util


def test_atomic_write_json_creates_file_without_temp(tmp_path):
    target = tmp_path / "out.json"
    util.atomic_write_json(target, {"a": 1, "b": [1, 2]})
    assert json.loads(target.read_text()) == {"a": 1, "b": [1, 2]}
    assert sorted(p.name for p in tmp_path.iterdir()) == ["out.json"]


def test_atomic_write_json_replaces_existing(tmp_path):
    target = tmp_path / "out.json"
    target.write_text("old")
    util.atomic_write_json(target, {"new": True})
    assert json.loads(target.read_text()) == {"new": True}
    assert sorted(p.name for p in tmp_path.iterdir()) == ["out.json"]


def test_atomic_write_json_unserializable_leaves_target_untouched(tmp_path):
    target = tmp_path / "out.json"
    target.write_bytes(b"original bytes")
    with pytest.raises(TypeError):
        util.atomic_write_json(target, {"x": object()})
    assert target.read_bytes() == b"original bytes"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["out.json"]


def test_atomic_write_bytes_failed_replace_removes_temp(tmp_path, monkeypatch):
    target = tmp_path / "out.bin"
    target.write_bytes(b"original")

    def boom(src, dst):
        raise OSError("replace failed")

    monkeypatch.setattr(util.os, "replace", boom)
    with pytest.raises(OSError):
        util.atomic_write_bytes(target, b"new")
    assert target.read_bytes() == b"original"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["out.bin"]


def test_atomic_write_text_roundtrip(tmp_path):
    target = tmp_path / "t.txt"
    util.atomic_write_text(target, "hello\n")
    assert target.read_text() == "hello\n"


def test_sha256_bytes_known_vector():
    assert (
        util.sha256_bytes(b"abc")
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_sha256_file_matches_bytes(tmp_path):
    p = tmp_path / "f"
    p.write_bytes(b"abc")
    assert util.sha256_file(p) == util.sha256_bytes(b"abc")


def test_canonical_json_sorted_compact():
    assert util.canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_utc_stamp_format():
    s = util.utc_stamp()
    assert len(s) == 16 and s[8] == "T" and s.endswith("Z")
    assert s[:8].isdigit() and s[9:15].isdigit()


def test_utc_now_iso_is_utc():
    s = util.utc_now_iso()
    assert s.endswith("Z") or s.endswith("+00:00")


def test_semgrep_bin_prefers_venv_copy(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "semgrep"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(bindir / "python"))
    monkeypatch.setenv("PATH", "")
    assert util.semgrep_bin() == str(fake)


def test_semgrep_bin_falls_back_to_path(tmp_path, monkeypatch):
    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    path_bin = tmp_path / "pathbin"
    path_bin.mkdir()
    on_path = path_bin / "semgrep"
    on_path.write_text("#!/bin/sh\n")
    on_path.chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(venv_bin / "python"))
    monkeypatch.setenv("PATH", str(path_bin))
    assert util.semgrep_bin() == str(on_path)


def test_network_is_blocked():
    with pytest.raises(RuntimeError):
        socket.create_connection(("example.com", 80))
