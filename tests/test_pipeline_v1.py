import json
from pathlib import Path

import pytest

from redpen.cli import main

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset" / "v1"
CONFIG = ROOT / "reviewers.yaml"

pytestmark = pytest.mark.skipif(not (DATASET / "manifest.json").exists(),
                                reason="dataset/v1 not built")


def test_mock_pipeline_over_v1(tmp_path, capsys):
    from redpen.dataset import load_dataset
    from redpen.report import load_run, run_metrics

    results = tmp_path / "results"
    assert main(["run", "--reviewer", "mock", "--judge", "mock", "--cases", "all",
                 "--dataset", str(DATASET), "--config", str(CONFIG),
                 "--results-dir", str(results)]) == 0
    assert main(["report", "--results-dir", str(results), "--dataset", str(DATASET)]) == 0
    out = capsys.readouterr().out

    (rd,) = [p for p in results.iterdir() if p.is_dir()]
    manifest = json.loads((DATASET / "manifest.json").read_text())
    assert manifest["case_count"] == 25
    records = [json.loads(p.read_text()) for p in (rd / "cases").glob("*.json")]
    assert len(records) == 25
    assert all(r[s]["status"] == "scored" for r in records for s in ("vuln", "fixed"))

    classes = sorted({c["guard_class"] for c in manifest["cases"]})
    m = run_metrics(load_run(rd), classes)
    assert (m["recall"]["k"], m["recall"]["n"]) == (25, 25)
    assert (m["fp"]["k"], m["fp"]["n"]) == (0, 25)
    assert m["pair"]["score"] == 1.0 and m["pair"]["n"] == 25

    assert "1.00 [1.00, 1.00] (25)" in out
    assert "100.0% [" in out and "(25)" in out
    assert "0.0% [0.0%, " in out
    for cls in classes:
        assert cls in out
    assert load_dataset(DATASET).manifest["case_set_sha256"] == manifest["case_set_sha256"]
