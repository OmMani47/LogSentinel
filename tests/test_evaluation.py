"""The README has to say what 0.904 is, and what it is not."""

from pathlib import Path

import json

from src.constants import DISCLAIMER
from src.model import split_of
from src.logs import parse_timestamp
from src.paths import METRICS_PATH, ROOT


def _metrics() -> dict:
    return json.loads(METRICS_PATH.read_text(encoding="utf-8"))


def _evaluation_section() -> str:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    pieces = readme.split("## Evaluation", 1)
    assert len(pieces) == 2, "README needs a dedicated Evaluation section"
    return pieces[1].split("\n## ", 1)[0]


def test_metrics_and_readme_share_the_disclaimer_and_the_headline():
    metrics = _metrics()
    section = _evaluation_section()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert metrics["disclaimer"] == DISCLAIMER
    assert DISCLAIMER in readme
    binary = metrics["binary_test"]
    assert f"{binary['f1']:.3f}" in section
    assert f"{binary['precision']:.3f}" in section
    assert f"{binary['recall']:.3f}" in section
    assert "0.904" in section
    assert "synthetic" in section.lower()
    assert "not an estimate of accuracy on real authentication logs" in section
    assert "not the number to quote" in section
    assert "seed" in section.lower() and "42" in section
    assert "2026-01-13" in section and "2026-01-15" in section
    for miss in metrics["known_misses"]:
        assert miss["campaign_id"] in section
    assert "tiny-spray-test-1" in section
    assert "0.000" in section
    assert metrics["logistic_per_attack_type"]["brute_force"]["f1"] == 0.0
    assert "brute_force" in section


def test_time_split_bounds_match_the_metrics_file():
    metrics = _metrics()
    assert split_of(parse_timestamp("2026-01-12T23:59:59Z")) == "fit"
    assert split_of(parse_timestamp("2026-01-13T00:00:00Z")) == "validation"
    assert split_of(parse_timestamp("2026-01-14T23:00:00Z")) == "validation"
    assert split_of(parse_timestamp("2026-01-15T00:00:00Z")) == "test"
    assert metrics["fit_rows"] + metrics["validation_rows"] + metrics["test_rows"] == metrics["rows"]
    assert metrics["campaigns_detected"] == 18
    assert metrics["campaigns_total"] == 20
    assert {row["campaign_id"] for row in metrics["known_misses"]} == {
        "slow-brute-test-1",
        "stealth-test-1",
    }


def test_workflow_runs_pytest_on_python_312_for_push_and_pull_request():
    workflow = Path(".github/workflows/tests.yml").read_text(encoding="utf-8")
    assert "push:" in workflow
    assert "pull_request:" in workflow
    assert 'python-version: "3.12"' in workflow
    assert "python -m pytest" in workflow
