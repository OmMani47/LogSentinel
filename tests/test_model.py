"""The saved detector agrees with the metrics file, including the misses."""

import json

import pandas as pd

from src.constants import DISCLAIMER, FEATURE_COLUMNS
from src.logs import load_log
from src.model import evaluate, load_bundle, score_frame
from src.paths import DATA_PATH, METRICS_PATH, MODEL_PATH


def _scored() -> pd.DataFrame:
    frame, _warnings = load_log(DATA_PATH)
    return score_frame(frame, load_bundle())


def _metrics() -> dict:
    return json.loads(METRICS_PATH.read_text(encoding="utf-8"))


def test_saved_artifacts_and_rescore_match_the_file():
    assert MODEL_PATH.exists()
    assert METRICS_PATH.exists()
    bundle = load_bundle()
    assert bundle["feature_columns"] == FEATURE_COLUMNS
    assert "label" not in bundle["feature_columns"]
    metrics = _metrics()
    assert metrics["disclaimer"] == DISCLAIMER
    assert metrics["seed"] == 42
    assert metrics["split"] == "time"
    scored = _scored()
    fresh = evaluate(scored, bundle)
    assert fresh["binary_test"] == metrics["binary_test"]
    assert fresh["per_attack_type"] == metrics["per_attack_type"]
    assert fresh["known_misses"] == metrics["known_misses"]
    assert metrics["logistic_per_attack_type"]["brute_force"]["f1"] == 0.0
    assert metrics["per_attack_type"]["stealth_takeover"]["f1"] == 0.0


def test_labels_do_not_change_alerts():
    frame, _warnings = load_log(DATA_PATH)
    full = score_frame(frame)
    stripped = frame.drop(columns=["label", "campaign_id", "scenario"])
    quiet = score_frame(stripped)
    assert full["alert"].tolist() == quiet["alert"].tolist()
    assert full["primary_reason"].tolist() == quiet["primary_reason"].tolist()


def test_loud_campaigns_alert_and_the_known_misses_do_not():
    scored = _scored()

    def campaign(name: str) -> pd.DataFrame:
        return scored[scored["campaign_id"] == name]

    for name in (
        "brute-test-1",
        "brute-test-2",
        "spray-test-1",
        "stuff-test-1",
        "stuff-dist-test-1",
        "travel-test-1",
        "geo-test-1",
        "offhours-test-1",
        "newdev-test-1",
        "success-test-1",
    ):
        group = campaign(name)
        assert not group.empty, name
        assert bool(group["rule_alert"].any()), name
        assert bool(group["alert"].any()), name

    slow = campaign("slow-brute-test-1")
    stealth = campaign("stealth-test-1")
    assert not slow.empty and not bool(slow["alert"].any())
    assert not stealth.empty and not bool(stealth["alert"].any())

    tiny = campaign("tiny-spray-test-1")
    assert not bool(tiny["rule_alert"].any())
    assert bool(tiny["alert"].all())
    assert set(tiny["primary_reason"]) == {"untyped_anomaly"}


def test_life_events_are_the_false_positives_the_readme_names():
    scored = _scored()
    laptop = scored[scored["campaign_id"] == "fp-laptop-test-1"].iloc[0]
    assert laptop["label"] == "benign"
    assert laptop["primary_reason"] == "new_device"
    oncall = scored[scored["campaign_id"] == "fp-oncall-test-1"].iloc[0]
    assert oncall["label"] == "benign"
    assert oncall["primary_reason"] == "off_hours"
    annex = scored[scored["campaign_id"] == "fp-annex-test-1"].iloc[0]
    assert annex["primary_reason"] == "unusual_geography"
    assert annex["lr_label"] == "benign"
    travel = scored[scored["campaign_id"] == "fp-travel-test-1"].iloc[0]
    assert travel["primary_reason"] == "unusual_geography"
    assert travel["lr_label"] == "benign"


def test_alert_reasons_name_a_signal():
    scored = _scored()
    brute = scored[(scored["campaign_id"] == "brute-test-1") & scored["rule_alert"]].iloc[0]
    assert brute["reasons"]
    assert "failed" in brute["reasons"][0]["text"]
    assert brute["top_features"]
    assert brute["model_note"]
    assert brute["lr_label"]
