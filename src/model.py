"""Fit the anomaly model and the supervised baseline, then score a log.

The operating detector is the rule set plus Isolation Forest. Logistic
regression is a labelled baseline. It does not decide alerts. Labels are used
to fit and to evaluate. They are not features.
"""

from __future__ import annotations

import json
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_fscore_support
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from src.constants import (
    ATTACK_TYPES,
    BRUTE_FAILS_15M,
    DISCLAIMER,
    FEATURE_COLUMNS,
    FIT_END,
    RULE_TO_LABEL,
    SEED,
    SPRAY_USERS_15M,
    SUCCESS_AFTER_FAILS,
    TRAVEL_SPEED_KMH,
    VAL_END,
)
from src.explain import logistic_contributions, model_note, reason_payload, top_features
from src.features import engineer
from src.logs import parse_timestamp
from src.paths import METRICS_PATH, MODEL_PATH


def split_of(value: datetime | str) -> str:
    stamp = parse_timestamp(value)
    if stamp < FIT_END:
        return "fit"
    if stamp < VAL_END:
        return "validation"
    return "test"


def load_bundle(path=MODEL_PATH) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"No detector at {path}. Run python -m src.train")
    return joblib.load(path)


def fit_bundle(featured: pd.DataFrame) -> dict:
    """Fit on the opening window only. The validation slice picks the forest threshold."""
    working = featured.copy()
    working["split"] = working["timestamp"].map(split_of)
    fit_rows = working[working["split"] == "fit"]
    val_rows = working[working["split"] == "validation"]
    if fit_rows.empty or val_rows.empty:
        raise ValueError("The log does not cover both the fit window and the validation window.")
    benign = fit_rows[fit_rows["label"] == "benign"]
    if benign.empty:
        raise ValueError("The fit window has no benign events to train Isolation Forest.")

    forest = IsolationForest(
        n_estimators=200,
        random_state=SEED,
        n_jobs=1,
        contamination="auto",
    )
    forest.fit(_matrix(benign))

    logistic = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "clf",
                LogisticRegression(
                    solver="lbfgs",
                    max_iter=2000,
                    class_weight="balanced",
                    random_state=SEED,
                ),
            ),
        ]
    )
    logistic.fit(_matrix(fit_rows), fit_rows["label"].astype(str))

    medians = {name: float(np.median(benign[name])) for name in FEATURE_COLUMNS}
    mads = {
        name: float(np.median(np.abs(benign[name].to_numpy(dtype=float) - medians[name])))
        for name in FEATURE_COLUMNS
    }
    threshold, val_summary = _choose_threshold(forest, val_rows)
    return {
        "forest": forest,
        "logistic": logistic,
        "medians": medians,
        "mads": mads,
        "if_threshold": float(threshold),
        "feature_columns": list(FEATURE_COLUMNS),
        "validation": val_summary,
    }


def score_frame(frame: pd.DataFrame, bundle: dict | None = None) -> pd.DataFrame:
    """Score a log. Label and campaign columns are ignored as inputs."""
    bundle = bundle or load_bundle()
    featured = engineer(frame)
    return _apply(featured, bundle)


def evaluate(scored: pd.DataFrame, bundle: dict) -> dict:
    """Metrics for the test window. This is the number the README has to quote."""
    working = scored.copy()
    if "split" not in working.columns:
        working["split"] = working["timestamp"].map(split_of)
    test = working[working["split"] == "test"].copy()
    fit_count = int((working["split"] == "fit").sum())
    val_count = int((working["split"] == "validation").sum())
    y_attack = test["label"].ne("benign").to_numpy()

    def binary(mask: np.ndarray) -> dict:
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_attack, mask, average="binary", zero_division=0
        )
        pred = mask.astype(bool)
        return {
            "precision": _round(precision),
            "recall": _round(recall),
            "f1": _round(f1),
            "true_positives": int((y_attack & pred).sum()),
            "false_positives": int((~y_attack & pred).sum()),
            "false_negatives": int((y_attack & ~pred).sum()),
            "true_negatives": int((~y_attack & ~pred).sum()),
            "support_attack": int(y_attack.sum()),
            "support_benign": int((~y_attack).sum()),
        }

    test["predicted_label"] = test.apply(_predicted_label, axis=1)
    per_type = {}
    for attack in ATTACK_TYPES:
        truth = test["label"].eq(attack).to_numpy()
        named = test["predicted_label"].eq(attack).to_numpy()
        precision, recall, f1, _ = precision_recall_fscore_support(
            truth, named, average="binary", zero_division=0
        )
        support = int(truth.sum())
        per_type[attack] = {
            "precision": _round(precision),
            "recall": _round(recall),
            "f1": _round(f1),
            "support": support,
            "any_alert_recall": _round(float(test.loc[truth, "alert"].mean()) if support else 0.0),
        }

    campaigns = []
    attack_rows = test[test["label"].ne("benign") & test["campaign_id"].astype(str).ne("")]
    for campaign_id, group in attack_rows.groupby("campaign_id", sort=True):
        campaigns.append(
            {
                "campaign_id": str(campaign_id),
                "attack_type": str(group["label"].iloc[0]),
                "events": int(len(group)),
                "alerts": int(group["alert"].sum()),
                "rule_alerts": int(group["rule_alert"].sum()),
                "detected": bool(group["alert"].any()),
                "detected_by_rule": bool(group["rule_alert"].any()),
            }
        )
    detected = sum(1 for row in campaigns if row["detected"])
    misses = [row for row in campaigns if not row["detected"]]
    rule_misses = [row for row in campaigns if not row["detected_by_rule"]]

    false_positives = []
    benign_alerts = test[test["label"].eq("benign") & test["alert"]]
    for _, row in benign_alerts.iterrows():
        false_positives.append(
            {
                "event_id": str(row["event_id"]) if "event_id" in row and pd.notna(row["event_id"]) else "",
                "campaign_id": str(row.get("campaign_id", "") or ""),
                "scenario": str(row.get("scenario", "") or ""),
                "username": str(row["username"]),
                "primary_reason": str(row["primary_reason"]),
                "lr_label": str(row["lr_label"]),
            }
        )

    lr_true = test["label"].astype(str)
    lr_pred = test["lr_label"].astype(str)
    lr_binary = binary(lr_pred.ne("benign").to_numpy())
    lr_per_type = {}
    for attack in ATTACK_TYPES:
        precision, recall, f1, _ = precision_recall_fscore_support(
            lr_true.eq(attack), lr_pred.eq(attack), average="binary", zero_division=0
        )
        lr_per_type[attack] = {
            "precision": _round(precision),
            "recall": _round(recall),
            "f1": _round(f1),
            "support": int(lr_true.eq(attack).sum()),
        }

    if_only = test["if_alert"] & ~test["rule_alert"]
    return {
        "disclaimer": DISCLAIMER,
        "seed": SEED,
        "split": "time",
        "fit_end": "2026-01-13T00:00:00Z",
        "validation_end": "2026-01-15T00:00:00Z",
        "test_end": "2026-01-19T00:00:00Z",
        "rows": int(len(working)),
        "fit_rows": fit_count,
        "validation_rows": val_count,
        "test_rows": int(len(test)),
        "detector": "rules_or_isolation_forest",
        "if_threshold": _round(bundle["if_threshold"]),
        "validation_operating": bundle.get("validation", {}),
        "thresholds": {
            "brute_fails_15m": BRUTE_FAILS_15M,
            "spray_users_15m": SPRAY_USERS_15M,
            "success_after_failures_band": [SUCCESS_AFTER_FAILS, BRUTE_FAILS_15M - 1],
            "travel_speed_kmh": TRAVEL_SPEED_KMH,
        },
        "binary_test": binary(test["alert"].to_numpy()),
        "rules_only_binary": binary(test["rule_alert"].to_numpy()),
        "isolation_forest_only_binary": binary(test["if_alert"].to_numpy()),
        "logistic_baseline_binary": lr_binary,
        "per_attack_type": per_type,
        "logistic_per_attack_type": lr_per_type,
        "campaigns": campaigns,
        "campaign_recall": _round(detected / len(campaigns) if campaigns else 0.0),
        "campaigns_detected": detected,
        "campaigns_total": len(campaigns),
        "known_misses": misses,
        "rule_misses": [
            {"campaign_id": row["campaign_id"], "attack_type": row["attack_type"], "events": row["events"]}
            for row in rule_misses
        ],
        "false_positive_alerts": false_positives,
        "if_only_alerts": {
            "events": int(if_only.sum()),
            "true_positives": int((if_only & test["label"].ne("benign")).sum()),
            "false_positives": int((if_only & test["label"].eq("benign")).sum()),
        },
        "logistic_top_weights": _top_weights(bundle),
        "benign_medians": {name: _round(bundle["medians"][name]) for name in FEATURE_COLUMNS},
    }


def write_metrics(metrics: dict, path=METRICS_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")


def _apply(featured: pd.DataFrame, bundle: dict) -> pd.DataFrame:
    scores = _anomaly_scores(bundle["forest"], featured)
    threshold = float(bundle["if_threshold"])
    probabilities = bundle["logistic"].predict_proba(_matrix(featured))
    classes = [str(label) for label in bundle["logistic"].named_steps["clf"].classes_]
    chosen = probabilities.argmax(axis=1)
    scaler = bundle["logistic"].named_steps["scaler"]
    scaled = scaler.transform(_matrix(featured))
    coefficients = bundle["logistic"].named_steps["clf"].coef_
    rows = []
    for index, record in enumerate(featured.to_dict(orient="records")):
        record["if_score"] = float(scores[index])
        record["if_alert"] = bool(scores[index] >= threshold)
        record["rules"] = [str(rule) for rule in record["rules"]]
        record["rule_alert"] = bool(record["rules"])
        record["alert"] = bool(record["rule_alert"] or record["if_alert"])
        if record["rules"]:
            record["primary_reason"] = record["rules"][0]
        elif record["if_alert"]:
            record["primary_reason"] = "untyped_anomaly"
        else:
            record["primary_reason"] = ""
        record["reasons"] = reason_payload(record)
        record["top_features"] = top_features(record, bundle["medians"], bundle["mads"])
        record["lr_label"] = classes[int(chosen[index])]
        record["lr_confidence"] = float(probabilities[index, int(chosen[index])])
        record["lr_top_features"] = logistic_contributions(
            scaled[index], coefficients[int(chosen[index])], FEATURE_COLUMNS
        )
        record["model_note"] = model_note(record)
        record["split"] = split_of(record["timestamp"])
        rows.append(record)
    return pd.DataFrame(rows)


def _choose_threshold(forest: IsolationForest, validation: pd.DataFrame) -> tuple[float, dict]:
    scores = _anomaly_scores(forest, validation)
    truth = validation["label"].ne("benign").to_numpy()
    rules = validation["rules"].map(bool).to_numpy()
    benign_scores = scores[~truth]
    ceiling = float(benign_scores.max()) + 1e-9 if len(benign_scores) else float(scores.max()) + 1.0
    candidates = [float(value) for value in np.quantile(benign_scores, np.linspace(0.50, 1.0, 21))]
    candidates.append(ceiling)
    best_threshold = ceiling
    best_key: tuple | None = None
    for threshold in candidates:
        predicted = rules | (scores >= threshold)
        precision, recall, f1, _ = precision_recall_fscore_support(
            truth, predicted, average="binary", zero_division=0
        )
        key = (float(f1), float(precision), float(threshold))
        if best_key is None or key > best_key:
            best_key = key
            best_threshold = float(threshold)
    chosen = rules | (scores >= best_threshold)
    precision, recall, f1, _ = precision_recall_fscore_support(
        truth, chosen, average="binary", zero_division=0
    )
    rule_p, rule_r, rule_f, _ = precision_recall_fscore_support(
        truth, rules, average="binary", zero_division=0
    )
    return best_threshold, {
        "f1": _round(f1),
        "precision": _round(precision),
        "recall": _round(recall),
        "rules_only_f1": _round(rule_f),
        "rules_only_precision": _round(rule_p),
        "rules_only_recall": _round(rule_r),
    }


def _predicted_label(row: pd.Series) -> str:
    reason = str(row["primary_reason"])
    if reason in RULE_TO_LABEL:
        return RULE_TO_LABEL[reason]
    if reason == "untyped_anomaly":
        return "untyped_anomaly"
    return "benign"


def _top_weights(bundle: dict) -> dict:
    clf = bundle["logistic"].named_steps["clf"]
    classes = [str(label) for label in clf.classes_]
    report = {}
    for index, label in enumerate(classes):
        weights = clf.coef_[index]
        order = np.argsort(weights)
        report[label] = {
            "toward_class": [
                {"feature": FEATURE_COLUMNS[int(pos)], "coefficient": _round(weights[int(pos)])}
                for pos in order[::-1][:5]
            ],
            "against_class": [
                {"feature": FEATURE_COLUMNS[int(pos)], "coefficient": _round(weights[int(pos)])}
                for pos in order[:5]
            ],
        }
    return report


def _anomaly_scores(forest: IsolationForest, frame: pd.DataFrame) -> np.ndarray:
    # decision_function is higher for inliers. Flip it so a larger score is a stranger event.
    return -forest.decision_function(_matrix(frame))


def _matrix(frame: pd.DataFrame) -> np.ndarray:
    return frame[FEATURE_COLUMNS].to_numpy(dtype=float)


def _round(value: float) -> float:
    return round(float(value), 6)
