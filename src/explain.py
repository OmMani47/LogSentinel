"""Human-readable reasons for one scored event."""

from __future__ import annotations

from src.constants import FEATURE_LABELS, READABLE_FEATURES
from src.features import explain_rule


def robust_z(value: float, median: float, mad: float) -> float:
    scale = max(float(mad) * 1.4826, 0.5)
    return (float(value) - float(median)) / scale


def top_features(row: dict, medians: dict, mads: dict, limit: int = 3) -> list[dict]:
    ranked = []
    for name in READABLE_FEATURES:
        value = float(row[name])
        median = float(medians[name])
        mad = float(mads[name])
        score = abs(robust_z(value, median, mad))
        ranked.append(
            {
                "feature": name,
                "label": FEATURE_LABELS[name],
                "value": round(value, 3),
                "benign_median": round(median, 3),
                "robust_z": round(score, 2),
            }
        )
    ranked.sort(key=lambda item: item["robust_z"], reverse=True)
    return ranked[:limit]


def logistic_contributions(scaled_row, coefficients, names: list[str], limit: int = 3) -> list[dict]:
    paired = []
    for name, value, weight in zip(names, scaled_row, coefficients):
        contribution = float(value) * float(weight)
        paired.append(
            {
                "feature": name,
                "label": FEATURE_LABELS.get(name, name),
                "contribution": round(contribution, 3),
            }
        )
    paired.sort(key=lambda item: item["contribution"], reverse=True)
    return paired[:limit]


def reason_payload(row: dict) -> list[dict]:
    return [{"id": rule, "text": explain_rule(rule, row)} for rule in row["rules"]]


def model_note(row: dict) -> str:
    if row["rules"] and row["if_alert"]:
        return "Isolation Forest also marked this event as anomalous. The alert name comes from the rule."
    if row["rules"]:
        return "Isolation Forest did not mark this event as anomalous. The alert is from the rule."
    if row["if_alert"]:
        return (
            "Isolation Forest scored this event above the validation threshold. "
            "No threshold rule fired, so the alert has no attack-type name."
        )
    return "No rule fired, and Isolation Forest stayed under its threshold."
