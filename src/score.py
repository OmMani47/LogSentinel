"""Score a sign-in log from the command line.

Examples, from the repository root:

    python -m src.score --demo
    python -m src.score --file data/sample_auth_logs.csv
    python -m src.score --file data/sample_auth_logs.csv --format json --output alerts.json

Nothing is uploaded. The saved detector runs on this machine. A column that
looks like a password is dropped before scoring and is not printed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pandas as pd

from src.logs import format_timestamp, load_log
from src.model import score_frame
from src.paths import DEMO_PATH


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Score a sign-in log with LogSentinel.")
    parser.add_argument("--file", type=Path, help="CSV or JSON log to score.")
    parser.add_argument("--demo", action="store_true", help="Score the built-in demo log.")
    parser.add_argument("--format", choices=("text", "json", "csv"), default="text")
    parser.add_argument("--output", type=Path, help="Write the report to this path instead of stdout.")
    parser.add_argument("--all-events", action="store_true", help="Include events that did not alert.")
    return parser.parse_args()


def alert_records(scored: pd.DataFrame, include_quiet: bool = False) -> list[dict]:
    view = scored if include_quiet else scored[scored["alert"]]
    records = []
    for row in view.to_dict(orient="records"):
        records.append(
            {
                "event_id": str(row.get("event_id", "")),
                "timestamp": format_timestamp(row["timestamp"]),
                "username": row["username"],
                "src_ip": row["src_ip"],
                "outcome": row["outcome"],
                "site": row["site"],
                "alert": bool(row["alert"]),
                "primary_reason": row["primary_reason"],
                "rules": [reason["id"] for reason in row["reasons"]],
                "reasons": [reason["text"] for reason in row["reasons"]],
                "model_note": row["model_note"],
                "if_score": round(float(row["if_score"]), 4),
                "if_alert": bool(row["if_alert"]),
                "top_features": row["top_features"],
                "baseline_label": row["lr_label"],
                "baseline_confidence": round(float(row["lr_confidence"]), 4),
                "baseline_top_features": row["lr_top_features"],
                "generator_label": str(row["label"]) if "label" in row and pd.notna(row["label"]) else "",
                "campaign_id": str(row["campaign_id"]) if "campaign_id" in row and pd.notna(row["campaign_id"]) else "",
            }
        )
    return records


def missed_campaigns(scored: pd.DataFrame) -> list[dict]:
    if "label" not in scored.columns or "campaign_id" not in scored.columns:
        return []
    labelled = scored[scored["label"].astype(str).ne("benign") & scored["campaign_id"].astype(str).ne("")]
    missed = []
    for campaign_id, group in labelled.groupby("campaign_id", sort=True):
        if bool(group["alert"].any()):
            continue
        missed.append(
            {
                "campaign_id": str(campaign_id),
                "attack_type": str(group["label"].iloc[0]),
                "events": int(len(group)),
                "username": str(group["username"].iloc[0]),
            }
        )
    return missed


def format_text(scored: pd.DataFrame, source_name: str, include_quiet: bool = False) -> str:
    records = alert_records(scored, include_quiet=include_quiet)
    alerts = [row for row in records if row["alert"]]
    lines = [
        f"LogSentinel scored {len(scored)} events from {source_name}",
        f"Alerts: {len(alerts)}",
    ]
    counts: dict[str, int] = {}
    for row in alerts:
        counts[row["primary_reason"]] = counts.get(row["primary_reason"], 0) + 1
    for reason, count in sorted(counts.items()):
        lines.append(f"  {reason}: {count}")
    lines.append("")
    if not alerts and not include_quiet:
        lines.append("No alerts.")
    for row in records:
        if not include_quiet and not row["alert"]:
            continue
        lines.append(
            f"{row['event_id']}  {row['timestamp']}  {row['username']}  {row['src_ip']}  {row['outcome']}"
        )
        if row["reasons"]:
            for text in row["reasons"]:
                lines.append(f"  {text}")
        else:
            lines.append(f"  {row['model_note']}")
        features = ", ".join(
            f"{item['feature']}={item['value']} (benign median {item['benign_median']})"
            for item in row["top_features"][:3]
        )
        lines.append(f"  top features: {features}")
        lines.append(
            f"  supervised baseline: {row['baseline_label']} ({row['baseline_confidence']:.2f}), not used for the alert"
        )
        lines.append("")
    missed = missed_campaigns(scored)
    if missed:
        lines.append("Generator labels with no alert:")
        for row in missed:
            lines.append(
                f"  {row['campaign_id']}  {row['attack_type']}  {row['events']} events  {row['username']}"
            )
        lines.append("These rows were built to look like ordinary sign-ins, or to stay under the window thresholds.")
    return "\n".join(lines).rstrip() + "\n"


def format_csv(records: list[dict]) -> str:
    frame = pd.DataFrame(records)
    if frame.empty:
        return ""
    frame["reasons"] = frame["reasons"].map(lambda items: " | ".join(items))
    frame["rules"] = frame["rules"].map(lambda items: ",".join(items))
    keep = [
        "event_id",
        "timestamp",
        "username",
        "src_ip",
        "outcome",
        "site",
        "alert",
        "primary_reason",
        "rules",
        "reasons",
        "model_note",
        "if_score",
        "baseline_label",
        "baseline_confidence",
        "generator_label",
        "campaign_id",
    ]
    return frame[keep].to_csv(index=False)


def score_path(path: Path, include_quiet: bool = False) -> tuple[pd.DataFrame, str]:
    frame, warnings = load_log(path)
    scored = score_frame(frame)
    report = format_text(scored, path.name, include_quiet=include_quiet)
    if warnings:
        report = "\n".join(warnings) + "\n" + report
    return scored, report


def main(argv: list[str] | None = None) -> int:
    args = _parse_args() if argv is None else _parse_args_from(argv)
    if args.demo and args.file:
        print("Use either --demo or --file, not both.", file=sys.stderr)
        return 2
    path = DEMO_PATH if args.demo else args.file
    if path is None:
        print("Pass --file or --demo.", file=sys.stderr)
        return 2
    try:
        frame, warnings = load_log(path)
        scored = score_frame(frame)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    records = alert_records(scored, include_quiet=args.all_events)
    if args.format == "json":
        payload = {
            "source": path.name,
            "events": int(len(scored)),
            "alerts": records,
            "warnings": warnings,
            "generator_labels_with_no_alert": missed_campaigns(scored),
        }
        text = json.dumps(payload, indent=2) + "\n"
    elif args.format == "csv":
        text = format_csv(records)
    else:
        text = format_text(scored, path.name, include_quiet=args.all_events)
        if warnings:
            text = "\n".join(warnings) + "\n" + text
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


def _parse_args_from(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Score a sign-in log with LogSentinel.")
    parser.add_argument("--file", type=Path)
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--format", choices=("text", "json", "csv"), default="text")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--all-events", action="store_true")
    return parser.parse_args(argv)


if __name__ == "__main__":
    raise SystemExit(main())
