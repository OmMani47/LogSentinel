"""Fit LogSentinel and write the held-out metrics.

From the repository root:

    python -m src.train
    python -m src.train --regenerate

The fit uses the first eight days. Two days choose the forest threshold.
The last four days are scored once. Those numbers are not real-world accuracy.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import joblib
import pandas as pd

from src.constants import SEED
from src.features import engineer
from src.generate import demo_events, generate_events
from src.logs import load_log, write_logs
from src.model import evaluate, fit_bundle, score_frame, write_metrics
from src.paths import DATA_PATH, DEMO_PATH, METRICS_PATH, MODEL_PATH


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the LogSentinel detector on the teaching log.")
    parser.add_argument("--data", type=Path, default=DATA_PATH)
    parser.add_argument("--model", type=Path, default=MODEL_PATH)
    parser.add_argument("--metrics", type=Path, default=METRICS_PATH)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument(
        "--regenerate",
        action="store_true",
        help="Rewrite the synthetic log with the fixed seed before training.",
    )
    return parser.parse_args()


def train(args: argparse.Namespace) -> dict:
    if args.regenerate or not args.data.exists():
        rows = generate_events(seed=args.seed)
        write_logs(args.data, rows)
        DEMO_PATH.parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(demo_events()).to_csv(DEMO_PATH, index=False)
        print(f"Wrote {len(rows)} synthetic events to {args.data}")

    frame, warnings = load_log(args.data)
    for warning in warnings:
        print(warning)
    if "label" not in frame.columns:
        raise SystemExit("The training log needs a label column. Scoring a raw log does not.")

    featured = engineer(frame)
    bundle = fit_bundle(featured)
    scored = score_frame(frame, bundle)
    metrics = evaluate(scored, bundle)
    args.model.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, args.model, compress=3)
    write_metrics(metrics, args.metrics)
    binary = metrics["binary_test"]
    print(
        f"Test events: {metrics['test_rows']}  "
        f"precision {binary['precision']:.3f}  recall {binary['recall']:.3f}  "
        f"F1 {binary['f1']:.3f}"
    )
    print(
        f"Campaigns detected: {metrics['campaigns_detected']}/{metrics['campaigns_total']} "
        f"(recall {metrics['campaign_recall']:.3f})"
    )
    print(metrics["disclaimer"])
    return metrics


if __name__ == "__main__":
    train(_parse_args())
