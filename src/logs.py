"""Read and write sign-in logs. No network, no geolocation, no secrets."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from src.constants import SENSITIVE_COLUMNS

REQUIRED_COLUMNS = [
    "timestamp",
    "username",
    "src_ip",
    "user_agent",
    "device_id",
    "site",
    "latitude",
    "longitude",
    "outcome",
]

GEO_HINT = (
    "This tool does not geolocate IP addresses. "
    "Include site, latitude, and longitude columns on each row."
)


def format_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp(value: object) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def write_logs(path: Path, events: list[dict]) -> None:
    """Write CSV. A sibling JSON file is written when the name is the sample log."""
    frame = pd.DataFrame(events)
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(path, index=False)
    if path.suffix == ".csv":
        json_path = path.with_suffix(".json")
        # Only the full sample is mirrored. Demo stays CSV.
        if path.name.startswith("sample_"):
            json_path.write_text(json.dumps(events, indent=2) + "\n", encoding="utf-8")


def load_log(source: Path | str | pd.DataFrame | bytes | str) -> tuple[pd.DataFrame, list[str]]:
    """Return a frame and any warnings about dropped columns.

    `source` may be a path, a dataframe, or CSV/JSON text.
    """
    warnings: list[str] = []
    if isinstance(source, pd.DataFrame):
        frame = source.copy()
    else:
        if isinstance(source, bytes):
            text = source.decode("utf-8-sig")
            frame = _frame_from_text(text)
        elif isinstance(source, Path) or (isinstance(source, str) and Path(source).expanduser().exists()):
            path = Path(source)
            raw = path.read_text(encoding="utf-8-sig")
            if path.suffix.lower() == ".json":
                frame = _frame_from_text(raw)
            else:
                frame = pd.read_csv(path, dtype=str, keep_default_na=False)
        else:
            frame = _frame_from_text(str(source))

    frame.columns = [str(column).strip() for column in frame.columns]
    lowered = {column.lower(): column for column in frame.columns}
    sensitive = [lowered[name] for name in SENSITIVE_COLUMNS if name in lowered]
    if sensitive:
        frame = frame.drop(columns=sensitive)
        warnings.append(
            "Dropped columns that look like secrets and did not score them: " + ", ".join(sensitive)
        )

    missing = [column for column in REQUIRED_COLUMNS if column not in frame.columns]
    if missing:
        raise ValueError("Log is missing columns: " + ", ".join(missing) + ". " + GEO_HINT)

    if frame.empty:
        raise ValueError("Log has no events.")

    cleaned = frame.copy()
    cleaned["timestamp"] = cleaned["timestamp"].map(parse_timestamp)
    cleaned["outcome"] = cleaned["outcome"].astype(str).str.strip().str.lower()
    bad = sorted(set(cleaned["outcome"]) - {"success", "failure"})
    if bad:
        raise ValueError("outcome must be success or failure. Found: " + ", ".join(bad))
    for column in ("username", "src_ip", "user_agent", "device_id", "site"):
        cleaned[column] = cleaned[column].astype(str).str.strip()
        if cleaned[column].eq("").any():
            raise ValueError(f"{column} has an empty value.")
    cleaned["latitude"] = pd.to_numeric(cleaned["latitude"], errors="coerce")
    cleaned["longitude"] = pd.to_numeric(cleaned["longitude"], errors="coerce")
    if cleaned["latitude"].isna().any() or cleaned["longitude"].isna().any():
        raise ValueError("latitude and longitude must be numbers. " + GEO_HINT)
    return cleaned, warnings


def _frame_from_text(text: str) -> pd.DataFrame:
    stripped = text.strip()
    if not stripped:
        raise ValueError("Log is empty.")
    if stripped[0] in "[{":
        payload = json.loads(stripped)
        if isinstance(payload, dict):
            payload = payload.get("events", payload.get("data"))
        if not isinstance(payload, list):
            raise ValueError("JSON log must be a list of events.")
        return pd.DataFrame(payload)
    from io import StringIO

    return pd.read_csv(StringIO(text), dtype=str, keep_default_na=False)
