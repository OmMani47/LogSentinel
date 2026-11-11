"""The command line scores the demo and rejects a bad file."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from src.logs import load_log


def test_demo_json_names_the_burst_and_the_stealth_miss():
    completed = subprocess.run(
        [sys.executable, "-m", "src.score", "--demo", "--format", "json"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    reasons = {row["primary_reason"] for row in payload["alerts"]}
    assert "brute_force_burst" in reasons
    burst = next(row for row in payload["alerts"] if row["primary_reason"] == "brute_force_burst")
    assert "failed sign-ins" in burst["reasons"][0]
    missed = {row["campaign_id"] for row in payload["generator_labels_with_no_alert"]}
    assert "stealth-demo" in missed


def test_missing_file_and_missing_arguments_exit_2():
    missing = subprocess.run(
        [sys.executable, "-m", "src.score", "--file", "data/does-not-exist.csv"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert missing.returncode == 2
    bare = subprocess.run(
        [sys.executable, "-m", "src.score"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert bare.returncode == 2


def test_secret_column_is_dropped_and_geo_is_required(tmp_path: Path):
    secret = tmp_path / "secret.csv"
    secret.write_text(
        "timestamp,username,src_ip,user_agent,device_id,site,latitude,longitude,outcome,password\n"
        "2026-03-01T12:00:00Z,ada.okonkwo@northwind.example,192.0.2.11,ua,dev,"
        "Northwind Campus,45.0,-120.0,success,hunter2\n",
        encoding="utf-8",
    )
    frame, warnings = load_log(secret)
    assert "password" not in frame.columns
    assert warnings and "password" in warnings[0]

    broken = tmp_path / "broken.csv"
    broken.write_text(
        "timestamp,username,src_ip,user_agent,device_id,outcome\n"
        "2026-03-01T12:00:00Z,ada.okonkwo@northwind.example,192.0.2.11,ua,dev,success\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="latitude"):
        load_log(broken)

    with pytest.raises(ValueError):
        load_log("   ")


def test_text_export_of_the_demo(tmp_path: Path):
    output = tmp_path / "demo.txt"
    completed = subprocess.run(
        [sys.executable, "-m", "src.score", "--demo", "--output", str(output)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    text = output.read_text(encoding="utf-8")
    assert "brute_force_burst" in text or "failed sign-ins" in text
    assert "stealth-demo" in text
    assert completed.stdout == ""
