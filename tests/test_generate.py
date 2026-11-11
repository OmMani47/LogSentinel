"""The teaching log is deterministic, fictional, and audited."""

import ipaddress
import json

import pandas as pd

from src.constants import ALLOWED_NETWORKS, ATTACK_TYPES, SEED
from src.generate import generate_events
from src.logs import load_log
from src.paths import DATA_PATH, JSON_PATH


def test_generator_is_deterministic_and_matches_the_committed_log():
    first = generate_events(SEED)
    second = generate_events(SEED)
    assert first == second
    saved = pd.read_csv(DATA_PATH, dtype=str, keep_default_na=False)
    assert saved["event_id"].tolist() == [row["event_id"] for row in first]
    assert saved["label"].tolist() == [row["label"] for row in first]
    assert saved["timestamp"].tolist() == [row["timestamp"] for row in first]
    payload = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert [row["event_id"] for row in payload] == saved["event_id"].tolist()


def test_only_documentation_addresses_and_example_names():
    frame, _warnings = load_log(DATA_PATH)
    assert "password" not in {column.lower() for column in frame.columns}
    for ip in frame["src_ip"]:
        addr = ipaddress.ip_address(ip)
        assert any(addr in network for network in ALLOWED_NETWORKS), ip
    assert frame["username"].str.endswith(".example").all()
    assert not frame["username"].str.contains(r"\.(?:com|net|org|edu)\b", regex=True).any()
    networks = {network.version for network in ALLOWED_NETWORKS}
    assert 4 in networks and 6 in networks
    assert frame["src_ip"].str.contains(":").any()
    assert frame["src_ip"].str.startswith("192.0.2.").any()
    assert frame["src_ip"].str.startswith("198.51.100.").any()
    assert frame["src_ip"].str.startswith("203.0.113.").any()


def test_every_attack_type_is_in_the_test_window_and_outcomes_are_closed():
    frame, _warnings = load_log(DATA_PATH)
    test = frame[frame["timestamp"] >= pd.Timestamp("2026-01-15T00:00:00Z")]
    assert set(test["label"]) >= set(ATTACK_TYPES) | {"benign"}
    assert set(frame["outcome"]) == {"success", "failure"}
    slow = frame[frame["campaign_id"] == "slow-brute-test-1"].sort_values("timestamp")
    gaps = slow["timestamp"].diff().dropna().dt.total_seconds()
    assert (gaps >= 45 * 60).all()
