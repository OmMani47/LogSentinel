"""Window rules on small logs, and the baseline that keeps 03:00 late."""

from datetime import datetime, timedelta, timezone

import pandas as pd

from src.features import circular_distance_hours, circular_mean_hour, engineer, explain_rule
from src.geo import HARBOR, NORTHWIND, OSTPORT, WESTPORT, haversine_km


def _row(
    stamp: datetime,
    *,
    user: str = "ada.okonkwo@northwind.example",
    ip: str = "192.0.2.11",
    outcome: str = "success",
    ua: str = "ua-work",
    device: str = "dev-work",
    site: str = "Northwind Campus",
    lat: float = 45.0,
    lon: float = -120.0,
    label: str = "benign",
) -> dict:
    return {
        "timestamp": stamp,
        "username": user,
        "src_ip": ip,
        "user_agent": ua,
        "device_id": device,
        "site": site,
        "latitude": lat,
        "longitude": lon,
        "outcome": outcome,
        "label": label,
    }


def _at(hour: int, minute: int = 0, day: int = 1) -> datetime:
    return datetime(2026, 3, day, hour, minute, tzinfo=timezone.utc)


def test_circular_mean_stays_between_morning_and_afternoon():
    usual = circular_mean_hour([9.3, 15.5, 9.4, 15.6, 9.2, 15.4])
    assert 11.5 < usual < 13.5
    assert circular_distance_hours(3.1, usual) >= 7

    night = circular_mean_hour([23.2, 3.2, 23.0, 3.1, 23.4, 2.8])
    assert circular_distance_hours(2.0, night) < 4


def test_brute_force_starts_at_the_eighth_failure():
    start = _at(14, 10)
    rows = [
        _row(
            start + timedelta(seconds=15 * index),
            outcome="failure",
            ip="203.0.113.150",
            site="External Relay",
            lat=-10.0,
            lon=-120.0,
        )
        for index in range(10)
    ]
    featured = engineer(pd.DataFrame(rows))
    assert "brute_force_burst" not in featured.iloc[6]["rules"]
    assert "brute_force_burst" in featured.iloc[7]["rules"]
    text = explain_rule("brute_force_burst", featured.iloc[7].to_dict())
    assert "8 failed sign-ins" in text
    assert "203.0.113.150" in text


def test_typos_do_not_fire_and_seven_failures_then_success_does():
    start = _at(11)
    typo = [
        _row(start, outcome="failure"),
        _row(start + timedelta(seconds=30), outcome="failure"),
        _row(start + timedelta(seconds=60), outcome="success"),
    ]
    typo_rules = engineer(pd.DataFrame(typo)).iloc[-1]["rules"]
    assert "success_after_failures" not in typo_rules
    assert "brute_force_burst" not in typo_rules

    burst = [
        _row(start + timedelta(seconds=20 * index), outcome="failure") for index in range(7)
    ]
    burst.append(_row(start + timedelta(seconds=20 * 7), outcome="success"))
    last = engineer(pd.DataFrame(burst)).iloc[-1]
    assert last["rules"] == ["success_after_failures"]
    assert "after 7 failures" in explain_rule("success_after_failures", last.to_dict())


def test_spray_fires_on_the_tenth_username_and_not_the_fourth():
    start = _at(11)
    wide = [
        _row(
            start + timedelta(seconds=5 * index),
            user=f"user{index}@students.northwind.example",
            ip="203.0.113.160",
            outcome="failure",
            ua="one-client",
            device="dev-spray",
            site="External Relay",
            lat=-10.0,
            lon=-120.0,
        )
        for index in range(10)
    ]
    featured = engineer(pd.DataFrame(wide))
    assert "password_spray" not in featured.iloc[8]["rules"]
    assert "password_spray" in featured.iloc[9]["rules"]

    tiny = engineer(pd.DataFrame(wide[:4]))
    assert all("password_spray" not in rules for rules in tiny["rules"])


def test_impossible_travel_and_a_short_walk():
    start = _at(9)
    trip = engineer(
        pd.DataFrame(
            [
                _row(start, lat=NORTHWIND[1], lon=NORTHWIND[2], site=NORTHWIND[0]),
                _row(
                    start + timedelta(minutes=20),
                    ip="203.0.113.90",
                    lat=OSTPORT[1],
                    lon=OSTPORT[2],
                    site=OSTPORT[0],
                ),
            ]
        )
    )
    assert "impossible_travel" in trip.iloc[1]["rules"]
    assert "km/h" in explain_rule("impossible_travel", trip.iloc[1].to_dict())

    walk = engineer(
        pd.DataFrame(
            [
                _row(start, lat=NORTHWIND[1], lon=NORTHWIND[2], site=NORTHWIND[0]),
                _row(
                    start + timedelta(minutes=30),
                    ip="198.51.100.40",
                    lat=HARBOR[1],
                    lon=HARBOR[2],
                    site=HARBOR[0],
                ),
            ]
        )
    )
    assert "impossible_travel" not in walk.iloc[1]["rules"]


def test_off_hours_for_a_day_worker_and_not_for_a_night_worker():
    day_rows = [_row(_at(12, day=day)) for day in range(1, 7)]
    day_rows.append(_row(_at(3, 10, day=7)))
    day_last = engineer(pd.DataFrame(day_rows)).iloc[-1]
    assert "off_hours" in day_last["rules"]
    assert day_last["hour_deviation"] >= 7

    night_rows = [_row(_at(2, 10, day=day)) for day in range(1, 7)]
    night_rows.append(_row(_at(2, 40, day=7)))
    night_last = engineer(pd.DataFrame(night_rows)).iloc[-1]
    assert "off_hours" not in night_last["rules"]


def test_new_device_requires_a_known_site_and_usual_hours():
    rows = [_row(_at(12, day=day)) for day in range(1, 7)]
    rows.append(_row(_at(12, day=7), ua="ua-new", device="dev-new"))
    last = engineer(pd.DataFrame(rows)).iloc[-1]
    assert "new_device" in last["rules"]


def test_labels_are_not_features():
    start = _at(14)
    rows = [
        _row(start + timedelta(seconds=10 * index), outcome="failure", label="brute_force")
        for index in range(4)
    ]
    flipped = [dict(row, label="benign", campaign_id="nope") for row in rows]
    left = engineer(pd.DataFrame(rows))
    right = engineer(pd.DataFrame(flipped).drop(columns=["label", "campaign_id"]))
    from src.constants import FEATURE_COLUMNS

    for column in FEATURE_COLUMNS:
        assert left[column].tolist() == right[column].tolist()
    assert "label" not in FEATURE_COLUMNS
    assert "fail_count_user_24h" not in FEATURE_COLUMNS


def test_site_distances_are_in_the_ranges_the_rules_assume():
    campus_harbor = haversine_km(NORTHWIND[1], NORTHWIND[2], HARBOR[1], HARBOR[2])
    campus_west = haversine_km(NORTHWIND[1], NORTHWIND[2], WESTPORT[1], WESTPORT[2])
    campus_ost = haversine_km(NORTHWIND[1], NORTHWIND[2], OSTPORT[1], OSTPORT[2])
    assert 4 < campus_harbor < 6
    assert 3500 < campus_west < 4500
    assert campus_ost > 8000
