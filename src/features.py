"""Window features and the threshold rules.

Each row is scored from events at or before its own timestamp. The label,
campaign, and scenario columns are copied through and never read.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from datetime import datetime, timedelta

import pandas as pd

from src.constants import (
    BRUTE_FAILS_15M,
    BRUTE_MAX_DISTINCT_USERS,
    DISTANCE_CAP,
    FEATURE_COLUMNS,
    GEO_MIN_SUCCESSES,
    MINUTES_CAP,
    NEW_DEVICE_MIN_SUCCESSES,
    OFF_HOURS_DEVIATION,
    OFF_HOURS_MIN_SUCCESSES,
    RULE_PRIORITY,
    SPEED_CAP,
    SPRAY_FAIL_RATIO,
    SPRAY_MAX_FAILS_PER_USER,
    SPRAY_MAX_UAS,
    SPRAY_USERS_15M,
    STUFF_FAIL_RATIO,
    STUFF_FAILS_USER_60M,
    STUFF_IPS_60M,
    STUFF_UAS_15M,
    STUFF_USERS_15M,
    SUCCESS_AFTER_FAILS,
    TRAVEL_MAX_MINUTES,
    TRAVEL_MIN_KM,
    TRAVEL_SPEED_KMH,
)
from src.geo import haversine_km
from src.logs import parse_timestamp

_WINDOW = timedelta(minutes=60)


def circular_distance_hours(left: float, right: float) -> float:
    delta = abs(left - right) % 24.0
    return min(delta, 24.0 - delta)


def circular_mean_hour(hours: list[float]) -> float:
    """Usual sign-in hour.

    The circular mean stays in the middle of a morning-and-afternoon habit.
    A circular median does not: with the same number of points in each cluster,
    every hour between them has the same total distance, and the minimizer
    collapses onto the edge of one cluster.
    """
    angles = [2.0 * math.pi * hour / 24.0 for hour in hours]
    sin_mean = sum(math.sin(angle) for angle in angles) / len(angles)
    cos_mean = sum(math.cos(angle) for angle in angles) / len(angles)
    angle = math.atan2(sin_mean, cos_mean)
    if angle < 0.0:
        angle += 2.0 * math.pi
    return angle * 24.0 / (2.0 * math.pi)


def rules_for(row: dict) -> list[str]:
    """Return fired rule ids, highest priority first."""
    users = row["distinct_users_ip_15m"]
    uas = row["distinct_ua_ip_15m"]
    fail_ratio = row["fail_ratio_ip_15m"]
    user_fails_15 = row["fail_count_user_15m"]
    fired: list[str] = []

    if (
        users >= SPRAY_USERS_15M
        and fail_ratio >= SPRAY_FAIL_RATIO
        and user_fails_15 <= SPRAY_MAX_FAILS_PER_USER
        and uas <= SPRAY_MAX_UAS
    ):
        fired.append("password_spray")

    stuffing_many_users = (
        users >= STUFF_USERS_15M and uas >= STUFF_UAS_15M and fail_ratio >= STUFF_FAIL_RATIO
    )
    stuffing_many_ips = (
        row["distinct_ips_user_60m"] >= STUFF_IPS_60M
        and row["fail_count_user_60m"] >= STUFF_FAILS_USER_60M
        and users <= 2
    )
    if stuffing_many_users or stuffing_many_ips:
        fired.append("credential_stuffing")

    if user_fails_15 >= BRUTE_FAILS_15M and users <= BRUTE_MAX_DISTINCT_USERS:
        fired.append("brute_force_burst")

    # Six or seven failures, then a success. Eight or more is the burst rule.
    if (
        row["outcome"] == "success"
        and SUCCESS_AFTER_FAILS <= user_fails_15 < BRUTE_FAILS_15M
    ):
        fired.append("success_after_failures")

    if (
        row["outcome"] == "success"
        and row["geo_speed_kmh"] >= TRAVEL_SPEED_KMH
        and row["minutes_since_prev_success"] <= TRAVEL_MAX_MINUTES
        and row["geo_distance_km"] >= TRAVEL_MIN_KM
    ):
        fired.append("impossible_travel")

    if (
        row["outcome"] == "success"
        and row["unseen_site"] == 1.0
        and row["prior_successes"] >= GEO_MIN_SUCCESSES
        and row["geo_speed_kmh"] < TRAVEL_SPEED_KMH
        and row["minutes_since_prev_success"] > TRAVEL_MAX_MINUTES
    ):
        fired.append("unusual_geography")

    if (
        row["outcome"] == "success"
        and row["prior_successes"] >= OFF_HOURS_MIN_SUCCESSES
        and row["hour_deviation"] >= OFF_HOURS_DEVIATION
    ):
        fired.append("off_hours")

    if (
        row["outcome"] == "success"
        and row["prior_successes"] >= NEW_DEVICE_MIN_SUCCESSES
        and row["unseen_ua"] == 1.0
        and row["unseen_device"] == 1.0
        and row["unseen_site"] == 0.0
        and row["hour_deviation"] < OFF_HOURS_DEVIATION
    ):
        fired.append("new_device")

    fired.sort(key=RULE_PRIORITY.index)
    return fired


def explain_rule(rule: str, row: dict) -> str:
    user = row["username"]
    ip = row["src_ip"]
    if rule == "brute_force_burst":
        count = int(row["fail_count_user_15m"])
        noun = "sign-in" if count == 1 else "sign-ins"
        return f"{count} failed {noun} for {user} from {ip} in 15 minutes."
    if rule == "password_spray":
        accounts = int(row["distinct_users_ip_15m"])
        agents = int(row["distinct_ua_ip_15m"])
        agent_word = "user-agent" if agents == 1 else "user-agents"
        return (
            f"{ip} failed against {accounts} usernames in 15 minutes "
            f"({row['fail_ratio_ip_15m']:.0%} failures, {agents} {agent_word})."
        )
    if rule == "credential_stuffing":
        if (
            row["distinct_ips_user_60m"] >= STUFF_IPS_60M
            and row["fail_count_user_60m"] >= STUFF_FAILS_USER_60M
            and row["distinct_users_ip_15m"] <= 2
        ):
            fails = int(row["fail_count_user_60m"])
            places = int(row["distinct_ips_user_60m"])
            return f"{user} failed {fails} times from {places} addresses in 60 minutes."
        accounts = int(row["distinct_users_ip_15m"])
        agents = int(row["distinct_ua_ip_15m"])
        return (
            f"{ip} failed against {accounts} usernames in 15 minutes using {agents} user-agents."
        )
    if rule == "success_after_failures":
        fails = int(row["fail_count_user_15m"])
        return f"Successful sign-in for {user} from {ip} after {fails} failures in 15 minutes."
    if rule == "impossible_travel":
        return (
            f"Successful sign-in for {user} at {row['site']} is {row['geo_distance_km']:.0f} km "
            f"from the previous success, {row['minutes_since_prev_success']:.0f} minutes later "
            f"({row['geo_speed_kmh']:.0f} km/h)."
        )
    if rule == "unusual_geography":
        return f"Successful sign-in for {user} at {row['site']}, a site this user has not used before."
    if rule == "off_hours":
        stamp = row["timestamp"]
        if not isinstance(stamp, datetime):
            stamp = parse_timestamp(stamp)
        return (
            f"Successful sign-in for {user} at {stamp.strftime('%H:%M')} UTC, "
            f"{row['hour_deviation']:.1f} hours from their usual time."
        )
    if rule == "new_device":
        return f"Successful sign-in for {user} from a user-agent and device this user has not used before."
    return rule


def engineer(frame: pd.DataFrame) -> pd.DataFrame:
    """Add window features. Input order does not matter; time order does."""
    working = frame.copy()
    working["_row"] = range(len(working))
    if "event_id" in working.columns:
        working = working.sort_values(["timestamp", "event_id", "_row"], kind="mergesort")
    else:
        working = working.sort_values(["timestamp", "_row"], kind="mergesort")

    by_user: dict[str, deque] = defaultdict(deque)
    by_ip: dict[str, deque] = defaultdict(deque)
    seen_ua: dict[str, set] = defaultdict(set)
    seen_device: dict[str, set] = defaultdict(set)
    seen_ip: dict[str, set] = defaultdict(set)
    seen_site: dict[str, set] = defaultdict(set)
    success_hours: dict[str, list[float]] = defaultdict(list)
    last_success: dict[str, tuple] = {}

    rows: list[dict] = []
    for record in working.to_dict(orient="records"):
        stamp = record["timestamp"]
        if not isinstance(stamp, datetime):
            stamp = parse_timestamp(stamp)
            record["timestamp"] = stamp
        user = record["username"]
        ip = record["src_ip"]
        outcome = record["outcome"]
        ua = record["user_agent"]
        device = record["device_id"]
        site = record["site"]
        lat = float(record["latitude"])
        lon = float(record["longitude"])

        _prune(by_user[user], stamp)
        _prune(by_ip[ip], stamp)
        user_60 = list(by_user[user])
        ip_60 = list(by_ip[ip])
        cutoff_15 = stamp - timedelta(minutes=15)
        user_15 = [item for item in user_60 if item[0] >= cutoff_15]
        ip_15 = [item for item in ip_60 if item[0] >= cutoff_15]

        current_failure = 1 if outcome == "failure" else 0
        fail_user_15 = _failures(user_15) + current_failure
        fail_user_60 = _failures(user_60) + current_failure
        fail_ip_15 = _failures(ip_15) + current_failure
        fail_ip_60 = _failures(ip_60) + current_failure
        ip_15_users = {item[1] for item in ip_15}
        ip_15_users.add(user)
        ip_60_users = {item[1] for item in ip_60}
        ip_60_users.add(user)
        ip_15_uas = {item[2] for item in ip_15}
        ip_15_uas.add(ua)
        user_60_ips = {item[3] for item in user_60}
        user_60_ips.add(ip)
        ip_attempts = len(ip_15) + 1
        fail_ratio = fail_ip_15 / ip_attempts

        hour = stamp.hour + stamp.minute / 60.0 + stamp.second / 3600.0
        angle = 2.0 * math.pi * hour / 24.0
        prior = success_hours[user]
        if len(prior) >= 3:
            deviation = circular_distance_hours(hour, circular_mean_hour(prior))
        else:
            deviation = 0.0

        previous = last_success.get(user)
        if previous is None:
            distance = 0.0
            speed = 0.0
            minutes = MINUTES_CAP
        else:
            prev_stamp, prev_lat, prev_lon = previous
            elapsed_hours = (stamp - prev_stamp).total_seconds() / 3600.0
            minutes = min(MINUTES_CAP, max(elapsed_hours, 0.0) * 60.0)
            raw_distance = haversine_km(prev_lat, prev_lon, lat, lon)
            distance = min(DISTANCE_CAP, raw_distance)
            if elapsed_hours <= 0:
                speed = 0.0 if raw_distance < 1.0 else SPEED_CAP
            else:
                speed = min(SPEED_CAP, raw_distance / elapsed_hours)

        features = {
            "fail_count_user_15m": float(fail_user_15),
            "fail_count_user_60m": float(fail_user_60),
            "fail_count_ip_15m": float(fail_ip_15),
            "fail_count_ip_60m": float(fail_ip_60),
            "distinct_users_ip_15m": float(len(ip_15_users)),
            "distinct_users_ip_60m": float(len(ip_60_users)),
            "distinct_ips_user_60m": float(len(user_60_ips)),
            "distinct_ua_ip_15m": float(len(ip_15_uas)),
            "fail_ratio_ip_15m": float(fail_ratio),
            "hour_sin": float(math.sin(angle)),
            "hour_cos": float(math.cos(angle)),
            "is_weekend": 1.0 if stamp.weekday() >= 5 else 0.0,
            "hour_deviation": float(deviation),
            "prior_successes": float(len(prior)),
            "unseen_ua": 0.0 if ua in seen_ua[user] else 1.0,
            "unseen_device": 0.0 if device in seen_device[user] else 1.0,
            "unseen_ip": 0.0 if ip in seen_ip[user] else 1.0,
            "unseen_site": 0.0 if site in seen_site[user] else 1.0,
            "geo_distance_km": float(distance),
            "geo_speed_kmh": float(speed),
            "minutes_since_prev_success": float(minutes),
            "is_failure": float(current_failure),
            "fails_before_success_15m": float(fail_user_15 if outcome == "success" else 0.0),
        }
        enriched = dict(record)
        enriched.update(features)
        enriched["rules"] = rules_for(enriched)
        rows.append(enriched)

        packet = (stamp, user, ua, ip, outcome)
        by_user[user].append(packet)
        by_ip[ip].append(packet)
        seen_ua[user].add(ua)
        seen_device[user].add(device)
        seen_ip[user].add(ip)
        seen_site[user].add(site)
        if outcome == "success":
            success_hours[user].append(hour)
            last_success[user] = (stamp, lat, lon)

    featured = pd.DataFrame(rows)
    featured = featured.drop(columns=["_row"], errors="ignore")
    missing = [column for column in FEATURE_COLUMNS if column not in featured.columns]
    if missing:
        raise RuntimeError("feature columns missing: " + ", ".join(missing))
    return featured


def _prune(items: deque, now: datetime) -> None:
    cutoff = now - _WINDOW
    while items and items[0][0] < cutoff:
        items.popleft()


def _failures(items: list[tuple]) -> int:
    return sum(1 for item in items if item[4] == "failure")
