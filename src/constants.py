"""Thresholds, column names, and the sentence the evaluation is not allowed to outrun."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

SEED = 42

# The teaching log is stamped in UTC. The fictional campus keeps UTC hours,
# so 03:00 is the middle of the night for every off-hours comparison.
LOG_START = datetime(2026, 1, 5, tzinfo=timezone.utc)
FIT_END = datetime(2026, 1, 13, tzinfo=timezone.utc)
VAL_END = datetime(2026, 1, 15, tzinfo=timezone.utc)
LOG_END = datetime(2026, 1, 19, tzinfo=timezone.utc)

DISCLAIMER = (
    "Scores are from a later time slice of a synthetic teaching log. "
    "They are not an estimate of accuracy on real authentication logs."
)

# RFC 5737 documentation ranges, plus the RFC 3849 documentation prefix.
ALLOWED_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

# Benign routine stays under these on purpose: at most two failures in 15
# minutes, and at most eight usernames on the shared lab address.
BRUTE_FAILS_15M = 8
BRUTE_MAX_DISTINCT_USERS = 3
SPRAY_USERS_15M = 10
SPRAY_FAIL_RATIO = 0.9
SPRAY_MAX_FAILS_PER_USER = 2
SPRAY_MAX_UAS = 2
STUFF_USERS_15M = 8
STUFF_UAS_15M = 3
STUFF_FAIL_RATIO = 0.75
STUFF_IPS_60M = 5
STUFF_FAILS_USER_60M = 6
TRAVEL_SPEED_KMH = 800.0
TRAVEL_MAX_MINUTES = 180.0
TRAVEL_MIN_KM = 500.0
GEO_MIN_SUCCESSES = 6
OFF_HOURS_DEVIATION = 7.0
OFF_HOURS_MIN_SUCCESSES = 4
NEW_DEVICE_MIN_SUCCESSES = 5
SUCCESS_AFTER_FAILS = 6

SPEED_CAP = 20_000.0
DISTANCE_CAP = 20_000.0
MINUTES_CAP = 10_080.0

FEATURE_COLUMNS = [
    "fail_count_user_15m",
    "fail_count_user_60m",
    "fail_count_ip_15m",
    "fail_count_ip_60m",
    "distinct_users_ip_15m",
    "distinct_users_ip_60m",
    "distinct_ips_user_60m",
    "distinct_ua_ip_15m",
    "fail_ratio_ip_15m",
    "hour_sin",
    "hour_cos",
    "is_weekend",
    "hour_deviation",
    "prior_successes",
    "unseen_ua",
    "unseen_device",
    "unseen_ip",
    "unseen_site",
    "geo_distance_km",
    "geo_speed_kmh",
    "minutes_since_prev_success",
    "is_failure",
    "fails_before_success_15m",
]

RULE_PRIORITY = [
    "password_spray",
    "credential_stuffing",
    "brute_force_burst",
    "success_after_failures",
    "impossible_travel",
    "unusual_geography",
    "off_hours",
    "new_device",
]

ATTACK_TYPES = [
    "brute_force",
    "password_spray",
    "credential_stuffing",
    "impossible_travel",
    "unusual_geography",
    "off_hours",
    "new_device",
    "success_after_failures",
    "stealth_takeover",
]

RULE_TO_LABEL = {
    "password_spray": "password_spray",
    "credential_stuffing": "credential_stuffing",
    "brute_force_burst": "brute_force",
    "success_after_failures": "success_after_failures",
    "impossible_travel": "impossible_travel",
    "unusual_geography": "unusual_geography",
    "off_hours": "off_hours",
    "new_device": "new_device",
}

SENSITIVE_COLUMNS = {
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "credentials",
    "refresh_token",
    "access_token",
}

FEATURE_LABELS = {
    "fail_count_user_15m": "failures for this user in 15 minutes",
    "fail_count_user_60m": "failures for this user in 60 minutes",
    "fail_count_ip_15m": "failures from this IP in 15 minutes",
    "fail_count_ip_60m": "failures from this IP in 60 minutes",
    "distinct_users_ip_15m": "distinct usernames from this IP in 15 minutes",
    "distinct_users_ip_60m": "distinct usernames from this IP in 60 minutes",
    "distinct_ips_user_60m": "distinct IPs for this user in 60 minutes",
    "distinct_ua_ip_15m": "distinct user-agents from this IP in 15 minutes",
    "fail_ratio_ip_15m": "failure ratio from this IP in 15 minutes",
    "hour_sin": "hour of day (sine)",
    "hour_cos": "hour of day (cosine)",
    "is_weekend": "weekend",
    "hour_deviation": "hours from this user's usual sign-in time",
    "prior_successes": "earlier successful sign-ins for this user",
    "unseen_ua": "user-agent not seen before for this user",
    "unseen_device": "device not seen before for this user",
    "unseen_ip": "IP not seen before for this user",
    "unseen_site": "site not seen before for this user",
    "geo_distance_km": "kilometers since this user's previous success",
    "geo_speed_kmh": "implied travel speed since the previous success",
    "minutes_since_prev_success": "minutes since this user's previous success",
    "is_failure": "this attempt failed",
    "fails_before_success_15m": "failures in the 15 minutes before this success",
}

READABLE_FEATURES = [
    "fail_count_user_15m",
    "fail_count_ip_15m",
    "distinct_users_ip_15m",
    "distinct_ips_user_60m",
    "distinct_ua_ip_15m",
    "fail_ratio_ip_15m",
    "hour_deviation",
    "unseen_ua",
    "unseen_device",
    "unseen_ip",
    "unseen_site",
    "geo_distance_km",
    "geo_speed_kmh",
    "fails_before_success_15m",
]
