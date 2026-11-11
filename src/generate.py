"""Deterministic sign-in log for LogSentinel.

Seed 42 rebuilds the same events. Every address is in an RFC 5737 or RFC 3849
documentation range. Every username ends in .example. There are no passwords
and no login attempts against anything.

The calendar is scripted where a rule has to fire, or has to stay quiet.
Routine sign-ins fill in the rest of the two weeks.
"""

from __future__ import annotations

import argparse
import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from src.constants import (
    ALLOWED_NETWORKS,
    ATTACK_TYPES,
    FIT_END,
    LOG_END,
    LOG_START,
    SEED,
    VAL_END,
)
from src.features import engineer
from src.geo import site_for_ip
from src.logs import format_timestamp, parse_timestamp, write_logs
from src.paths import DATA_PATH, DEMO_PATH

UA_CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36"
UA_SAFARI = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.2 Safari/605.1.15"
UA_FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"
UA_IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Version/17.3 Mobile/15E148 Safari/604.1"
NEW_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"
STUFF_UAS = [
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 Chrome/90.0.4430.93 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 Version/14.1.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/100.0.4896.75 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
]
UAS = [UA_CHROME, UA_SAFARI, UA_FIREFOX, UA_IPHONE]

_COLUMNS = [
    "event_id",
    "timestamp",
    "username",
    "src_ip",
    "user_agent",
    "device_id",
    "site",
    "latitude",
    "longitude",
    "outcome",
    "label",
    "campaign_id",
    "scenario",
]


def build_users() -> list[dict]:
    """Fixed directory. Indexes only pick a stable user-agent."""
    rows = [
        ("ada.okonkwo", "northwind.example", "day", "192.0.2.11"),
        ("ben.cho", "northwind.example", "day", "192.0.2.12"),
        ("chioma.adebayo", "northwind.example", "day", "192.0.2.13"),
        ("david.nguyen", "northwind.example", "day", "192.0.2.14"),
        ("elena.vasquez", "northwind.example", "day", "192.0.2.15"),
        ("farid.hassan", "northwind.example", "day", "192.0.2.16"),
        ("ines.moreau", "northwind.example", "day", "192.0.2.17"),
        ("jamal.wright", "northwind.example", "day", "192.0.2.18"),
        ("kira.novak", "northwind.example", "day", "192.0.2.19"),
        ("leo.bergstrom", "northwind.example", "day", "192.0.2.20"),
        ("grace.okello", "northwind.example", "day", "2001:db8:1::10"),
        ("hiro.tanaka", "northwind.example", "day", "2001:db8:1::11"),
        ("maya.singh", "students.northwind.example", "student", "192.0.2.50"),
        ("noah.kim", "students.northwind.example", "student", "192.0.2.50"),
        ("olivia.berg", "students.northwind.example", "student", "192.0.2.50"),
        ("priya.nair", "students.northwind.example", "student", "192.0.2.50"),
        ("quinn.dalton", "students.northwind.example", "student", "192.0.2.50"),
        ("ravi.mehta", "students.northwind.example", "student", "192.0.2.50"),
        ("sofia.alvarez", "students.northwind.example", "student", "192.0.2.50"),
        ("theo.martin", "students.northwind.example", "student", "192.0.2.50"),
        ("uma.frost", "harbor.example", "day", "198.51.100.11"),
        ("victor.osei", "harbor.example", "day", "198.51.100.12"),
        ("wren.pall", "harbor.example", "day", "198.51.100.13"),
        ("xavier.dunn", "harbor.example", "day", "198.51.100.14"),
        ("yasmin.koroma", "library.northwind.example", "night", "192.0.2.31"),
        ("zoe.hart", "library.northwind.example", "night", "192.0.2.32"),
        ("amir.said", "library.northwind.example", "night", "192.0.2.33"),
        ("bea.lind", "library.northwind.example", "night", "192.0.2.34"),
    ]
    users = []
    for index, (local, domain, cohort, ip) in enumerate(rows):
        users.append(
            {
                "email": f"{local}@{domain}",
                "cohort": cohort,
                "ip": ip,
                "ua": UAS[index % len(UAS)],
                "device": f"dev-{local}-work",
                "index": index,
            }
        )
    return users


def generate_events(seed: int = SEED) -> list[dict]:
    """Return the teaching log. Raises if a scripted campaign missed its rule."""
    rng = np.random.default_rng(seed)
    users = build_users()
    by_email = {user["email"]: user for user in users}
    scripted, specs, extra_quiet = _scripted(by_email)
    _assert_scripted_spacing(scripted)
    quiet = _quiet_intervals(scripted, specs, extra_quiet)
    routine = _routine(users, rng, quiet)
    events = scripted + routine
    events.sort(key=lambda row: (row["timestamp"], row["username"], row["campaign_id"], row["outcome"]))
    for index, row in enumerate(events, start=1):
        row["event_id"] = f"evt-{index:06d}"
        ordered = {column: row.get(column, "") for column in _COLUMNS}
        row.clear()
        row.update(ordered)
    _audit(events, specs)
    return events


def demo_events() -> list[dict]:
    """A short file for the CLI: a burst, a typo, and a takeover that looks routine."""
    nora = {
        "email": "nora.quist@northwind.example",
        "ip": "192.0.2.80",
        "ua": UA_CHROME,
        "device": "dev-nora-work",
    }
    idris = {
        "email": "idris.cole@library.northwind.example",
        "ip": "192.0.2.81",
        "ua": UA_FIREFOX,
        "device": "dev-idris-work",
    }
    rows: list[dict] = []
    for stamp in (
        "2026-01-20T09:20:00Z",
        "2026-01-20T12:10:00Z",
        "2026-01-20T15:40:00Z",
        "2026-01-21T09:20:00Z",
    ):
        rows.append(_row(parse_timestamp(stamp), nora, nora["ip"], nora["ua"], nora["device"], "success", "benign", "", "routine"))
    rows.append(_row(parse_timestamp("2026-01-21T11:00:40Z"), nora, nora["ip"], nora["ua"], nora["device"], "failure", "benign", "", "routine"))
    rows.append(_row(parse_timestamp("2026-01-21T11:01:20Z"), nora, nora["ip"], nora["ua"], nora["device"], "failure", "benign", "", "routine"))
    rows.append(_row(parse_timestamp("2026-01-21T11:02:00Z"), nora, nora["ip"], nora["ua"], nora["device"], "success", "benign", "", "routine"))
    start = parse_timestamp("2026-01-21T14:10:00Z")
    for attempt in range(12):
        rows.append(
            _row(
                start + timedelta(seconds=15 * attempt),
                nora,
                "203.0.113.200",
                STUFF_UAS[0],
                "dev-demo-brute",
                "failure",
                "brute_force",
                "brute-demo",
                "attack",
            )
        )
    night = [
        "2026-01-18T23:10:00Z",
        "2026-01-19T01:05:00Z",
        "2026-01-19T03:15:00Z",
        "2026-01-19T23:40:00Z",
        "2026-01-20T01:20:00Z",
        "2026-01-20T03:05:00Z",
        "2026-01-20T23:25:00Z",
        "2026-01-21T01:15:00Z",
    ]
    for stamp in night:
        rows.append(_row(parse_timestamp(stamp), idris, idris["ip"], idris["ua"], idris["device"], "success", "benign", "", "routine"))
    rows.append(
        _row(
            parse_timestamp("2026-01-21T02:40:00Z"),
            idris,
            idris["ip"],
            idris["ua"],
            idris["device"],
            "failure",
            "stealth_takeover",
            "stealth-demo",
            "attack",
        )
    )
    rows.append(
        _row(
            parse_timestamp("2026-01-21T02:41:30Z"),
            idris,
            idris["ip"],
            idris["ua"],
            idris["device"],
            "success",
            "stealth_takeover",
            "stealth-demo",
            "attack",
        )
    )
    rows.sort(key=lambda row: (row["timestamp"], row["username"], row["outcome"]))
    for index, row in enumerate(rows, start=1):
        row["event_id"] = f"demo-{index:04d}"
        ordered = {column: row.get(column, "") for column in _COLUMNS}
        row.clear()
        row.update(ordered)
    return rows


def _scripted(by_email: dict[str, dict]) -> tuple[list[dict], list[dict], list[tuple]]:
    events: list[dict] = []
    specs: list[dict] = []
    extra: list[tuple] = []

    def add_spec(campaign_id: str, label: str, scenario: str, expect_rule: str | None, pad: int) -> None:
        specs.append(
            {
                "campaign_id": campaign_id,
                "label": label,
                "scenario": scenario,
                "expect_rule": expect_rule,
                "pad_minutes": pad,
            }
        )

    def burst(campaign_id, label, expect, user, ip, start, count, spacing, ua, device, outcomes="failures"):
        add_spec(campaign_id, label, "attack", expect, 80)
        stamp = parse_timestamp(start)
        for attempt in range(count):
            outcome = "failure"
            if outcomes == "success_last" and attempt == count - 1:
                outcome = "success"
            events.append(
                _row(
                    stamp + timedelta(seconds=spacing * attempt),
                    user,
                    ip,
                    ua,
                    device,
                    outcome,
                    label,
                    campaign_id,
                    "attack",
                )
            )

    def singles(campaign_id, label, scenario, expect, user, ip, start, ua, device, outcome="success", pad=25):
        add_spec(campaign_id, label, scenario, expect, pad)
        events.append(
            _row(parse_timestamp(start), user, ip, ua, device, outcome, label, campaign_id, scenario)
        )

    spray_users = [user for user in by_email.values() if user["cohort"] in {"student", "night"} or user["email"].endswith("@harbor.example")]
    stuff_users = [
        user
        for user in by_email.values()
        if user["cohort"] == "student" or user["email"].endswith("@harbor.example") and user["email"] != "uma.frost@harbor.example"
    ]
    students = [user for user in by_email.values() if user["cohort"] == "student"]

    def spray(campaign_id, start, ip):
        add_spec(campaign_id, "password_spray", "attack", "password_spray", 80)
        stamp = parse_timestamp(start)
        for index, user in enumerate(spray_users):
            events.append(
                _row(
                    stamp + timedelta(seconds=8 * index),
                    user,
                    ip,
                    UA_CHROME,
                    f"dev-{campaign_id}",
                    "failure",
                    "password_spray",
                    campaign_id,
                    "attack",
                )
            )

    def stuff(campaign_id, start, ip):
        add_spec(campaign_id, "credential_stuffing", "attack", "credential_stuffing", 80)
        stamp = parse_timestamp(start)
        order = stuff_users + stuff_users
        for index, user in enumerate(order):
            events.append(
                _row(
                    stamp + timedelta(seconds=6 * index),
                    user,
                    ip,
                    STUFF_UAS[index % len(STUFF_UAS)],
                    f"dev-{campaign_id}-{index % len(STUFF_UAS)}",
                    "failure",
                    "credential_stuffing",
                    campaign_id,
                    "attack",
                )
            )

    def tiny(campaign_id, start, ip):
        add_spec(campaign_id, "password_spray", "attack", None, 80)
        stamp = parse_timestamp(start)
        for index, user in enumerate(students[:4]):
            events.append(
                _row(
                    stamp + timedelta(seconds=20 * index),
                    user,
                    ip,
                    UA_CHROME,
                    f"dev-{campaign_id}",
                    "failure",
                    "password_spray",
                    campaign_id,
                    "attack",
                )
            )

    def dist(campaign_id, user, start):
        add_spec(campaign_id, "credential_stuffing", "attack", "credential_stuffing", 80)
        stamp = parse_timestamp(start)
        ips = [f"203.0.113.{host}" for host in range(191, 197)]
        attempt = 0
        for ip in ips:
            for _ in range(2):
                events.append(
                    _row(
                        stamp + timedelta(minutes=4 * attempt),
                        user,
                        ip,
                        STUFF_UAS[attempt % len(STUFF_UAS)],
                        f"dev-{campaign_id}-{attempt % len(STUFF_UAS)}",
                        "failure",
                        "credential_stuffing",
                        campaign_id,
                        "attack",
                    )
                )
                attempt += 1

    def slow(campaign_id, user, start):
        add_spec(campaign_id, "brute_force", "attack", None, 80)
        stamp = parse_timestamp(start)
        for attempt in range(8):
            events.append(
                _row(
                    stamp + timedelta(minutes=50 * attempt),
                    user,
                    user["ip"],
                    user["ua"],
                    user["device"],
                    "failure",
                    "brute_force",
                    campaign_id,
                    "attack",
                )
            )

    def success_after(campaign_id, user, start):
        add_spec(campaign_id, "success_after_failures", "attack", "success_after_failures", 80)
        stamp = parse_timestamp(start)
        for attempt in range(7):
            events.append(
                _row(
                    stamp + timedelta(seconds=20 * attempt),
                    user,
                    user["ip"],
                    user["ua"],
                    user["device"],
                    "failure",
                    "success_after_failures",
                    campaign_id,
                    "attack",
                )
            )
        events.append(
            _row(
                stamp + timedelta(seconds=20 * 7),
                user,
                user["ip"],
                user["ua"],
                user["device"],
                "success",
                "success_after_failures",
                campaign_id,
                "attack",
            )
        )

    def stealth(campaign_id, user, start):
        add_spec(campaign_id, "stealth_takeover", "attack", None, 40)
        stamp = parse_timestamp(start)
        events.append(
            _row(stamp, user, user["ip"], user["ua"], user["device"], "failure", "stealth_takeover", campaign_id, "attack")
        )
        events.append(
            _row(
                stamp + timedelta(seconds=90),
                user,
                user["ip"],
                user["ua"],
                user["device"],
                "success",
                "stealth_takeover",
                campaign_id,
                "attack",
            )
        )

    def travel(campaign_id, user, start):
        """Home success, then a far success 20 minutes later."""
        add_spec(campaign_id, "impossible_travel", "attack", "impossible_travel", 40)
        stamp = parse_timestamp(start)
        events.append(
            _row(stamp, user, user["ip"], user["ua"], user["device"], "success", "benign", "", "anchor")
        )
        events.append(
            _row(
                stamp + timedelta(minutes=20),
                user,
                "203.0.113.90",
                user["ua"],
                user["device"],
                "success",
                "impossible_travel",
                campaign_id,
                "attack",
            )
        )
        # Keep the next success far enough out that the trip home is not a second
        # impossible-travel alert. Campus is already a known site, so once the
        # gap clears 180 minutes the return is ordinary.
        extra.append((user["email"], stamp - timedelta(hours=6), stamp + timedelta(hours=18)))

    def geo(campaign_id, user, attack_start, ip):
        add_spec(campaign_id, "unusual_geography", "attack", "unusual_geography", 40)
        stamp = parse_timestamp(attack_start)
        events.append(
            _row(stamp, user, ip, user["ua"], user["device"], "success", "unusual_geography", campaign_id, "attack")
        )
        # Quiet before the sign-in so the previous success is hours old, and quiet
        # after it so the trip back to campus is not scored as impossible travel.
        extra.append((user["email"], stamp - timedelta(hours=40), stamp + timedelta(hours=18)))

    def new_device(campaign_id, user, start, label, scenario, expect):
        add_spec(campaign_id, label, scenario, expect, 40)
        events.append(
            _row(
                parse_timestamp(start),
                user,
                user["ip"],
                NEW_UA,
                f"dev-{campaign_id}",
                "success",
                label,
                campaign_id,
                scenario,
            )
        )

    def off_hours(campaign_id, user, start, label, scenario, expect):
        add_spec(campaign_id, label, scenario, expect, 40)
        events.append(
            _row(
                parse_timestamp(start),
                user,
                user["ip"],
                user["ua"],
                user["device"],
                "success",
                label,
                campaign_id,
                scenario,
            )
        )

    def annex(campaign_id, user, start):
        add_spec(campaign_id, "benign", "false_positive", "unusual_geography", 40)
        stamp = parse_timestamp(start)
        events.append(
            _row(
                stamp,
                user,
                "198.51.100.40",
                user["ua"],
                user["device"],
                "success",
                "benign",
                campaign_id,
                "false_positive",
            )
        )
        extra.append((user["email"], stamp - timedelta(hours=8), stamp - timedelta(minutes=1)))

    def mistype(campaign_id, start):
        add_spec(campaign_id, "benign", "benign_mistype", None, 40)
        stamp = parse_timestamp(start)
        for index, user in enumerate(students[:4]):
            events.append(
                _row(
                    stamp + timedelta(seconds=25 * index),
                    user,
                    user["ip"],
                    user["ua"],
                    user["device"],
                    "failure",
                    "benign",
                    campaign_id,
                    "benign_mistype",
                )
            )

    def partner_visit(campaign_id, user, start, ip, expect, scenario):
        add_spec(campaign_id, "benign", scenario, expect, 40)
        stamp = parse_timestamp(start)
        events.append(
            _row(stamp, user, ip, user["ua"], user["device"], "success", "benign", campaign_id, scenario)
        )

    # Fit window -----------------------------------------------------------
    burst("brute-fit-1", "brute_force", "brute_force_burst", by_email["ben.cho@northwind.example"], "203.0.113.150", "2026-01-06T14:10:00Z", 16, 15, STUFF_UAS[0], "dev-brute-fit-1")
    spray("spray-fit-1", "2026-01-07T11:00:00Z", "203.0.113.160")
    stuff("stuff-fit-1", "2026-01-08T15:10:00Z", "203.0.113.170")
    dist("stuff-dist-fit-1", by_email["chioma.adebayo@northwind.example"], "2026-01-09T10:00:00Z")
    travel("travel-fit-1", by_email["david.nguyen@northwind.example"], "2026-01-10T09:00:00Z")
    geo("geo-fit-1", by_email["farid.hassan@northwind.example"], "2026-01-12T15:00:00Z", "203.0.113.100")
    off_hours("offhours-fit-1", by_email["ines.moreau@northwind.example"], "2026-01-08T03:10:00Z", "off_hours", "attack", "off_hours")
    new_device("newdev-fit-1", by_email["jamal.wright@northwind.example"], "2026-01-12T11:00:00Z", "new_device", "attack", "new_device")
    success_after("success-fit-1", by_email["leo.bergstrom@northwind.example"], "2026-01-12T16:10:00Z")
    slow("slow-brute-fit-1", by_email["leo.bergstrom@northwind.example"], "2026-01-07T08:10:00Z")
    tiny("tiny-spray-fit-1", "2026-01-08T09:40:00Z", "203.0.113.181")
    stealth("stealth-fit-1", by_email["yasmin.koroma@library.northwind.example"], "2026-01-07T01:20:00Z")
    new_device("fp-laptop-fit-1", by_email["elena.vasquez@northwind.example"], "2026-01-12T10:00:00Z", "benign", "false_positive", "new_device")
    off_hours("fp-oncall-fit-1", by_email["hiro.tanaka@northwind.example"], "2026-01-09T03:15:00Z", "benign", "false_positive", "off_hours")
    annex("fp-annex-fit-1", by_email["ben.cho@northwind.example"], "2026-01-11T15:00:00Z")
    mistype("benign-mistype-fit", "2026-01-06T11:30:00Z")
    partner_visit("fp-travel-fit-1", by_email["ada.okonkwo@northwind.example"], "2026-01-09T16:00:00Z", "203.0.113.10", "unusual_geography", "false_positive")
    # Later Westport sign-ins are the same site, so the rule should stay quiet.
    events.append(
        _row(
            parse_timestamp("2026-01-10T11:00:00Z"),
            by_email["ada.okonkwo@northwind.example"],
            "203.0.113.10",
            by_email["ada.okonkwo@northwind.example"]["ua"],
            by_email["ada.okonkwo@northwind.example"]["device"],
            "success",
            "benign",
            "",
            "benign_travel",
        )
    )
    events.append(
        _row(
            parse_timestamp("2026-01-11T18:00:00Z"),
            by_email["ada.okonkwo@northwind.example"],
            by_email["ada.okonkwo@northwind.example"]["ip"],
            by_email["ada.okonkwo@northwind.example"]["ua"],
            by_email["ada.okonkwo@northwind.example"]["device"],
            "success",
            "benign",
            "",
            "benign_travel",
        )
    )
    extra.append(
        (
            "ada.okonkwo@northwind.example",
            parse_timestamp("2026-01-08T16:00:00Z"),
            parse_timestamp("2026-01-11T20:00:00Z"),
        )
    )

    # Validation window ----------------------------------------------------
    burst("brute-val-1", "brute_force", "brute_force_burst", by_email["ben.cho@northwind.example"], "203.0.113.152", "2026-01-13T14:10:00Z", 16, 15, STUFF_UAS[1], "dev-brute-val-1")
    spray("spray-val-1", "2026-01-13T16:20:00Z", "203.0.113.162")
    new_device("fp-laptop-val-1", by_email["david.nguyen@northwind.example"], "2026-01-14T11:00:00Z", "benign", "false_positive", "new_device")

    # Test window ----------------------------------------------------------
    burst("brute-test-1", "brute_force", "brute_force_burst", by_email["ben.cho@northwind.example"], "203.0.113.150", "2026-01-15T14:10:00Z", 16, 15, STUFF_UAS[0], "dev-brute-test-1")
    burst("brute-test-2", "brute_force", "brute_force_burst", by_email["chioma.adebayo@northwind.example"], "203.0.113.151", "2026-01-17T09:20:00Z", 16, 15, STUFF_UAS[1], "dev-brute-test-2")
    spray("spray-test-1", "2026-01-15T11:05:00Z", "203.0.113.160")
    spray("spray-test-2", "2026-01-18T10:15:00Z", "203.0.113.161")
    stuff("stuff-test-1", "2026-01-16T13:00:00Z", "203.0.113.170")
    dist("stuff-dist-test-1", by_email["jamal.wright@northwind.example"], "2026-01-17T10:00:00Z")
    travel("travel-test-1", by_email["david.nguyen@northwind.example"], "2026-01-15T09:00:00Z")
    travel("travel-test-2", by_email["ines.moreau@northwind.example"], "2026-01-18T13:00:00Z")
    geo("geo-test-1", by_email["kira.novak@northwind.example"], "2026-01-17T12:00:00Z", "203.0.113.101")
    geo("geo-test-2", by_email["hiro.tanaka@northwind.example"], "2026-01-18T14:00:00Z", "203.0.113.102")
    off_hours("offhours-test-1", by_email["elena.vasquez@northwind.example"], "2026-01-16T03:05:00Z", "off_hours", "attack", "off_hours")
    off_hours("offhours-test-2", by_email["leo.bergstrom@northwind.example"], "2026-01-18T03:30:00Z", "off_hours", "attack", "off_hours")
    new_device("newdev-test-1", by_email["chioma.adebayo@northwind.example"], "2026-01-15T10:30:00Z", "new_device", "attack", "new_device")
    new_device("newdev-test-2", by_email["ben.cho@northwind.example"], "2026-01-16T11:00:00Z", "new_device", "attack", "new_device")
    new_device("newdev-test-3", by_email["uma.frost@harbor.example"], "2026-01-16T16:40:00Z", "new_device", "attack", "new_device")
    success_after("success-test-1", by_email["jamal.wright@northwind.example"], "2026-01-15T16:00:00Z")
    success_after("success-test-2", by_email["farid.hassan@northwind.example"], "2026-01-18T09:40:00Z")
    slow("slow-brute-test-1", by_email["grace.okello@northwind.example"], "2026-01-16T08:15:00Z")
    tiny("tiny-spray-test-1", "2026-01-17T11:40:00Z", "203.0.113.182")
    stealth("stealth-test-1", by_email["zoe.hart@library.northwind.example"], "2026-01-16T02:10:00Z")
    new_device("fp-laptop-test-1", by_email["hiro.tanaka@northwind.example"], "2026-01-15T15:00:00Z", "benign", "false_positive", "new_device")
    new_device("fp-laptop-test-2", by_email["leo.bergstrom@northwind.example"], "2026-01-17T11:00:00Z", "benign", "false_positive", "new_device")
    new_device("fp-laptop-test-3", by_email["ines.moreau@northwind.example"], "2026-01-17T10:30:00Z", "benign", "false_positive", "new_device")
    off_hours("fp-oncall-test-1", by_email["leo.bergstrom@northwind.example"], "2026-01-16T03:20:00Z", "benign", "false_positive", "off_hours")
    off_hours("fp-oncall-test-2", by_email["ben.cho@northwind.example"], "2026-01-18T04:10:00Z", "benign", "false_positive", "off_hours")
    annex("fp-annex-test-1", by_email["elena.vasquez@northwind.example"], "2026-01-17T15:00:00Z")
    partner_visit(
        "fp-travel-test-1",
        by_email["chioma.adebayo@northwind.example"],
        "2026-01-17T16:00:00Z",
        "203.0.113.11",
        "unusual_geography",
        "false_positive",
    )
    extra.append(
        (
            "chioma.adebayo@northwind.example",
            parse_timestamp("2026-01-15T18:00:00Z"),
            parse_timestamp("2026-01-17T15:59:00Z"),
        )
    )
    # Ada's second trip is a known site. It should not alert.
    events.append(
        _row(
            parse_timestamp("2026-01-17T16:00:00Z"),
            by_email["ada.okonkwo@northwind.example"],
            "203.0.113.10",
            by_email["ada.okonkwo@northwind.example"]["ua"],
            by_email["ada.okonkwo@northwind.example"]["device"],
            "success",
            "benign",
            "",
            "benign_travel",
        )
    )
    events.append(
        _row(
            parse_timestamp("2026-01-18T11:00:00Z"),
            by_email["ada.okonkwo@northwind.example"],
            "203.0.113.10",
            by_email["ada.okonkwo@northwind.example"]["ua"],
            by_email["ada.okonkwo@northwind.example"]["device"],
            "success",
            "benign",
            "",
            "benign_travel",
        )
    )
    extra.append(
        (
            "ada.okonkwo@northwind.example",
            parse_timestamp("2026-01-16T12:00:00Z"),
            parse_timestamp("2026-01-18T20:00:00Z"),
        )
    )
    return events, specs, extra


def _quiet_intervals(events: list[dict], specs: list[dict], extra: list[tuple]) -> list[tuple]:
    pads = {spec["campaign_id"]: spec["pad_minutes"] for spec in specs}
    grouped: dict[str, list[dict]] = defaultdict(list)
    intervals = list(extra)
    for row in events:
        if row["campaign_id"]:
            grouped[row["campaign_id"]].append(row)
        else:
            stamp = parse_timestamp(row["timestamp"])
            intervals.append((row["username"], stamp - timedelta(minutes=20), stamp + timedelta(minutes=20)))
    for campaign_id, rows in grouped.items():
        stamps = [parse_timestamp(row["timestamp"]) for row in rows]
        pad = timedelta(minutes=pads.get(campaign_id, 40))
        start = min(stamps) - pad
        end = max(stamps) + pad
        for username in {row["username"] for row in rows}:
            intervals.append((username, start, end))
    return intervals


def _blocked(username: str, stamp: datetime, intervals: list[tuple]) -> bool:
    for user, start, end in intervals:
        if user == username and start <= stamp <= end:
            return True
    return False


def _routine(users: list[dict], rng: np.random.Generator, intervals: list[tuple]) -> list[dict]:
    rows: list[dict] = []
    day = LOG_START.date()
    while day < LOG_END.date():
        for user in users:
            if user["cohort"] == "night":
                for hour, minute in ((23, 10), (3, 10)):
                    stamp = datetime(
                        day.year,
                        day.month,
                        day.day,
                        hour,
                        minute,
                        tzinfo=timezone.utc,
                    ) + timedelta(minutes=int(user["index"] % 4) + int(rng.integers(0, 8)))
                    _session(rows, user, stamp, rng, intervals)
                continue
            if user["cohort"] == "student":
                if day.weekday() < 5:
                    for hour, minute in ((9, 5), (13, 5)):
                        stamp = datetime(day.year, day.month, day.day, hour, minute, tzinfo=timezone.utc)
                        stamp += timedelta(seconds=40 * (user["index"] % 8))
                        _session(rows, user, stamp, rng, intervals)
                    if float(rng.random()) < 0.45:
                        extra = datetime(day.year, day.month, day.day, 17, 30, tzinfo=timezone.utc)
                        extra += timedelta(minutes=int(rng.integers(0, 20)))
                        _session(rows, user, extra, rng, intervals)
                elif float(rng.random()) < 0.4:
                    stamp = datetime(day.year, day.month, day.day, 15, 0, tzinfo=timezone.utc)
                    stamp += timedelta(minutes=int(rng.integers(0, 30)))
                    _session(rows, user, stamp, rng, intervals)
                continue
            if day.weekday() >= 5:
                if float(rng.random()) < 0.35:
                    stamp = datetime(day.year, day.month, day.day, 11, 0, tzinfo=timezone.utc)
                    stamp += timedelta(minutes=int(user["index"] % 5) + int(rng.integers(0, 15)))
                    _session(rows, user, stamp, rng, intervals)
                continue
            for hour, minute in ((9, 15), (15, 30)):
                stamp = datetime(day.year, day.month, day.day, hour, minute, tzinfo=timezone.utc)
                stamp += timedelta(minutes=int(user["index"] % 5) + int(rng.integers(0, 12)))
                _session(rows, user, stamp, rng, intervals)
            if float(rng.random()) < 0.35:
                stamp = datetime(day.year, day.month, day.day, 12, 5, tzinfo=timezone.utc)
                stamp += timedelta(minutes=int(rng.integers(0, 20)))
                _session(rows, user, stamp, rng, intervals)
        day += timedelta(days=1)
    return rows


def _session(rows: list[dict], user: dict, stamp: datetime, rng: np.random.Generator, intervals: list[tuple]) -> None:
    if stamp < LOG_START or stamp >= LOG_END or _blocked(user["email"], stamp, intervals):
        return
    roll = float(rng.random())
    fails = 2 if roll < 0.03 else 1 if roll < 0.15 else 0
    for index in range(fails, 0, -1):
        rows.append(
            _row(
                stamp - timedelta(seconds=40 * index),
                user,
                user["ip"],
                user["ua"],
                user["device"],
                "failure",
                "benign",
                "",
                "routine",
            )
        )
    rows.append(
        _row(stamp, user, user["ip"], user["ua"], user["device"], "success", "benign", "", "routine")
    )


def _row(stamp, user, ip, ua, device, outcome, label, campaign_id, scenario) -> dict:
    if isinstance(user, dict):
        email = user["email"]
    else:
        email = user
    site, lat, lon = site_for_ip(ip)
    return {
        "timestamp": format_timestamp(stamp),
        "username": email,
        "src_ip": str(ipaddress.ip_address(ip)),
        "user_agent": ua,
        "device_id": device,
        "site": site,
        "latitude": round(lat, 4),
        "longitude": round(lon, 4),
        "outcome": outcome,
        "label": label,
        "campaign_id": campaign_id,
        "scenario": scenario,
    }


def _assert_scripted_spacing(events: list[dict]) -> None:
    per_user: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
    for row in events:
        if not row["campaign_id"]:
            continue
        per_user[row["username"]].append((parse_timestamp(row["timestamp"]), row["campaign_id"]))
    for username, items in per_user.items():
        items.sort()
        for (left_ts, left_id), (right_ts, right_id) in zip(items, items[1:]):
            if left_id == right_id:
                continue
            gap = right_ts - left_ts
            if gap < timedelta(hours=3):
                raise AssertionError(
                    f"{username} has {left_id} and {right_id} {gap} apart. Campaigns would share a window."
                )


def _audit(events: list[dict], specs: list[dict]) -> None:
    frame = pd.DataFrame(events)
    frame["timestamp"] = frame["timestamp"].map(parse_timestamp)
    featured = engineer(frame)
    by_campaign: dict[str, list[dict]] = defaultdict(list)
    for row in featured.to_dict(orient="records"):
        by_campaign[row["campaign_id"]].append(row)
        addr = ipaddress.ip_address(row["src_ip"])
        if not any(addr in network for network in ALLOWED_NETWORKS):
            raise AssertionError(f"{row['src_ip']} is not a documentation address")
        if not str(row["username"]).endswith(".example"):
            raise AssertionError(f"username {row['username']} is not on a .example domain")
        if row["label"] not in {"benign", *ATTACK_TYPES}:
            raise AssertionError(f"unexpected label {row['label']}")
        if row["label"] == "benign" and set(row["rules"]) & {
            "password_spray",
            "credential_stuffing",
            "brute_force_burst",
            "success_after_failures",
            "impossible_travel",
        }:
            raise AssertionError(f"benign {row['event_id']} fired {row['rules']}")
        if row.get("scenario") == "benign_travel" and row["rules"]:
            raise AssertionError(f"quiet travel {row['event_id']} fired {row['rules']}")
        if row["label"] == "benign" and row["fail_count_user_15m"] > 2:
            raise AssertionError(
                f"benign {row['event_id']} has {row['fail_count_user_15m']} failures in 15 minutes"
            )
    for spec in specs:
        rows = by_campaign.get(spec["campaign_id"], [])
        if not rows:
            raise AssertionError(f"{spec['campaign_id']} produced no events")
        fired = {rule for row in rows for rule in row["rules"]}
        if spec["expect_rule"] is None:
            if fired:
                raise AssertionError(f"{spec['campaign_id']} should be quiet, fired {fired}")
        elif spec["expect_rule"] not in fired:
            sample = rows[-1]
            raise AssertionError(
                f"{spec['campaign_id']} expected {spec['expect_rule']} but fired {fired}. "
                f"last row deviation={sample['hour_deviation']:.2f} "
                f"prior={sample['prior_successes']} unseen_site={sample['unseen_site']} "
                f"speed={sample['geo_speed_kmh']:.1f} minutes={sample['minutes_since_prev_success']:.1f} "
                f"fails15={sample['fail_count_user_15m']} users15={sample['distinct_users_ip_15m']} "
                f"uas={sample['distinct_ua_ip_15m']} ips60={sample['distinct_ips_user_60m']}"
            )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write the synthetic LogSentinel sign-in log.")
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--csv", type=Path, default=DATA_PATH)
    parser.add_argument("--demo", type=Path, default=DEMO_PATH)
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    rows = generate_events(seed=args.seed)
    write_logs(args.csv, rows)
    demo = demo_events()
    args.demo.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(demo).to_csv(args.demo, index=False)
    labels = pd.Series([row["label"] for row in rows]).value_counts().to_dict()
    print(f"Wrote {len(rows)} events to {args.csv} and {args.csv.with_suffix('.json')}")
    print(f"Wrote {len(demo)} demo events to {args.demo}")
    for label, count in sorted(labels.items()):
        print(f"  {label}: {count}")
