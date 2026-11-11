"""Local Streamlit review for LogSentinel.

Run from the repository root:

    streamlit run src/app.py

The page scores a log on this machine. It does not geolocate addresses and it
does not send the file anywhere. Upload a CSV or JSON export, or open the
synthetic sample that ships with the repo.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pandas as pd
import streamlit as st

from src.constants import DISCLAIMER
from src.logs import format_timestamp, load_log
from src.model import load_bundle, score_frame
from src.paths import DATA_PATH, METRICS_PATH
from src.score import missed_campaigns

st.set_page_config(
    page_title="LogSentinel",
    page_icon="◎",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .block-container {padding-top: 1.4rem; padding-bottom: 3rem; max-width: 1180px;}
    .logsentinel-kicker {letter-spacing: 0.14em; text-transform: uppercase;
        font-size: 0.78rem; color: #8A6A2F; margin-bottom: 0.2rem;}
    div[data-testid="stMetric"] {background: #EBE4D4; padding: 0.6rem 0.8rem; border-radius: 8px;}
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def cached_bundle():
    return load_bundle()


@st.cache_data
def cached_metrics() -> dict | None:
    if not METRICS_PATH.exists():
        return None
    return json.loads(METRICS_PATH.read_text(encoding="utf-8"))


@st.cache_data
def cached_sample() -> pd.DataFrame:
    frame, _warnings = load_log(DATA_PATH)
    return frame


def _display_table(scored: pd.DataFrame) -> pd.DataFrame:
    alerts = scored[scored["alert"]].copy()
    if alerts.empty:
        return alerts
    alerts["when"] = alerts["timestamp"].map(format_timestamp)
    alerts["reason"] = alerts["reasons"].map(
        lambda items: items[0]["text"] if items else "Anomaly score only."
    )
    columns = ["when", "username", "src_ip", "outcome", "primary_reason", "reason"]
    if "label" in alerts.columns:
        alerts["generator_label"] = alerts["label"]
        columns.append("generator_label")
    return alerts[columns]


def _render_detail(row: pd.Series) -> None:
    if row["reasons"]:
        for reason in row["reasons"]:
            st.markdown(f"**{reason['id']}.** {reason['text']}")
    else:
        st.markdown(row["model_note"])
    st.caption(row["model_note"])
    st.markdown("**Largest gaps versus the benign baseline**")
    st.dataframe(pd.DataFrame(row["top_features"]), hide_index=True, use_container_width=True)
    st.markdown(
        f"**Supervised baseline:** {row['lr_label']} "
        f"({row['lr_confidence']:.0%} of the linear model's probability). "
        "The baseline does not decide the alert. It was fit on generator labels, "
        "which a real export does not have."
    )
    st.dataframe(pd.DataFrame(row["lr_top_features"]), hide_index=True, use_container_width=True)


st.markdown('<p class="logsentinel-kicker">Authentication log review</p>', unsafe_allow_html=True)
st.title("LogSentinel")
st.write(
    "Flags suspicious sign-ins in a log you already have, and names the rule or "
    "the feature gap that fired. Brute-force bursts, password spraying, credential "
    "stuffing, impossible travel, a new site, off-hours, a new device, and a success "
    "after a run of failures."
)
st.caption(DISCLAIMER)

with st.sidebar:
    st.header("Log")
    upload = st.file_uploader("CSV or JSON export", type=["csv", "json"])
    st.caption(
        "The sample is synthetic: .example usernames and documentation IP ranges. "
        "LogSentinel does not geolocate addresses and does not try passwords."
    )
    metrics = cached_metrics()
    if metrics:
        binary = metrics["binary_test"]
        st.metric("Test precision", f"{binary['precision']:.3f}")
        st.metric("Test recall", f"{binary['recall']:.3f}")
        st.metric("Test F1", f"{binary['f1']:.3f}")
        st.caption(DISCLAIMER)
        st.caption(
            f"Time split, seed {metrics['seed']}. "
            f"Campaigns detected {metrics['campaigns_detected']}/{metrics['campaigns_total']}."
        )

try:
    bundle = cached_bundle()
    if upload is None:
        frame = cached_sample()
        warnings: list[str] = []
        source_name = DATA_PATH.name
    else:
        frame, warnings = load_log(upload.getvalue())
        source_name = upload.name
    scored = score_frame(frame, bundle)
except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
    st.error(str(exc))
    st.stop()

for warning in warnings:
    st.warning(warning)

alerts = scored[scored["alert"]]
left, right = st.columns(2)
left.metric("Events", len(scored))
right.metric("Alerts", len(alerts))
st.caption(f"Source: {source_name}. Rules fire on thresholds. Isolation Forest adds a score.")
st.caption(
    "Rows at the start of a file can alert because that account has no earlier success in the file. "
    "The precision, recall, and F1 in the sidebar are the later test window only."
)

if "label" in scored.columns:
    st.caption(
        "This file includes a generator label. The detector does not read it. "
        "A production export will not have that column."
    )

chart_left, chart_right = st.columns(2)
if alerts.empty:
    chart_left.info("No alerts in this log.")
else:
    by_day = (
        alerts.assign(day=alerts["timestamp"].map(lambda stamp: format_timestamp(stamp)[:10]))
        .groupby("day")
        .size()
    )
    chart_left.markdown("**Alerts by day**")
    chart_left.bar_chart(by_day)
    by_reason = alerts["primary_reason"].value_counts()
    chart_right.markdown("**Alerts by primary reason**")
    chart_right.bar_chart(by_reason)

st.subheader("Alerts")
table = _display_table(scored)
if table.empty:
    st.info("Nothing crossed a rule or the forest threshold.")
else:
    st.dataframe(table, hide_index=True, use_container_width=True)
    labels = {
        str(row.event_id): f"{row.event_id}  {row.primary_reason}  {row.username}"
        for row in alerts.itertuples(index=False)
    }
    selected = st.selectbox("Explain an alert", options=list(labels), format_func=lambda key: labels[key])
    detail = alerts[alerts["event_id"].astype(str) == str(selected)].iloc[0]
    _render_detail(detail)

if "label" in scored.columns:
    st.subheader("Generator labels with no alert")
    missed = missed_campaigns(scored)
    if not missed:
        st.write("Every labelled attack campaign in this file produced at least one alert.")
    else:
        st.write(
            "These campaigns carry an attack label and produced no alert. "
            "Slow bursts stay under the 15-minute and 60-minute windows. "
            "A four-account spray stays under the username threshold. "
            "A takeover from the usual address, at the usual hour, with the usual client, "
            "matches a typo."
        )
        st.dataframe(pd.DataFrame(missed), hide_index=True, use_container_width=True)
        for row in missed:
            st.markdown(
                f"**{row['campaign_id']}** — {row['attack_type']}, {row['events']} events, {row['username']}"
            )
