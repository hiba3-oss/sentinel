"""Sentinel Security Operations Center dashboard."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from sentinel.dashboard.data import (
    clear_dashboard_cache,
    get_alert_timeline,
    get_alerts,
    get_alerts_by_rule,
    get_alerts_by_severity,
    get_alerts_by_source_ip,
    get_dashboard_stats,
    get_incidents,
    get_incidents_by_severity,
    get_incidents_by_status,
)

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="Sentinel SOC",
    page_icon="S",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================================
# STYLE
# ============================================================================

st.markdown(
    """
    <style>
        .block-container {
            padding-top: 1.5rem;
            padding-bottom: 2rem;
            max-width: 1550px;
        }

        .sentinel-header {
            padding: 1.4rem 1.6rem;
            border-radius: 14px;
            background:
                linear-gradient(
                    135deg,
                    #0f172a 0%,
                    #1e293b 100%
                );
            border: 1px solid #334155;
            margin-bottom: 1.4rem;
        }

        .sentinel-title {
            font-size: 2rem;
            font-weight: 750;
            color: #f8fafc;
            margin: 0;
        }

        .sentinel-subtitle {
            margin-top: 0.35rem;
            color: #94a3b8;
            font-size: 0.95rem;
        }

        .status-online {
            display: inline-block;
            padding: 0.3rem 0.7rem;
            border-radius: 999px;
            background: #064e3b;
            color: #6ee7b7;
            font-size: 0.78rem;
            font-weight: 700;
        }

        div[data-testid="stMetric"] {
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 0.9rem;
        }

        .empty-state {
            padding: 2rem;
            text-align: center;
            border: 1px dashed #475569;
            border-radius: 12px;
            color: #94a3b8;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================================
# HELPERS
# ============================================================================


def severity_label(severity: str) -> str:
    """Return a readable severity label."""

    labels = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
    }

    return labels.get(
        str(severity).lower(),
        str(severity).upper(),
    )


def status_label(status: str) -> str:
    """Return a readable incident status."""

    labels = {
        "open": "OPEN",
        "investigating": "INVESTIGATING",
        "resolved": "RESOLVED",
    }

    return labels.get(
        str(status).lower(),
        str(status).upper(),
    )


def show_empty_state(message: str) -> None:
    """Display a consistent empty state."""

    st.markdown(
        f'<div class="empty-state">{message}</div>',
        unsafe_allow_html=True,
    )


# ============================================================================
# SIDEBAR
# ============================================================================

with st.sidebar:
    st.markdown("## Sentinel")

    st.caption(
        "Defensive Cybersecurity Monitoring"
    )

    st.divider()

    st.markdown("### Navigation")

    page = st.radio(
        "Section",
        [
            "Overview",
            "Alerts",
            "Incidents",
        ],
        label_visibility="collapsed",
    )

    st.divider()

    st.markdown("### System")

    st.markdown(
        '<span class="status-online">DATABASE ONLINE</span>',
        unsafe_allow_html=True,
    )

    st.caption(
        "SQLite / read-only dashboard"
    )

    st.divider()

    if st.button(
        "Refresh data",
        width="stretch",
    ):
        clear_dashboard_cache()
        st.rerun()

    st.caption(
        "Automatic cache refresh: 5 seconds"
    )


# ============================================================================
# HEADER
# ============================================================================

st.markdown(
    "## Sentinel Security Operations Center"
)

st.caption(
    "Defensive threat monitoring, detection and incident visibility"
)


# ============================================================================
# DATABASE
# ============================================================================

try:
    stats = get_dashboard_stats()

except Exception as exc:
    st.error(
        "Impossible de charger la base Sentinel."
    )

    st.markdown(
        """
        Vérifie que la base suivante existe :

        `data/sentinel.db`
        """
    )

    st.exception(exc)
    st.stop()


# ============================================================================
# OVERVIEW
# ============================================================================

if page == "Overview":

    st.markdown("## Security Overview")

    st.caption(
        "Real-time visibility into alerts, incidents and risk."
    )

    # ------------------------------------------------------------------------
    # KPI
    # ------------------------------------------------------------------------

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Total Alerts",
            stats["total_alerts"],
        )

    with col2:
        st.metric(
            "Critical",
            stats["critical_alerts"],
        )

    with col3:
        st.metric(
            "High",
            stats["high_alerts"],
        )

    with col4:
        st.metric(
            "Open Incidents",
            stats["open_incidents"],
        )

    # ------------------------------------------------------------------------
    # ALERT ACTIVITY
    # ------------------------------------------------------------------------

    st.markdown("### Alert Activity")

    try:
        timeline_df = get_alert_timeline()

    except Exception as exc:
        st.error(
            "Unable to load alert activity."
        )
        st.exception(exc)

    else:
        if timeline_df.empty:
            show_empty_state(
                "No alert activity has been recorded yet."
            )

        elif "timestamp" not in timeline_df.columns:
            show_empty_state(
                "Alert timeline data is unavailable."
            )

        elif "count" not in timeline_df.columns:
            show_empty_state(
                "Alert timeline count data is unavailable."
            )

        else:
            timeline_chart = timeline_df[
                [
                    "timestamp",
                    "count",
                ]
            ].copy()

            timeline_chart["timestamp"] = pd.to_datetime(
                timeline_chart["timestamp"],
                errors="coerce",
            )

            timeline_chart["count"] = pd.to_numeric(
                timeline_chart["count"],
                errors="coerce",
            )

            timeline_chart = timeline_chart.dropna(
                subset=[
                    "timestamp",
                    "count",
                ]
            )

            if timeline_chart.empty:
                show_empty_state(
                    "No valid alert timeline data is available."
                )

            else:
                timeline_chart = timeline_chart.set_index(
                    "timestamp"
                )

                timeline_chart = timeline_chart.rename(
                    columns={
                        "count": "Alerts",
                    }
                )

                st.line_chart(
                    timeline_chart["Alerts"],
                    height=300,
                )

    # ------------------------------------------------------------------------
    # SEVERITY + RULES
    # ------------------------------------------------------------------------

    st.markdown("### Risk & Detection Activity")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Alerts by Severity")

        severity_df = get_alerts_by_severity()

        if severity_df.empty:
            show_empty_state(
                "No severity data available."
            )

        else:
            chart_df = severity_df.set_index(
                "severity"
            )

            st.bar_chart(
                chart_df["count"],
                height=280,
            )

    with col2:
        st.markdown("#### Detection Rules")

        rules_df = get_alerts_by_rule()

        if rules_df.empty:
            show_empty_state(
                "No detection activity yet."
            )

        else:
            chart_df = rules_df.set_index(
                "rule_id"
            )

            st.bar_chart(
                chart_df["count"],
                height=280,
            )

    # ------------------------------------------------------------------------
    # SOURCE IPS
    # ------------------------------------------------------------------------

    st.markdown("### Top Source IPs")

    source_df = get_alerts_by_source_ip()

    if source_df.empty:
        show_empty_state(
            "No source IP activity recorded yet."
        )

    else:
        display_source_df = source_df.rename(
            columns={
                "source_ip": "Source IP",
                "count": "Alerts",
                "max_risk_score": "Max Risk",
            }
        )

        st.dataframe(
            display_source_df,
            width="stretch",
            hide_index=True,
            column_config={
                "Source IP": st.column_config.TextColumn(
                    "Source IP",
                    width="medium",
                ),
                "Alerts": st.column_config.NumberColumn(
                    "Alerts",
                    width="small",
                ),
                "Max Risk": st.column_config.NumberColumn(
                    "Max Risk",
                    min_value=0,
                    max_value=100,
                ),
            },
        )

    # ------------------------------------------------------------------------
    # RECENT ALERTS
    # ------------------------------------------------------------------------

    st.markdown("### Recent Alerts")

    alerts_df = get_alerts(limit=10)

    if alerts_df.empty:
        show_empty_state(
            "No alerts have been generated yet."
        )

    else:
        recent = alerts_df[
            [
                "id",
                "rule_id",
                "title",
                "severity",
                "risk_score",
                "source_ip",
                "created_at",
            ]
        ].copy()

        recent["severity"] = recent[
            "severity"
        ].map(severity_label)

        recent = recent.rename(
            columns={
                "id": "Alert ID",
                "rule_id": "Rule",
                "title": "Title",
                "severity": "Severity",
                "risk_score": "Risk",
                "source_ip": "Source IP",
                "created_at": "Created",
            }
        )

        st.dataframe(
            recent,
            width="stretch",
            hide_index=True,
        )


# ============================================================================
# ALERTS
# ============================================================================

elif page == "Alerts":

    st.markdown("## Security Alerts")

    st.caption(
        "Alerts generated by Sentinel's detection engine."
    )

    alerts_df = get_alerts(limit=500)

    if alerts_df.empty:
        show_empty_state(
            "No alerts found in the Sentinel database."
        )

    else:
        filter_col1, filter_col2 = st.columns(2)

        with filter_col1:
            severities = sorted(
                alerts_df["severity"]
                .dropna()
                .astype(str)
                .unique()
                .tolist()
            )

            selected_severities = st.multiselect(
                "Severity",
                severities,
                default=severities,
            )

        with filter_col2:
            rules = sorted(
                alerts_df["rule_id"]
                .dropna()
                .astype(str)
                .unique()
                .tolist()
            )

            selected_rules = st.multiselect(
                "Detection rule",
                rules,
                default=rules,
            )

        filtered = alerts_df[
            alerts_df["severity"].isin(
                selected_severities
            )
            & alerts_df["rule_id"].isin(
                selected_rules
            )
        ].copy()

        st.markdown(
            f"**{len(filtered)}** alert(s) displayed"
        )

        filtered["severity"] = filtered[
            "severity"
        ].map(severity_label)

        filtered = filtered.rename(
            columns={
                "id": "Alert ID",
                "rule_id": "Rule",
                "title": "Title",
                "description": "Description",
                "severity": "Severity",
                "risk_score": "Risk",
                "source_ip": "Source IP",
                "username": "Username",
                "created_at": "Created",
            }
        )

        st.dataframe(
            filtered,
            width="stretch",
            hide_index=True,
            height=550,
            column_config={
                "Alert ID": st.column_config.TextColumn(
                    "Alert ID",
                ),
                "Rule": st.column_config.TextColumn(
                    "Rule",
                ),
                "Title": st.column_config.TextColumn(
                    "Title",
                ),
                "Description": st.column_config.TextColumn(
                    "Description",
                ),
                "Risk": st.column_config.NumberColumn(
                    "Risk",
                    min_value=0,
                    max_value=100,
                ),
            },
        )


# ============================================================================
# INCIDENTS
# ============================================================================

elif page == "Incidents":

    st.markdown("## Security Incidents")

    st.caption(
        "Correlated security alerts grouped into incidents."
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Open",
            stats["open_incidents"],
        )

    with col2:
        st.metric(
            "Investigating",
            stats["investigating_incidents"],
        )

    with col3:
        st.metric(
            "Resolved",
            stats["resolved_incidents"],
        )

    incidents_df = get_incidents(limit=500)

    if incidents_df.empty:
        show_empty_state(
            "No incidents found in the Sentinel database."
        )

    else:
        st.markdown("### Incident Overview")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### Incidents by Severity")

            severity_df = get_incidents_by_severity()

            if severity_df.empty:
                show_empty_state(
                    "No incident severity data."
                )

            else:
                chart_df = severity_df.set_index(
                    "severity"
                )

                st.bar_chart(
                    chart_df["count"],
                    height=250,
                )

        with col2:
            st.markdown("#### Incidents by Status")

            status_df = get_incidents_by_status()

            if status_df.empty:
                show_empty_state(
                    "No incident status data."
                )

            else:
                chart_df = status_df.set_index(
                    "status"
                )

                st.bar_chart(
                    chart_df["count"],
                    height=250,
                )

        st.markdown("### Incident Queue")

        display_incidents = incidents_df.copy()

        display_incidents["severity"] = (
            display_incidents["severity"]
            .map(severity_label)
        )

        display_incidents["status"] = (
            display_incidents["status"]
            .map(status_label)
        )

        display_incidents = display_incidents.rename(
            columns={
                "incident_id": "Incident ID",
                "title": "Title",
                "description": "Description",
                "status": "Status",
                "severity": "Severity",
                "risk_score": "Risk",
                "source_ip": "Source IP",
                "created_at": "Created",
                "updated_at": "Updated",
            }
        )

        st.dataframe(
            display_incidents,
            width="stretch",
            hide_index=True,
            height=550,
            column_config={
                "Incident ID": st.column_config.TextColumn(
                    "Incident ID",
                ),
                "Title": st.column_config.TextColumn(
                    "Title",
                ),
                "Description": st.column_config.TextColumn(
                    "Description",
                ),
                "Risk": st.column_config.NumberColumn(
                    "Risk",
                    min_value=0,
                    max_value=100,
                ),
            },
        )


# ============================================================================
# FOOTER
# ============================================================================

st.divider()

st.caption(
    "Sentinel v0.5.0 • Defensive cybersecurity monitoring • "
    "Read-only SOC dashboard"
)

