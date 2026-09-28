"""Sentinel Security Operations Center dashboard."""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from sentinel import __version__
from sentinel.dashboard.data import (
    clear_dashboard_cache,
    get_alert_timeline,
    get_alerts,
    get_alerts_by_rule,
    get_alerts_by_severity,
    get_alerts_by_source_ip,
    get_dashboard_stats,
    get_incident,
    get_incident_alerts,
    get_incident_threat_intelligence,
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
            padding-top: 1.2rem;
            padding-bottom: 2rem;
            max-width: 1550px;
        }

        .soc-header {
            padding: 1.5rem 1.7rem;
            border-radius: 14px;
            background:
                linear-gradient(
                    135deg,
                    #0f172a 0%,
                    #1e293b 100%
                );
            border: 1px solid #334155;
            margin-bottom: 1.5rem;
        }

        .soc-title {
            font-size: 2rem;
            font-weight: 800;
            color: #f8fafc;
            margin: 0;
        }

        .soc-subtitle {
            margin-top: 0.4rem;
            color: #94a3b8;
            font-size: 0.95rem;
        }

        .soc-badge {
            display: inline-block;
            margin-top: 0.9rem;
            padding: 0.3rem 0.75rem;
            border-radius: 999px;
            background: #064e3b;
            color: #6ee7b7;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.03em;
        }

        div[data-testid="stMetric"] {
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 0.85rem;
        }

        .empty-state {
            padding: 2rem;
            text-align: center;
            border: 1px dashed #475569;
            border-radius: 12px;
            color: #94a3b8;
        }

        .incident-card {
            padding: 1rem 1.1rem;
            border: 1px solid #334155;
            border-radius: 12px;
            background: #0f172a;
            margin-bottom: 0.8rem;
        }

        .incident-id {
            font-family: monospace;
            font-size: 0.82rem;
            color: #94a3b8;
        }

        .risk-high {
            color: #fca5a5;
            font-weight: 800;
        }

        .risk-medium {
            color: #fcd34d;
            font-weight: 800;
        }

        .risk-low {
            color: #86efac;
            font-weight: 800;
        }

        .timeline-item {
            padding: 0.8rem 1rem;
            border-left: 3px solid #475569;
            margin-left: 0.4rem;
            margin-bottom: 0.8rem;
            background: #0f172a;
            border-radius: 0 8px 8px 0;
        }

        .timeline-time {
            color: #94a3b8;
            font-family: monospace;
            font-size: 0.8rem;
        }

        .timeline-title {
            font-weight: 700;
            margin-top: 0.2rem;
        }

        .timeline-meta {
            color: #94a3b8;
            font-size: 0.85rem;
            margin-top: 0.2rem;
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


def risk_class(score: int) -> str:
    """Return a CSS risk class."""

    if score >= 80:
        return "risk-high"

    if score >= 50:
        return "risk-medium"

    return "risk-low"


def show_empty_state(message: str) -> None:
    """Display a consistent empty state."""

    st.markdown(
        f'<div class="empty-state">{message}</div>',
        unsafe_allow_html=True,
    )


def show_header() -> None:
    """Display the Sentinel SOC header."""

    st.markdown(
        """
        <div class="soc-header">
            <div class="soc-title">
                Sentinel Security Operations Center
            </div>
            <div class="soc-subtitle">
                Defensive threat monitoring, detection and incident visibility
            </div>
            <div class="soc-badge">
                DATABASE ONLINE
            </div>
        </div>
        """,
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
            "Investigation",
        ],
        label_visibility="collapsed",
    )

    st.divider()

    st.markdown("### System")

    st.success(
        "SQLite database online",
         icon="🟢",
    )

    st.caption(
        f"Sentinel v{__version__}"
    )

    st.caption(
        "Read-only dashboard"
    )

    st.divider()

    if st.button(
        "Refresh data",
        width="stretch",
    ):
        clear_dashboard_cache()
        st.rerun()

    st.caption(
        "Data cache refresh: 5 seconds"
    )


# ============================================================================
# HEADER
# ============================================================================

show_header()

# ============================================================================
# DATABASE
# ============================================================================

try:
    stats = get_dashboard_stats()

except Exception as exc:
    st.error(
        "Unable to load the Sentinel database."
    )

    st.markdown(
        """
        Verify that the following database exists:

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
        "High-level visibility into alerts, incidents and detection activity."
    )

    # ------------------------------------------------------------------------
    # KPI
    # ------------------------------------------------------------------------

    col1, col2, col3, col4, col5, col6 = st.columns(6)

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

    with col5:
        st.metric(
            "Investigating",
            stats["investigating_incidents"],
        )

    with col6:
        st.metric(
            "Resolved",
            stats["resolved_incidents"],
        )

    # ------------------------------------------------------------------------
    # ALERT ACTIVITY
    # ------------------------------------------------------------------------

    st.markdown("### Alert Activity")

    timeline_df = get_alert_timeline()

    if timeline_df.empty:
        show_empty_state(
            "No alert activity has been recorded yet."
        )

    else:
        timeline_chart = timeline_df.copy()

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
    # DETECTION ACTIVITY
    # ------------------------------------------------------------------------

    st.markdown("### Detection Activity")

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
                "Max Risk": st.column_config.ProgressColumn(
                    "Max Risk",
                    min_value=0,
                    max_value=100,
                    format="%d",
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
            column_config={
                "Risk": st.column_config.ProgressColumn(
                    "Risk",
                    min_value=0,
                    max_value=100,
                    format="%d",
                ),
            },
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
                "Risk": st.column_config.ProgressColumn(
                    "Risk",
                    min_value=0,
                    max_value=100,
                    format="%d",
                ),
            },
        )


# ============================================================================
# INCIDENTS
# ============================================================================

elif page == "Incidents":

    st.markdown("## Security Incidents")

    st.caption(
        "Correlated security alerts grouped into investigation-ready incidents."
    )

    # ------------------------------------------------------------------------
    # INCIDENT STATUS KPI
    # ------------------------------------------------------------------------

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

               # --------------------------------------------------------------------
        # INCIDENT ANALYTICS
        # --------------------------------------------------------------------

        st.markdown("### Incident Analytics")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### Incidents by Severity")

            severity_df = get_incidents_by_severity()

            if severity_df.empty:
                show_empty_state(
                    "No incident severity data."
                )

            else:
                chart_df = severity_df.copy()

                chart_df["count"] = pd.to_numeric(
                    chart_df["count"],
                    errors="coerce",
                )

                chart_df = chart_df.dropna(
                    subset=["count"]
                )

                fig = px.bar(
                    chart_df,
                    x="severity",
                    y="count",
                    text="count",
                    labels={
                        "severity": "Severity",
                        "count": "Incidents",
                    },
                    template="plotly_dark",
                )

                fig.update_layout(
                    height=300,
                    margin=dict(
                        l=20,
                        r=20,
                        t=20,
                        b=20,
                    ),
                    xaxis_title=None,
                    yaxis_title="Incidents",
                )

                fig.update_traces(
                    textposition="outside",
                )

                st.plotly_chart(
                    fig,
                    width="stretch",
                )

        with col2:
            st.markdown("#### Incidents by Status")

            status_df = get_incidents_by_status()

            if status_df.empty:
                show_empty_state(
                    "No incident status data."
                )

            else:
                chart_df = status_df.copy()

                chart_df["count"] = pd.to_numeric(
                    chart_df["count"],
                    errors="coerce",
                )

                chart_df = chart_df.dropna(
                    subset=["count"]
                )

                fig = px.bar(
                    chart_df,
                    x="status",
                    y="count",
                    text="count",
                    labels={
                        "status": "Status",
                        "count": "Incidents",
                    },
                    template="plotly_dark",
                )

                fig.update_layout(
                    height=300,
                    margin=dict(
                        l=20,
                        r=20,
                        t=20,
                        b=20,
                    ),
                    xaxis_title=None,
                    yaxis_title="Incidents",
                )

                fig.update_traces(
                    textposition="outside",
                )

                st.plotly_chart(
                    fig,
                    width="stretch",
                )

        # --------------------------------------------------------------------
        # INCIDENT QUEUE
        # --------------------------------------------------------------------

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
                "Risk": st.column_config.ProgressColumn(
                    "Risk",
                    min_value=0,
                    max_value=100,
                    format="%d",
                ),
            },
        )


# ============================================================================
# INVESTIGATION
# ============================================================================

elif page == "Investigation":

    st.markdown("## Incident Investigation")

    st.caption(
        "Analyze a correlated incident from its alerts to its threat intelligence."
    )

    incidents_df = get_incidents(limit=500)

    if incidents_df.empty:
        show_empty_state(
            "No incidents are available for investigation."
        )

    else:

        # --------------------------------------------------------------------
        # INCIDENT SELECTOR
        # --------------------------------------------------------------------

        incident_options = (
            incidents_df["incident_id"]
            .astype(str)
            .tolist()
        )

        selected_incident_id = st.selectbox(
            "Incident",
            incident_options,
        )

        incident_df = get_incident(
            selected_incident_id
        )

        if incident_df.empty:
            st.error(
                "The selected incident could not be loaded."
            )
            st.stop()

        incident = incident_df.iloc[0]

        related_alerts = get_incident_alerts(
            selected_incident_id
        )

        threat_intel = get_incident_threat_intelligence(
            selected_incident_id
        )

        # --------------------------------------------------------------------
        # INCIDENT HEADER
        # --------------------------------------------------------------------

        st.markdown("---")

        header_col1, header_col2 = st.columns(
            [3, 1]
        )

        with header_col1:
            st.markdown(
                f"### {incident['incident_id']}"
            )

            st.caption(
                str(incident["title"])
            )

        with header_col2:
            st.metric(
                "Risk Score",
                f"{int(incident['risk_score'])} / 100",
            )

        # --------------------------------------------------------------------
        # INCIDENT KPIs
        # --------------------------------------------------------------------

        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:
            st.metric(
                "Severity",
                severity_label(
                    incident["severity"]
                ),
            )

        with col2:
            st.metric(
                "Status",
                status_label(
                    incident["status"]
                ),
            )

        with col3:
            source_ip = incident["source_ip"]

            st.metric(
                "Source IP",
                source_ip
                if pd.notna(source_ip)
                else "Unknown",
            )

        with col4:
            st.metric(
                "Related Alerts",
                len(related_alerts),
            )

        with col5:
            st.metric(
                "TI Matches",
                len(threat_intel),
            )

        # --------------------------------------------------------------------
        # RISK
        # --------------------------------------------------------------------

        risk_score = int(
            incident["risk_score"]
        )

        st.markdown("### Risk Assessment")

        st.progress(
            max(
                0,
                min(
                    risk_score,
                    100,
                ),
            ),
            text=f"Risk score: {risk_score}/100",
        )

        if risk_score >= 80:
            st.error(
                "High-risk incident requiring investigation."
            )

        elif risk_score >= 50:
            st.warning(
                "Medium-risk incident requiring review."
            )

        else:
            st.success(
                "Lower-risk incident."
            )

        # --------------------------------------------------------------------
        # CONTEXT
        # --------------------------------------------------------------------

        st.markdown("### Incident Context")

        st.info(
            str(incident["description"])
        )

        metadata_col1, metadata_col2 = st.columns(2)

        with metadata_col1:
            st.markdown("**Created**")
            st.code(
                str(incident["created_at"])
            )

        with metadata_col2:
            st.markdown("**Last Updated**")
            st.code(
                str(incident["updated_at"])
            )

        # --------------------------------------------------------------------
        # INVESTIGATION TABS
        # --------------------------------------------------------------------

        tab_alerts, tab_ti, tab_timeline = st.tabs(
            [
                "Related Alerts",
                "Threat Intelligence",
                "Timeline",
            ]
        )

        # --------------------------------------------------------------------
        # RELATED ALERTS
        # --------------------------------------------------------------------

        with tab_alerts:

            if related_alerts.empty:
                show_empty_state(
                    "No alerts are associated with this incident."
                )

            else:
                st.markdown(
                    f"**{len(related_alerts)}** related alert(s)"
                )

                display_alerts = related_alerts.copy()

                display_alerts["severity"] = (
                    display_alerts["severity"]
                    .map(severity_label)
                )

                display_alerts = display_alerts.rename(
                    columns={
                        "id": "Alert ID",
                        "rule_id": "Detection Rule",
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
                    display_alerts,
                    width="stretch",
                    hide_index=True,
                    height=350,
                    column_config={
                        "Risk": st.column_config.ProgressColumn(
                            "Risk",
                            min_value=0,
                            max_value=100,
                            format="%d",
                        ),
                    },
                )

                st.markdown("#### Detection Rules")

                rules = (
                    related_alerts["rule_id"]
                    .dropna()
                    .astype(str)
                    .drop_duplicates()
                    .tolist()
                )

                if rules:
                    rule_columns = st.columns(
                        min(
                            len(rules),
                            4,
                        )
                    )

                    for index, rule in enumerate(rules):
                        with rule_columns[
                            index % len(rule_columns)
                        ]:
                            st.code(
                                rule
                            )

        # --------------------------------------------------------------------
        # THREAT INTELLIGENCE
        # --------------------------------------------------------------------

        with tab_ti:

            if threat_intel.empty:
                show_empty_state(
                    "No threat intelligence matches were found for this incident."
                )

            else:

                ti_col1, ti_col2, ti_col3 = st.columns(3)

                confidence_values = pd.to_numeric(
                    threat_intel["confidence"],
                    errors="coerce",
                )

                adjusted_risk_values = pd.to_numeric(
                    threat_intel["adjusted_risk_score"],
                    errors="coerce",
                )

                with ti_col1:
                    max_confidence = int(
                        confidence_values.max()
                    )

                    st.metric(
                        "Highest Confidence",
                        f"{max_confidence}%",
                    )

                with ti_col2:
                    max_adjusted_risk = int(
                        adjusted_risk_values.max()
                    )

                    st.metric(
                        "Adjusted Risk",
                        f"{max_adjusted_risk}/100",
                    )

                with ti_col3:
                    feeds = (
                        threat_intel["source"]
                        .dropna()
                        .astype(str)
                        .nunique()
                    )

                    st.metric(
                        "Intel Feeds",
                        feeds,
                    )

                st.markdown(
                    f"**{len(threat_intel)}** intelligence match(es)"
                )

                display_ti = threat_intel.copy()

                display_ti["severity"] = (
                    display_ti["severity"]
                    .map(severity_label)
                )

                display_ti = display_ti.rename(
                    columns={
                        "alert_id": "Alert ID",
                        "indicator_value": "Indicator",
                        "indicator_type": "Type",
                        "matched_value": "Matched Value",
                        "observable_type": "Observable",
                        "confidence": "Confidence",
                        "severity": "Severity",
                        "source": "Feed",
                        "description": "Description",
                        "adjusted_risk_score": "Adjusted Risk",
                    }
                )

                st.dataframe(
                    display_ti,
                    width="stretch",
                    hide_index=True,
                    column_config={
                        "Confidence": st.column_config.ProgressColumn(
                            "Confidence",
                            min_value=0,
                            max_value=100,
                            format="%d%%",
                        ),
                        "Adjusted Risk": st.column_config.ProgressColumn(
                            "Adjusted Risk",
                            min_value=0,
                            max_value=100,
                            format="%d",
                        ),
                    },
                )

        # --------------------------------------------------------------------
        # TIMELINE
        # --------------------------------------------------------------------

        with tab_timeline:

            if related_alerts.empty:
                show_empty_state(
                    "No timeline events are available."
                )

            else:

                st.markdown(
                    "### Investigation Timeline"
                )

                timeline = related_alerts[
                    [
                        "created_at",
                        "title",
                        "rule_id",
                        "severity",
                        "risk_score",
                    ]
                ].copy()

                timeline = timeline.sort_values(
                    "created_at"
                )

                for _, alert in timeline.iterrows():

                    severity = severity_label(
                        alert["severity"]
                    )

                    timestamp = str(
                        alert["created_at"]
                    )

                    title = str(
                        alert["title"]
                    )

                    rule = str(
                        alert["rule_id"]
                    )

                    risk = int(
                        alert["risk_score"]
                    )

                    st.markdown(
                        f"""
                        <div class="timeline-item">
                            <div class="timeline-time">
                                {timestamp}
                            </div>
                            <div class="timeline-title">
                                {severity} — {title}
                            </div>
                            <div class="timeline-meta">
                                Detection rule:
                                <code>{rule}</code>
                                &nbsp; | &nbsp;
                                Risk:
                                <strong>{risk}/100</strong>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

# ============================================================================
# FOOTER
# ============================================================================

st.divider()

st.caption(
    f"Sentinel v{__version__} • Defensive cybersecurity monitoring • "
    "Read-only SOC dashboard"
)

