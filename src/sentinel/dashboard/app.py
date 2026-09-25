"""Sentinel SOC dashboard."""

from __future__ import annotations

import streamlit as st

from sentinel.dashboard.data import (
    clear_dashboard_cache,
    get_alerts,
    get_alerts_by_rule,
    get_alerts_by_severity,
    get_alerts_by_source_ip,
    get_dashboard_stats,
    get_incidents,
    get_incidents_by_severity,
    get_incidents_by_status,
)

st.set_page_config(
    page_title="Sentinel SOC",
    page_icon="???",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------

st.markdown(
    """
    <style>
        .block-container {
            padding-top: 2rem;
            padding-bottom: 2rem;
            max-width: 1500px;
        }

        .sentinel-header {
            padding: 1.2rem 1.5rem;
            border-radius: 14px;
            background: linear-gradient(
                135deg,
                #111827 0%,
                #1f2937 100%
            );
            border: 1px solid #374151;
            margin-bottom: 1.5rem;
        }

        .sentinel-title {
            font-size: 2rem;
            font-weight: 700;
            margin: 0;
            color: #f9fafb;
        }

        .sentinel-subtitle {
            margin-top: 0.35rem;
            color: #9ca3af;
            font-size: 0.95rem;
        }

        .status-online {
            display: inline-block;
            padding: 0.3rem 0.7rem;
            border-radius: 999px;
            background: #064e3b;
            color: #6ee7b7;
            font-size: 0.8rem;
            font-weight: 600;
        }

        .section-title {
            margin-top: 1.5rem;
            margin-bottom: 0.8rem;
        }

        div[data-testid="stMetric"] {
            border: 1px solid #374151;
            border-radius: 12px;
            padding: 1rem;
            background: #111827;
        }

        .empty-state {
            padding: 2rem;
            text-align: center;
            border: 1px dashed #4b5563;
            border-radius: 12px;
            color: #9ca3af;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def severity_badge(severity: str) -> str:
    """Return a visual severity label."""

    labels = {
        "critical": "?? CRITICAL",
        "high": "?? HIGH",
        "medium": "?? MEDIUM",
        "low": "?? LOW",
    }

    return labels.get(
        str(severity).lower(),
        str(severity).upper(),
    )


def status_badge(status: str) -> str:
    """Return a visual incident status label."""

    labels = {
        "open": "?? OPEN",
        "investigating": "?? INVESTIGATING",
        "resolved": "?? RESOLVED",
    }

    return labels.get(
        str(status).lower(),
        str(status).upper(),
    )


def show_empty_state(message: str) -> None:
    """Display a consistent empty-state message."""

    st.markdown(
        f'<div class="empty-state">{message}</div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("## ??? Sentinel")
    st.caption("Defensive Cybersecurity Monitoring")

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
        '<span class="status-online">? DATABASE ONLINE</span>',
        unsafe_allow_html=True,
    )

    st.caption("SQLite / read-only dashboard")

    st.divider()

    if st.button(
        "? Refresh data",
        use_container_width=True,
    ):
        clear_dashboard_cache()
        st.rerun()

    st.caption("Data refresh interval: 5 seconds")


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.markdown(
    """
    <div class="sentinel-header">
        <div class="sentinel-title">??? Sentinel SOC</div>
        <div class="sentinel-subtitle">
            Security Operations Center — threat monitoring & incident visibility
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------

try:
    stats = get_dashboard_stats()
except Exception as exc:
    st.error(
        "Impossible de charger la base Sentinel. "
        "Vérifie que data/sentinel.db existe."
    )
    st.exception(exc)
    st.stop()


# ---------------------------------------------------------------------------
# OVERVIEW
# ---------------------------------------------------------------------------

if page == "Overview":

    st.markdown("## Security Overview")

    st.caption(
        "Vue synthétique des alertes et incidents détectés par Sentinel."
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "Total alerts",
            stats["total_alerts"],
            border=True,
        )

    with col2:
        st.metric(
            "Critical alerts",
            stats["critical_alerts"],
            border=True,
        )

    with col3:
        st.metric(
            "High alerts",
            stats["high_alerts"],
            border=True,
        )

    with col4:
        st.metric(
            "Open incidents",
            stats["open_incidents"],
            border=True,
        )

    st.markdown("### Detection intelligence")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Alerts by severity")

        severity_df = get_alerts_by_severity()

        if severity_df.empty:
            show_empty_state("No alerts recorded yet.")
        else:
            chart_df = severity_df.set_index("severity")
            st.bar_chart(
                chart_df["count"],
                height=280,
            )

    with col2:
        st.markdown("#### Detection rules")

        rules_df = get_alerts_by_rule()

        if rules_df.empty:
            show_empty_state("No detection activity yet.")
        else:
            chart_df = rules_df.set_index("rule_id")
            st.bar_chart(
                chart_df["count"],
                height=280,
            )

    st.markdown("### Source activity")

    source_df = get_alerts_by_source_ip()

    if source_df.empty:
        show_empty_state("No source IP activity recorded yet.")
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
            use_container_width=True,
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
                    width="small",
                    min_value=0,
                    max_value=100,
                ),
            },
        )

    st.markdown("### Recent alerts")

    alerts_df = get_alerts(limit=10)

    if alerts_df.empty:
        show_empty_state(
            "No alerts have been generated yet. "
            "Run Sentinel against sample logs to populate the dashboard."
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

        recent["severity"] = recent["severity"].map(severity_badge)

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
            use_container_width=True,
            hide_index=True,
        )


# ---------------------------------------------------------------------------
# ALERTS
# ---------------------------------------------------------------------------

elif page == "Alerts":

    st.markdown("## ?? Security Alerts")

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
            alerts_df["severity"].isin(selected_severities)
            & alerts_df["rule_id"].isin(selected_rules)
        ].copy()

        st.markdown(
            f"**{len(filtered)}** alert(s) displayed"
        )

        filtered["severity"] = filtered["severity"].map(
            severity_badge
        )

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
            use_container_width=True,
            hide_index=True,
            height=550,
            column_config={
                "Alert ID": st.column_config.TextColumn(
                    "Alert ID",
                    width="medium",
                ),
                "Rule": st.column_config.TextColumn(
                    "Rule",
                    width="medium",
                ),
                "Title": st.column_config.TextColumn(
                    "Title",
                    width="large",
                ),
                "Description": st.column_config.TextColumn(
                    "Description",
                    width="large",
                ),
                "Risk": st.column_config.NumberColumn(
                    "Risk",
                    min_value=0,
                    max_value=100,
                ),
            },
        )


# ---------------------------------------------------------------------------
# INCIDENTS
# ---------------------------------------------------------------------------

elif page == "Incidents":

    st.markdown("## ?? Security Incidents")

    st.caption(
        "Correlated security alerts grouped into incidents."
    )

    incident_col1, incident_col2, incident_col3 = st.columns(3)

    with incident_col1:
        st.metric(
            "Open",
            stats["open_incidents"],
            border=True,
        )

    with incident_col2:
        st.metric(
            "Investigating",
            stats["investigating_incidents"],
            border=True,
        )

    with incident_col3:
        st.metric(
            "Resolved",
            stats["resolved_incidents"],
            border=True,
        )

    incidents_df = get_incidents(limit=500)

    if incidents_df.empty:
        show_empty_state(
            "No incidents found in the Sentinel database."
        )
    else:
        st.markdown("### Incident severity")

        severity_df = get_incidents_by_severity()

        if not severity_df.empty:
            chart_df = severity_df.set_index("severity")
            st.bar_chart(
                chart_df["count"],
                height=250,
            )

        st.markdown("### Incident status")

        status_df = get_incidents_by_status()

        if not status_df.empty:
            status_chart = status_df.set_index("status")
            st.bar_chart(
                status_chart["count"],
                height=250,
            )

        st.markdown("### Incident queue")

        display_incidents = incidents_df.copy()

        display_incidents["severity"] = display_incidents[
            "severity"
        ].map(severity_badge)

        display_incidents["status"] = display_incidents[
            "status"
        ].map(status_badge)

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
            use_container_width=True,
            hide_index=True,
            height=550,
            column_config={
                "Incident ID": st.column_config.TextColumn(
                    "Incident ID",
                    width="medium",
                ),
                "Title": st.column_config.TextColumn(
                    "Title",
                    width="large",
                ),
                "Description": st.column_config.TextColumn(
                    "Description",
                    width="large",
                ),
                "Risk": st.column_config.NumberColumn(
                    "Risk",
                    min_value=0,
                    max_value=100,
                ),
            },
        )


# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------

st.divider()

st.caption(
    "Sentinel v0.1.0 • Defensive cybersecurity monitoring • "
    "Dashboard operates in read-only mode"
)


