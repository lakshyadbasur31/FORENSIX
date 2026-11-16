"""Incident Reconstruction Timeline page for FORENSIX.

Visualizes correlated chronological forensic events across auth logs,
browser history, file downloads, and evidence acquisitions.
"""
import streamlit as st
import pandas as pd
import plotly.express as px
from modules.incident_reconstruction import get_investigation_timeline
from modules.event_correlator import detect_brute_force, correlate_attack_chain
from database.db import execute_query


def render():
    st.markdown("## ⏱️ Incident Reconstruction Timeline")
    st.markdown("Reconstruct security incidents in chronological sequence across disparate data sources.")

    active_inv = st.session_state.get("active_investigation_id")
    if not active_inv:
        st.warning("Please select or initialize an active investigation in the Overview tab first.")
        return

    # Load events for active investigation
    df = get_investigation_timeline(active_inv)

    if df.empty:
        st.info("No timeline events registered for this investigation yet. Ingest log sources or load the simulated demonstration scenario from the Overview page.")
        return

    # Security correlation summary
    events_list = df.to_dict(orient="records")
    brute_findings = detect_brute_force(events_list)
    attack_stages = correlate_attack_chain(events_list)

    st.markdown("### 🔍 Automated Threat Correlation & Stages")
    
    col_s1, col_s2 = st.columns([1, 1])
    with col_s1:
        st.markdown("#### Attack Chain Stages")
        if attack_stages:
            for s in attack_stages:
                st.markdown(f"- **{s['stage']}**: {s['summary']}")
        else:
            st.caption("No unified attack chains identified.")

    with col_s2:
        st.markdown("#### Correlation Findings")
        if brute_findings:
            for f in brute_findings:
                st.warning(f"⚠️ **{f['pattern']}**: {f['message']}")
        else:
            st.success("No brute force patterns detected.")

    st.markdown("---")
    st.markdown("### 📊 Interactive Visual Timeline")

    # Prepare timeline plot using Plotly
    # Use dummy end date for single point events so Plotly can display
    df_plot = df.copy()
    df_plot["end"] = df_plot["timestamp"] + pd.Timedelta(minutes=2)
    df_plot["time_label"] = df_plot["timestamp"].dt.strftime("%H:%M:%S")

    # Color mapping for severity
    color_map = {
        "INFO": "#2ecc71",
        "NOTICE": "#3498db",
        "WARNING": "#f39c12",
        "HIGH": "#e74c3c"
    }

    fig = px.timeline(
        df_plot,
        x_start="timestamp",
        x_end="end",
        y="event_type",
        color="severity",
        color_discrete_map=color_map,
        hover_data=["time_label", "actor", "source", "description"],
        title="Chronological Event Stream",
        template="plotly_dark"
    )
    fig.update_yaxes(autorange="reversed")
    fig.update_layout(height=320, margin=dict(l=20, r=20, t=40, b=20))
    st.plotly_chart(fig, use_container_width=True)

    st.markdown("### 📋 Chronological Forensic Ledger")

    # Severity filter
    col_f1, col_f2 = st.columns([2, 1])
    with col_f1:
        sev_filter = st.multiselect("Filter Severity", options=["INFO", "NOTICE", "WARNING", "HIGH"], default=["INFO", "NOTICE", "WARNING", "HIGH"])
    with col_f2:
        sim_only = st.checkbox("Show Only Simulated Records", value=False)

    filtered_df = df[df["severity"].isin(sev_filter)]
    if sim_only:
        filtered_df = filtered_df[filtered_df["is_simulated"] == 1]

    display_table = filtered_df[["timestamp", "event_type", "actor", "source", "description", "severity", "is_simulated"]].copy()
    display_table.rename(columns={
        "timestamp": "Timestamp (UTC)",
        "event_type": "Event Class",
        "actor": "Actor",
        "source": "Source Origin",
        "description": "Event Narrative",
        "severity": "Severity",
        "is_simulated": "Simulated"
    }, inplace=True)

    st.dataframe(display_table, use_container_width=True, hide_index=True)
