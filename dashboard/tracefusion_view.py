"""TRACEFUSION — Cross-Module Forensic Correlation Dashboard.

Features:
- Investigation & Scope summary metrics
- Multi-Source Unified Forensic Timeline
- Cross-Module Correlation Matrix with Confidence & Reasons
- Source and Event Type filters
- Interactive deep-dive into correlated pairs
"""
import streamlit as st
import pandas as pd
import plotly.express as px
from modules.tracefusion import (
    retrieve_all_investigation_events,
    correlate_events,
    get_unified_forensic_timeline
)
from modules.evidence_manager import list_evidence


def render():
    st.markdown("## 🧬 TRACEFUSION — Cross-Module Forensic Correlation")
    st.markdown(
        "Correlate events across CHAINLOCK, WEBTRACE, and forensic authentication logs into "
        "an explainable chronological graph."
    )

    active_inv = st.session_state.get("active_investigation_id")
    if not active_inv:
        st.warning("⚠️ Please select or initialize an active investigation in the Overview tab first.")
        return

    # 1. Retrieve all normalized events & findings
    raw_events = retrieve_all_investigation_events(active_inv)
    findings = correlate_events(raw_events)
    evidence_items = list_evidence(active_inv)

    # 2. Top-level metrics
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Forensic Events", len(raw_events))
    c2.metric("Cross-Module Correlations", len(findings))
    c3.metric("Registered Evidence Items", len(evidence_items))
    high_conf = sum(1 for f in findings if f.confidence == "HIGH")
    c4.metric("High Confidence Links", high_conf)

    st.markdown("---")

    tab_corr, tab_timeline = st.tabs(["🔗 Correlation Matrix", "⏱️ Unified Timeline"])

    # ==============================================================================
    # TAB 1: CORRELATION MATRIX
    # ==============================================================================
    with tab_corr:
        st.markdown("### 🔍 Discovered Forensic Correlations")
        st.markdown(
            "Deterministic, multi-signal relationships connecting browser downloads, "
            "network authentications, and vault evidence artifacts."
        )

        if not findings:
            st.info("No cross-module correlations identified for this investigation yet.")
        else:
            findings_data = [f.to_dict() for f in findings]
            df_findings = pd.DataFrame(findings_data)

            # Filtering controls
            col_f1, col_f2 = st.columns(2)
            with col_f1:
                rel_filter = st.selectbox(
                    "Filter Relationship Type:",
                    ["ALL"] + list(df_findings["relationship_type"].unique())
                )
            with col_f2:
                conf_filter = st.selectbox("Filter Confidence:", ["ALL", "HIGH", "MEDIUM", "LOW"])

            filtered = df_findings
            if rel_filter != "ALL":
                filtered = filtered[filtered["relationship_type"] == rel_filter]
            if conf_filter != "ALL":
                filtered = filtered[filtered["confidence"] == conf_filter]

            display_cols = [
                "relationship_type", "confidence", "source_time", "source_type",
                "target_type", "reason", "time_delta_seconds"
            ]
            df_disp = filtered[display_cols].copy()
            df_disp.rename(columns={
                "relationship_type": "Relationship",
                "confidence": "Confidence",
                "source_time": "Source Time (UTC)",
                "source_type": "Source Event",
                "target_type": "Target Event",
                "reason": "Explainable Reason",
                "time_delta_seconds": "Delta (s)"
            }, inplace=True)

            st.dataframe(df_disp, use_container_width=True, hide_index=True)

            st.markdown("---")
            st.markdown("#### 🔬 Correlation Pair Inspector")
            pair_options = {
                f"{row['source_event_id']} ↔ {row['target_event_id']} ({row['relationship_type']})": idx
                for idx, row in filtered.iterrows()
            }
            if pair_options:
                sel_pair = st.selectbox("Inspect Link Details:", list(pair_options.keys()))
                sel_idx = pair_options[sel_pair]
                sel_finding = findings[sel_idx]

                p_col1, p_col2 = st.columns(2)
                with p_col1:
                    st.markdown("##### Source Event")
                    st.write(f"- **ID:** `{sel_finding.source_event.event_id}`")
                    st.write(f"- **Source:** {sel_finding.source_event.source}")
                    st.write(f"- **Type:** `{sel_finding.source_event.event_type}`")
                    st.write(f"- **Timestamp:** `{sel_finding.source_event.timestamp_str}`")
                    st.write(f"- **Narrative:** {sel_finding.source_event.description}")
                with p_col2:
                    st.markdown("##### Correlated Target Event")
                    st.write(f"- **ID:** `{sel_finding.target_event.event_id}`")
                    st.write(f"- **Source:** {sel_finding.target_event.source}")
                    st.write(f"- **Type:** `{sel_finding.target_event.event_type}`")
                    st.write(f"- **Timestamp:** `{sel_finding.target_event.timestamp_str}`")
                    st.write(f"- **Narrative:** {sel_finding.target_event.description}")

    # ==============================================================================
    # TAB 2: UNIFIED TIMELINE
    # ==============================================================================
    with tab_timeline:
        st.markdown("### ⏱️ Unified Chronological Forensic Timeline")
        st.markdown("Aggregated event ledger spanning all active telemetry modules.")

        timeline_df = get_unified_forensic_timeline(active_inv)
        if timeline_df.empty:
            st.info("No timeline records available.")
        else:
            tf_col1, tf_col2 = st.columns([2, 1])
            with tf_col1:
                source_filter = st.multiselect(
                    "Filter Telemetry Sources:",
                    options=list(timeline_df["source"].unique()),
                    default=list(timeline_df["source"].unique())
                )
            with tf_col2:
                sev_filter = st.multiselect(
                    "Filter Severity:",
                    options=["INFO", "NOTICE", "WARNING", "HIGH"],
                    default=["INFO", "NOTICE", "WARNING", "HIGH"]
                )

            filtered_tl = timeline_df[
                timeline_df["source"].isin(source_filter) &
                timeline_df["severity"].isin(sev_filter)
            ]

            st.dataframe(
                filtered_tl[[
                    "timestamp", "source", "event_type", "actor", "description", "filename", "severity"
                ]].rename(columns={
                    "timestamp": "Timestamp (UTC)",
                    "source": "Source Layer",
                    "event_type": "Event Class",
                    "actor": "Actor",
                    "description": "Narrative Details",
                    "filename": "Associated File",
                    "severity": "Severity"
                }),
                use_container_width=True,
                hide_index=True
            )
