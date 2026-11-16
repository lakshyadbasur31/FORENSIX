"""RECON-X — Incident Reconstruction & Forensic Reporting Dashboard.

Features:
- Incident Overview and Stage Sequence
- Milestone Interval Analysis
- Interactive Multi-Lane Chronological Timeline (Plotly)
- Comprehensive 15-Section Forensic Dossier Viewer
- Multi-format Export Controls: Markdown, JSON, CSV ledger, Printable HTML/PDF
"""
import json
import streamlit as st
import pandas as pd
from modules.tracefusion import retrieve_all_investigation_events, get_unified_forensic_timeline
from modules.sentinel import evaluate_sentinel_risk
from modules.recon_x import (
    get_incident_stages,
    calculate_incident_intervals,
    build_recon_x_plotly_timeline,
    generate_forensic_dossier_markdown,
    generate_printable_html
)


def render():
    st.markdown("## 🧭 RECON-X — Incident Reconstruction & Forensic Reporting")
    st.markdown(
        "Chronological multi-lane incident reconstruction, stage interval tracking, "
        "and complete 15-section forensic examination dossier generation."
    )

    active_inv = st.session_state.get("active_investigation_id")
    if not active_inv:
        st.warning("⚠️ Please select or initialize an active investigation in the Overview tab first.")
        return

    # Load unified telemetry
    events = retrieve_all_investigation_events(active_inv)
    stages = get_incident_stages(events)
    intervals = calculate_incident_intervals(events)
    sentinel = evaluate_sentinel_risk(active_inv, events=events)

    tab_recon, tab_report, tab_export = st.tabs([
        "⏱️ Incident Reconstruction",
        "📑 Forensic Dossier",
        "📤 Multi-Format Export"
    ])

    # ==============================================================================
    # TAB 1: INCIDENT RECONSTRUCTION & TIMELINE
    # ==============================================================================
    with tab_recon:
        st.markdown("### 🔍 Reconstructed Incident Progression")

        # Top summary cards
        c1, c2, c3 = st.columns(3)
        c1.metric("Identified Stages", len(stages))
        c2.metric("Milestone Intervals", len(intervals))
        c3.metric("SENTINEL Priority", f"{sentinel['risk_level']} ({sentinel['risk_score']})")

        st.markdown("---")
        st.markdown("#### 1. Attack & Incident Sequence Stages")
        if not stages:
            st.info("No sequence stages identified yet. Ingest telemetry or run the demonstration scenario.")
        else:
            for idx, s in enumerate(stages, 1):
                st.markdown(f"**Step {idx}: {s['stage']}** ➔ {s['summary']}")

        if intervals:
            st.markdown("---")
            st.markdown("#### 2. Milestone Time Interval Analysis")
            df_intervals = pd.DataFrame(intervals)
            st.dataframe(
                df_intervals[["from_stage", "to_stage", "interval_formatted", "interval_seconds"]].rename(columns={
                    "from_stage": "Starting Milestone",
                    "to_stage": "Consequent Milestone",
                    "interval_formatted": "Elapsed Time",
                    "interval_seconds": "Duration (Seconds)"
                }),
                use_container_width=True,
                hide_index=True
            )

        st.markdown("---")
        st.markdown("#### 3. Interactive Multi-Lane Timeline Flow")
        fig = build_recon_x_plotly_timeline(events)
        if fig:
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No dated events available to render timeline.")

    # ==============================================================================
    # TAB 2: FORENSIC DOSSIER PREVIEW
    # ==============================================================================
    with tab_report:
        st.markdown("### 📑 15-Section Comprehensive Forensic Dossier")
        st.markdown("Structured digital evidence report strictly categorizing observed facts, indicators, and hypotheses.")

        dossier_text = generate_forensic_dossier_markdown(active_inv)
        st.text_area("Full Report Dossier (Markdown)", value=dossier_text, height=450)

    # ==============================================================================
    # TAB 3: MULTI-FORMAT EXPORT
    # ==============================================================================
    with tab_export:
        st.markdown("### 📤 Multi-Format Dossier Export")
        st.markdown("Download standardized forensic reports sanitized of sensitive credentials.")

        dossier_text = generate_forensic_dossier_markdown(active_inv)
        printable_html = generate_printable_html(dossier_text)
        timeline_df = get_unified_forensic_timeline(active_inv)

        col_ex1, col_ex2 = st.columns(2)
        with col_ex1:
            st.download_button(
                label="💾 Download Markdown Dossier (.md)",
                data=dossier_text,
                file_name=f"FORENSIX_Dossier_{active_inv}.md",
                mime="text/markdown",
                use_container_width=True
            )
            st.download_button(
                label="🖨️ Download Printable HTML / PDF Dossier (.html)",
                data=printable_html,
                file_name=f"FORENSIX_Dossier_Printable_{active_inv}.html",
                mime="text/html",
                use_container_width=True,
                help="Open in browser and choose 'Print to PDF' for high-resolution forensic export."
            )

        with col_ex2:
            if not timeline_df.empty:
                csv_bytes = timeline_df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="📊 Download Unified Forensic Ledger (.csv)",
                    data=csv_bytes,
                    file_name=f"FORENSIX_Unified_Ledger_{active_inv}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            summary_json = json.dumps(sentinel, indent=2).encode("utf-8")
            st.download_button(
                label="📑 Download Incident Intelligence Summary (.json)",
                data=summary_json,
                file_name=f"FORENSIX_Intelligence_{active_inv}.json",
                mime="application/json",
                use_container_width=True
            )
