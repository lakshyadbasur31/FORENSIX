"""Investigation Report generation module for FORENSIX.

Generates structured markdown, JSON, or CSV forensic incident briefs
summarizing evidence integrity status, timeline, and correlation findings.
"""
import streamlit as st
import pandas as pd
from datetime import datetime
from database.db import execute_query
from modules.evidence_manager import list_evidence
from modules.incident_reconstruction import get_investigation_timeline
from modules.event_correlator import correlate_attack_chain, detect_brute_force
from config import REPORTS_DIR


def render():
    st.markdown("## 📑 Forensic Investigation Report")
    st.markdown("Generate forensic findings dossiers, Chain of Custody statements, and incident summaries.")

    active_inv = st.session_state.get("active_investigation_id")
    if not active_inv:
        st.warning("Please select or initialize an active investigation in the Overview tab first.")
        return

    # Fetch investigation details
    inv_rows = execute_query("SELECT * FROM investigations WHERE id = ?", (active_inv,))
    if not inv_rows:
        st.error("Active investigation not found.")
        return

    inv = inv_rows[0]
    evidence_list = list_evidence(investigation_id=active_inv)
    timeline_df = get_investigation_timeline(active_inv)

    st.markdown("### Report Preview")
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"**Case Reference:** `{inv['id']}`")
        st.markdown(f"**Case Title:** {inv['case_name']}")
        st.markdown(f"**Lead Examiner:** {inv['lead_investigator']}")
    with col2:
        st.markdown(f"**Case Status:** {inv['status']}")
        st.markdown(f"**Total Registered Evidence Items:** {len(evidence_list)}")
        st.markdown(f"**Total Chronological Events:** {len(timeline_df)}")

    # Generate Markdown Report
    events_list = timeline_df.to_dict(orient="records") if not timeline_df.empty else []
    chains = correlate_attack_chain(events_list)
    brute = detect_brute_force(events_list)

    report_lines = [
        f"# FORENSIX FORENSIC EXAMINATION REPORT",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Platform:** FORENSIX Phase 1 Core",
        "",
        "---",
        "## 1. INVESTIGATION DETAILS",
        f"- **Investigation ID:** {inv['id']}",
        f"- **Case Name:** {inv['case_name']}",
        f"- **Lead Investigator:** {inv['lead_investigator']}",
        f"- **Scope & Summary:** {inv['description'] or 'Not specified'}",
        "",
        "## 2. DIGITAL EVIDENCE INTEGRITY AUDIT",
    ]

    if evidence_list:
        report_lines.append("| Evidence ID | Artifact Name | Size (Bytes) | Baseline SHA-256 | Current Integrity |")
        report_lines.append("|---|---|---|---|---|")
        for e in evidence_list:
            report_lines.append(f"| {e['id']} | {e['evidence_name']} | {e['file_size_bytes']} | `{e['sha256']}` | {e['integrity_status']} |")
    else:
        report_lines.append("_No digital evidence items registered for this case._")

    report_lines.extend([
        "",
        "## 3. INCIDENT RECONSTRUCTION & TIMELINE CORRELATION",
    ])

    if chains:
        report_lines.append("### Identified Attack Chain Progression")
        for c in chains:
            report_lines.append(f"- **{c['stage']}**: {c['summary']}")
        report_lines.append("")

    if brute:
        report_lines.append("### Specific Correlation Findings")
        for b in brute:
            report_lines.append(f"- **{b['pattern']}**: {b['message']}")
        report_lines.append("")

    if not timeline_df.empty:
        report_lines.append("### Chronological Event Ledger")
        report_lines.append("| Timestamp (UTC) | Event Class | Origin | Actor | Narrative | Severity |")
        report_lines.append("|---|---|---|---|---|---|")
        for _, r in timeline_df.iterrows():
            ts = r["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            report_lines.append(f"| {ts} | {r['event_type']} | {r['source']} | {r['actor']} | {r['description']} | {r['severity']} |")
    else:
        report_lines.append("_No chronological events registered for this investigation._")

    report_lines.extend([
        "",
        "---",
        "## 4. DISCLAIMER & FORENSIC BOUNDARIES",
        "> **Notice**: This report was generated locally by FORENSIX Phase 1. Cryptographic hashes reflect local verification. FORENSIX does not claim guaranteed tamper-proof physical storage or legal certification. Simulated demonstration entries are marked accordingly.",
        ""
    ])

    report_text = "\n".join(report_lines)

    st.markdown("---")
    st.text_area("Markdown Dossier Output", value=report_text, height=350)

    # Download report buttons
    col_d1, col_d2 = st.columns(2)
    with col_d1:
        st.download_button(
            label="💾 Download Markdown Report (.md)",
            data=report_text,
            file_name=f"FORENSIX_Report_{inv['id']}.md",
            mime="text/markdown",
            use_container_width=True
        )
    with col_d2:
        if not timeline_df.empty:
            csv_data = timeline_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="📊 Export Timeline Ledger (.csv)",
                data=csv_data,
                file_name=f"FORENSIX_Timeline_{inv['id']}.csv",
                mime="text/csv",
                use_container_width=True
            )
