"""Investigation Overview page for FORENSIX.

Provides high-level situational awareness, active cases selector,
investigation creation, and case status tracking.
"""
import streamlit as st
import pandas as pd
from database.db import execute_query, execute_commit
from data.sample_evidence.seed_demo import seed_demo_data
import uuid


def render():
    st.markdown("## 🔎 Investigation Overview")
    st.markdown("Central coordination workspace for digital forensics investigations and cases.")

    # Actions row
    col_a, col_b = st.columns([3, 1])
    with col_b:
        if st.button("📥 Load Demo Scenario (Nov 16, 2026)", use_container_width=True):
            cid = seed_demo_data(force_refresh=True)
            st.session_state["active_investigation_id"] = cid
            st.success(f"Loaded simulated demonstration case {cid}!")
            st.rerun()

    # Create New Investigation form inside expander
    with st.expander("➕ Open New Investigation Case", expanded=False):
        with st.form("new_case_form"):
            case_name = st.text_input("Investigation Name *", placeholder="e.g., Unauthorized Lateral Movement")
            investigator = st.text_input("Lead Investigator *", placeholder="e.g., Jane Doe, GCFE")
            description = st.text_area("Case Scope & Objectives", placeholder="Initial indicators, scope of search...")
            submitted = st.form_submit_button("Initialize Case")

            if submitted:
                if not case_name.strip() or not investigator.strip():
                    st.error("Case name and lead investigator are required.")
                else:
                    new_id = f"CAS-{uuid.uuid4().hex[:6].upper()}"
                    execute_commit(
                        "INSERT INTO investigations (id, case_name, lead_investigator, description, status) VALUES (?, ?, ?, ?, ?)",
                        (new_id, case_name.strip(), investigator.strip(), description.strip(), "ACTIVE")
                    )
                    st.session_state["active_investigation_id"] = new_id
                    st.success(f"Investigation initialized: {new_id}")
                    st.rerun()

    # List all investigations
    investigations = execute_query("SELECT * FROM investigations ORDER BY created_at DESC")

    if not investigations:
        st.info("No investigations found. Create a new case above or click 'Load Demo Scenario' to explore with simulated data.")
        return

    # Metrics summary for active investigations
    cases_df = pd.DataFrame(investigations)
    total_cases = len(cases_df)
    active_cases = len(cases_df[cases_df["status"] == "ACTIVE"])

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Investigations", total_cases)
    col2.metric("Active Investigations", active_cases)
    
    # Active investigation switcher
    case_options = {row["id"]: f"{row['case_name']} [{row['id']}]" for row in investigations}
    current_selected = st.session_state.get("active_investigation_id", investigations[0]["id"])
    if current_selected not in case_options:
        current_selected = investigations[0]["id"]

    selected_case = st.selectbox(
        "Active Working Investigation:",
        options=list(case_options.keys()),
        format_func=lambda x: case_options[x],
        index=list(case_options.keys()).index(current_selected)
    )
    st.session_state["active_investigation_id"] = selected_case

    # Display active case card
    active_row = next(r for r in investigations if r["id"] == selected_case)
    st.markdown("---")
    st.markdown(f"### Active Case Details: `{active_row['case_name']}`")

    c1, c2, c3 = st.columns(3)
    with c1:
        st.caption("CASE IDENTIFIER")
        st.code(active_row["id"], language="text")
    with c2:
        st.caption("LEAD INVESTIGATOR")
        st.write(active_row["lead_investigator"])
    with c3:
        st.caption("STATUS")
        st.write(f"🟢 **{active_row['status']}**")

    st.caption("CASE SCOPE & DESCRIPTION")
    st.write(active_row["description"] or "No description specified.")

    # Summary counts for the active case
    ev_count = execute_query("SELECT COUNT(*) as c FROM evidence WHERE investigation_id = ?", (selected_case,))[0]["c"]
    evt_count = execute_query("SELECT COUNT(*) as c FROM forensic_events WHERE investigation_id = ?", (selected_case,))[0]["c"]

    col_m1, col_m2 = st.columns(2)
    col_m1.metric("Registered Evidence Artifacts", ev_count)
    col_m2.metric("Chronological Timeline Events", evt_count)
