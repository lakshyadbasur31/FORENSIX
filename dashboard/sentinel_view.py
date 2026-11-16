"""SENTINEL — Explainable Threat Intelligence and Risk Prioritization Dashboard.

Features:
- Deterministic 0-100 Risk Score Gauge with Plotly
- Risk Level Badges (LOW, MEDIUM, HIGH, CRITICAL)
- Contributing Observations Ledger with Exact Point Allocations
- Explainable Indicator Details & Related Telemetry Links
- Prioritized Investigator Recommendations
"""
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from modules.sentinel import evaluate_sentinel_risk


def render():
    st.markdown("## 🛡️ SENTINEL — Threat Intelligence & Risk Prioritization")
    st.markdown(
        "Deterministic, explainable risk prioritization scoring based strictly on observed indicators, "
        "correlations, and evidence integrity states."
    )

    active_inv = st.session_state.get("active_investigation_id")
    if not active_inv:
        st.warning("⚠️ Please select or initialize an active investigation in the Overview tab first.")
        return

    # Evaluate Sentinel Risk
    assessment = evaluate_sentinel_risk(active_inv)
    score = assessment["risk_score"]
    level = assessment["risk_level"]
    findings = assessment["findings"]
    recommendations = assessment["recommendations"]

    # 1. High-level score display
    col_g1, col_g2 = st.columns([2, 3])

    with col_g1:
        # Gauge chart using Plotly
        color_map = {
            "LOW": "#2ecc71",
            "MEDIUM": "#f39c12",
            "HIGH": "#e67e22",
            "CRITICAL": "#e74c3c"
        }
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': f"INVESTIGATION RISK: {level}", 'font': {'size': 20, 'color': color_map[level]}},
            number={'font': {'size': 38, 'color': '#e6edf3'}},
            gauge={
                'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#8b949e"},
                'bar': {'color': color_map[level]},
                'bgcolor': "#161b22",
                'borderwidth': 1,
                'bordercolor': "#30363d",
                'steps': [
                    {'range': [0, 30], 'color': '#2ecc7122'},
                    {'range': [30, 60], 'color': '#f39c1222'},
                    {'range': [60, 80], 'color': '#e67e2222'},
                    {'range': [80, 100], 'color': '#e74c3c22'}
                ]
            }
        ))
        fig.update_layout(height=260, margin=dict(l=20, r=20, t=30, b=20), paper_bgcolor="#0c1017")
        st.plotly_chart(fig, use_container_width=True)

    with col_g2:
        st.markdown("#### Risk Assessment Summary")
        st.markdown(f"**Calculated Score:** `{score} / 100` &nbsp;|&nbsp; **Risk Classification:** `{level}`")
        st.markdown(f"**Contributing Indicator Rules Triggered:** `{assessment['applied_rules_count']}`")
        st.info(f"💡 {assessment['disclaimer']}")

    st.markdown("---")

    # 2. Findings Ledger with Explanations
    st.markdown("### 📋 Contributing Forensic Observations")
    if not findings:
        st.success("✓ No anomalous observations detected for this investigation. Risk baseline remains minimal.")
    else:
        for f in findings:
            sev_badge = "🔴" if f["severity"] in ("CRITICAL", "HIGH") else ("🟠" if f["severity"] == "MEDIUM" else "🔵")
            with st.expander(f"{sev_badge} +{f['score_contribution']} Pts | {f['title']} [{f['severity']}]"):
                c1, c2 = st.columns([3, 1])
                with c1:
                    st.markdown(f"**Explanation:** {f['explanation']}")
                    st.markdown(f"**Evidence Reference:** `{f['evidence']}`")
                    st.caption(f"Source: `{f['source']}` | Timestamp: `{f['timestamp']}`")
                with c2:
                    st.metric("Score Impact", f"+{f['score_contribution']}")

    st.markdown("---")

    # 3. Prioritized Investigator Actions
    st.markdown("### 🎯 Prioritized Investigator Actions")
    st.markdown("Recommended follow-up verification actions derived from the observed technical findings:")

    for r in recommendations:
        p_color = "🔴" if r["priority"] in ("CRITICAL", "HIGH") else ("🟠" if r["priority"] == "MEDIUM" else "🟢")
        st.markdown(f"- **{p_color} [{r['priority']}] {r['action']}**: {r['details']}")
