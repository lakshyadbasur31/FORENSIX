"""FORENSIX — Integrated Digital Forensics, Evidence Integrity & Incident Reconstruction Platform.

Tagline: Preserve. Investigate. Reconstruct.
Main Streamlit application entry point.
"""
import streamlit as st
from config import APP_TITLE, APP_SUBTITLE, TAGLINE, VERSION
from database.db import init_db
from dashboard import (
    overview,
    evidence_vault,
    browser_lab,
    incident_timeline,
    investigation_report,
    tracefusion_view,
    sentinel_view,
    recon_x_view
)

# Page configuration
st.set_page_config(
    page_title=f"{APP_TITLE} | Digital Forensics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom cybersecurity dark styling
CUSTOM_CSS = """
<style>
    /* Global cybersecurity aesthetics */
    .stApp {
        background-color: #0c1017;
        color: #e6edf3;
    }
    /* Brand header */
    .brand-title {
        font-family: 'Courier New', Courier, monospace;
        font-size: 2.1rem;
        font-weight: 800;
        letter-spacing: 2px;
        color: #58a6ff;
        margin-bottom: 0px;
    }
    .brand-tagline {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        font-size: 0.88rem;
        font-weight: 600;
        color: #8b949e;
        letter-spacing: 1px;
        text-transform: uppercase;
        margin-bottom: 12px;
    }
    .status-badge {
        display: inline-block;
        padding: 2px 8px;
        font-size: 0.72rem;
        border-radius: 4px;
        background-color: #1f6feb22;
        border: 1px solid #1f6feb;
        color: #58a6ff;
        margin-bottom: 15px;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


def init_app():
    """Initializes SQLite database and session state defaults."""
    init_db()
    if "active_investigation_id" not in st.session_state:
        st.session_state["active_investigation_id"] = None


def main():
    init_app()

    # Sidebar Navigation & Branding
    with st.sidebar:
        st.markdown(f"<div class='brand-title'>🛡️ {APP_TITLE}</div>", unsafe_allow_html=True)
        st.markdown(f"<div class='brand-tagline'>{TAGLINE}</div>", unsafe_allow_html=True)
        st.markdown(f"<span class='status-badge'>CORE ENGINE v{VERSION}</span>", unsafe_allow_html=True)

        st.markdown("### Forensic Modules")
        page = st.radio(
            "Select Workspace:",
            [
                "🔎 Investigation Overview",
                "🔒 Evidence Vault & Integrity (CHAINLOCK)",
                "🌐 Browser Forensics (WEBTRACE)",
                "🧬 Forensic Correlation (TRACEFUSION)",
                "🛡️ Threat Prioritization (SENTINEL)",
                "🧭 Incident Reconstruction (RECON-X)",
                "⏱️ Activity Timeline (Legacy)",
                "📑 Investigation Dossiers (Legacy)"
            ],
            index=0
        )

        st.markdown("---")
        st.caption("Active Session Context:")
        active_inv = st.session_state.get("active_investigation_id")
        if active_inv:
            st.code(f"Case: {active_inv}", language="text")
        else:
            st.caption("No case active. Go to Overview.")

        st.markdown("---")
        st.caption("FORENSIX Local DFIR Engine\nNo external cloud or telemetry dependencies.")

    # Page routing
    if "Overview" in page:
        overview.render()
    elif "Evidence Vault" in page or "CHAINLOCK" in page:
        evidence_vault.render()
    elif "Browser Forensics" in page or "WEBTRACE" in page:
        browser_lab.render()
    elif "TRACEFUSION" in page:
        tracefusion_view.render()
    elif "SENTINEL" in page:
        sentinel_view.render()
    elif "RECON-X" in page:
        recon_x_view.render()
    elif "Activity Timeline" in page:
        incident_timeline.render()
    elif "Investigation Dossiers" in page or "Investigation Reports" in page:
        investigation_report.render()


if __name__ == "__main__":
    main()
