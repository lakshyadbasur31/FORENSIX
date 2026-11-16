"""Unit tests for Phase 6: RECON-X module.

Validates:
- Multi-source chronological incident reconstruction
- Incident stage progression detection
- Milestone interval calculations
- Multi-lane Plotly timeline generation
- Forensic Dossier 15-section compilation (Markdown & printable HTML)
- Export structures (CSV, JSON, Markdown, HTML)
"""
from datetime import datetime, timezone, timedelta
from modules.tracefusion import NormalizedEvent
from modules.recon_x import (
    get_incident_stages,
    calculate_incident_intervals,
    build_recon_x_plotly_timeline,
    generate_forensic_dossier_markdown,
    generate_printable_html
)
from database.db import init_db, execute_commit


def test_incident_stages_detection():
    """Validates accurate identification of forensic incident stages."""
    t0 = datetime(2026, 11, 16, 9, 2, 0, tzinfo=timezone.utc)
    evts = [
        NormalizedEvent("E1", t0, "LOG", "AUTH_FAILED", "Failed root"),
        NormalizedEvent("E2", t0 + timedelta(minutes=5), "LOG", "AUTH_SUCCESS", "Accepted user"),
        NormalizedEvent("E3", t0 + timedelta(minutes=12), "WEBTRACE", "PAGE_VISIT", "Visited mirror", hostname="mirror.net"),
        NormalizedEvent("E4", t0 + timedelta(minutes=16), "WEBTRACE", "DOWNLOAD", "Downloaded patch.zip", filename="patch.zip"),
        NormalizedEvent("E5", t0 + timedelta(minutes=19), "CHAINLOCK", "EVIDENCE_ACQUIRED", "Acquired patch.zip", evidence_id="EV-1"),
        NormalizedEvent("E6", t0 + timedelta(minutes=20), "CHAINLOCK", "CUSTODY_VERIFIED", "Integrity verified", evidence_id="EV-1")
    ]

    stages = get_incident_stages(evts)
    names = [s["stage"] for s in stages]

    assert "AUTHENTICATION_ACTIVITY" in names
    assert "WEB_NAVIGATION" in names
    assert "FILE_DOWNLOAD_RECORDED" in names
    assert "EVIDENCE_PRESERVATION" in names
    assert "INTEGRITY_VERIFICATION" in names
    assert len(stages) == 5


def test_milestone_interval_analysis():
    """Validates calculation of time gaps between key milestone stages."""
    t0 = datetime(2026, 11, 16, 9, 7, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=7, seconds=13)  # Web visit
    t2 = t1 + timedelta(minutes=3, seconds=29)  # Download
    t3 = t2 + timedelta(minutes=2, seconds=56)  # Vault intake

    evts = [
        NormalizedEvent("E1", t0, "LOG", "AUTH_SUCCESS", "Login jsmith", actor="jsmith"),
        NormalizedEvent("E2", t1, "WEBTRACE", "PAGE_VISIT", "Visited site", hostname="mirror99.net"),
        NormalizedEvent("E3", t2, "WEBTRACE", "DOWNLOAD", "Download patch-v4.zip", filename="patch-v4.zip"),
        NormalizedEvent("E4", t3, "CHAINLOCK", "EVIDENCE_ACQUIRED", "Intake", evidence_id="EV-DEMO", filename="patch-v4.zip")
    ]

    intervals = calculate_incident_intervals(evts)
    assert len(intervals) >= 3

    # Check first interval (Login -> Web Visit: 7m 13s = 433s)
    assert intervals[0]["from_stage"] == "Login (jsmith)"
    assert intervals[0]["interval_seconds"] == 433.0
    assert intervals[0]["interval_formatted"] == "7m 13s"

    # Check second interval (Web Visit -> Download: 3m 29s = 209s)
    assert intervals[1]["interval_seconds"] == 209.0
    assert intervals[1]["interval_formatted"] == "3m 29s"


def test_recon_x_plotly_timeline_generation():
    """Validates multi-lane Plotly visual timeline generation."""
    t0 = datetime(2026, 11, 16, 9, 0, 0, tzinfo=timezone.utc)
    evts = [
        NormalizedEvent("E1", t0, "FORENSIC_LOG", "AUTH_SUCCESS", "Login"),
        NormalizedEvent("E2", t0 + timedelta(minutes=2), "WEBTRACE", "PAGE_VISIT", "Visit"),
        NormalizedEvent("E3", t0 + timedelta(minutes=4), "WEBTRACE", "DOWNLOAD", "DL", filename="tool.exe"),
        NormalizedEvent("E4", t0 + timedelta(minutes=6), "CHAINLOCK:VAULT", "EVIDENCE_ACQUIRED", "Intake", evidence_id="EV-1")
    ]

    fig = build_recon_x_plotly_timeline(evts)
    assert fig is not None
    # Figure has data traces
    assert len(fig.data) > 0


def test_dossier_markdown_and_html_compilation():
    """Validates compilation of the 15-section Forensic Dossier."""
    init_db()
    case_id = "CAS-RECONX-TEST"

    try:
        execute_commit(
            "INSERT INTO investigations (id, case_name, lead_investigator, description) VALUES (?, ?, ?, ?)",
            (case_id, "Operation BlackIce", "Special Agent Fox", "Incident reconstruction verification")
        )

        dossier_md = generate_forensic_dossier_markdown(case_id)
        assert "# FORENSIX FORENSIC INVESTIGATION REPORT" in dossier_md
        assert "1. CASE INFORMATION" in dossier_md
        assert "2. INVESTIGATION SUMMARY" in dossier_md
        assert "3. EVIDENCE INVENTORY" in dossier_md
        assert "4. EVIDENCE INTEGRITY AUDIT" in dossier_md
        assert "5. CHAIN OF CUSTODY" in dossier_md
        assert "6. BROWSER ACTIVITY SUMMARY" in dossier_md
        assert "7. DOWNLOAD ACTIVITY" in dossier_md
        assert "8. FORENSIC EVENTS (LOG TELEMETRY)" in dossier_md
        assert "9. TRACEFUSION CORRELATIONS" in dossier_md
        assert "10. SENTINEL RISK ASSESSMENT" in dossier_md
        assert "11. INCIDENT RECONSTRUCTION" in dossier_md
        assert "12. UNIFIED TIMELINE (CHRONOLOGICAL LEDGER)" in dossier_md
        assert "13. KEY FINDINGS" in dossier_md
        assert "14. INVESTIGATOR NOTES & HYPOTHESES" in dossier_md
        assert "15. LIMITATIONS & FORENSIC BOUNDARIES" in dossier_md

        # HTML generation
        html = generate_printable_html(dossier_md)
        assert "<!DOCTYPE html>" in html
        assert "FORENSIX Forensic Examination Dossier" in html

    finally:
        execute_commit("DELETE FROM investigations WHERE id = ?", (case_id,))
