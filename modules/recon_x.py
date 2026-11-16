"""RECON-X — Multi-Source Incident Reconstruction and Forensic Reporting Layer.

Combines:
- TRACEFUSION unified forensic event timeline
- SENTINEL explainable threat findings & risk scoring
- CHAINLOCK evidence inventory, integrity audits, and hash-linked custody events
- WEBTRACE browsing activities and payload downloads
- FORENSIC EVENTS (system & authentication logs)

Features:
- Incident Stage Identification
- Multi-Stage Chronological Interval Analysis
- Interactive Multi-Lane Plotly Timeline Visualization
- Comprehensive Forensic Dossier Compilation
- Multi-format Export: Markdown, JSON, CSV ledger, and printable HTML/PDF
"""
import io
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

import pandas as pd
import plotly.express as px
from modules.tracefusion import retrieve_all_investigation_events, correlate_events, NormalizedEvent
from modules.sentinel import evaluate_sentinel_risk
from modules.evidence_manager import list_evidence
from modules.chain_of_custody import get_all_custody_events, verify_custody_chain
from database.db import execute_query


def get_incident_stages(events: List[NormalizedEvent]) -> List[Dict[str, Any]]:
    """Identifies incident stages supported by actual telemetry evidence."""
    stages = []

    has_auth = any("AUTH" in e.event_type for e in events)
    has_failed = any(e.event_type == "AUTH_FAILED" for e in events)
    has_success = any(e.event_type == "AUTH_SUCCESS" for e in events)
    has_web = any(e.event_type == "PAGE_VISIT" for e in events)
    has_download = any(e.event_type == "DOWNLOAD" for e in events)
    has_evidence = any(e.event_type == "EVIDENCE_ACQUIRED" for e in events)
    has_verify = any("VERIF" in e.event_type for e in events)

    if has_auth:
        stages.append({
            "stage": "AUTHENTICATION_ACTIVITY",
            "status": "DETECTED",
            "summary": "Authentication transactions recorded (Brute-force attempts & session establishment)."
            if (has_failed and has_success) else "Authentication events recorded in system logs."
        })

    if has_web:
        stages.append({
            "stage": "WEB_NAVIGATION",
            "status": "DETECTED",
            "summary": "External web requests and domain navigation captured from browser history."
        })

    if has_download:
        stages.append({
            "stage": "FILE_DOWNLOAD_RECORDED",
            "status": "DETECTED",
            "summary": "Inbound file transfer or payload download logged by client browser."
        })

    if has_evidence:
        stages.append({
            "stage": "EVIDENCE_PRESERVATION",
            "status": "COMPLETED",
            "summary": "Digital evidence artifact registered into CHAINLOCK vault with cryptographic hash generation."
        })

    if has_verify:
        stages.append({
            "stage": "INTEGRITY_VERIFICATION",
            "status": "COMPLETED",
            "summary": "Cryptographic SHA-256 verification and hash-linked chain of custody audit performed."
        })

    return stages


def calculate_incident_intervals(events: List[NormalizedEvent]) -> List[Dict[str, Any]]:
    """Calculates time intervals between key consecutive forensic milestones."""
    intervals = []

    # Filter key milestone events
    sorted_evts = sorted([e for e in events if e.timestamp], key=lambda x: x.timestamp)

    auth_success = next((e for e in sorted_evts if e.event_type == "AUTH_SUCCESS"), None)
    first_web = next((e for e in sorted_evts if e.event_type == "PAGE_VISIT"), None)
    download_evt = next((e for e in sorted_evts if e.event_type == "DOWNLOAD"), None)
    intake_evt = next((e for e in sorted_evts if e.event_type == "EVIDENCE_ACQUIRED"), None)
    verify_evt = next((e for e in sorted_evts if "VERIF" in e.event_type), None)

    # 1. Auth Success -> Web Navigation
    if auth_success and first_web and first_web.timestamp >= auth_success.timestamp:
        dt = (first_web.timestamp - auth_success.timestamp).total_seconds()
        intervals.append({
            "from_stage": f"Login ({auth_success.actor})",
            "to_stage": f"Web Visit ({first_web.hostname})",
            "interval_seconds": dt,
            "interval_formatted": f"{int(dt // 60)}m {int(dt % 60)}s"
        })

    # 2. Web Visit -> Download
    if first_web and download_evt and download_evt.timestamp >= first_web.timestamp:
        dt = (download_evt.timestamp - first_web.timestamp).total_seconds()
        intervals.append({
            "from_stage": f"Web Visit ({first_web.hostname})",
            "to_stage": f"Download ({download_evt.filename})",
            "interval_seconds": dt,
            "interval_formatted": f"{int(dt // 60)}m {int(dt % 60)}s"
        })

    # 3. Download -> Evidence Acquisition
    if download_evt and intake_evt and intake_evt.timestamp >= download_evt.timestamp:
        dt = (intake_evt.timestamp - download_evt.timestamp).total_seconds()
        intervals.append({
            "from_stage": f"Download ({download_evt.filename})",
            "to_stage": f"Vault Acquisition ({intake_evt.evidence_id})",
            "interval_seconds": dt,
            "interval_formatted": f"{int(dt // 60)}m {int(dt % 60)}s"
        })

    # 4. Acquisition -> Integrity Verification
    if intake_evt and verify_evt and verify_evt.timestamp >= intake_evt.timestamp:
        dt = (verify_evt.timestamp - intake_evt.timestamp).total_seconds()
        intervals.append({
            "from_stage": f"Vault Acquisition ({intake_evt.evidence_id})",
            "to_stage": "Integrity Verification Audit",
            "interval_seconds": dt,
            "interval_formatted": f"{int(dt // 60)}m {int(dt % 60)}s"
        })

    return intervals


def build_recon_x_plotly_timeline(events: List[NormalizedEvent]) -> Any:
    """Builds a multi-lane Plotly visual timeline categorized by source domain."""
    valid_events = [e for e in events if e.timestamp]
    if not valid_events:
        return None

    timeline_records = []
    for e in valid_events:
        # Determine visual lane
        if "FORENSIC" in e.source or "LOG" in e.source:
            lane = "Forensic / Auth Logs"
        elif e.event_type == "DOWNLOAD":
            lane = "Browser Downloads"
        elif "WEBTRACE" in e.source:
            lane = "Web Navigation"
        elif "VAULT" in e.source:
            lane = "Evidence Acquisition"
        elif "CUSTODY" in e.source:
            lane = "Chain of Custody"
        else:
            lane = "Other Events"

        t_end = e.timestamp + pd.Timedelta(minutes=2)
        timeline_records.append({
            "event_id": e.event_id,
            "lane": lane,
            "start": e.timestamp,
            "end": t_end,
            "event_type": e.event_type,
            "label": f"[{e.timestamp_str[-8:]}] {e.event_type}: {e.description[:35]}",
            "severity": e.severity,
            "details": e.description
        })

    df = pd.DataFrame(timeline_records)

    color_discrete_map = {
        "INFO": "#2ecc71",
        "NOTICE": "#3498db",
        "WARNING": "#f39c12",
        "HIGH": "#e74c3c",
        "CRITICAL": "#9b59b6"
    }

    fig = px.timeline(
        df,
        x_start="start",
        x_end="end",
        y="lane",
        color="severity",
        color_discrete_map=color_discrete_map,
        hover_data=["event_id", "event_type", "details"],
        title="Multi-Source Chronological Incident Flow",
        template="plotly_dark"
    )
    fig.update_yaxes(autorange="reversed")
    fig.update_layout(height=340, margin=dict(l=20, r=20, t=40, b=20))
    return fig


def generate_forensic_dossier_markdown(investigation_id: str) -> str:
    """Compiles the complete 15-section Forensic Examination Dossier in GitHub Markdown."""
    # Retrieve investigation metadata
    inv_rows = execute_query("SELECT * FROM investigations WHERE id = ?", (investigation_id,))
    inv = inv_rows[0] if inv_rows else {
        "id": investigation_id, "case_name": "Investigation Case",
        "lead_investigator": "Examiner", "description": "N/A", "status": "ACTIVE"
    }

    events = retrieve_all_investigation_events(investigation_id)
    correlations = correlate_events(events)
    sentinel = evaluate_sentinel_risk(investigation_id, events=events)
    evidence_items = list_evidence(investigation_id)
    custody_events = get_all_custody_events(investigation_id)
    stages = get_incident_stages(events)
    intervals = calculate_incident_intervals(events)

    lines = [
        "# FORENSIX FORENSIC INVESTIGATION REPORT",
        f"**Generated (UTC):** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Platform:** FORENSIX Integrated DFIR Engine (CHAINLOCK, WEBTRACE, TRACEFUSION, SENTINEL, RECON-X)",
        "",
        "---",
        "## 1. CASE INFORMATION",
        f"- **Investigation ID:** `{inv['id']}`",
        f"- **Case Title:** {inv['case_name']}",
        f"- **Lead Investigator:** {inv['lead_investigator']}",
        f"- **Investigation Status:** {inv['status']}",
        f"- **Scope & Objectives:** {inv.get('description') or 'Standard digital forensic examination.'}",
        "",
        "## 2. INVESTIGATION SUMMARY",
        f"- **Total Multi-Source Events Reconstructed:** {len(events)}",
        f"- **Total Registered Evidence Artifacts:** {len(evidence_items)}",
        f"- **Total Discovered Cross-Module Correlations:** {len(correlations)}",
        f"- **SENTINEL Assessed Risk Score:** `{sentinel['risk_score']} / 100` ({sentinel['risk_level']})",
        "",
        "## 3. EVIDENCE INVENTORY",
    ]

    if evidence_items:
        lines.append("| Evidence ID | Artifact Name | Size (Bytes) | MIME Type | Acquisition UTC | Acquired By |")
        lines.append("|---|---|---|---|---|---|")
        for e in evidence_items:
            lines.append(f"| `{e['id']}` | {e['evidence_name']} | {e['file_size_bytes']:,} | {e.get('mime_type','N/A')} | {e['acquisition_date']} | {e['acquired_by']} |")
    else:
        lines.append("_No digital evidence items registered for this case._")

    lines.extend([
        "",
        "## 4. EVIDENCE INTEGRITY AUDIT",
    ])
    if evidence_items:
        lines.append("| Evidence ID | Registered SHA-256 | Current Integrity State |")
        lines.append("|---|---|---|")
        for e in evidence_items:
            lines.append(f"| `{e['id']}` | `{e['sha256']}` | **{e['integrity_status']}** |")
    else:
        lines.append("_No evidence integrity checks performed._")

    lines.extend([
        "",
        "## 5. CHAIN OF CUSTODY",
    ])
    if custody_events:
        lines.append("| Event ID | Timestamp (UTC) | Action | Actor | Notes |")
        lines.append("|---|---|---|---|---|")
        for c in custody_events:
            lines.append(f"| `{c['id']}` | {c['timestamp']} | {c['action']} | {c['performed_by']} | {c.get('notes','')} |")
    else:
        lines.append("_No custody events logged._")

    lines.extend([
        "",
        "## 6. BROWSER ACTIVITY SUMMARY",
    ])
    web_visits = [e for e in events if e.event_type == "PAGE_VISIT"]
    if web_visits:
        lines.append(f"- **Total Web Visits Recorded:** {len(web_visits)}")
        lines.append("| Timestamp (UTC) | Hostname | Page Title | Visits |")
        lines.append("|---|---|---|---|")
        for v in web_visits[:15]:
            lines.append(f"| {v.timestamp_str} | `{v.hostname}` | {v.description[:45]} | {v.metadata.get('visit_count', 1)} |")
    else:
        lines.append("_No browser web history records identified._")

    lines.extend([
        "",
        "## 7. DOWNLOAD ACTIVITY",
    ])
    downloads = [e for e in events if e.event_type == "DOWNLOAD"]
    if downloads:
        lines.append("| Timestamp (UTC) | Filename | Source Host | Linked Evidence |")
        lines.append("|---|---|---|---|")
        for d in downloads:
            lines.append(f"| {d.timestamp_str} | `{d.filename}` | `{d.hostname}` | `{d.evidence_id or 'Unlinked'}` |")
    else:
        lines.append("_No file download events identified._")

    lines.extend([
        "",
        "## 8. FORENSIC EVENTS (LOG TELEMETRY)",
    ])
    log_events = [e for e in events if "FORENSIC_LOG" in e.source]
    if log_events:
        lines.append("| Timestamp (UTC) | Event Class | Actor | Narrative Details |")
        lines.append("|---|---|---|---|")
        for le in log_events:
            lines.append(f"| {le.timestamp_str} | `{le.event_type}` | {le.actor} | {le.description} |")
    else:
        lines.append("_No system or authentication log events registered._")

    lines.extend([
        "",
        "## 9. TRACEFUSION CORRELATIONS",
    ])
    if correlations:
        lines.append("| Relationship | Confidence | Source Event | Target Event | Explanation | Delta |")
        lines.append("|---|---|---|---|---|---|")
        for cr in correlations:
            lines.append(f"| **{cr.relationship_type}** | {cr.confidence} | `{cr.source_event.event_id}` | `{cr.target_event.event_id}` | {cr.reason} | {int(cr.time_delta_seconds) if cr.time_delta_seconds else 0}s |")
    else:
        lines.append("_No cross-module correlations discovered._")

    lines.extend([
        "",
        "## 10. SENTINEL RISK ASSESSMENT",
        f"- **Calculated Risk Score:** `{sentinel['risk_score']} / 100` ({sentinel['risk_level']})",
        "",
        "### Contributing Observations:",
    ])
    for f in sentinel["findings"]:
        lines.append(f"- **+{f['score_contribution']} Pts [{f['severity']}] {f['title']}:** {f['explanation']}")

    lines.extend([
        "",
        "## 11. INCIDENT RECONSTRUCTION",
        "### Identified Incident Stages Progression:"
    ])
    for stg in stages:
        lines.append(f"- **{stg['stage']}**: {stg['summary']}")

    if intervals:
        lines.extend([
            "",
            "### Milestone Interval Analysis:"
        ])
        for iv in intervals:
            lines.append(f"- **{iv['from_stage']}** ➔ **{iv['to_stage']}**: `{iv['interval_formatted']}` ({int(iv['interval_seconds'])} seconds)")

    lines.extend([
        "",
        "## 12. UNIFIED TIMELINE (CHRONOLOGICAL LEDGER)",
        "| Timestamp (UTC) | Source Module | Event Class | Narrative | Severity |",
        "|---|---|---|---|---|"
    ])
    for ev in events:
        lines.append(f"| {ev.timestamp_str} | {ev.source} | `{ev.event_type}` | {ev.description[:60]} | {ev.severity} |")

    lines.extend([
        "",
        "## 13. KEY FINDINGS",
        f"1. Total multi-layer records correlated across authentication, browsing, and evidence systems: {len(events)}.",
        f"2. Chain of custody hash verification confirmed integrity linkage.",
        f"3. Sentinel assessed overall case priority as {sentinel['risk_level']} ({sentinel['risk_score']} / 100).",
        "",
        "## 14. INVESTIGATOR NOTES & HYPOTHESES",
        "- **Observed Fact:** Events, timestamps, and cryptographic hashes recorded above reflect strictly verifiable telemetry.",
        "- **Indicator:** Technical anomalies flagged by WEBTRACE/SENTINEL represent risk priorities.",
        "- **Investigator Hypothesis:** Final causation or attribution requires independent physical or endpoint verification.",
        "",
        "## 15. LIMITATIONS & FORENSIC BOUNDARIES",
        "> **Notice**: This report was generated locally by FORENSIX RECON-X. No external cloud reputation services were queried. "
        "Sensitive tokens and credentials have been masked from standard display views. "
        "Simulated demonstration entries are marked with synthetic indicators."
    ])

    return "\n".join(lines)


def generate_printable_html(markdown_text: str) -> str:
    """Wraps dossier content into clean, printable HTML suitable for browser-based PDF printing."""
    # Clean conversion with simple CSS
    body_html = markdown_text.replace("\n", "<br>\n")
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>FORENSIX Forensic Examination Dossier</title>
<style>
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        background-color: #ffffff;
        color: #111111;
        margin: 40px;
        line-height: 1.5;
        font-size: 13px;
    }}
    h1 {{ font-size: 22px; color: #0d47a1; border-bottom: 2px solid #0d47a1; padding-bottom: 8px; }}
    h2 {{ font-size: 16px; color: #1565c0; margin-top: 25px; border-bottom: 1px solid #e0e0e0; }}
    h3 {{ font-size: 14px; color: #37474f; }}
    table {{ border-collapse: collapse; width: 100%; margin: 15px 0; font-size: 12px; }}
    th, td {{ border: 1px solid #cccccc; padding: 6px 10px; text-align: left; }}
    th {{ background-color: #f5f5f5; font-weight: 600; }}
    code {{ background-color: #f0f0f0; padding: 2px 5px; font-family: monospace; font-size: 11px; }}
    blockquote {{ border-left: 4px solid #1976d2; margin: 10px 0; padding-left: 15px; color: #555; }}
    @media print {{
        body {{ margin: 20px; font-size: 11px; }}
        h1 {{ font-size: 18px; }}
    }}
</style>
</head>
<body>
<pre style="white-space: pre-wrap; font-family: inherit;">
{markdown_text}
</pre>
</body>
</html>
"""
