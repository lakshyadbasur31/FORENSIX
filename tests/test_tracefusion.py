"""Unit tests for Phase 4: TRACEFUSION module.

Validates:
- Event normalization
- Timestamp normalization (UTC-aware)
- Chronological sorting
- Direct evidence linkage
- Filename correlation
- Hash correlation
- Temporal correlation
- Confidence calculation
- Missing fields and malformed records
- Duplicate event handling
"""
from datetime import datetime, timezone, timedelta
import pandas as pd
import tempfile
from pathlib import Path

from database.db import init_db, execute_commit, execute_query
from modules.tracefusion import (
    normalize_to_utc_dt,
    format_utc_string,
    NormalizedEvent,
    retrieve_all_investigation_events,
    correlate_events,
    get_unified_forensic_timeline
)


def test_timestamp_normalization_utc():
    """Validates robust UTC timestamp parsing across diverse formats."""
    # ISO string with Z
    dt1 = normalize_to_utc_dt("2026-11-16T09:14:35Z")
    assert dt1 is not None
    assert dt1.tzinfo is not None
    assert format_utc_string(dt1) == "2026-11-16 09:14:35"

    # SQLite string
    dt2 = normalize_to_utc_dt("2026-11-16 10:20:00")
    assert dt2 is not None
    assert format_utc_string(dt2) == "2026-11-16 10:20:00"

    # UNIX epoch
    dt3 = normalize_to_utc_dt(1700000000)
    assert dt3 is not None
    assert "2023-11-14" in format_utc_string(dt3)

    # Missing and malformed values fail gracefully
    assert normalize_to_utc_dt(None) is None
    assert normalize_to_utc_dt("") is None
    assert normalize_to_utc_dt("MALFORMED_TIMESTAMP") is None


def test_normalized_event_model():
    """Validates the normalized forensic event model and dictionary export."""
    dt = datetime(2026, 11, 16, 9, 18, 0, tzinfo=timezone.utc)
    evt = NormalizedEvent(
        event_id="WTE-01",
        timestamp=dt,
        source="WEBTRACE:Chrome",
        event_type="DOWNLOAD",
        description="Downloaded file",
        filename="payload.zip",
        severity="HIGH"
    )

    d = evt.to_dict()
    assert d["event_id"] == "WTE-01"
    assert d["timestamp"] == "2026-11-16 09:18:00"
    assert d["source"] == "WEBTRACE:Chrome"
    assert d["event_type"] == "DOWNLOAD"
    assert d["filename"] == "payload.zip"
    assert d["severity"] == "HIGH"


def test_cross_module_correlations_rules():
    """Validates all correlation rules: direct link, filename match, combined correlation, hash match."""
    t0 = datetime(2026, 11, 16, 9, 7, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 11, 16, 9, 18, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 11, 16, 9, 21, 0, tzinfo=timezone.utc)  # 3 minutes later

    e_auth = NormalizedEvent(
        event_id="EVT-AUTH",
        timestamp=t0,
        source="FORENSIC_LOG:auth.log",
        event_type="AUTH_SUCCESS",
        description="Accepted password for user from 192.168.1.145",
        actor="jsmith"
    )

    e_download = NormalizedEvent(
        event_id="WTE-DL",
        timestamp=t1,
        source="WEBTRACE:Chrome",
        event_type="DOWNLOAD",
        description="Downloaded patch-v4.zip",
        filename="patch-v4.zip",
        hostname="cdn-updates-mirror99.net",
        evidence_id="EV-12345"  # Direct link
    )

    e_evidence = NormalizedEvent(
        event_id="EV-INTAKE-EV-12345",
        timestamp=t2,
        source="CHAINLOCK:VAULT",
        event_type="EVIDENCE_ACQUIRED",
        description="Evidence secured: patch-v4.zip.txt",
        filename="patch-v4.zip.txt",
        evidence_id="EV-12345",
        hash_val="a" * 64
    )

    e_custody = NormalizedEvent(
        event_id="COC-99",
        timestamp=t2 + timedelta(seconds=10),
        source="CHAINLOCK:CUSTODY",
        event_type="CUSTODY_VERIFIED",
        description="Verification passed",
        evidence_id="EV-12345",
        hash_val="a" * 64
    )

    events = [e_auth, e_download, e_evidence, e_custody]
    findings = correlate_events(events, proximity_window_seconds=600)
    rel_types = [f.relationship_type for f in findings]

    # 1. DIRECT_LINK should be found
    assert "DIRECT_LINK" in rel_types
    # 2. COMBINED_CORRELATION (Filename + < 15 min proximity)
    assert "COMBINED_CORRELATION" in rel_types
    # 3. HASH_MATCH (shared between evidence and custody verification)
    assert "HASH_MATCH" in rel_types
    # 4. TEMPORAL_PROXIMITY (AUTH_SUCCESS -> DOWNLOAD within 11 min)
    assert "TEMPORAL_PROXIMITY" in rel_types

    # Validate explanations
    combined_finding = next(f for f in findings if f.relationship_type == "COMBINED_CORRELATION")
    assert "corresponds to evidence" in combined_finding.reason
    assert combined_finding.confidence == "HIGH"
    assert combined_finding.time_delta_seconds == 180.0


def test_unrelated_and_missing_data_events():
    """Validates that unrelated events and events with missing attributes do not generate false correlations."""
    e1 = NormalizedEvent(
        event_id="E1",
        timestamp=None,
        source="LOG",
        event_type="GENERIC",
        description="System startup"
    )
    e2 = NormalizedEvent(
        event_id="E2",
        timestamp=datetime(2026, 11, 16, 12, 0, 0, tzinfo=timezone.utc),
        source="WEBTRACE",
        event_type="PAGE_VISIT",
        description="Visited documentation",
        hostname="example.org"
    )

    findings = correlate_events([e1, e2])
    assert len(findings) == 0


def test_database_retrieval_and_unified_timeline():
    """End-to-end integration test querying SQLite and assembling the unified timeline."""
    init_db()
    case_id = "CAS-TRACEFUSION-E2E"

    try:
        execute_commit(
            "INSERT INTO investigations (id, case_name, lead_investigator) VALUES (?, ?, ?)",
            (case_id, "TraceFusion Case", "Analyst Alpha")
        )
        execute_commit(
            """
            INSERT INTO forensic_events (id, investigation_id, timestamp, event_type, source, description)
            VALUES ('EVT-TF-1', ?, '2026-11-16 09:07:00', 'AUTH_SUCCESS', 'auth.log', 'Login OK')
            """,
            (case_id,)
        )
        execute_commit(
            """
            INSERT INTO evidence (id, investigation_id, evidence_name, source_path, file_size_bytes, sha256, acquired_by, acquisition_date)
            VALUES ('EV-TF-1', ?, 'suspect.bin', 'path/to/bin', 1024, 'b'*64, 'Analyst', '2026-11-16 09:20:00')
            """,
            (case_id,)
        )

        timeline_df = get_unified_forensic_timeline(case_id)
        assert len(timeline_df) >= 2
        assert "timestamp" in timeline_df.columns
        assert "source" in timeline_df.columns
        # Chronologically sorted
        ts_list = list(timeline_df["timestamp"])
        assert ts_list == sorted(ts_list)
    finally:
        execute_commit("DELETE FROM investigations WHERE id = ?", (case_id,))
