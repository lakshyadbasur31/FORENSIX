"""Helper script to ingest the Phase 1 demonstration dataset into FORENSIX.

All data is strictly synthetic and clearly marked as simulated.
"""
import sys
from pathlib import Path

# Add project root to sys.path so script can be run standalone
BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from database.db import init_db, execute_query, execute_commit
from modules.evidence_manager import register_evidence
from modules.incident_reconstruction import insert_forensic_event
from config import SAMPLE_EVIDENCE_DIR

DEMO_CASE_ID = "CAS-2026-DEMO"
DEMO_CASE_NAME = "Operation Echo Trail (Simulated Unauthorized Access)"
INVESTIGATOR = "Lead Analyst (DFIR Unit)"


def seed_demo_data(force_refresh: bool = False) -> str:
    """Seeds the database with the Phase 1 simulated incident sequence if not already present."""
    init_db()

    existing = execute_query("SELECT id FROM investigations WHERE id = ?", (DEMO_CASE_ID,))
    if existing and not force_refresh:
        return DEMO_CASE_ID

    if existing and force_refresh:
        execute_commit("DELETE FROM investigations WHERE id = ?", (DEMO_CASE_ID,))

    # 1. Create Demonstration Investigation
    execute_commit(
        """
        INSERT INTO investigations (id, case_name, lead_investigator, description, status)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            DEMO_CASE_ID,
            DEMO_CASE_NAME,
            INVESTIGATOR,
            "Simulated incident sequence demonstrating brute-force access, web navigation, download, and evidence registration on 16 November 2026.",
            "ACTIVE"
        )
    )

    # 2. Register Sample Evidence File into Vault
    sample_file = SAMPLE_EVIDENCE_DIR / "sample_payload_simulated.txt"
    if sample_file.exists():
        ev_info = register_evidence(
            investigation_id=DEMO_CASE_ID,
            source_path=str(sample_file),
            acquired_by=INVESTIGATOR,
            evidence_name="patch-v4.zip.txt (Simulated Download)",
            description="Simulated downloaded payload recovered from host disk artifact on 2026-11-16."
        )
        evidence_id = ev_info["id"]
    else:
        evidence_id = "EV-DEMO"

    # 3. Create the Chronological Simulated Forensic Events Sequence
    # 09:02 — Multiple failed login attempts
    insert_forensic_event(
        investigation_id=DEMO_CASE_ID,
        timestamp="2026-11-16 09:02:11",
        event_type="AUTH_FAILED",
        source="auth_simulated.log",
        actor="admin",
        description="Failed SSH password attempt from 192.168.1.145 (invalid user admin)",
        severity="WARNING",
        is_simulated=1
    )
    insert_forensic_event(
        investigation_id=DEMO_CASE_ID,
        timestamp="2026-11-16 09:02:44",
        event_type="AUTH_FAILED",
        source="auth_simulated.log",
        actor="root",
        description="Failed SSH password attempt from 192.168.1.145 (invalid user root)",
        severity="WARNING",
        is_simulated=1
    )
    insert_forensic_event(
        investigation_id=DEMO_CASE_ID,
        timestamp="2026-11-16 09:03:15",
        event_type="AUTH_FAILED",
        source="auth_simulated.log",
        actor="jsmith",
        description="Failed SSH password attempt from 192.168.1.145 (user jsmith)",
        severity="WARNING",
        is_simulated=1
    )

    # 09:07 — Successful login
    insert_forensic_event(
        investigation_id=DEMO_CASE_ID,
        timestamp="2026-11-16 09:07:22",
        event_type="AUTH_SUCCESS",
        source="auth_simulated.log",
        actor="jsmith",
        description="Successful SSH authentication for jsmith from 192.168.1.145",
        severity="NOTICE",
        is_simulated=1
    )

    # 09:14 — Visit to an unfamiliar website
    insert_forensic_event(
        investigation_id=DEMO_CASE_ID,
        timestamp="2026-11-16 09:14:35",
        event_type="WEB_NAVIGATION",
        source="browser_history_simulated.csv",
        actor="jsmith",
        description="Browser navigation recorded to unfamiliar domain: https://cdn-updates-mirror99.net/packages/x64",
        severity="WARNING",
        is_simulated=1
    )

    # 09:18 — A file download is recorded
    insert_forensic_event(
        investigation_id=DEMO_CASE_ID,
        timestamp="2026-11-16 09:18:04",
        event_type="FILE_DOWNLOAD",
        source="browser_downloads_simulated.csv",
        actor="jsmith",
        description="File download recorded: patch-v4.zip (45,892 bytes) from cdn-updates-mirror99.net",
        severity="HIGH",
        is_simulated=1
    )

    # 09:21 — Downloaded file is registered as digital evidence
    insert_forensic_event(
        investigation_id=DEMO_CASE_ID,
        timestamp="2026-11-16 09:21:00",
        event_type="EVIDENCE_REGISTRATION",
        source="FORENSIX Vault",
        actor=INVESTIGATOR,
        description=f"Downloaded file secured as evidence item {evidence_id} with SHA-256 verification.",
        severity="INFO",
        is_simulated=1
    )

    return DEMO_CASE_ID


if __name__ == "__main__":
    cid = seed_demo_data(force_refresh=True)
    print(f"Sample data successfully initialized for investigation: {cid}")
