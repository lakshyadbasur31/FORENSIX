"""Unit tests for SQLite database initialization, schema integrity, and evidence records."""
import tempfile
from pathlib import Path
from database.db import init_db, execute_query, execute_commit
from modules.evidence_manager import register_evidence, get_evidence_by_id, verify_evidence_integrity
from modules.chain_of_custody import get_custody_history


def test_database_init_and_tables():
    """Validates that schema initialization creates all 4 required tables and indices."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        test_db_path = Path(tf.name)

    try:
        init_db(db_path=test_db_path)
        tables = execute_query(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;",
            db_path=test_db_path
        )
        table_names = [t["name"] for t in tables]
        assert "investigations" in table_names
        assert "evidence" in table_names
        assert "custody_events" in table_names
        assert "forensic_events" in table_names
    finally:
        if test_db_path.exists():
            test_db_path.unlink()


def test_evidence_creation_and_custody():
    """Validates creating an investigation, registering evidence, verifying hashes and custody logs."""
    # Create test evidence sample file
    with tempfile.NamedTemporaryFile("w+", suffix=".bin", delete=False) as sample_file:
        sample_file.write("SAMPLE_FORENSIC_EVIDENCE_PAYLOAD_TEST_DATA")
        sample_path = Path(sample_file.name)

    case_id = "CAS-TEST-001"
    try:
        # Initialize primary DB (ensures tables exist)
        init_db()

        # Insert test case
        execute_commit(
            "INSERT INTO investigations (id, case_name, lead_investigator, description) VALUES (?, ?, ?, ?)",
            (case_id, "Test Unit Case", "Investigator Miller", "Automated test scope")
        )

        # Register evidence
        ev_data = register_evidence(
            investigation_id=case_id,
            source_path=str(sample_path),
            acquired_by="Investigator Miller",
            evidence_name="sample_test_artifact.bin",
            description="Acquired from unit testing harness"
        )

        ev_id = ev_data["id"]
        assert ev_id.startswith("EV-")
        assert len(ev_data["sha256"]) == 64

        # Verify record retrieval
        record = get_evidence_by_id(ev_id)
        assert record is not None
        assert record["evidence_name"] == "sample_test_artifact.bin"
        assert record["integrity_status"] == "VERIFIED"

        # Verify integrity on vault file
        v_check = verify_evidence_integrity(ev_id, verified_by="Test Verifier")
        assert v_check["is_valid"] is True

        # Check Chain of Custody entries
        coc = get_custody_history(ev_id)
        assert len(coc) >= 2  # 1 for registration, 1 for verification
        actions = [c["action"] for c in coc]
        assert ("ACQUIRED" in actions or "ACQUISITION_AND_REGISTRATION" in actions)
        assert ("VERIFIED" in actions or "INTEGRITY_VERIFICATION" in actions)

    finally:
        # Clean up database records
        execute_commit("DELETE FROM investigations WHERE id = ?", (case_id,))
        if sample_path.exists():
            sample_path.unlink()
