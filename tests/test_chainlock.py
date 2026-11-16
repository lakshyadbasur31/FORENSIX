"""Unit tests for CHAINLOCK: Evidence registration, integrity verification, and hash-linked custody chain."""
import tempfile
import os
import stat
from pathlib import Path
from database.db import init_db, execute_query, execute_commit
from modules.evidence_manager import (
    register_evidence,
    get_evidence_by_id,
    verify_evidence_integrity,
    get_vault_statistics,
    sanitize_filename
)
from modules.chain_of_custody import (
    record_custody_event,
    get_custody_history,
    verify_custody_chain,
    migrate_legacy_custody_events,
    CHAINLOCK_GENESIS_HASH
)


def _setup_test_environment():
    """Helper to initialize isolated temp db and temp directories."""
    temp_db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    test_db_path = Path(temp_db_file.name)
    temp_db_file.close()

    temp_vault_dir = Path(tempfile.mkdtemp())
    return test_db_path, temp_vault_dir


def test_chainlock_1_registration_and_unique_id():
    """1. Evidence registration, 2. Unique evidence ID generation, 3. SHA-256 fingerprint storage."""
    with tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False) as tf:
        tf.write("FORENSIC EVIDENCE ARTIFACT CONTENT - TEST 1")
        sample_path = Path(tf.name)

    case_id = "CAS-CHAINLOCK-01"
    init_db()

    try:
        execute_commit(
            "INSERT INTO investigations (id, case_name, lead_investigator) VALUES (?, ?, ?)",
            (case_id, "Registration Test Case", "Investigator Alpha")
        )

        reg1 = register_evidence(
            investigation_id=case_id,
            source_path=str(sample_path),
            acquired_by="Investigator Alpha",
            evidence_name="sample_report.txt",
            description="Initial acquisition"
        )
        reg2 = register_evidence(
            investigation_id=case_id,
            source_path=str(sample_path),
            acquired_by="Investigator Alpha",
            evidence_name="sample_report_duplicate.txt"
        )

        # 1 & 2: Unique IDs
        assert reg1["id"].startswith("EV-")
        assert reg2["id"].startswith("EV-")
        assert reg1["id"] != reg2["id"]

        # 3: SHA-256 fingerprint storage
        assert len(reg1["sha256"]) == 64
        rec1 = get_evidence_by_id(reg1["id"])
        assert rec1["sha256"] == reg1["sha256"]
        assert rec1["mime_type"] == "text/plain"

        # 7: ACQUIRED custody event created
        coc = get_custody_history(reg1["id"])
        assert len(coc) == 1
        assert coc[0]["action"] == "ACQUIRED"
        assert coc[0]["previous_event_hash"] == CHAINLOCK_GENESIS_HASH
        assert len(coc[0]["current_event_hash"]) == 64

    finally:
        execute_commit("DELETE FROM investigations WHERE id = ?", (case_id,))
        if sample_path.exists():
            sample_path.unlink()


def test_chainlock_4_successful_integrity_verification():
    """4. Successful integrity verification returning MATCH."""
    with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tf:
        tf.write('{"evidence": "tamper_free_state"}')
        sample_path = Path(tf.name)

    case_id = "CAS-CHAINLOCK-02"
    init_db()

    try:
        execute_commit(
            "INSERT INTO investigations (id, case_name, lead_investigator) VALUES (?, ?, ?)",
            (case_id, "Integrity Pass Case", "Investigator Beta")
        )

        reg = register_evidence(
            investigation_id=case_id,
            source_path=str(sample_path),
            acquired_by="Investigator Beta"
        )

        result = verify_evidence_integrity(reg["id"], verified_by="Auditor")
        assert result["result"] == "MATCH"
        assert result["is_valid"] is True
        assert result["current_sha256"] == reg["sha256"]

        # Check custody event added
        history = get_custody_history(reg["id"])
        assert len(history) == 2
        assert history[1]["action"] == "VERIFIED"

    finally:
        execute_commit("DELETE FROM investigations WHERE id = ?", (case_id,))
        if sample_path.exists():
            sample_path.unlink()


def test_chainlock_5_detection_of_modified_evidence():
    """5. Detection of modified evidence returning MISMATCH while preserving original hash."""
    with tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False) as tf:
        tf.write("ORIGINAL LOG CONTENT - LINE 1\n")
        sample_path = Path(tf.name)

    case_id = "CAS-CHAINLOCK-03"
    init_db()

    try:
        execute_commit(
            "INSERT INTO investigations (id, case_name, lead_investigator) VALUES (?, ?, ?)",
            (case_id, "Tamper Detection Case", "Investigator Gamma")
        )

        reg = register_evidence(
            investigation_id=case_id,
            source_path=str(sample_path),
            acquired_by="Investigator Gamma"
        )
        orig_hash = reg["sha256"]
        vault_file = Path(reg["vault_path"])

        # Intentionally tamper with the stored vault copy
        # Remove read-only attribute if on Windows
        os.chmod(vault_file, stat.S_IWRITE)
        with open(vault_file, "a") as vf:
            vf.write("TAMPERED LINE INSERTION BY MALICIOUS ACTOR\n")

        # Verify integrity
        result = verify_evidence_integrity(reg["id"], verified_by="Forensic Examiner")
        assert result["result"] == "MISMATCH"
        assert result["is_valid"] is False
        assert result["registered_sha256"] == orig_hash
        assert result["current_sha256"] != orig_hash

        # Confirm original registered baseline hash was NOT overwritten in DB
        db_rec = get_evidence_by_id(reg["id"])
        assert db_rec["sha256"] == orig_hash
        assert db_rec["integrity_status"] == "MISMATCH"

    finally:
        execute_commit("DELETE FROM investigations WHERE id = ?", (case_id,))
        if sample_path.exists():
            sample_path.unlink()


def test_chainlock_6_detection_of_missing_evidence():
    """6. Detection of missing evidence file returning MISSING."""
    with tempfile.NamedTemporaryFile("w+", suffix=".csv", delete=False) as tf:
        tf.write("col1,col2\nval1,val2\n")
        sample_path = Path(tf.name)

    case_id = "CAS-CHAINLOCK-04"
    init_db()

    try:
        execute_commit(
            "INSERT INTO investigations (id, case_name, lead_investigator) VALUES (?, ?, ?)",
            (case_id, "Missing File Case", "Investigator Delta")
        )

        reg = register_evidence(
            investigation_id=case_id,
            source_path=str(sample_path),
            acquired_by="Investigator Delta"
        )
        vault_file = Path(reg["vault_path"])

        # Delete the stored vault file to simulate loss
        os.chmod(vault_file, stat.S_IWRITE)
        vault_file.unlink()

        result = verify_evidence_integrity(reg["id"], verified_by="Auditor")
        assert result["result"] == "MISSING"
        assert result["is_valid"] is False

        db_rec = get_evidence_by_id(reg["id"])
        assert db_rec["integrity_status"] == "MISSING"

    finally:
        execute_commit("DELETE FROM investigations WHERE id = ?", (case_id,))
        if sample_path.exists():
            sample_path.unlink()


def test_chainlock_8_and_9_custody_hash_chain_and_tamper_detection():
    """8. Custody hash-chain verification, and 9. Detection of modified custody records."""
    case_id = "CAS-CHAINLOCK-05"
    ev_id = "EV-CUSTODY-TEST"
    init_db()

    try:
        execute_commit(
            "INSERT INTO investigations (id, case_name, lead_investigator) VALUES (?, ?, ?)",
            (case_id, "Custody Chain Case", "Investigator Epsilon")
        )
        execute_commit(
            """
            INSERT INTO evidence (id, investigation_id, evidence_name, source_path, file_size_bytes, sha256, acquired_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (ev_id, case_id, "test_evidence.bin", "dummy/path", 100, "f"*64, "Investigator Epsilon")
        )

        # 7 & 8: Record sequential custody events
        e1 = record_custody_event(ev_id, "ACQUIRED", "Investigator Epsilon", "Initial intake")
        e2 = record_custody_event(ev_id, "ACCESSED", "Analyst 1", "Loaded into analysis workstation")
        e3 = record_custody_event(ev_id, "VERIFIED", "Auditor", "Routine audit check")
        e4 = record_custody_event(ev_id, "EXPORTED", "Analyst 2", "Exported hash dossier")

        # Verify chain linkage
        assert e1["previous_event_hash"] == CHAINLOCK_GENESIS_HASH
        assert e2["previous_event_hash"] == e1["current_event_hash"]
        assert e3["previous_event_hash"] == e2["current_event_hash"]
        assert e4["previous_event_hash"] == e3["current_event_hash"]

        audit = verify_custody_chain(ev_id)
        assert audit["is_valid"] is True
        assert audit["status"] == "CHAIN_INTEGRITY_VERIFIED"
        assert audit["total_events"] == 4

        # 9: Simulate tampering with custody event record in SQLite
        execute_commit(
            "UPDATE custody_events SET notes = ? WHERE id = ?",
            ("TAMPERED NOTES INSERTED DIRECTLY INTO DATABASE", e2["id"])
        )

        tampered_audit = verify_custody_chain(ev_id)
        assert tampered_audit["is_valid"] is False
        assert tampered_audit["status"] == "CHAIN_TAMPER_DETECTED"
        assert len(tampered_audit["broken_events"]) > 0

    finally:
        execute_commit("DELETE FROM investigations WHERE id = ?", (case_id,))


def test_chainlock_10_prevention_of_accidental_overwrite():
    """10. Prevention of accidental evidence overwrite and safe filenames."""
    with tempfile.NamedTemporaryFile("w+", suffix=".txt", delete=False) as tf:
        tf.write("FIRST VERSION OF ARTIFACT")
        sample_path = Path(tf.name)

    case_id = "CAS-CHAINLOCK-06"
    init_db()

    try:
        execute_commit(
            "INSERT INTO investigations (id, case_name, lead_investigator) VALUES (?, ?, ?)",
            (case_id, "Overwrite Prevention Case", "Investigator Zeta")
        )

        # Sanitize filename path traversal prevention test
        dirty_name = "../../../etc/passwd.log"
        clean = sanitize_filename(dirty_name)
        assert "/" not in clean and "\\" not in clean
        assert clean == "passwd.log"

        # Register two items with identical filename in same investigation
        reg1 = register_evidence(
            investigation_id=case_id,
            source_path=str(sample_path),
            acquired_by="Investigator Zeta"
        )
        reg2 = register_evidence(
            investigation_id=case_id,
            source_path=str(sample_path),
            acquired_by="Investigator Zeta"
        )

        # Distinct vault paths and distinct IDs guaranteed
        assert reg1["vault_path"] != reg2["vault_path"]
        assert Path(reg1["vault_path"]).exists()
        assert Path(reg2["vault_path"]).exists()

    finally:
        execute_commit("DELETE FROM investigations WHERE id = ?", (case_id,))
        if sample_path.exists():
            sample_path.unlink()


def test_chainlock_legacy_event_handling_and_migration():
    """Regression test: accurately identifies unverified legacy events and supports explicit migration."""
    case_id = "CAS-LEGACY-REGRESSION"
    ev_id = "EV-LEGACY-SAMPLE"
    init_db()

    try:
        execute_commit(
            "INSERT INTO investigations (id, case_name, lead_investigator) VALUES (?, ?, ?)",
            (case_id, "Legacy Regression Case", "Investigator Miller")
        )
        execute_commit(
            """
            INSERT INTO evidence (id, investigation_id, evidence_name, source_path, file_size_bytes, sha256, acquired_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (ev_id, case_id, "legacy_file.bin", "dummy/path", 512, "e"*64, "Investigator Miller")
        )

        # 1. Simulate an old Phase 1 legacy record without hashes
        execute_commit(
            """
            INSERT INTO custody_events (id, evidence_id, timestamp, action, performed_by, notes, verified_hash, previous_event_hash, current_event_hash)
            VALUES ('COC-LEGACY-01', ?, '2026-11-16 10:00:00', 'ACQUISITION_AND_REGISTRATION', 'Examiner Old', 'Phase 1 legacy record', 'e'*64, NULL, NULL)
            """,
            (ev_id,)
        )

        # 2. Add a subsequent verification event using CHAINLOCK
        evt2 = record_custody_event(ev_id, "VERIFIED", "Examiner New", "Routine verification")

        # 3. Verify custody chain: must report legacy event specifically, NOT conflate with data tampering
        audit_pre = verify_custody_chain(ev_id)
        assert audit_pre["is_valid"] is False
        assert audit_pre["status"] == "CONTAINS_UNVERIFIED_LEGACY_EVENTS"
        assert audit_pre["legacy_events_count"] == 1
        assert audit_pre["broken_events"][0]["reason"] == "UNVERIFIED_LEGACY_RECORD"

        # 4. Perform explicit documented migration
        migration = migrate_legacy_custody_events(ev_id, migrated_by="Lead Auditor")
        assert migration["status"] == "MIGRATION_COMPLETED"
        assert migration["migrated_count"] == 1

        # 5. After migration, chain integrity should be cryptographically bridged and verified
        audit_post = verify_custody_chain(ev_id)
        assert audit_post["is_valid"] is True
        assert audit_post["status"] == "CHAIN_INTEGRITY_VERIFIED"
        assert audit_post["legacy_events_count"] == 0

        # Verify notes explicitly indicate migration
        history = get_custody_history(ev_id)
        assert "[MIGRATED LEGACY RECORD by Lead Auditor]" in history[0]["notes"]
        assert history[0]["action"] == "ACQUIRED"
        assert history[0]["previous_event_hash"] == CHAINLOCK_GENESIS_HASH
        assert history[1]["previous_event_hash"] == history[0]["current_event_hash"]

    finally:
        execute_commit("DELETE FROM investigations WHERE id = ?", (case_id,))
