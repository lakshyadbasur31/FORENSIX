"""Evidence acquisition, vault registration, and integrity management module (CHAINLOCK Engine).

Maintains digital evidence records without modifying original source files.
Creates read-only vault replicas, sanitizes storage filenames to prevent path traversal,
calculates SHA-256 fingerprints, tracks MIME types, and verifies integrity.
"""
import os
import shutil
import uuid
import mimetypes
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from config import VAULT_STORAGE_DIR
from database.db import execute_query, execute_commit
from modules.hash_verification import compute_file_hashes, verify_integrity
from modules.chain_of_custody import record_custody_event, verify_custody_chain

# Permitted forensic extensions
ALLOWED_EXTENSIONS = {
    ".txt", ".csv", ".json", ".pdf", ".png", ".jpg", ".jpeg", ".zip", ".log", ".docx", ".bin"
}


def sanitize_filename(filename: str) -> str:
    """Strips directory traversal sequences and unsafe characters from filenames."""
    # Retain only the basename
    cleaned = Path(filename).name
    # Remove any null bytes or remaining path delimiters
    cleaned = cleaned.replace("\x00", "").replace("/", "").replace("\\", "").strip()
    return cleaned or "unnamed_evidence.bin"


def register_evidence(
    investigation_id: str,
    source_path: str,
    acquired_by: str,
    evidence_name: Optional[str] = None,
    description: Optional[str] = None,
    custom_vault_dir: Optional[Path] = None
) -> Dict[str, Any]:
    """Registers an external file as digital evidence, hashing it and saving a vault copy.
    
    1. Validates source path.
    2. Validates supported extension.
    3. Computes SHA-256 baseline cryptographic fingerprint.
    4. Detects MIME type.
    5. Saves a protected working copy in the isolated vault repository without overwriting.
    6. Stores metadata in SQLite.
    7. Logs an ACQUIRED custody event into the CHAINLOCK hash chain.
    """
    src = Path(source_path)
    if not src.is_file():
        raise FileNotFoundError(f"Source evidence file does not exist: {source_path}")

    # Validate file extension
    ext = src.suffix.lower()
    if ext not in ALLOWED_EXTENSIONS and ext != "":
        # Also allow dotless or check if allowed
        if ext not in ALLOWED_EXTENSIONS:
            raise ValueError(f"Unsupported evidence file extension '{ext}'. Supported: {', '.join(sorted(ALLOWED_EXTENSIONS))}")

    # Compute baseline cryptographic hashes directly from source
    hashes = compute_file_hashes(src)
    file_size = src.stat().st_size
    file_type = ext or ".bin"
    original_filename = sanitize_filename(src.name)
    display_name = evidence_name or original_filename

    # Determine MIME type
    mime_type, _ = mimetypes.guess_type(str(src))
    if not mime_type:
        mime_map = {
            ".log": "text/plain",
            ".csv": "text/csv",
            ".json": "application/json",
            ".txt": "text/plain",
            ".pdf": "application/pdf",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".zip": "application/zip",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        }
        mime_type = mime_map.get(ext, "application/octet-stream")

    evidence_id = f"EV-{uuid.uuid4().hex[:8].upper()}"
    acquisition_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # Vault storage isolation
    storage_root = custom_vault_dir or VAULT_STORAGE_DIR
    vault_dest_dir = storage_root / evidence_id
    vault_dest_dir.mkdir(parents=True, exist_ok=True)
    
    # Safe storage filename preventing path traversal and collision
    safe_target_name = sanitize_filename(src.name)
    vault_dest_path = vault_dest_dir / safe_target_name

    # Prevent accidental overwrites
    if vault_dest_path.exists():
        counter = 1
        stem = vault_dest_path.stem
        suffix = vault_dest_path.suffix
        while vault_dest_path.exists():
            vault_dest_path = vault_dest_dir / f"{stem}_{counter}{suffix}"
            counter += 1

    # Safely copy into vault repository
    shutil.copy2(src, vault_dest_path)

    # Set vault file to read-only attribute where possible
    try:
        os.chmod(vault_dest_path, 0o444)
    except Exception:
        pass

    query = """
    INSERT INTO evidence (
        id, investigation_id, evidence_name, source_path, vault_path,
        file_size_bytes, file_type, mime_type, sha256, md5, sha1, acquired_by,
        acquisition_date, description, integrity_status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    execute_commit(query, (
        evidence_id,
        investigation_id,
        display_name,
        str(src.resolve()),
        str(vault_dest_path.resolve()),
        file_size,
        file_type,
        mime_type,
        hashes["sha256"],
        hashes["md5"],
        hashes["sha1"],
        acquired_by,
        acquisition_utc,
        description or "",
        "VERIFIED"
    ))

    # Log initial Chain of Custody entry (ACQUIRED)
    record_custody_event(
        evidence_id=evidence_id,
        action="ACQUIRED",
        performed_by=acquired_by,
        notes=f"Evidence ingested from {original_filename} ({file_size} bytes). MIME: {mime_type}.",
        verified_hash=hashes["sha256"],
        custom_timestamp=acquisition_utc
    )

    return {
        "id": evidence_id,
        "evidence_name": display_name,
        "original_filename": original_filename,
        "file_size": file_size,
        "file_size_bytes": file_size,
        "file_type": file_type,
        "mime_type": mime_type,
        "sha256": hashes["sha256"],
        "md5": hashes["md5"],
        "sha1": hashes["sha1"],
        "vault_path": str(vault_dest_path),
        "acquisition_date": acquisition_utc,
        "integrity_status": "VERIFIED"
    }


def get_evidence_by_id(evidence_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an evidence record by ID."""
    rows = execute_query("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    return rows[0] if rows else None


def list_evidence(investigation_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Lists evidence items filtered by investigation, or all items."""
    if investigation_id:
        return execute_query(
            "SELECT * FROM evidence WHERE investigation_id = ? ORDER BY acquisition_date DESC",
            (investigation_id,)
        )
    return execute_query("SELECT * FROM evidence ORDER BY acquisition_date DESC")


def verify_evidence_integrity(evidence_id: str, verified_by: str) -> Dict[str, Any]:
    """Re-computes the SHA-256 fingerprint of the stored vault file and compares against baseline.
    
    Returns explicit result:
    - MATCH: Stored content fingerprint matches registered baseline.
    - MISMATCH: Stored content fingerprint differs from registered baseline.
    - MISSING: Stored evidence file cannot be found on disk.
    
    Never replaces or overwrites the original registered baseline hash.
    Records a VERIFIED custody event with the verification outcome.
    """
    evidence = get_evidence_by_id(evidence_id)
    if not evidence:
        raise ValueError(f"Evidence {evidence_id} not found.")

    registered_sha256 = evidence["sha256"].strip().lower()
    vault_path_str = evidence.get("vault_path")
    target_path = Path(vault_path_str) if vault_path_str else None

    # Check existence
    if not target_path or not target_path.exists():
        new_status = "MISSING"
        current_hash = ""
        is_valid = False
        notes = f"Evidence file missing at designated vault path: {vault_path_str}"
    else:
        computed = compute_file_hashes(target_path)
        current_hash = computed["sha256"].lower()
        if current_hash == registered_sha256:
            new_status = "MATCH"
            is_valid = True
            notes = f"SHA-256 integrity match confirmed: {current_hash}"
        else:
            new_status = "MISMATCH"
            is_valid = False
            notes = f"SHA-256 fingerprint mismatch! Expected {registered_sha256}, got {current_hash}."

    # Update current integrity status in database without touching registered sha256
    execute_commit(
        "UPDATE evidence SET integrity_status = ? WHERE id = ?",
        (new_status, evidence_id)
    )

    # Record VERIFIED event in Chain of Custody
    record_custody_event(
        evidence_id=evidence_id,
        action="VERIFIED",
        performed_by=verified_by,
        notes=f"Integrity check completed. Result: {new_status}. {notes}",
        verified_hash=current_hash or registered_sha256
    )

    return {
        "evidence_id": evidence_id,
        "result": new_status,
        "is_valid": is_valid,
        "status": new_status,
        "registered_sha256": registered_sha256,
        "current_sha256": current_hash,
        "baseline_sha256": registered_sha256,
        "file_path": str(target_path) if target_path else None
    }


def get_vault_statistics(investigation_id: Optional[str] = None) -> Dict[str, Any]:
    """Calculates real evidence vault metrics directly from current records and disk states."""
    items = list_evidence(investigation_id)
    total_items = len(items)
    total_bytes = sum(item.get("file_size_bytes", 0) for item in items)
    
    verified_count = sum(1 for item in items if item.get("integrity_status") in ("MATCH", "VERIFIED"))
    mismatch_count = sum(1 for item in items if item.get("integrity_status") in ("MISMATCH", "TAMPERED_OR_CORRUPT"))
    missing_count = sum(1 for item in items if item.get("integrity_status") == "MISSING")

    return {
        "total_items": total_items,
        "total_bytes": total_bytes,
        "verified_count": verified_count,
        "mismatch_count": mismatch_count,
        "missing_count": missing_count
    }
