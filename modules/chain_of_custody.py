"""Chain of Custody tracking and verification module (CHAINLOCK Engine).

Maintains a cryptographic hash-linked chronological audit trail for digital evidence.
Every action (ACQUIRED, ACCESSED, VERIFIED, EXPORTED) is bound to the previous
record via SHA-256 hash chaining to detect post-facto tampering.

Handles legacy records gracefully without fabricating historical claims or weakening
tamper-detection for cryptographically linked records.
"""
import uuid
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from database.db import execute_query, execute_commit

# Documented Genesis Hash for the first event in an evidence custody chain
CHAINLOCK_GENESIS_HASH = "0" * 64

# Documented Sentinel Hash indicating a transitional bridge from an unhashed legacy event
CHAINLOCK_LEGACY_BRIDGE_HASH = "LEGACY_PRE_CHAINLOCK_" + ("0" * 43)

# Allowed standard event types
ALLOWED_EVENT_TYPES = {"ACQUIRED", "ACCESSED", "VERIFIED", "EXPORTED"}


def calculate_event_hash(
    event_id: str,
    evidence_id: str,
    action: str,
    timestamp_utc: str,
    performed_by: str,
    notes: str,
    previous_event_hash: str
) -> str:
    """Calculates a deterministic SHA-256 fingerprint for a custody event.
    
    Hash composition fields:
    event_id | evidence_id | action | timestamp_utc | performed_by | notes | previous_event_hash
    """
    payload = "|".join([
        event_id.strip(),
        evidence_id.strip(),
        action.strip().upper(),
        timestamp_utc.strip(),
        performed_by.strip(),
        (notes or "").strip(),
        previous_event_hash.strip().lower()
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest().lower()


def record_custody_event(
    evidence_id: str,
    action: str,
    performed_by: str,
    notes: Optional[str] = None,
    verified_hash: Optional[str] = None,
    custom_timestamp: Optional[str] = None
) -> Dict[str, Any]:
    """Records an audit action into the hash-linked chain of custody log.
    
    Enforces chronological linkage:
    1. Looks up the most recent custody event for the given evidence_id.
    2. If the previous event has a current_event_hash, links to it directly.
    3. If there are no prior events, links to CHAINLOCK_GENESIS_HASH.
    4. If the prior event is an unhashed legacy event, links to CHAINLOCK_LEGACY_BRIDGE_HASH.
    5. Computes the new current_event_hash deterministically and commits to SQLite.
    """
    action_clean = action.strip().upper()
    if action_clean in ("ACQUISITION_AND_REGISTRATION", "ACQUISITION"):
        action_clean = "ACQUIRED"
    elif action_clean in ("INTEGRITY_VERIFICATION", "VERIFY", "VERIFICATION"):
        action_clean = "VERIFIED"
    elif action_clean in ("ACCESS", "VIEW"):
        action_clean = "ACCESSED"
    elif action_clean in ("EXPORT", "DOWNLOAD"):
        action_clean = "EXPORTED"

    event_id = f"COC-{uuid.uuid4().hex[:8].upper()}"
    timestamp_str = custom_timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # Fetch the latest existing event for this evidence item
    latest_rows = execute_query(
        """
        SELECT id, current_event_hash, previous_event_hash
        FROM custody_events
        WHERE evidence_id = ?
        ORDER BY timestamp DESC, rowid DESC
        LIMIT 1
        """,
        (evidence_id,)
    )

    if latest_rows:
        latest = latest_rows[0]
        if latest.get("current_event_hash"):
            previous_event_hash = latest["current_event_hash"].lower()
        else:
            # Prior record is a legacy unhashed event
            previous_event_hash = CHAINLOCK_LEGACY_BRIDGE_HASH.lower()
    else:
        previous_event_hash = CHAINLOCK_GENESIS_HASH

    current_event_hash = calculate_event_hash(
        event_id=event_id,
        evidence_id=evidence_id,
        action=action_clean,
        timestamp_utc=timestamp_str,
        performed_by=performed_by,
        notes=notes or "",
        previous_event_hash=previous_event_hash
    )

    query = """
    INSERT INTO custody_events (
        id, evidence_id, timestamp, action, performed_by, notes,
        verified_hash, previous_event_hash, current_event_hash
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    execute_commit(query, (
        event_id,
        evidence_id,
        timestamp_str,
        action_clean,
        performed_by,
        notes or "",
        verified_hash or "",
        previous_event_hash,
        current_event_hash
    ))

    return {
        "id": event_id,
        "evidence_id": evidence_id,
        "timestamp": timestamp_str,
        "action": action_clean,
        "performed_by": performed_by,
        "notes": notes or "",
        "verified_hash": verified_hash or "",
        "previous_event_hash": previous_event_hash,
        "current_event_hash": current_event_hash
    }


def get_custody_history(evidence_id: str) -> List[Dict[str, Any]]:
    """Retrieves all chronological custody events for a specific evidence item."""
    query = """
    SELECT id, evidence_id, timestamp, action, performed_by, notes, verified_hash,
           previous_event_hash, current_event_hash
    FROM custody_events
    WHERE evidence_id = ?
    ORDER BY timestamp ASC, rowid ASC
    """
    return execute_query(query, (evidence_id,))


def get_all_custody_events(investigation_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves all custody logs across an investigation or the entire system."""
    if investigation_id:
        query = """
        SELECT c.id, c.evidence_id, c.timestamp, c.action, c.performed_by, c.notes,
               c.verified_hash, c.previous_event_hash, c.current_event_hash, e.evidence_name
        FROM custody_events c
        JOIN evidence e ON c.evidence_id = e.id
        WHERE e.investigation_id = ?
        ORDER BY c.timestamp DESC, c.rowid DESC
        """
        return execute_query(query, (investigation_id,))
    else:
        query = """
        SELECT c.id, c.evidence_id, c.timestamp, c.action, c.performed_by, c.notes,
               c.verified_hash, c.previous_event_hash, c.current_event_hash, e.evidence_name
        FROM custody_events c
        JOIN evidence e ON c.evidence_id = e.id
        ORDER BY c.timestamp DESC, c.rowid DESC
        """
        return execute_query(query)


def verify_custody_chain(evidence_id: str) -> Dict[str, Any]:
    """Cryptographically audits the hash chain of custody records for an evidence item.
    
    Distinguishes:
    1. Cryptographically verified CHAINLOCK records.
    2. Legacy unhashed records (identifies them transparently as UNVERIFIED_LEGACY_RECORD
       without conflating them with deliberate data tampering).
    3. Genuine chain tampering (mismatched calculated hashes or broken hash pointers).
    """
    events = get_custody_history(evidence_id)
    if not events:
        return {
            "evidence_id": evidence_id,
            "is_valid": True,
            "status": "EMPTY_CHAIN",
            "total_events": 0,
            "legacy_events_count": 0,
            "broken_events": []
        }

    expected_prev = CHAINLOCK_GENESIS_HASH
    broken = []
    legacy_count = 0

    for idx, evt in enumerate(events):
        evt_id = evt["id"]
        stored_prev = (evt.get("previous_event_hash") or "").strip().lower()
        stored_curr = (evt.get("current_event_hash") or "").strip().lower()

        # Handle unhashed legacy records
        if not stored_curr:
            legacy_count += 1
            broken.append({
                "event_id": evt_id,
                "index": idx,
                "is_legacy": True,
                "reason": "UNVERIFIED_LEGACY_RECORD",
                "details": "Pre-CHAINLOCK legacy event recorded without cryptographic hash signature."
            })
            # For subsequent events that immediately follow this legacy record,
            # allow CHAINLOCK_LEGACY_BRIDGE_HASH or genesis as acceptable prior pointers
            expected_prev = None
            continue

        # Check chain pointer for hashed events
        if expected_prev is not None:
            if stored_prev != expected_prev:
                broken.append({
                    "event_id": evt_id,
                    "index": idx,
                    "is_legacy": False,
                    "reason": "BROKEN_CHAIN_LINK",
                    "expected_previous": expected_prev,
                    "actual_previous": stored_prev
                })
        else:
            # First hashed event following legacy records:
            # Must bridge with CHAINLOCK_LEGACY_BRIDGE_HASH or GENESIS_HASH
            valid_bridge_hashes = {
                CHAINLOCK_LEGACY_BRIDGE_HASH.lower(),
                CHAINLOCK_GENESIS_HASH.lower()
            }
            if stored_prev not in valid_bridge_hashes:
                broken.append({
                    "event_id": evt_id,
                    "index": idx,
                    "is_legacy": False,
                    "reason": "BROKEN_CHAIN_LINK",
                    "expected_previous": f"One of {valid_bridge_hashes}",
                    "actual_previous": stored_prev
                })

        # Recompute hash for this event
        recalculated = calculate_event_hash(
            event_id=evt_id,
            evidence_id=evt["evidence_id"],
            action=evt["action"],
            timestamp_utc=str(evt["timestamp"]),
            performed_by=evt["performed_by"],
            notes=evt.get("notes") or "",
            previous_event_hash=stored_prev
        )

        if recalculated != stored_curr:
            broken.append({
                "event_id": evt_id,
                "index": idx,
                "is_legacy": False,
                "reason": "TAMPERED_EVENT_DATA",
                "expected_current": recalculated,
                "stored_current": stored_curr
            })

        # Next event in chain must link to this event's stored hash
        expected_prev = stored_curr

    # Determine status
    has_tampering = any(not b.get("is_legacy", False) for b in broken)
    if has_tampering:
        status = "CHAIN_TAMPER_DETECTED"
        is_valid = False
    elif legacy_count > 0:
        status = "CONTAINS_UNVERIFIED_LEGACY_EVENTS"
        is_valid = False
    else:
        status = "CHAIN_INTEGRITY_VERIFIED"
        is_valid = True

    return {
        "evidence_id": evidence_id,
        "is_valid": is_valid,
        "status": status,
        "total_events": len(events),
        "legacy_events_count": legacy_count,
        "broken_events": broken
    }


def migrate_legacy_custody_events(evidence_id: str, migrated_by: str) -> Dict[str, Any]:
    """Explicit migration utility for historical unhashed custody records.
    
    Transforms legacy events into a documented migrated chain without fabricating
    unverifiable original signatures:
    - Sets action to documented standard (e.g. ACQUIRED).
    - Annotates notes with an explicit '[MIGRATED LEGACY RECORD]' prefix.
    - Deterministically calculates chain hashes starting from CHAINLOCK_GENESIS_HASH.
    - Re-links any subsequent CHAINLOCK events to the newly bridged chain.
    """
    events = get_custody_history(evidence_id)
    if not events:
        return {"status": "NO_EVENTS", "migrated_count": 0}

    migrated_count = 0
    running_prev = CHAINLOCK_GENESIS_HASH

    for evt in events:
        evt_id = evt["id"]
        stored_curr = evt.get("current_event_hash")
        action_clean = evt["action"].strip().upper()
        if action_clean in ("ACQUISITION_AND_REGISTRATION", "ACQUISITION"):
            action_clean = "ACQUIRED"
        elif action_clean in ("INTEGRITY_VERIFICATION", "VERIFY", "VERIFICATION"):
            action_clean = "VERIFIED"

        if not stored_curr:
            # Unhashed legacy event
            migrated_count += 1
            notes_migrated = f"[MIGRATED LEGACY RECORD by {migrated_by}] {evt.get('notes') or ''}".strip()
            new_curr = calculate_event_hash(
                event_id=evt_id,
                evidence_id=evidence_id,
                action=action_clean,
                timestamp_utc=str(evt["timestamp"]),
                performed_by=evt["performed_by"],
                notes=notes_migrated,
                previous_event_hash=running_prev
            )
            execute_commit(
                """
                UPDATE custody_events
                SET action = ?, notes = ?, previous_event_hash = ?, current_event_hash = ?
                WHERE id = ?
                """,
                (action_clean, notes_migrated, running_prev, new_curr, evt_id)
            )
            running_prev = new_curr
        else:
            # Already hashed event: re-anchor previous_event_hash if chain was bridged
            if evt.get("previous_event_hash") != running_prev:
                new_curr = calculate_event_hash(
                    event_id=evt_id,
                    evidence_id=evidence_id,
                    action=action_clean,
                    timestamp_utc=str(evt["timestamp"]),
                    performed_by=evt["performed_by"],
                    notes=evt.get("notes") or "",
                    previous_event_hash=running_prev
                )
                execute_commit(
                    """
                    UPDATE custody_events
                    SET previous_event_hash = ?, current_event_hash = ?
                    WHERE id = ?
                    """,
                    (running_prev, new_curr, evt_id)
                )
                running_prev = new_curr
            else:
                running_prev = stored_curr

    return {
        "status": "MIGRATION_COMPLETED",
        "migrated_count": migrated_count,
        "evidence_id": evidence_id
    }
