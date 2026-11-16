"""TRACEFUSION — Cross-Module Forensic Correlation Engine for FORENSIX.

Correlates:
- CHAINLOCK (registered evidence, vault replicas, hash verifications, custody events)
- WEBTRACE (page visits, downloads, forensic indicators, direct links)
- FORENSIC EVENTS (system logs, auth failures/successes, demo sequence events)

Provides:
- Normalized forensic event model
- UTC-aware timestamp conversion and parsing
- Deterministic explainable multi-signal correlation rules:
    * DIRECT_LINK
    * FILENAME_MATCH
    * HASH_MATCH
    * HOST_MATCH
    * TEMPORAL_PROXIMITY
    * COMBINED_CORRELATION
- Unified chronological timeline with source attribution
"""
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union

import pandas as pd
from database.db import execute_query
from modules.evidence_manager import list_evidence
from modules.chain_of_custody import get_all_custody_events
from modules.webtrace import get_webtrace_events, get_webtrace_indicators


# ==============================================================================
# 1. TIMESTAMP NORMALIZATION (UTC-AWARE)
# ==============================================================================

def normalize_to_utc_dt(ts_val: Any) -> Optional[datetime]:
    """Converts diverse date/timestamp values into a timezone-aware UTC datetime object.
    
    Handles:
    - Missing or None values
    - ISO 8601 strings
    - UNIX timestamps (seconds and milliseconds)
    - SQLite TIMESTAMP strings ('YYYY-MM-DD HH:MM:SS')
    """
    if not ts_val:
        return None
    try:
        # If already datetime
        if isinstance(ts_val, datetime):
            if ts_val.tzinfo is None:
                return ts_val.replace(tzinfo=timezone.utc)
            return ts_val.astimezone(timezone.utc)

        # If numeric string/number
        ts_str = str(ts_val).strip()
        if ts_str.isdigit():
            epoch = float(ts_str)
            if epoch > 1000000000000:  # ms
                epoch /= 1000.0
            return datetime.fromtimestamp(epoch, tz=timezone.utc)

        # Robust parsing via pandas
        pdt = pd.to_datetime(ts_str, utc=True)
        if pd.isna(pdt):
            return None
        return pdt.to_pydatetime()
    except Exception:
        return None


def format_utc_string(dt: Optional[datetime]) -> str:
    """Formats a datetime object to a standardized string 'YYYY-MM-DD HH:MM:SS'."""
    if not dt:
        return "1970-01-01 00:00:00"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ==============================================================================
# 2. NORMALIZED FORENSIC EVENT MODEL
# ==============================================================================

class NormalizedEvent:
    """Standardized forensic event abstraction across all FORENSIX sources."""

    def __init__(
        self,
        event_id: str,
        timestamp: Optional[datetime],
        source: str,
        event_type: str,
        description: str,
        actor: Optional[str] = None,
        hostname: Optional[str] = None,
        url: Optional[str] = None,
        filename: Optional[str] = None,
        evidence_id: Optional[str] = None,
        hash_val: Optional[str] = None,
        severity: str = "INFO",
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.event_id = event_id
        self.timestamp = timestamp
        self.timestamp_str = format_utc_string(timestamp) if timestamp else "1970-01-01 00:00:00"
        self.source = source
        self.event_type = event_type
        self.description = description
        self.actor = actor or "UNKNOWN"
        self.hostname = hostname
        self.url = url
        self.filename = filename
        self.evidence_id = evidence_id
        self.hash_val = hash_val.lower() if hash_val else None
        self.severity = severity.upper()
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp_str,
            "timestamp_dt": self.timestamp,
            "source": self.source,
            "event_type": self.event_type,
            "description": self.description,
            "actor": self.actor,
            "hostname": self.hostname,
            "url": self.url,
            "filename": self.filename,
            "evidence_id": self.evidence_id,
            "hash": self.hash_val,
            "severity": self.severity,
            "metadata": self.metadata
        }


# ==============================================================================
# 3. MULTI-SOURCE EVENT RETRIEVAL & NORMALIZATION
# ==============================================================================

def retrieve_all_investigation_events(investigation_id: str) -> List[NormalizedEvent]:
    """Retrieves and normalizes events across all FORENSIX database tables for an investigation."""
    events: List[NormalizedEvent] = []

    # 1. Retrieve Forensic Events (auth, system, simulated scenario)
    fe_rows = execute_query(
        "SELECT * FROM forensic_events WHERE investigation_id = ? ORDER BY timestamp ASC",
        (investigation_id,)
    )
    for r in fe_rows:
        dt = normalize_to_utc_dt(r.get("timestamp"))
        events.append(NormalizedEvent(
            event_id=r["id"],
            timestamp=dt,
            source=f"FORENSIC_LOG:{r.get('source', 'syslog')}",
            event_type=r.get("event_type", "GENERIC_EVENT"),
            description=r.get("description", ""),
            actor=r.get("actor", "UNKNOWN"),
            severity=r.get("severity", "INFO"),
            metadata={"raw_record": r.get("raw_record", ""), "is_simulated": r.get("is_simulated", 0)}
        ))

    # 2. Retrieve WEBTRACE Events (history visits and downloads)
    wt_rows = get_webtrace_events(investigation_id)
    for r in wt_rows:
        dt = normalize_to_utc_dt(r.get("timestamp_utc"))
        ev_type = r.get("event_type", "PAGE_VISIT")
        desc = r.get("page_title") or r.get("url") or "Web Navigation"
        if ev_type == "DOWNLOAD":
            desc = f"Downloaded {r.get('download_filename')} from {r.get('hostname')}"
        
        events.append(NormalizedEvent(
            event_id=r["id"],
            timestamp=dt,
            source=f"WEBTRACE:{r.get('browser', 'Browser')}",
            event_type=ev_type,
            description=desc,
            actor="browser_user",
            hostname=r.get("hostname"),
            url=r.get("url"),
            filename=r.get("download_filename"),
            evidence_id=r.get("linked_evidence_id"),
            severity="HIGH" if ev_type == "DOWNLOAD" else "INFO",
            metadata={
                "import_id": r.get("import_id"),
                "referrer": r.get("referrer"),
                "download_path": r.get("download_path"),
                "source_record_number": r.get("source_record_number")
            }
        ))

    # 3. Retrieve CHAINLOCK Evidence Records
    ev_rows = list_evidence(investigation_id)
    evidence_map = {e["id"]: e for e in ev_rows}

    for e in ev_rows:
        dt = normalize_to_utc_dt(e.get("acquisition_date"))
        events.append(NormalizedEvent(
            event_id=f"EV-INTAKE-{e['id']}",
            timestamp=dt,
            source="CHAINLOCK:VAULT",
            event_type="EVIDENCE_ACQUIRED",
            description=f"Evidence artifact secured: {e['evidence_name']} ({e['file_size_bytes']:,} bytes)",
            actor=e.get("acquired_by", "Examiner"),
            filename=e.get("evidence_name"),
            evidence_id=e["id"],
            hash_val=e.get("sha256"),
            severity="NOTICE",
            metadata={
                "vault_path": e.get("vault_path"),
                "file_type": e.get("file_type"),
                "mime_type": e.get("mime_type"),
                "integrity_status": e.get("integrity_status")
            }
        ))

    # 4. Retrieve CHAINLOCK Custody Events
    coc_rows = get_all_custody_events(investigation_id)
    for c in coc_rows:
        dt = normalize_to_utc_dt(c.get("timestamp"))
        action = c.get("action", "CUSTODY_ACTION")
        target_ev = evidence_map.get(c.get("evidence_id"), {})
        fname = target_ev.get("evidence_name")
        
        events.append(NormalizedEvent(
            event_id=c["id"],
            timestamp=dt,
            source="CHAINLOCK:CUSTODY",
            event_type=f"CUSTODY_{action}",
            description=f"Custody {action}: {c.get('notes', '')}",
            actor=c.get("performed_by", "Examiner"),
            filename=fname,
            evidence_id=c.get("evidence_id"),
            hash_val=c.get("verified_hash"),
            severity="WARNING" if "TAMPER" in str(c.get("notes", "")).upper() else "INFO",
            metadata={
                "previous_event_hash": c.get("previous_event_hash"),
                "current_event_hash": c.get("current_event_hash")
            }
        ))

    # Sort deterministically by timestamp (None timestamps placed at beginning or end safely)
    events.sort(key=lambda x: (x.timestamp or datetime.min.replace(tzinfo=timezone.utc), x.event_id))
    return events


# ==============================================================================
# 4. CROSS-MODULE CORRELATION ENGINE
# ==============================================================================

class CorrelationFinding:
    """Represents an explainable multi-signal link between two forensic events."""

    def __init__(
        self,
        source_event: NormalizedEvent,
        target_event: NormalizedEvent,
        relationship_type: str,
        reason: str,
        confidence: str,
        time_delta_seconds: Optional[float] = None
    ):
        self.source_event = source_event
        self.target_event = target_event
        self.relationship_type = relationship_type
        self.reason = reason
        self.confidence = confidence  # HIGH, MEDIUM, LOW
        self.time_delta_seconds = time_delta_seconds

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_event_id": self.source_event.event_id,
            "source_type": self.source_event.event_type,
            "source_source": self.source_event.source,
            "source_time": self.source_event.timestamp_str,
            "target_event_id": self.target_event.event_id,
            "target_type": self.target_event.event_type,
            "target_source": self.target_event.source,
            "target_time": self.target_event.timestamp_str,
            "relationship_type": self.relationship_type,
            "reason": self.reason,
            "confidence": self.confidence,
            "time_delta_seconds": self.time_delta_seconds
        }


def correlate_events(
    events: List[NormalizedEvent],
    proximity_window_seconds: int = 900  # 15 minutes default
) -> List[CorrelationFinding]:
    """Executes rule-based correlation across normalized events.
    
    Correlation Rules:
    1. DIRECT_LINK: Browser download record explicitly linked to evidence_id.
    2. HASH_MATCH: Identical SHA-256 fingerprint shared between events.
    3. FILENAME_MATCH: Browser download filename matches an evidence artifact filename.
    4. COMBINED_CORRELATION: Filename match + temporal proximity (< 15 min).
    5. HOST_MATCH: Hostname referenced across web events and forensic network/auth events.
    6. TEMPORAL_PROXIMITY: High-risk events (failed auth -> success -> download) occurring in short windows.
    """
    findings: List[CorrelationFinding] = []
    seen_pairs = set()

    def add_finding(s: NormalizedEvent, t: NormalizedEvent, r_type: str, reason: str, conf: str, dt_sec: Optional[float] = None):
        pair_key = tuple(sorted([s.event_id, t.event_id])) + (r_type,)
        if pair_key not in seen_pairs:
            seen_pairs.add(pair_key)
            findings.append(CorrelationFinding(s, t, r_type, reason, conf, dt_sec))

    # Partition events by category for efficient cross-evaluation
    downloads = [e for e in events if e.event_type == "DOWNLOAD"]
    evidence_acquisitions = [e for e in events if e.event_type == "EVIDENCE_ACQUIRED"]
    page_visits = [e for e in events if e.event_type == "PAGE_VISIT"]
    auth_events = [e for e in events if "AUTH" in e.event_type or "LOGIN" in e.event_type]

    # --- RULE 1: DIRECT EVIDENCE LINK ---
    for dl in downloads:
        if dl.evidence_id:
            for ev in evidence_acquisitions:
                if ev.evidence_id == dl.evidence_id:
                    dt = None
                    if dl.timestamp and ev.timestamp:
                        dt = abs((ev.timestamp - dl.timestamp).total_seconds())
                    add_finding(
                        dl, ev, "DIRECT_LINK",
                        f"Browser download record is explicitly linked to registered evidence artifact {ev.evidence_id}.",
                        "HIGH", dt
                    )

    # --- RULE 2: HASH MATCH ---
    events_with_hash = [e for e in events if e.hash_val]
    for i in range(len(events_with_hash)):
        for j in range(i + 1, len(events_with_hash)):
            e1, e2 = events_with_hash[i], events_with_hash[j]
            if e1.hash_val == e2.hash_val and e1.source != e2.source:
                dt = None
                if e1.timestamp and e2.timestamp:
                    dt = abs((e2.timestamp - e1.timestamp).total_seconds())
                add_finding(
                    e1, e2, "HASH_MATCH",
                    f"Cryptographic hash collision/identity: SHA-256 {e1.hash_val[:16]}... matches across {e1.source} and {e2.source}.",
                    "HIGH", dt
                )

    # --- RULE 3 & 4: FILENAME MATCH & COMBINED CORRELATION ---
    for dl in downloads:
        dl_fname = (dl.filename or "").strip().lower()
        if not dl_fname or dl_fname == "unknown":
            continue
        for ev in evidence_acquisitions:
            ev_fname = (ev.filename or "").strip().lower()
            # Normalize possible extensions (e.g., .txt wrapper)
            base_dl = dl_fname.split(".")[0]
            base_ev = ev_fname.split(".")[0]

            if dl_fname in ev_fname or ev_fname in dl_fname or (base_dl and base_dl == base_ev):
                dt = None
                if dl.timestamp and ev.timestamp:
                    dt = (ev.timestamp - dl.timestamp).total_seconds()

                if dt is not None and 0 <= dt <= proximity_window_seconds:
                    # Combined strong signal
                    add_finding(
                        dl, ev, "COMBINED_CORRELATION",
                        f"Browser download '{dl.filename}' corresponds to evidence '{ev.filename}' and was acquired {int(dt)}s later.",
                        "HIGH", dt
                    )
                else:
                    # Pure filename match
                    add_finding(
                        dl, ev, "FILENAME_MATCH",
                        f"Downloaded filename '{dl.filename}' matches name of evidence artifact '{ev.filename}'.",
                        "MEDIUM", dt
                    )

    # --- RULE 5: HOST MATCH ACROSS LOGS & BROWSING ---
    for pv in page_visits:
        if not pv.hostname or pv.hostname == "UNKNOWN":
            continue
        host_clean = pv.hostname.split(":")[0].lower()
        for fe in events:
            if fe.event_id == pv.event_id:
                continue
            desc_lower = fe.description.lower()
            if host_clean in desc_lower and "WEBTRACE" not in fe.source:
                dt = None
                if pv.timestamp and fe.timestamp:
                    dt = abs((fe.timestamp - pv.timestamp).total_seconds())
                add_finding(
                    pv, fe, "HOST_MATCH",
                    f"Host/domain '{pv.hostname}' accessed in browser is also referenced in {fe.source} ({fe.event_type}).",
                    "MEDIUM", dt
                )

    # --- RULE 6: TEMPORAL ATTACK CHAIN PROXIMITY ---
    # Correlation: AUTH_SUCCESS -> WEB_NAVIGATION -> DOWNLOAD (< 30 minutes)
    for auth in auth_events:
        if "SUCCESS" in auth.event_type and auth.timestamp:
            for dl in downloads:
                if dl.timestamp:
                    delta = (dl.timestamp - auth.timestamp).total_seconds()
                    if 0 < delta <= 1800:  # within 30 minutes
                        add_finding(
                            auth, dl, "TEMPORAL_PROXIMITY",
                            f"Account authentication ({auth.event_type}) was followed by file download '{dl.filename}' within {int(delta / 60)} minutes.",
                            "MEDIUM", delta
                        )

    return findings


# ==============================================================================
# 5. UNIFIED TIMELINE RETRIEVAL
# ==============================================================================

def get_unified_forensic_timeline(investigation_id: str) -> pd.DataFrame:
    """Returns a unified pandas DataFrame of all chronological investigation events."""
    raw_events = retrieve_all_investigation_events(investigation_id)
    if not raw_events:
        return pd.DataFrame(columns=[
            "event_id", "timestamp", "source", "event_type", "description",
            "actor", "hostname", "url", "filename", "evidence_id", "hash", "severity"
        ])

    data = [e.to_dict() for e in raw_events]
    df = pd.DataFrame(data)
    df["timestamp_dt"] = pd.to_datetime(df["timestamp"], utc=True)
    df = df.sort_values(by="timestamp_dt", ascending=True)
    return df
