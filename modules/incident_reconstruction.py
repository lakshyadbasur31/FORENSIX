"""Incident Reconstruction module.

Rebuilds chronological forensic timelines from registered events,
calculates time gaps, and formats timeline artifacts.
"""
import uuid
from typing import List, Dict, Any, Optional
import pandas as pd
from database.db import execute_query, execute_commit, execute_many


def insert_forensic_event(
    investigation_id: str,
    timestamp: str,
    event_type: str,
    source: str,
    description: str,
    actor: Optional[str] = None,
    raw_record: Optional[str] = None,
    severity: str = "INFO",
    is_simulated: int = 0
) -> str:
    """Inserts an individual forensic event into SQLite."""
    event_id = f"EVT-{uuid.uuid4().hex[:8].upper()}"
    query = """
    INSERT INTO forensic_events (
        id, investigation_id, timestamp, event_type, source,
        actor, description, raw_record, severity, is_simulated
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    execute_commit(query, (
        event_id, investigation_id, timestamp, event_type, source,
        actor or "UNKNOWN", description, raw_record or "", severity, is_simulated
    ))
    return event_id


def batch_insert_events(events: List[Dict[str, Any]]) -> int:
    """Inserts a batch of normalized forensic events in a single transaction."""
    if not events:
        return 0
    query = """
    INSERT INTO forensic_events (
        id, investigation_id, timestamp, event_type, source,
        actor, description, raw_record, severity, is_simulated
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    param_list = [
        (
            f"EVT-{uuid.uuid4().hex[:8].upper()}",
            e["investigation_id"],
            e["timestamp"],
            e["event_type"],
            e["source"],
            e.get("actor", "UNKNOWN"),
            e["description"],
            e.get("raw_record", ""),
            e.get("severity", "INFO"),
            e.get("is_simulated", 0)
        )
        for e in events
    ]
    return execute_many(query, param_list)


def get_investigation_timeline(investigation_id: str) -> pd.DataFrame:
    """Retrieves all forensic events for an investigation ordered by timestamp."""
    query = """
    SELECT id, timestamp, event_type, source, actor, description, severity, is_simulated
    FROM forensic_events
    WHERE investigation_id = ?
    ORDER BY timestamp ASC
    """
    rows = execute_query(query, (investigation_id,))
    if not rows:
        return pd.DataFrame(columns=["id", "timestamp", "event_type", "source", "actor", "description", "severity", "is_simulated"])
    
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df
