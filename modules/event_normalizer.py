"""Event Normalizer module.

Normalizes heterogeneous forensic artefacts (browser logs, auth logs, evidence ingestions)
into a unified schema format ready for correlation and chronological reconstruction.
"""
from datetime import datetime
from typing import Dict, Any, Optional
import pandas as pd


def normalize_event(
    investigation_id: str,
    timestamp: Any,
    event_type: str,
    source: str,
    description: str,
    actor: Optional[str] = None,
    raw_record: Optional[str] = None,
    severity: str = "INFO",
    is_simulated: int = 0
) -> Dict[str, Any]:
    """Converts diverse log indicators into the standard FORENSIX forensic_events schema."""
    
    # Handle pandas Timestamps and string dates cleanly
    if isinstance(timestamp, pd.Timestamp):
        ts_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    elif isinstance(timestamp, datetime):
        ts_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    else:
        ts_str = str(timestamp).replace("T", " ")[:19]

    return {
        "investigation_id": investigation_id,
        "timestamp": ts_str,
        "event_type": str(event_type).upper(),
        "source": str(source),
        "actor": actor or "UNKNOWN",
        "description": str(description),
        "raw_record": raw_record or "",
        "severity": severity.upper(),
        "is_simulated": int(is_simulated)
    }
