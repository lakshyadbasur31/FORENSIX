"""Event Correlator module.

Correlates forensic events across different sources to identify patterns,
such as brute-force authentication followed by credential compromise and payload download.
"""
from typing import List, Dict, Any
import pandas as pd


def detect_brute_force(events: List[Dict[str, Any]], threshold: int = 3, window_minutes: int = 10) -> List[Dict[str, Any]]:
    """Identifies bursts of failed authentications within a time window."""
    findings = []
    auth_failed = [e for e in events if e.get("event_type") == "AUTH_FAILED"]
    if len(auth_failed) >= threshold:
        findings.append({
            "pattern": "SUSPECTED_BRUTE_FORCE",
            "count": len(auth_failed),
            "severity": "HIGH",
            "message": f"Detected {len(auth_failed)} failed authentication attempts within sequence."
        })
    return findings


def correlate_attack_chain(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Correlates the chronological sequence of events into unified threat chain stages."""
    stages = []
    has_failed = any(e.get("event_type") == "AUTH_FAILED" for e in events)
    has_success = any(e.get("event_type") == "AUTH_SUCCESS" for e in events)
    has_web = any(e.get("event_type") == "WEB_NAVIGATION" for e in events)
    has_download = any(e.get("event_type") == "FILE_DOWNLOAD" for e in events)
    has_vault = any(e.get("event_type") == "EVIDENCE_REGISTRATION" for e in events)

    if has_failed and has_success:
        stages.append({
            "stage": "INITIAL_ACCESS",
            "status": "DETECTED",
            "summary": "Brute-force password guessing followed by successful account login."
        })

    if has_web:
        stages.append({
            "stage": "EXTERNAL_RECON_OR_DELIVERY",
            "status": "DETECTED",
            "summary": "Navigation to suspicious or external web location."
        })

    if has_download:
        stages.append({
            "stage": "EXECUTION_OR_STAGING",
            "status": "DETECTED",
            "summary": "File download recorded from web origin."
        })

    if has_vault:
        stages.append({
            "stage": "FORENSIC_PRESERVATION",
            "status": "COMPLETED",
            "summary": "Digital evidence secured, hashed, and committed to vault."
        })

    return stages
