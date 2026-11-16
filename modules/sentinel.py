"""SENTINEL — Explainable Threat Intelligence and Risk Prioritization Engine.

Features:
- Deterministic 0-100 Risk Scoring Model:
    * Critical integrity anomaly (+30)
    * Correlated delivery/download chain (+25)
    * Executable or script payload download (+20)
    * Direct-IP access or non-standard port (+10)
    * Multiple failed authentications / brute force (+15)
- Deduplication of scored observations
- Score capping at 100
- Risk Level thresholds:
    * 0-29: LOW
    * 30-59: MEDIUM
    * 60-79: HIGH
    * 80-100: CRITICAL
- Structured Explainable Finding Model
- Prioritized Investigator Recommendations
- Non-malicious forensic phrasing
"""
from typing import List, Dict, Any, Optional
from modules.tracefusion import retrieve_all_investigation_events, correlate_events, NormalizedEvent
from modules.webtrace import get_webtrace_indicators
from modules.evidence_manager import list_evidence


class SentinelFinding:
    """Individual explainable threat finding and risk score contributor."""

    def __init__(
        self,
        finding_id: str,
        rule_id: str,
        title: str,
        severity: str,
        score_contribution: int,
        evidence: str,
        explanation: str,
        source: str,
        timestamp: Optional[str] = None,
        related_event_ids: Optional[List[str]] = None,
        related_evidence_ids: Optional[List[str]] = None
    ):
        self.finding_id = finding_id
        self.rule_id = rule_id
        self.title = title
        self.severity = severity.upper()
        self.score_contribution = score_contribution
        self.evidence = evidence
        self.explanation = explanation
        self.source = source
        self.timestamp = timestamp or "UNKNOWN"
        self.related_event_ids = related_event_ids or []
        self.related_evidence_ids = related_evidence_ids or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "score_contribution": self.score_contribution,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "source": self.source,
            "timestamp": self.timestamp,
            "related_event_ids": self.related_event_ids,
            "related_evidence_ids": self.related_evidence_ids
        }


def calculate_risk_level(score: int) -> str:
    """Classifies risk score into deterministic levels."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    return "LOW"


def evaluate_sentinel_risk(
    investigation_id: str,
    events: Optional[List[NormalizedEvent]] = None,
    indicators: Optional[List[Dict[str, Any]]] = None,
    evidence_list: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """Evaluates case risk score, findings, and prioritized actions with explainability."""
    # 1. Fetch data if not supplied
    if events is None:
        events = retrieve_all_investigation_events(investigation_id)
    if indicators is None:
        indicators = get_webtrace_indicators(investigation_id)
    if evidence_list is None:
        evidence_list = list_evidence(investigation_id)

    correlations = correlate_events(events)

    findings: List[SentinelFinding] = []
    applied_rules = set()
    total_score = 0

    # --------------------------------------------------------------------------
    # RULE 1: Critical Evidence Integrity Anomaly (+30)
    # --------------------------------------------------------------------------
    for ev in evidence_list:
        status = ev.get("integrity_status", "VERIFIED")
        if status in ("MISMATCH", "TAMPERED_OR_CORRUPT"):
            rule_id = f"RULE_INTEGRITY_COMPROMISED_{ev['id']}"
            if rule_id not in applied_rules:
                applied_rules.add(rule_id)
                score_pts = 30
                total_score += score_pts
                findings.append(SentinelFinding(
                    finding_id=f"SNT-{len(findings)+1:02d}",
                    rule_id="RULE_INTEGRITY_COMPROMISED",
                    title="Cryptographic Evidence Integrity Mismatch",
                    severity="CRITICAL",
                    score_contribution=score_pts,
                    evidence=f"Evidence ID: {ev['id']} ({ev.get('evidence_name')})",
                    explanation=(
                        f"Stored vault artifact recalculation yielded a hash mismatch against baseline SHA-256 "
                        f"{ev.get('sha256', '')[:16]}... Indicates post-acquisition file mutation or storage error."
                    ),
                    source="CHAINLOCK:INTEGRITY",
                    timestamp=ev.get("acquisition_date"),
                    related_evidence_ids=[ev["id"]]
                ))
                break  # Score once for integrity compromise

    # --------------------------------------------------------------------------
    # RULE 2: Correlated Delivery / Download Chain (+25)
    # --------------------------------------------------------------------------
    strong_correlations = [
        c for c in correlations if c.relationship_type in ("DIRECT_LINK", "COMBINED_CORRELATION")
    ]
    if strong_correlations and "RULE_CORRELATED_CHAIN" not in applied_rules:
        applied_rules.add("RULE_CORRELATED_CHAIN")
        score_pts = 25
        total_score += score_pts
        c_top = strong_correlations[0]
        findings.append(SentinelFinding(
            finding_id=f"SNT-{len(findings)+1:02d}",
            rule_id="RULE_CORRELATED_CHAIN",
            title="Correlated Web Delivery to Evidence Intake Chain",
            severity="HIGH",
            score_contribution=score_pts,
            evidence=f"{c_top.source_event.event_id} ↔ {c_top.target_event.event_id}",
            explanation=(
                f"Multi-signal correlation confirmed browser payload download is directly connected to "
                f"an acquired forensic evidence artifact ({c_top.reason})."
            ),
            source="TRACEFUSION",
            timestamp=c_top.source_event.timestamp_str,
            related_event_ids=[c_top.source_event.event_id, c_top.target_event.event_id]
        ))

    # --------------------------------------------------------------------------
    # RULE 3: Executable / Script Payload Download (+20)
    # --------------------------------------------------------------------------
    payload_indicators = [
        ind for ind in indicators if ind.get("indicator_name") in ("EXECUTABLE_DOWNLOAD", "SCRIPT_DOWNLOAD")
    ]
    if payload_indicators and "RULE_PAYLOAD_DOWNLOAD" not in applied_rules:
        applied_rules.add("RULE_PAYLOAD_DOWNLOAD")
        score_pts = 20
        total_score += score_pts
        p_top = payload_indicators[0]
        findings.append(SentinelFinding(
            finding_id=f"SNT-{len(findings)+1:02d}",
            rule_id="RULE_PAYLOAD_DOWNLOAD",
            title=f"Browser {p_top.get('indicator_name')}",
            severity="HIGH",
            score_contribution=score_pts,
            evidence=str(p_top.get("observed_value")),
            explanation=(
                f"Observed download of binary executable or script payload ({p_top.get('observed_value')}). "
                f"Requires verification to examine execution provenance and file safety."
            ),
            source="WEBTRACE",
            timestamp=p_top.get("timestamp_utc"),
            related_event_ids=[p_top.get("event_id")] if p_top.get("event_id") else []
        ))

    # --------------------------------------------------------------------------
    # RULE 4: Direct-IP Access or Non-Standard Port (+10)
    # --------------------------------------------------------------------------
    network_indicators = [
        ind for ind in indicators if ind.get("indicator_name") in ("DIRECT_IP_ACCESS", "NON_STANDARD_PORT")
    ]
    if network_indicators and "RULE_NETWORK_ANOMALY" not in applied_rules:
        applied_rules.add("RULE_NETWORK_ANOMALY")
        score_pts = 10
        total_score += score_pts
        n_top = network_indicators[0]
        findings.append(SentinelFinding(
            finding_id=f"SNT-{len(findings)+1:02d}",
            rule_id="RULE_NETWORK_ANOMALY",
            title=f"Unconventional Web Routing ({n_top.get('indicator_name')})",
            severity="MEDIUM",
            score_contribution=score_pts,
            evidence=str(n_top.get("observed_value")),
            explanation=(
                f"Observed web navigation to host or URL using direct IP address or non-standard port. "
                f"Observed value: {n_top.get('observed_value')}."
            ),
            source="WEBTRACE",
            timestamp=n_top.get("timestamp_utc")
        ))

    # --------------------------------------------------------------------------
    # RULE 5: Multiple Failed Authentications / Brute Force (+15)
    # --------------------------------------------------------------------------
    failed_auths = [e for e in events if e.event_type == "AUTH_FAILED"]
    if len(failed_auths) >= 3 and "RULE_BRUTE_FORCE" not in applied_rules:
        applied_rules.add("RULE_BRUTE_FORCE")
        score_pts = 15
        total_score += score_pts
        findings.append(SentinelFinding(
            finding_id=f"SNT-{len(findings)+1:02d}",
            rule_id="RULE_BRUTE_FORCE",
            title="Authentication Anomaly (Multiple Failed Logins)",
            severity="MEDIUM",
            score_contribution=score_pts,
            evidence=f"{len(failed_auths)} failed authentication events recorded",
            explanation=(
                f"Detected a sequence of {len(failed_auths)} failed login attempts across monitored hosts. "
                f"Consistent with password guessing or unauthorized credential access attempts."
            ),
            source="FORENSIC_LOG",
            timestamp=failed_auths[0].timestamp_str,
            related_event_ids=[e.event_id for e in failed_auths[:5]]
        ))

    # Cap score at 100
    capped_score = min(total_score, 100)
    risk_level = calculate_risk_level(capped_score)

    # Prioritized Investigator Recommendations
    recommendations: List[Dict[str, str]] = []
    if any(f.severity == "CRITICAL" for f in findings):
        recommendations.append({
            "priority": "CRITICAL",
            "action": "Immediate Evidence Vault Audit",
            "details": "Examine storage integrity mismatch for flagged evidence items; verify backup replicas."
        })
    if any(f.rule_id == "RULE_CORRELATED_CHAIN" for f in findings):
        recommendations.append({
            "priority": "HIGH",
            "action": "Investigate Delivery-to-Intake Pipeline",
            "details": "Cross-examine web history around the download timestamp to ascertain user or automated provenance."
        })
    if any(f.rule_id == "RULE_PAYLOAD_DOWNLOAD" for f in findings):
        recommendations.append({
            "priority": "HIGH",
            "action": "Static Inspection of Downloaded Payload",
            "details": "Perform local static analysis, string extraction, and signature checking on the downloaded artifact."
        })
    if any(f.rule_id == "RULE_BRUTE_FORCE" for f in findings):
        recommendations.append({
            "priority": "MEDIUM",
            "action": "Audit User Account Session Times",
            "details": "Review sessions created following the authentication attempts to verify lateral movements."
        })

    if not recommendations:
        recommendations.append({
            "priority": "LOW",
            "action": "Baseline Telemetry Review",
            "details": "Continue routine telemetry collection; no elevated indicators detected."
        })

    return {
        "investigation_id": investigation_id,
        "risk_score": capped_score,
        "risk_level": risk_level,
        "findings": [f.to_dict() for f in findings],
        "findings_count": len(findings),
        "recommendations": recommendations,
        "applied_rules_count": len(applied_rules),
        "disclaimer": (
            "Risk scores are calculated deterministically from observed indicators and correlations. "
            "They represent investigation priority and do NOT constitute legal proof of malicious intent."
        )
    }
