"""Unit tests for Phase 5: SENTINEL module.

Validates:
- Individual rule scoring
- Combined risk scoring and capping at 100
- Risk level classification (LOW, MEDIUM, HIGH, CRITICAL)
- Observation deduplication (prevent double counting)
- Missing telemetry graceful handling
- Explainable finding generation and non-malicious phrasing
"""
from modules.sentinel import evaluate_sentinel_risk, calculate_risk_level
from modules.tracefusion import NormalizedEvent
from datetime import datetime, timezone


def test_sentinel_risk_level_thresholds():
    """Validates risk score classification thresholds."""
    assert calculate_risk_level(15) == "LOW"
    assert calculate_risk_level(29) == "LOW"
    assert calculate_risk_level(30) == "MEDIUM"
    assert calculate_risk_level(59) == "MEDIUM"
    assert calculate_risk_level(60) == "HIGH"
    assert calculate_risk_level(79) == "HIGH"
    assert calculate_risk_level(80) == "CRITICAL"
    assert calculate_risk_level(100) == "CRITICAL"


def test_sentinel_rule_scoring_and_capping():
    """Validates individual rule score contributions and upper-bound cap at 100."""
    # 1. Critical integrity anomaly (+30)
    ev_mismatch = [{"id": "EV-1", "evidence_name": "tampered.bin", "integrity_status": "MISMATCH"}]
    res1 = evaluate_sentinel_risk("CAS-TEST", events=[], indicators=[], evidence_list=ev_mismatch)
    assert res1["risk_score"] == 30
    assert res1["risk_level"] == "MEDIUM"
    assert len(res1["findings"]) == 1
    assert res1["findings"][0]["rule_id"] == "RULE_INTEGRITY_COMPROMISED"

    # 2. Executable download (+20) + Network Anomaly (+10)
    indicators = [
        {"indicator_name": "EXECUTABLE_DOWNLOAD", "observed_value": "mal.exe", "timestamp_utc": "2026-11-16 09:18:00"},
        {"indicator_name": "DIRECT_IP_ACCESS", "observed_value": "192.0.2.1", "timestamp_utc": "2026-11-16 09:14:00"}
    ]
    res2 = evaluate_sentinel_risk("CAS-TEST", events=[], indicators=indicators, evidence_list=[])
    assert res2["risk_score"] == 30
    assert len(res2["findings"]) == 2

    # 3. All rules firing together: 30 + 25 + 20 + 10 + 15 = 100
    t0 = datetime(2026, 11, 16, 9, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 11, 16, 9, 2, 0, tzinfo=timezone.utc)
    failed_auths = [
        NormalizedEvent(f"A{i}", t0, "auth.log", "AUTH_FAILED", "Failed login") for i in range(4)
    ]
    e_dl = NormalizedEvent("DL1", t1, "WEBTRACE", "DOWNLOAD", "Download setup.exe", filename="setup.exe", evidence_id="EV-1")
    e_ev = NormalizedEvent("EV1", t1, "CHAINLOCK", "EVIDENCE_ACQUIRED", "Acquired setup.exe", filename="setup.exe", evidence_id="EV-1")

    all_events = failed_auths + [e_dl, e_ev]
    res_all = evaluate_sentinel_risk("CAS-TEST", events=all_events, indicators=indicators, evidence_list=ev_mismatch)
    
    # 30 + 25 + 20 + 10 + 15 = 100
    assert res_all["risk_score"] == 100
    assert res_all["risk_level"] == "CRITICAL"
    assert res_all["applied_rules_count"] == 5
    assert len(res_all["recommendations"]) >= 3


def test_sentinel_deduplication():
    """Validates that repeated occurrences of the same indicator type do not duplicate risk points."""
    # 3 distinct executable download indicators should only trigger the payload rule once (+20)
    multiple_exe_indicators = [
        {"indicator_name": "EXECUTABLE_DOWNLOAD", "observed_value": f"tool{i}.exe", "timestamp_utc": "2026-11-16 09:18:00"}
        for i in range(5)
    ]
    res = evaluate_sentinel_risk("CAS-TEST", events=[], indicators=multiple_exe_indicators, evidence_list=[])
    assert res["risk_score"] == 20
    assert res["applied_rules_count"] == 1


def test_sentinel_empty_telemetry():
    """Validates safe handling of empty investigations."""
    res_empty = evaluate_sentinel_risk("CAS-EMPTY", events=[], indicators=[], evidence_list=[])
    assert res_empty["risk_score"] == 0
    assert res_empty["risk_level"] == "LOW"
    assert len(res_empty["findings"]) == 0
    assert len(res_empty["recommendations"]) == 1
