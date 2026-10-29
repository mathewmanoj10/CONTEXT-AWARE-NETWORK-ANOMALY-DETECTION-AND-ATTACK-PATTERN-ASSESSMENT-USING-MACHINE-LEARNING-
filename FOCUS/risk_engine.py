"""
risk_engine.py
Context-Aware Heuristic Risk Engine for Network Security Monitoring.

This module provides a deterministic, explainable risk assessment by combining
ML traffic anomaly indicators with host port exposure, process identification,
and temporal persistence.
"""

# Configurable Scoring Constants (Project-defined heuristics)
WEIGHT_ML_ANOMALY = 40
WEIGHT_PORT_HIGH = 20
WEIGHT_PORT_MEDIUM = 10
WEIGHT_PORT_LOW = 0
WEIGHT_PORT_UNKNOWN = 0

WEIGHT_UNKNOWN_PROCESS = 20
WEIGHT_PERSISTENCE = 20
PERSISTENCE_THRESHOLD = 3

# Severity Level Thresholds
# 0-25: LOW | 26-50: MEDIUM | 51-75: HIGH | 76-100: CRITICAL
SEVERITY_THRESHOLDS = {
    'LOW': (0, 25),
    'MEDIUM': (26, 50),
    'HIGH': (51, 75),
    'CRITICAL': (76, 100)
}

def get_severity(score: int) -> str:
    """
    Maps an integer risk score (0-100) to its corresponding severity tier.
    """
    clamped_score = max(0, min(100, int(score)))
    if clamped_score <= 25:
        return 'LOW'
    elif clamped_score <= 50:
        return 'MEDIUM'
    elif clamped_score <= 75:
        return 'HIGH'
    else:
        return 'CRITICAL'

def calculate_risk(
    ml_anomaly: bool,
    inbound_deviation: float = 0.0,
    outbound_deviation: float = 0.0,
    port_risk: str = "UNKNOWN",
    process_name: str = "Unknown",
    consecutive_anomalies: int = 0,
    port: int = None
) -> dict:
    """
    Calculates a context-aware heuristic risk score and generates
    human-readable, explainable reasons for security assessment.

    Returns:
    {
        "score": integer 0-100,
        "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
        "breakdown": {
            "ml_anomaly": int,
            "port_risk": int,
            "unknown_process": int,
            "persistence": int
        },
        "reasons": list of str
    }
    """
    breakdown = {
        "ml_anomaly": 0,
        "port_risk": 0,
        "unknown_process": 0,
        "persistence": 0
    }
    reasons = []

    # 1. ML Traffic Anomaly Evaluation
    if ml_anomaly:
        breakdown["ml_anomaly"] = WEIGHT_ML_ANOMALY
        reasons.append("ML traffic anomaly detected")

    # 2. Port Exposure Risk Evaluation
    normalized_port_risk = str(port_risk).upper().strip() if port_risk else "UNKNOWN"
    port_label = f"Port {port}" if port is not None and str(port).isdigit() else "Identified port"

    if normalized_port_risk == 'HIGH':
        breakdown["port_risk"] = WEIGHT_PORT_HIGH
        reasons.append(f"{port_label} has HIGH exposure risk")
    elif normalized_port_risk == 'MEDIUM':
        breakdown["port_risk"] = WEIGHT_PORT_MEDIUM
        reasons.append(f"{port_label} has MEDIUM exposure risk")
    elif normalized_port_risk == 'LOW':
        breakdown["port_risk"] = WEIGHT_PORT_LOW
    else:
        breakdown["port_risk"] = WEIGHT_PORT_UNKNOWN

    # 3. Process Context Evaluation
    if process_name is None or str(process_name).strip().lower() in ("unknown", "", "none"):
        breakdown["unknown_process"] = WEIGHT_UNKNOWN_PROCESS
        reasons.append("Associated process could not be identified")
    else:
        breakdown["unknown_process"] = 0

    # 4. Temporal Persistence Evaluation
    if consecutive_anomalies >= PERSISTENCE_THRESHOLD:
        breakdown["persistence"] = WEIGHT_PERSISTENCE
        reasons.append(f"Anomaly persisted for {consecutive_anomalies} consecutive observations")
    else:
        breakdown["persistence"] = 0

    # Total score calculation clamped between 0 and 100
    raw_score = sum(breakdown.values())
    total_score = max(0, min(100, raw_score))
    severity = get_severity(total_score)

    return {
        "score": total_score,
        "severity": severity,
        "breakdown": breakdown,
        "reasons": reasons
    }

if __name__ == '__main__':
    # Unit tests for verification
    print("Testing risk_engine.py...")
    test_cases = [
        ("Case 1 (Normal ML, LOW port, known proc, no persist)", False, 0.0, 0.0, "LOW", "python.exe", 0, None, 0, "LOW"),
        ("Case 2 (ML anomaly, LOW port, known proc, no persist)", True, 0.5, 0.5, "LOW", "python.exe", 1, None, 40, "MEDIUM"), # 40 falls into MEDIUM 26-50
        ("Case 3 (ML anomaly, HIGH port, known proc, no persist)", True, 0.5, 0.5, "HIGH", "python.exe", 1, 445, 60, "HIGH"),
        ("Case 4 (ML anomaly, HIGH port, unknown proc, persist >= 3)", True, 0.5, 0.5, "HIGH", "Unknown", 3, 445, 100, "CRITICAL"),
        ("Case 5 (Normal ML, HIGH port, unknown proc)", False, 0.0, 0.0, "HIGH", "Unknown", 0, 445, 40, "MEDIUM"),
    ]

    for name, ml, in_dev, out_dev, pr, proc, consec, p_num, exp_score, exp_sev in test_cases:
        res = calculate_risk(ml, in_dev, out_dev, pr, proc, consec, p_num)
        print(f"\n{name}")
        print(f"  Score: {res['score']} (Expected: {exp_score}) | Severity: {res['severity']} (Expected: {exp_sev})")
        print(f"  Breakdown: {res['breakdown']}")
        print(f"  Reasons: {res['reasons']}")
        assert res['score'] == exp_score, f"Score mismatch: {res['score']} != {exp_score}"
        assert res['severity'] == exp_sev, f"Severity mismatch: {res['severity']} != {exp_sev}"
    print("\nAll risk engine test assertions passed successfully!")
