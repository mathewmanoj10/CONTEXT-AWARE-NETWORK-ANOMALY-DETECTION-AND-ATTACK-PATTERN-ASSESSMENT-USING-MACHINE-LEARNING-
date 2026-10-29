"""
attack_pattern_assessor.py
Condition-Based Attack Pattern Assessment for Network Security Monitoring.

Provides explainable, behavioural indications of attack patterns that anomalous
network behaviour MAY resemble.

IMPORTANT:
This module provides behavioural pattern matching, NOT confirmed attack classification.
It does NOT claim that an attack actually occurred.
"""

# Configurable Threshold Constants
DEVIATION_THRESHOLD = 0.50  # 50% normalized deviation
PERSISTENCE_THRESHOLD = 3   # >= 3 consecutive anomaly observations

# Attack Pattern Names
PATTERN_DOS_DDOS = "Possible DoS/DDoS-like Traffic Surge"
PATTERN_UNUSUAL_OUTBOUND = "Possible Unusual Outbound Transfer"
PATTERN_SUSPICIOUS_SERVICE = "Possible Suspicious Network Service Activity"
PATTERN_UNCLASSIFIED = "Unclassified Network Anomaly"

# Explanations
EXPLANATION_DOS_DDOS = (
    "Traffic behaviour shows a sustained inbound deviation consistent with "
    "a possible DoS/DDoS-like traffic surge."
)
EXPLANATION_UNUSUAL_OUTBOUND = (
    "Traffic behaviour shows a sustained outbound deviation that may warrant "
    "investigation as unusual outbound transfer activity."
)
EXPLANATION_SUSPICIOUS_SERVICE = (
    "An anomalous traffic event is associated with a high-exposure port and "
    "an unidentified process."
)
EXPLANATION_UNCLASSIFIED = (
    "Traffic behaviour was flagged as anomalous, but current indicators "
    "do not sufficiently match a recognized attack pattern."
)
EXPLANATION_NORMAL = "Traffic behaviour is within normal parameters."


def assess_attack_pattern(
    ml_anomaly: bool,
    inbound_deviation: float = 0.0,
    outbound_deviation: float = 0.0,
    port_risk: str = "UNKNOWN",
    process_name: str = "Unknown",
    consecutive_anomalies: int = 0
) -> dict:
    """
    Evaluates observed anomalous network behaviour against condition-based rules
    to provide an explainable indication of what attack pattern the behaviour MAY resemble.

    Returns a structured dictionary:
    {
        "pattern": str or None,
        "matched": bool,
        "evidence_level": "LOW" | "MEDIUM" | "HIGH",
        "matched_conditions": list of str,
        "explanation": str,
        "additional_patterns": list of str
    }
    """
    # Safe input normalization
    try:
        in_dev = float(inbound_deviation) if inbound_deviation is not None else 0.0
    except (ValueError, TypeError):
        in_dev = 0.0

    try:
        out_dev = float(outbound_deviation) if outbound_deviation is not None else 0.0
    except (ValueError, TypeError):
        out_dev = 0.0

    try:
        consec = int(consecutive_anomalies) if consecutive_anomalies is not None else 0
    except (ValueError, TypeError):
        consec = 0

    norm_port_risk = str(port_risk).upper().strip() if port_risk else "UNKNOWN"
    is_unknown_process = (process_name is None) or (str(process_name).strip().lower() in ("unknown", "", "none"))
    is_anomaly = bool(ml_anomaly)

    # 1. Normal traffic (no anomaly)
    if not is_anomaly:
        return {
            "pattern": None,
            "matched": False,
            "evidence_level": "LOW",
            "matched_conditions": [],
            "explanation": EXPLANATION_NORMAL,
            "additional_patterns": []
        }

    matched_rules = []

    # Rule 1: POSSIBLE DoS/DDoS-LIKE TRAFFIC SURGE
    # Trigger when: ML anomaly = True, inbound deviation >= 50%, persistent anomaly (consecutive_anomalies >= 3)
    if in_dev >= DEVIATION_THRESHOLD and consec >= PERSISTENCE_THRESHOLD:
        matched_rules.append({
            "pattern": PATTERN_DOS_DDOS,
            "explanation": EXPLANATION_DOS_DDOS,
            "conditions": [
                "ML traffic anomaly detected",
                f"High inbound deviation (>= 50%): {in_dev * 100:.2f}%",
                f"Persistent anomaly ({consec} consecutive observations)"
            ]
        })

    # Rule 2: POSSIBLE UNUSUAL OUTBOUND TRANSFER
    # Trigger when: ML anomaly = True, outbound deviation >= 50%, persistent anomaly (consecutive_anomalies >= 3)
    if out_dev >= DEVIATION_THRESHOLD and consec >= PERSISTENCE_THRESHOLD:
        matched_rules.append({
            "pattern": PATTERN_UNUSUAL_OUTBOUND,
            "explanation": EXPLANATION_UNUSUAL_OUTBOUND,
            "conditions": [
                "ML traffic anomaly detected",
                f"High outbound deviation (>= 50%): {out_dev * 100:.2f}%",
                f"Persistent anomaly ({consec} consecutive observations)"
            ]
        })

    # Rule 3: POSSIBLE SUSPICIOUS NETWORK SERVICE ACTIVITY
    # Trigger when: ML anomaly = True, port risk is HIGH, process is Unknown/None
    if norm_port_risk == "HIGH" and is_unknown_process:
        proc_display = str(process_name) if process_name else "Unknown/None"
        matched_rules.append({
            "pattern": PATTERN_SUSPICIOUS_SERVICE,
            "explanation": EXPLANATION_SUSPICIOUS_SERVICE,
            "conditions": [
                "ML traffic anomaly detected",
                f"High port exposure risk ({norm_port_risk})",
                f"Unidentified associated process ({proc_display})"
            ]
        })

    # Rule 4: OTHERWISE (Anomalous, but insufficient evidence for defined patterns)
    if not matched_rules:
        return {
            "pattern": PATTERN_UNCLASSIFIED,
            "matched": False,
            "evidence_level": "LOW",
            "matched_conditions": ["ML traffic anomaly detected"],
            "explanation": EXPLANATION_UNCLASSIFIED,
            "additional_patterns": []
        }

    # Single match
    if len(matched_rules) == 1:
        primary = matched_rules[0]
        return {
            "pattern": primary["pattern"],
            "matched": True,
            "evidence_level": "MEDIUM",
            "matched_conditions": list(primary["conditions"]),
            "explanation": primary["explanation"],
            "additional_patterns": []
        }

    # Multiple matches: select strongest/most relevant pattern as primary
    has_r1 = any(r["pattern"] == PATTERN_DOS_DDOS for r in matched_rules)
    has_r2 = any(r["pattern"] == PATTERN_UNUSUAL_OUTBOUND for r in matched_rules)

    if has_r1 and has_r2:
        if in_dev >= out_dev:
            primary_name = PATTERN_DOS_DDOS
        else:
            primary_name = PATTERN_UNUSUAL_OUTBOUND
    elif has_r1:
        primary_name = PATTERN_DOS_DDOS
    elif has_r2:
        primary_name = PATTERN_UNUSUAL_OUTBOUND
    else:
        primary_name = PATTERN_SUSPICIOUS_SERVICE

    primary = next(r for r in matched_rules if r["pattern"] == primary_name)
    additional = [r for r in matched_rules if r["pattern"] != primary_name]
    additional_names = [r["pattern"] for r in additional]

    # Preserve all valid matching conditions without duplicate strings
    combined_conditions = []
    for r in [primary] + additional:
        for cond in r["conditions"]:
            if cond not in combined_conditions:
                combined_conditions.append(cond)

    for add_name in additional_names:
        combined_conditions.append(f"Co-occurring pattern: {add_name}")

    return {
        "pattern": primary["pattern"],
        "matched": True,
        "evidence_level": "HIGH",
        "matched_conditions": combined_conditions,
        "explanation": primary["explanation"],
        "additional_patterns": additional_names
    }


if __name__ == '__main__':
    print("Running self-check tests for attack_pattern_assessor.py...")

    # 1. Normal traffic -> no attack pattern
    res1 = assess_attack_pattern(
        ml_anomaly=False,
        inbound_deviation=0.10,
        outbound_deviation=0.10,
        port_risk="LOW",
        process_name="python.exe",
        consecutive_anomalies=0
    )
    assert not res1["matched"], "Test 1 failed: matched should be False for normal traffic"
    assert res1["pattern"] is None, "Test 1 failed: pattern should be None for normal traffic"
    assert res1["evidence_level"] == "LOW"
    print("Test 1 (Normal traffic): PASSED")

    # 2. ML anomaly + inbound dev >= 50% + persistence >= 3 -> Possible DoS/DDoS-like Traffic Surge
    res2 = assess_attack_pattern(
        ml_anomaly=True,
        inbound_deviation=0.75,
        outbound_deviation=0.10,
        port_risk="LOW",
        process_name="python.exe",
        consecutive_anomalies=3
    )
    assert res2["matched"] is True
    assert res2["pattern"] == PATTERN_DOS_DDOS
    assert res2["evidence_level"] == "MEDIUM"
    assert res2["explanation"] == EXPLANATION_DOS_DDOS
    print("Test 2 (DoS/DDoS surge): PASSED")

    # 3. ML anomaly + outbound dev >= 50% + persistence >= 3 -> Possible Unusual Outbound Transfer
    res3 = assess_attack_pattern(
        ml_anomaly=True,
        inbound_deviation=0.10,
        outbound_deviation=0.80,
        port_risk="LOW",
        process_name="python.exe",
        consecutive_anomalies=4
    )
    assert res3["matched"] is True
    assert res3["pattern"] == PATTERN_UNUSUAL_OUTBOUND
    assert res3["evidence_level"] == "MEDIUM"
    assert res3["explanation"] == EXPLANATION_UNUSUAL_OUTBOUND
    print("Test 3 (Unusual Outbound Transfer): PASSED")

    # 4. ML anomaly + HIGH port risk + Unknown process -> Possible Suspicious Network Service Activity
    res4 = assess_attack_pattern(
        ml_anomaly=True,
        inbound_deviation=0.20,
        outbound_deviation=0.20,
        port_risk="HIGH",
        process_name="Unknown",
        consecutive_anomalies=1
    )
    assert res4["matched"] is True
    assert res4["pattern"] == PATTERN_SUSPICIOUS_SERVICE
    assert res4["evidence_level"] == "MEDIUM"
    assert res4["explanation"] == EXPLANATION_SUSPICIOUS_SERVICE
    print("Test 4 (Suspicious Service Activity): PASSED")

    # 5. Multiple matching conditions -> primary + additional evidence
    res5 = assess_attack_pattern(
        ml_anomaly=True,
        inbound_deviation=0.90,
        outbound_deviation=0.20,
        port_risk="HIGH",
        process_name="Unknown",
        consecutive_anomalies=3
    )
    assert res5["matched"] is True
    assert res5["pattern"] == PATTERN_DOS_DDOS
    assert PATTERN_SUSPICIOUS_SERVICE in res5["additional_patterns"]
    assert res5["evidence_level"] == "HIGH"
    print("Test 5 (Multiple matching conditions): PASSED")

    # 6. ML anomaly with insufficient evidence -> Unclassified Network Anomaly
    res6 = assess_attack_pattern(
        ml_anomaly=True,
        inbound_deviation=0.20,
        outbound_deviation=0.20,
        port_risk="LOW",
        process_name="python.exe",
        consecutive_anomalies=1
    )
    assert not res6["matched"]
    assert res6["pattern"] == PATTERN_UNCLASSIFIED
    assert res6["evidence_level"] == "LOW"
    print("Test 6 (Unclassified anomaly): PASSED")

    # 7. Boundary checks: 49.99% -> False, 50.00% -> True
    res7_below = assess_attack_pattern(
        ml_anomaly=True,
        inbound_deviation=0.4999,
        outbound_deviation=0.0,
        port_risk="LOW",
        process_name="python.exe",
        consecutive_anomalies=3
    )
    assert not res7_below["matched"]
    assert res7_below["pattern"] == PATTERN_UNCLASSIFIED

    res7_exact = assess_attack_pattern(
        ml_anomaly=True,
        inbound_deviation=0.5000,
        outbound_deviation=0.0,
        port_risk="LOW",
        process_name="python.exe",
        consecutive_anomalies=3
    )
    assert res7_exact["matched"] is True
    assert res7_exact["pattern"] == PATTERN_DOS_DDOS
    print("Test 7 (Boundary checks 49.99% vs 50.00%): PASSED")

    print("\nAll attack_pattern_assessor.py self-checks passed successfully!")
