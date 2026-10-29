"""
attack_tree.py
Lightweight Analytical Attack Tree Evaluation for Academic Cybersecurity Modeling.

ROOT:
Potential Network Compromise
    OR
    ├── Exploitable Network Exposure
    │   ├── HIGH-risk exposed port
    │   └── MEDIUM-risk exposed port
    ├── Abnormal Network Behaviour
    │   ├── ML traffic anomaly
    │   ├── High inbound deviation
    │   └── High outbound deviation
    └── Suspicious Process / Connection
        ├── Unknown process
        └── Repeated anomalous behaviour
"""

# Threshold Constants
HIGH_DEVIATION_THRESHOLD = 0.50  # 50% normalized deviation
PERSISTENCE_THRESHOLD = 3         # >= 3 consecutive anomaly observations

def evaluate_attack_tree(
    ml_anomaly: bool,
    inbound_deviation: float = 0.0,
    outbound_deviation: float = 0.0,
    port_risk: str = "UNKNOWN",
    process_name: str = "Unknown",
    consecutive_anomalies: int = 0
) -> dict:
    """
    Evaluates observed system indicators against the conceptual attack tree.
    Returns structured boolean indicators without claiming proven compromise.
    """
    normalized_port_risk = str(port_risk).upper().strip() if port_risk else "UNKNOWN"
    is_unknown_process = (process_name is None) or (str(process_name).strip().lower() in ("unknown", "", "none"))
    
    # 1. Exploitable Network Exposure Branch
    ind_port_high = (normalized_port_risk == "HIGH")
    ind_port_med = (normalized_port_risk == "MEDIUM")
    branch_exposure_triggered = ind_port_high or ind_port_med

    # 2. Abnormal Network Behaviour Branch
    ind_ml_anomaly = bool(ml_anomaly)
    ind_inbound_dev = (float(inbound_deviation) >= HIGH_DEVIATION_THRESHOLD)
    ind_outbound_dev = (float(outbound_deviation) >= HIGH_DEVIATION_THRESHOLD)
    branch_behavior_triggered = ind_ml_anomaly or ind_inbound_dev or ind_outbound_dev

    # 3. Suspicious Process / Connection Branch
    ind_unknown_proc = is_unknown_process
    ind_repeated = (int(consecutive_anomalies) >= PERSISTENCE_THRESHOLD)
    branch_process_triggered = ind_unknown_proc or ind_repeated

    branches = {
        "network_exposure": {
            "name": "Exploitable Network Exposure",
            "triggered": branch_exposure_triggered,
            "indicators": [
                {"name": "HIGH-risk exposed port", "triggered": ind_port_high},
                {"name": "MEDIUM-risk exposed port", "triggered": ind_port_med}
            ]
        },
        "abnormal_behavior": {
            "name": "Abnormal Network Behaviour",
            "triggered": branch_behavior_triggered,
            "indicators": [
                {"name": "ML traffic anomaly", "triggered": ind_ml_anomaly},
                {"name": "High inbound deviation (>=50%)", "triggered": ind_inbound_dev},
                {"name": "High outbound deviation (>=50%)", "triggered": ind_outbound_dev}
            ]
        },
        "suspicious_process": {
            "name": "Suspicious Process / Connection",
            "triggered": branch_process_triggered,
            "indicators": [
                {"name": "Unknown process", "triggered": ind_unknown_proc},
                {"name": "Repeated anomalous behaviour (>=3)", "triggered": ind_repeated}
            ]
        }
    }

    triggered_indicators = []
    for b_key, b_val in branches.items():
        for ind in b_val["indicators"]:
            if ind["triggered"]:
                triggered_indicators.append(ind["name"])

    return {
        "root": "Potential Network Compromise",
        "branches": branches,
        "triggered_indicators": triggered_indicators
    }

def print_attack_tree(result: dict) -> None:
    """
    Renders an ASCII tree displaying all branches and indicators with their evaluation states.
    """
    print("\nATTACK TREE ANALYSIS")
    print("====================")
    print(result.get("root", "Potential Network Compromise"))
    print("|")

    branches = result.get("branches", {})
    branch_keys = list(branches.keys())
    
    for i, b_key in enumerate(branch_keys):
        branch = branches[b_key]
        is_last_branch = (i == len(branch_keys) - 1)
        b_prefix = "+--"
        b_indent = "    " if is_last_branch else "|   "

        print(f"{b_prefix} {branch['name']}")
        print(f"{b_indent}|")
        
        indicators = branch.get("indicators", [])
        for j, ind in enumerate(indicators):
            status = "[TRIGGERED]" if ind["triggered"] else "[NOT TRIGGERED]"
            print(f"{b_indent}+-- {ind['name']:<35} {status}")
        
        if not is_last_branch:
            print("|")

if __name__ == '__main__':
    print("Running attack_tree.py standalone validation tests...\n")

    # TEST 1: Baseline / Low activity
    res1 = evaluate_attack_tree(
        ml_anomaly=False,
        inbound_deviation=0.10,
        outbound_deviation=0.15,
        port_risk="LOW",
        process_name="python.exe",
        consecutive_anomalies=0
    )
    print("--- TEST 1: Baseline (Expected: 0 indicators triggered) ---")
    print("Triggered indicators:", res1["triggered_indicators"])
    assert len(res1["triggered_indicators"]) == 0
    assert not res1["branches"]["network_exposure"]["triggered"]
    assert not res1["branches"]["abnormal_behavior"]["triggered"]
    assert not res1["branches"]["suspicious_process"]["triggered"]
    print("TEST 1 PASSED.\n")

    # TEST 2: High anomaly / High risk
    res2 = evaluate_attack_tree(
        ml_anomaly=True,
        inbound_deviation=0.85,
        outbound_deviation=0.60,
        port_risk="HIGH",
        process_name="Unknown",
        consecutive_anomalies=3
    )
    print("--- TEST 2: High anomaly (Expected: All primary indicators triggered) ---")
    print("Triggered indicators:", res2["triggered_indicators"])
    assert res2["branches"]["network_exposure"]["triggered"]
    assert res2["branches"]["abnormal_behavior"]["triggered"]
    assert res2["branches"]["suspicious_process"]["triggered"]
    print_attack_tree(res2)
    print("\nTEST 2 PASSED.\n")

    # TEST 3: Threshold tests around 50% deviation (49.99%, 50.00%, 50.01%)
    print("--- TEST 3: Boundary threshold verification (49.99%, 50.00%, 50.01%) ---")
    t_below = evaluate_attack_tree(False, 0.4999, 0.0, "LOW", "proc", 0)
    assert not t_below["branches"]["abnormal_behavior"]["indicators"][1]["triggered"]

    t_exact = evaluate_attack_tree(False, 0.5000, 0.0, "LOW", "proc", 0)
    assert t_exact["branches"]["abnormal_behavior"]["indicators"][1]["triggered"]

    t_above = evaluate_attack_tree(False, 0.5001, 0.0, "LOW", "proc", 0)
    assert t_above["branches"]["abnormal_behavior"]["indicators"][1]["triggered"]
    print("Threshold tests (49.99% -> False, 50.00% -> True, 50.01% -> True) PASSED.\n")

    print("All attack_tree.py unit tests completed successfully!")
