"""
test_attack_pattern_assessor.py
Focused unit tests for condition-based attack pattern assessment.

Tests:
1. Normal traffic -> no attack pattern
2. ML anomaly + inbound deviation >= 50% + persistence >= 3 -> Possible DoS/DDoS-like Traffic Surge
3. ML anomaly + outbound deviation >= 50% + persistence >= 3 -> Possible Unusual Outbound Transfer
4. ML anomaly + HIGH port risk + Unknown process -> Possible Suspicious Network Service Activity
5. Multiple matching conditions -> primary + additional evidence handled correctly
6. ML anomaly with insufficient evidence -> Unclassified Network Anomaly
7. Boundary checks: 49.99% vs 50.00% deviation, persistence 2 vs 3
"""

import unittest
from attack_pattern_assessor import (
    assess_attack_pattern,
    PATTERN_DOS_DDOS,
    PATTERN_UNUSUAL_OUTBOUND,
    PATTERN_SUSPICIOUS_SERVICE,
    PATTERN_UNCLASSIFIED,
    EXPLANATION_DOS_DDOS,
    EXPLANATION_UNUSUAL_OUTBOUND,
    EXPLANATION_SUSPICIOUS_SERVICE,
    EXPLANATION_UNCLASSIFIED,
    EXPLANATION_NORMAL,
)


class TestAttackPatternAssessor(unittest.TestCase):

    # 1. Normal traffic -> no attack pattern
    def test_normal_traffic(self):
        result = assess_attack_pattern(
            ml_anomaly=False,
            inbound_deviation=0.15,
            outbound_deviation=0.10,
            port_risk="LOW",
            process_name="python.exe",
            consecutive_anomalies=0
        )
        self.assertFalse(result["matched"])
        self.assertIsNone(result["pattern"])
        self.assertEqual(result["evidence_level"], "LOW")
        self.assertEqual(result["matched_conditions"], [])
        self.assertEqual(result["explanation"], EXPLANATION_NORMAL)
        self.assertEqual(result["additional_patterns"], [])

    # 2. ML anomaly + inbound deviation >= 50% + persistence >= 3 -> Possible DoS/DDoS-like Traffic Surge
    def test_dos_ddos_surge(self):
        result = assess_attack_pattern(
            ml_anomaly=True,
            inbound_deviation=0.75,  # 75% deviation
            outbound_deviation=0.10,
            port_risk="LOW",
            process_name="python.exe",
            consecutive_anomalies=3
        )
        self.assertTrue(result["matched"])
        self.assertEqual(result["pattern"], PATTERN_DOS_DDOS)
        self.assertEqual(result["evidence_level"], "MEDIUM")
        self.assertEqual(result["explanation"], EXPLANATION_DOS_DDOS)
        self.assertIn("ML traffic anomaly detected", result["matched_conditions"])
        self.assertTrue(any("inbound deviation" in c.lower() for c in result["matched_conditions"]))
        self.assertTrue(any("persistent anomaly" in c.lower() for c in result["matched_conditions"]))
        self.assertEqual(result["additional_patterns"], [])

    # 3. ML anomaly + outbound deviation >= 50% + persistence >= 3 -> Possible Unusual Outbound Transfer
    def test_unusual_outbound_transfer(self):
        result = assess_attack_pattern(
            ml_anomaly=True,
            inbound_deviation=0.10,
            outbound_deviation=0.85,  # 85% deviation
            port_risk="LOW",
            process_name="python.exe",
            consecutive_anomalies=4
        )
        self.assertTrue(result["matched"])
        self.assertEqual(result["pattern"], PATTERN_UNUSUAL_OUTBOUND)
        self.assertEqual(result["evidence_level"], "MEDIUM")
        self.assertEqual(result["explanation"], EXPLANATION_UNUSUAL_OUTBOUND)
        self.assertIn("ML traffic anomaly detected", result["matched_conditions"])
        self.assertTrue(any("outbound deviation" in c.lower() for c in result["matched_conditions"]))
        self.assertTrue(any("persistent anomaly" in c.lower() for c in result["matched_conditions"]))
        self.assertEqual(result["additional_patterns"], [])

    # 4. ML anomaly + HIGH port risk + Unknown process -> Possible Suspicious Network Service Activity
    def test_suspicious_network_service_activity(self):
        # Case 4a: process_name = "Unknown"
        result_unknown = assess_attack_pattern(
            ml_anomaly=True,
            inbound_deviation=0.20,
            outbound_deviation=0.20,
            port_risk="HIGH",
            process_name="Unknown",
            consecutive_anomalies=1
        )
        self.assertTrue(result_unknown["matched"])
        self.assertEqual(result_unknown["pattern"], PATTERN_SUSPICIOUS_SERVICE)
        self.assertEqual(result_unknown["evidence_level"], "MEDIUM")
        self.assertEqual(result_unknown["explanation"], EXPLANATION_SUSPICIOUS_SERVICE)
        self.assertIn("ML traffic anomaly detected", result_unknown["matched_conditions"])
        self.assertTrue(any("high port exposure risk" in c.lower() for c in result_unknown["matched_conditions"]))
        self.assertTrue(any("unidentified" in c.lower() for c in result_unknown["matched_conditions"]))

        # Case 4b: process_name = None
        result_none = assess_attack_pattern(
            ml_anomaly=True,
            inbound_deviation=0.20,
            outbound_deviation=0.20,
            port_risk="HIGH",
            process_name=None,
            consecutive_anomalies=1
        )
        self.assertTrue(result_none["matched"])
        self.assertEqual(result_none["pattern"], PATTERN_SUSPICIOUS_SERVICE)

    # 5. Multiple matching conditions -> primary + additional evidence handled correctly
    def test_multiple_matching_conditions(self):
        # Case 5a: DoS Surge (Rule 1) + Suspicious Service (Rule 3)
        res_r1_r3 = assess_attack_pattern(
            ml_anomaly=True,
            inbound_deviation=0.90,
            outbound_deviation=0.10,
            port_risk="HIGH",
            process_name="Unknown",
            consecutive_anomalies=3
        )
        self.assertTrue(res_r1_r3["matched"])
        self.assertEqual(res_r1_r3["pattern"], PATTERN_DOS_DDOS)
        self.assertEqual(res_r1_r3["evidence_level"], "HIGH")
        self.assertIn(PATTERN_SUSPICIOUS_SERVICE, res_r1_r3["additional_patterns"])
        # All conditions preserved
        conditions_text = " ".join(res_r1_r3["matched_conditions"]).lower()
        self.assertIn("inbound deviation", conditions_text)
        self.assertIn("persistent anomaly", conditions_text)
        self.assertIn("high port exposure risk", conditions_text)
        self.assertIn("unidentified", conditions_text)

        # Case 5b: Outbound Transfer (Rule 2) + Suspicious Service (Rule 3)
        res_r2_r3 = assess_attack_pattern(
            ml_anomaly=True,
            inbound_deviation=0.10,
            outbound_deviation=0.90,
            port_risk="HIGH",
            process_name="None",
            consecutive_anomalies=3
        )
        self.assertTrue(res_r2_r3["matched"])
        self.assertEqual(res_r2_r3["pattern"], PATTERN_UNUSUAL_OUTBOUND)
        self.assertEqual(res_r2_r3["evidence_level"], "HIGH")
        self.assertIn(PATTERN_SUSPICIOUS_SERVICE, res_r2_r3["additional_patterns"])

        # Case 5c: Both Inbound and Outbound surges (Rule 1 + Rule 2)
        res_both_surges = assess_attack_pattern(
            ml_anomaly=True,
            inbound_deviation=1.20,
            outbound_deviation=0.60,
            port_risk="LOW",
            process_name="app.exe",
            consecutive_anomalies=3
        )
        self.assertTrue(res_both_surges["matched"])
        self.assertEqual(res_both_surges["pattern"], PATTERN_DOS_DDOS)
        self.assertEqual(res_both_surges["evidence_level"], "HIGH")
        self.assertIn(PATTERN_UNUSUAL_OUTBOUND, res_both_surges["additional_patterns"])

    # 6. ML anomaly with insufficient evidence -> Unclassified Network Anomaly
    def test_unclassified_network_anomaly(self):
        result = assess_attack_pattern(
            ml_anomaly=True,
            inbound_deviation=0.25,  # < 50%
            outbound_deviation=0.15,  # < 50%
            port_risk="MEDIUM",       # Not HIGH
            process_name="python.exe", # Known process
            consecutive_anomalies=1   # < 3
        )
        self.assertFalse(result["matched"])
        self.assertEqual(result["pattern"], PATTERN_UNCLASSIFIED)
        self.assertEqual(result["evidence_level"], "LOW")
        self.assertEqual(result["explanation"], EXPLANATION_UNCLASSIFIED)
        self.assertIn("ML traffic anomaly detected", result["matched_conditions"])
        self.assertEqual(result["additional_patterns"], [])

    # 7. Boundary checks: 49.99% -> should NOT satisfy 50% rule, 50.00% -> SHOULD satisfy 50% rule
    def test_boundary_checks(self):
        # 49.99% inbound deviation should NOT satisfy Rule 1
        res_below = assess_attack_pattern(
            ml_anomaly=True,
            inbound_deviation=0.4999,
            outbound_deviation=0.0,
            port_risk="LOW",
            process_name="python.exe",
            consecutive_anomalies=3
        )
        self.assertFalse(res_below["matched"])
        self.assertEqual(res_below["pattern"], PATTERN_UNCLASSIFIED)

        # 50.00% inbound deviation SHOULD satisfy Rule 1
        res_exact = assess_attack_pattern(
            ml_anomaly=True,
            inbound_deviation=0.5000,
            outbound_deviation=0.0,
            port_risk="LOW",
            process_name="python.exe",
            consecutive_anomalies=3
        )
        self.assertTrue(res_exact["matched"])
        self.assertEqual(res_exact["pattern"], PATTERN_DOS_DDOS)

        # 50.01% inbound deviation SHOULD satisfy Rule 1
        res_above = assess_attack_pattern(
            ml_anomaly=True,
            inbound_deviation=0.5001,
            outbound_deviation=0.0,
            port_risk="LOW",
            process_name="python.exe",
            consecutive_anomalies=3
        )
        self.assertTrue(res_above["matched"])
        self.assertEqual(res_above["pattern"], PATTERN_DOS_DDOS)

        # Outbound boundary: 49.99% vs 50.00%
        res_out_below = assess_attack_pattern(
            ml_anomaly=True,
            inbound_deviation=0.0,
            outbound_deviation=0.4999,
            port_risk="LOW",
            process_name="python.exe",
            consecutive_anomalies=3
        )
        self.assertFalse(res_out_below["matched"])
        self.assertEqual(res_out_below["pattern"], PATTERN_UNCLASSIFIED)

        res_out_exact = assess_attack_pattern(
            ml_anomaly=True,
            inbound_deviation=0.0,
            outbound_deviation=0.5000,
            port_risk="LOW",
            process_name="python.exe",
            consecutive_anomalies=3
        )
        self.assertTrue(res_out_exact["matched"])
        self.assertEqual(res_out_exact["pattern"], PATTERN_UNUSUAL_OUTBOUND)

        # Persistence boundary: consecutive_anomalies = 2 vs 3
        res_persist_below = assess_attack_pattern(
            ml_anomaly=True,
            inbound_deviation=0.60,
            outbound_deviation=0.0,
            port_risk="LOW",
            process_name="python.exe",
            consecutive_anomalies=2  # Below 3
        )
        self.assertFalse(res_persist_below["matched"])
        self.assertEqual(res_persist_below["pattern"], PATTERN_UNCLASSIFIED)

        res_persist_exact = assess_attack_pattern(
            ml_anomaly=True,
            inbound_deviation=0.60,
            outbound_deviation=0.0,
            port_risk="LOW",
            process_name="python.exe",
            consecutive_anomalies=3  # Exact 3
        )
        self.assertTrue(res_persist_exact["matched"])
        self.assertEqual(res_persist_exact["pattern"], PATTERN_DOS_DDOS)

        # Known process should NOT satisfy Rule 3 even with HIGH port risk
        res_known_proc = assess_attack_pattern(
            ml_anomaly=True,
            inbound_deviation=0.10,
            outbound_deviation=0.10,
            port_risk="HIGH",
            process_name="trusted_service.exe",
            consecutive_anomalies=1
        )
        self.assertFalse(res_known_proc["matched"])
        self.assertEqual(res_known_proc["pattern"], PATTERN_UNCLASSIFIED)

        # MEDIUM port risk should NOT satisfy Rule 3 even with Unknown process
        res_med_port = assess_attack_pattern(
            ml_anomaly=True,
            inbound_deviation=0.10,
            outbound_deviation=0.10,
            port_risk="MEDIUM",
            process_name="Unknown",
            consecutive_anomalies=1
        )
        self.assertFalse(res_med_port["matched"])
        self.assertEqual(res_med_port["pattern"], PATTERN_UNCLASSIFIED)


if __name__ == '__main__':
    unittest.main(verbosity=2)
