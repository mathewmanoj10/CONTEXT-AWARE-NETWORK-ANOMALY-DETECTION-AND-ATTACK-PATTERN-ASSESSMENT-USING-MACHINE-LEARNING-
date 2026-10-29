"""
security_logger.py
Lightweight CSV-based security event logger for persistent alert recording.
"""

import os
import csv
from datetime import datetime

DEFAULT_LOG_FILE = 'security_events.csv'

# Fixed, deterministic CSV schema
CSV_HEADERS = [
    'timestamp',
    'severity',
    'risk_score',
    'ml_anomaly',
    'isolation_forest_score',
    'inbound_actual',
    'inbound_expected',
    'inbound_deviation',
    'outbound_actual',
    'outbound_expected',
    'outbound_deviation',
    'port',
    'port_risk',
    'pid',
    'process',
    'consecutive_anomalies',
    'reasons'
]

def log_security_event(event_data: dict, filepath: str = DEFAULT_LOG_FILE) -> bool:
    """
    Persistently logs a security event dictionary to security_events.csv.
    Gracefully handles missing files, header creation, and never raises
    unhandled exceptions that could crash the caller.
    """
    try:
        file_exists = os.path.exists(filepath)
        
        # Extract fields with safe formatting
        timestamp = event_data.get('timestamp') or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        severity = str(event_data.get('severity', 'UNKNOWN'))
        risk_score = event_data.get('risk_score', 0)
        ml_anomaly = 'YES' if event_data.get('ml_anomaly') else 'NO'
        
        iso_score = event_data.get('isolation_forest_score')
        iso_score_str = f"{float(iso_score):.4f}" if iso_score is not None else ""
        
        in_act = event_data.get('inbound_actual')
        in_act_str = f"{float(in_act):.2f}" if in_act is not None else ""
        
        in_exp = event_data.get('inbound_expected')
        in_exp_str = f"{float(in_exp):.2f}" if in_exp is not None else ""
        
        in_dev = event_data.get('inbound_deviation')
        in_dev_str = f"{float(in_dev) * 100:.2f}%" if in_dev is not None else ""
        
        out_act = event_data.get('outbound_actual')
        out_act_str = f"{float(out_act):.2f}" if out_act is not None else ""
        
        out_exp = event_data.get('outbound_expected')
        out_exp_str = f"{float(out_exp):.2f}" if out_exp is not None else ""
        
        out_dev = event_data.get('outbound_deviation')
        out_dev_str = f"{float(out_dev) * 100:.2f}%" if out_dev is not None else ""
        
        port = str(event_data.get('port', 'Unknown'))
        port_risk = str(event_data.get('port_risk', 'UNKNOWN'))
        pid = str(event_data.get('pid', 'Unknown'))
        process = str(event_data.get('process', 'Unknown'))
        consecutive_anomalies = event_data.get('consecutive_anomalies', 0)
        
        # Combine list of reasons into a single semicolon-separated string
        raw_reasons = event_data.get('reasons', [])
        if isinstance(raw_reasons, list):
            reasons_str = "; ".join(str(r) for r in raw_reasons)
        else:
            reasons_str = str(raw_reasons)

        row = [
            timestamp,
            severity,
            risk_score,
            ml_anomaly,
            iso_score_str,
            in_act_str,
            in_exp_str,
            in_dev_str,
            out_act_str,
            out_exp_str,
            out_dev_str,
            port,
            port_risk,
            pid,
            process,
            consecutive_anomalies,
            reasons_str
        ]

        with open(filepath, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if not file_exists or os.path.getsize(filepath) == 0:
                writer.writerow(CSV_HEADERS)
            writer.writerow(row)

        return True

    except Exception as e:
        print(f"[WARNING] Failed to write security event log: {e}")
        return False

def view_security_events(filepath: str = DEFAULT_LOG_FILE, max_events: int = 10) -> None:
    """
    Read-only viewer for recent security events from security_events.csv.
    Displays up to max_events recent entries in a clean, human-readable format.
    Does not use pandas.
    """
    if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
        print("\nNo security events recorded.")
        return

    try:
        events = []
        with open(filepath, mode='r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                events.append(row)

        if not events:
            print("\nNo security events recorded.")
            return

        recent_events = events[-max_events:]
        print(f"\n==================================================")
        print(f" SECURITY EVENT LOG (Most Recent {len(recent_events)} Events)")
        print(f"==================================================")

        for idx, ev in enumerate(recent_events, 1):
            print(f"\n[Event #{idx}] - {ev.get('timestamp', 'N/A')}")
            print(f"  Severity       : {ev.get('severity', 'UNKNOWN')}")
            print(f"  Risk Score     : {ev.get('risk_score', 'N/A')}/100")
            print(f"  ML Anomaly     : {ev.get('ml_anomaly', 'N/A')}")
            print(f"  Port           : {ev.get('port', 'Unknown')} (Risk: {ev.get('port_risk', 'UNKNOWN')})")
            print(f"  Process        : {ev.get('process', 'Unknown')} (PID: {ev.get('pid', 'Unknown')})")
            print(f"  Traffic        : In: {ev.get('inbound_actual', 'N/A')} Mbps | Out: {ev.get('outbound_actual', 'N/A')} Mbps")
            
            reasons = ev.get('reasons', '')
            if reasons:
                print("  Reasons        :")
                for r in reasons.split(';'):
                    if r.strip():
                        print(f"    - {r.strip()}")
            print("-" * 50)

    except Exception as e:
        print(f"[ERROR] Could not read security events file: {e}")

if __name__ == '__main__':
    # Direct test
    test_event = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'severity': 'CRITICAL',
        'risk_score': 100,
        'ml_anomaly': True,
        'isolation_forest_score': -0.6521,
        'inbound_actual': 12.50,
        'inbound_expected': 0.35,
        'inbound_deviation': 34.71,
        'outbound_actual': 8.20,
        'outbound_expected': 0.08,
        'outbound_deviation': 101.50,
        'port': 445,
        'port_risk': 'HIGH',
        'pid': 1234,
        'process': 'unknown_payload.exe',
        'consecutive_anomalies': 3,
        'reasons': [
            'ML traffic anomaly detected',
            'Port 445 has HIGH exposure risk',
            'Associated process could not be identified',
            'Anomaly persisted for 3 consecutive observations'
        ]
    }
    success = log_security_event(test_event, 'test_security_events.csv')
    print("Test log success:", success)
    view_security_events('test_security_events.csv')
    if os.path.exists('test_security_events.csv'):
        os.remove('test_security_events.csv')
