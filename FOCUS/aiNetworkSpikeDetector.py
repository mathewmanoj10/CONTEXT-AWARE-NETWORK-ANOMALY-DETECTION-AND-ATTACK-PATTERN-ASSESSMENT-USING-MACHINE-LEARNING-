import psutil, time, joblib, subprocess, os, sys
import pandas as pd
from colorama import Fore, Style, init
from functions import clear, get_active_network_context, get_port_exposure_risk, get_port_process_info
from isolationForestModel import extract_single_feature_vector
from risk_engine import calculate_risk
from security_logger import log_security_event
from attack_tree import evaluate_attack_tree
from attack_pattern_assessor import assess_attack_pattern

# Initialize colorama
init(autoreset=True)

def load_rf_model(filepath):
    """
    Loads a Random Forest model and ensures cross-version compatibility
    with scikit-learn without re-training or modifying files on disk.
    """
    model = joblib.load(filepath)
    if hasattr(model, 'estimators_'):
        for est in model.estimators_:
            if not hasattr(est, 'monotonic_cst'):
                setattr(est, 'monotonic_cst', None)
    return model

# Load existing Random Forest models
try:
    inboundModel = load_rf_model('inboundModel.joblib')
    outboundModel = load_rf_model('outboundModel.joblib')
except Exception as e:
    print(f"{Fore.RED}Error loading Random Forest models: {e}{Fore.RESET}")
    print("Ensure 'inboundModel.joblib' and 'outboundModel.joblib' exist in the current directory.")
    sys.exit(1)

# Load Isolation Forest model
iso_forest_path = 'isolationForestModel.joblib'
if not os.path.exists(iso_forest_path):
    print(f"{Fore.RED}Isolation Forest model not found at '{iso_forest_path}'.{Fore.RESET}")
    print(f"{Fore.YELLOW}Please run: python isolationForestModel.py to train and save the model.{Fore.RESET}")
    sys.exit(1)

try:
    isolationForestModel = joblib.load(iso_forest_path)
except Exception as e:
    print(f"{Fore.RED}Error loading Isolation Forest model: {e}{Fore.RESET}")
    print("Please run: python isolationForestModel.py to regenerate it.")
    sys.exit(1)

# Function to get the current network I/O
def get_network_data():
    net_io = psutil.net_io_counters()
    return net_io.bytes_recv, net_io.bytes_sent

# Convert bytes to megabits per second and round to 2 decimal places
def bytes_to_mbps(bytes_value):
    kb_value = bytes_value / 1024  # Convert bytes to kilobytes
    mbps_value = (kb_value * 8) / 1000  # Convert kilobytes to Mbps
    return round(mbps_value, 2)

# Calculate normalized deviation: abs(actual - predicted) / max(abs(predicted), epsilon)
def calculate_deviation(actual, predicted, epsilon=1e-4):
    pred_val = float(predicted)
    denom = max(abs(pred_val), epsilon)
    return abs(float(actual) - pred_val) / denom

def run_monitor(max_iterations=None, sleep_interval=1.0, simulate_anomaly=False):
    start_time = time.time()
    prev_inbound, prev_outbound = get_network_data()
    spikesDetected = 0
    iteration = 0

    try:
        while True:
            time.sleep(sleep_interval)

            # Get current time and network data
            current_time = time.time()
            elapsed_time = int(current_time - start_time)
            input_data = pd.DataFrame([[max(0, elapsed_time - 1)]], columns=["elapsed_time"])

            current_inbound, current_outbound = get_network_data()

            # Calculate inbound and outbound speeds (Mbps)
            inbound_speed = bytes_to_mbps(current_inbound - prev_inbound)
            outbound_speed = bytes_to_mbps(current_outbound - prev_outbound)

            # Random Forest predictions
            inboundPrediction = float(inboundModel.predict(input_data)[0])
            outboundPrediction = float(outboundModel.predict(input_data)[0])

            # Calculate normalized deviations
            inbound_dev = calculate_deviation(inbound_speed, inboundPrediction)
            outbound_dev = calculate_deviation(outbound_speed, outboundPrediction)

            # Isolation Forest anomaly detection
            iso_features = extract_single_feature_vector(inbound_speed, outbound_speed)
            iso_pred = isolationForestModel.predict(iso_features)[0]  # 1 for normal, -1 for anomaly
            iso_score = float(isolationForestModel.score_samples(iso_features)[0])  # Lower score indicates anomaly

            # Anomaly evaluation
            is_anomaly = (iso_pred == -1) or simulate_anomaly

            # Track consecutive anomalies for persistence evaluation in risk engine
            if is_anomaly:
                spikesDetected += 1
            else:
                spikesDetected = 0

            # Update previous values for next iteration
            prev_inbound, prev_outbound = current_inbound, current_outbound

            if is_anomaly:
                clear()
                # Correlate network context when anomaly occurs
                net_context = get_active_network_context()

                # Attack Pattern Assessment (Explainable heuristic)
                pattern_assessment = assess_attack_pattern(
                    ml_anomaly=True,
                    inbound_deviation=inbound_dev,
                    outbound_deviation=outbound_dev,
                    port_risk=net_context.get('port_risk', 'UNKNOWN'),
                    process_name=net_context.get('process', 'Unknown'),
                    consecutive_anomalies=spikesDetected
                )

                # Call the risk engine (Single Source of Truth)
                risk_assessment = calculate_risk(
                    ml_anomaly=True,
                    inbound_deviation=inbound_dev,
                    outbound_deviation=outbound_dev,
                    port_risk=net_context.get('port_risk', 'UNKNOWN'),
                    process_name=net_context.get('process', 'Unknown'),
                    consecutive_anomalies=spikesDetected,
                    port=net_context.get('port')
                )

                # Evaluate lightweight Attack Tree representation
                attack_tree_eval = evaluate_attack_tree(
                    ml_anomaly=True,
                    inbound_deviation=inbound_dev,
                    outbound_deviation=outbound_dev,
                    port_risk=net_context.get('port_risk', 'UNKNOWN'),
                    process_name=net_context.get('process', 'Unknown'),
                    consecutive_anomalies=spikesDetected
                )

                sev = risk_assessment['severity']
                sev_color = Fore.RED if sev in ('HIGH', 'CRITICAL') else Fore.YELLOW

                # Display the Network Security Alert
                print(f"{Fore.RED}--------------------------------------------------{Fore.RESET}")
                print(f"{Fore.LIGHTRED_EX}NETWORK SECURITY ALERT{Fore.RESET} (Elapsed: {elapsed_time}s)")
                print(f"{Fore.RED}--------------------------------------------------{Fore.RESET}")
                print(f"ML Anomaly       : {Fore.RED}YES{Fore.RESET}\n")

                print(f"{Fore.LIGHTBLUE_EX}Inbound:{Fore.RESET}")
                print(f"  Actual         : {inbound_speed:.2f} Mbps")
                print(f"  Expected       : {inboundPrediction:.2f} Mbps")
                print(f"  Deviation      : {inbound_dev * 100:.2f}%\n")

                print(f"{Fore.LIGHTMAGENTA_EX}Outbound:{Fore.RESET}")
                print(f"  Actual         : {outbound_speed:.2f} Mbps")
                print(f"  Expected       : {outboundPrediction:.2f} Mbps")
                print(f"  Deviation      : {outbound_dev * 100:.2f}%\n")

                print(f"{Fore.LIGHTYELLOW_EX}Isolation Forest:{Fore.RESET}")
                print(f"  Status         : {Fore.RED}ANOMALY{Fore.RESET}")
                print(f"  Score          : {iso_score:.4f}\n")

                print(f"{Fore.LIGHTCYAN_EX}Network Context:{Fore.RESET}")
                print(f"  Port           : {net_context['port']}")
                print(f"  PID            : {net_context['pid']}")
                print(f"  Process        : {net_context['process']}")
                print(f"  Port Risk      : {net_context['port_risk']}\n")

                # Attack Pattern Assessment Display
                print(f"{Fore.LIGHTCYAN_EX}Attack Pattern Assessment (Explainable):{Fore.RESET}")
                print(f"Possible Attack Pattern:\n  {pattern_assessment['pattern']}")
                print(f"Evidence Level:\n  {pattern_assessment['evidence_level']}")
                print(f"Evidence:")
                if pattern_assessment['matched_conditions']:
                    for cond in pattern_assessment['matched_conditions']:
                        print(f"  - {cond}")
                else:
                    print("  - None")
                print(f"Explanation:\n  {pattern_assessment['explanation']}\n")

                print(f"{Fore.LIGHTGREEN_EX}Risk Assessment (Context-aware heuristic):{Fore.RESET}")
                print(f"  Score          : {risk_assessment['score']}/100")
                print(f"  Severity       : {sev_color}{sev}{Fore.RESET}\n")

                print(f"{Fore.WHITE}Reasons:{Fore.RESET}")
                if risk_assessment['reasons']:
                    for r in risk_assessment['reasons']:
                        print(f"  - {r}")
                else:
                    print("  - None")
                print("")

                # Concise Attack Tree Indicators summary
                at_branches = attack_tree_eval.get("branches", {})
                print(f"{Fore.LIGHTYELLOW_EX}Attack Tree Indicators (Analytical):{Fore.RESET}")
                for b_key, b_info in at_branches.items():
                    status_text = f"{Fore.RED}TRIGGERED{Fore.RESET}" if b_info["triggered"] else f"{Fore.GREEN}NOT TRIGGERED{Fore.RESET}"
                    print(f"  {b_info['name']:<30}: {status_text}")
                print(f"{Fore.RED}--------------------------------------------------{Fore.RESET}")

                # Build explainable reasons combining risk breakdown and attack pattern
                event_reasons = list(risk_assessment['reasons'])
                if pattern_assessment.get('pattern'):
                    event_reasons.append(f"possible_pattern={pattern_assessment['pattern']}")
                    evidence_conditions = [
                        c for c in pattern_assessment.get('matched_conditions', [])
                        if not c.startswith("Co-occurring")
                    ]
                    evidence_str = " + ".join(evidence_conditions) if evidence_conditions else "unclassified"
                    event_reasons.append(f"evidence={evidence_str}")
                    if pattern_assessment.get('additional_patterns'):
                        event_reasons.append(f"additional_patterns={', '.join(pattern_assessment['additional_patterns'])}")

                # Persistently log the alert to security_events.csv
                event_data = {
                    'severity': sev,
                    'risk_score': risk_assessment['score'],
                    'ml_anomaly': True,
                    'isolation_forest_score': iso_score,
                    'inbound_actual': inbound_speed,
                    'inbound_expected': inboundPrediction,
                    'inbound_deviation': inbound_dev,
                    'outbound_actual': outbound_speed,
                    'outbound_expected': outboundPrediction,
                    'outbound_deviation': outbound_dev,
                    'port': net_context.get('port', 'Unknown'),
                    'port_risk': net_context.get('port_risk', 'UNKNOWN'),
                    'pid': net_context.get('pid', 'Unknown'),
                    'process': net_context.get('process', 'Unknown'),
                    'consecutive_anomalies': spikesDetected,
                    'reasons': event_reasons
                }
                log_security_event(event_data)

            else:
                # Concise single-line output for normal traffic (no event logging)
                print(f"[MONITOR] Traffic normal | In: {inbound_speed:.2f} Mbps | Out: {outbound_speed:.2f} Mbps | Elapsed: {elapsed_time}s")

            iteration += 1
            if max_iterations is not None and iteration >= max_iterations:
                break

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

if __name__ == '__main__':
    run_monitor()