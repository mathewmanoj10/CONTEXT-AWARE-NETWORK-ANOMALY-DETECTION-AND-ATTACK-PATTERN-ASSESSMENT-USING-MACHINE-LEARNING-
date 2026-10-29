import sys
import os
import platform
import socket
import time
import subprocess
import psutil
from colorama import Fore, Style, init

from functions import clear, multiPortScanner, OpenPorts, WhitelistedPortsList
from security_logger import view_security_events

# Initialize colorama
init(autoreset=True)

def show_header():
    clear()
    print("==================================================")
    print("           NETWORK SECURITY MONITOR               ")
    print("     Context-Aware ML Security Assessment         ")
    print("==================================================")

def show_menu():
    print("")
    print("1. Port Scanner")
    print("2. ML Network Anomaly Monitor")
    print("3. View Security Event Log")
    print("4. System Information")
    print("0. Exit")
    print("")

def display_system_info():
    """
    Displays local, non-sensitive system summary using psutil and platform.
    """
    print("\n==================================================")
    print(" SYSTEM INFORMATION")
    print("==================================================")
    try:
        os_name = f"{platform.system()} {platform.release()} (Version: {platform.version()})"
        cpu_count = psutil.cpu_count(logical=True)
        ram_bytes = psutil.virtual_memory().total
        ram_gb = ram_bytes / (1024 ** 3)
        hostname = socket.gethostname()

        print(f"  Operating System : {os_name}")
        print(f"  Hostname         : {hostname}")
        print(f"  CPU Cores (Logical): {cpu_count}")
        print(f"  Total RAM        : {ram_gb:.2f} GB")
    except Exception as e:
        print(f"  [ERROR] Could not retrieve full system information: {e}")
    print("==================================================")

def run_port_scanner():
    """
    Runs the existing multi-threaded port scanner across ports 1-65535,
    honoring WhitePorts.txt without destructive process killing.
    """
    print("\n==================================================")
    print(" PORT SCANNER")
    print("==================================================")
    print("Starting multi-threaded port scan (1 to 65535)...")
    print("Note: Ports in WhitePorts.txt are excluded from scan.")
    
    OpenPorts.clear()
    start_t = time.time()
    try:
        multiPortScanner(1, 65536)
        end_t = time.time()

        print("\nScan Complete!")
        print(f"Time Elapsed: {end_t - start_t:.2f} seconds")
        if len(OpenPorts) == 0:
            print("No open ports detected.")
        else:
            print(f"Open Ports Detected ({len(OpenPorts)}):")
            for p in sorted(set(OpenPorts)):
                print(f"  - Port {p}")
    except KeyboardInterrupt:
        print("\n[INFO] Port scan cancelled by user.")
    except Exception as e:
        print(f"\n[ERROR] Port scan encountered an issue: {e}")

def run_ml_monitor():
    """
    Launches aiNetworkSpikeDetector.py safely and returns gracefully on Ctrl+C.
    """
    print("\n==================================================")
    print(" ML NETWORK ANOMALY MONITOR")
    print("==================================================")
    print("Initializing ML models and telemetry...")
    print("Press Ctrl+C at any time to stop monitoring and return to menu.\n")

    # Verify model files exist before launching
    required_models = ['inboundModel.joblib', 'outboundModel.joblib', 'isolationForestModel.joblib']
    missing_models = [m for m in required_models if not os.path.exists(m)]
    if missing_models:
        print(f"[ERROR] Required ML model files are missing: {', '.join(missing_models)}")
        if 'isolationForestModel.joblib' in missing_models:
            print("[INFO] Please run 'python isolationForestModel.py' to generate the Isolation Forest model.")
        return

    try:
        # Launch using Python interpreter subprocess
        subprocess.run([sys.executable, 'aiNetworkSpikeDetector.py'])
    except KeyboardInterrupt:
        print("\n[INFO] Network monitoring stopped by user.")
    except Exception as e:
        print(f"\n[ERROR] An error occurred while running the ML monitor: {e}")

def main():
    while True:
        try:
            show_header()
            show_menu()
            choice = input("Enter your choice: ").strip()

            if choice == '1':
                run_port_scanner()
                input("\nHit Enter to return to main menu...")
            elif choice == '2':
                run_ml_monitor()
                input("\nHit Enter to return to main menu...")
            elif choice == '3':
                view_security_events()
                input("\nHit Enter to return to main menu...")
            elif choice == '4':
                display_system_info()
                input("\nHit Enter to return to main menu...")
            elif choice == '0':
                print("\nExiting Network Security Monitor. Goodbye!")
                break
            else:
                print("\n[WARNING] Invalid choice. Please enter a valid menu option (0-4).")
                input("Hit Enter to continue...")

        except KeyboardInterrupt:
            print("\n\n[INFO] Session interrupted by user. Exiting cleanly.")
            break
        except Exception as e:
            print(f"\n[ERROR] An unexpected error occurred: {e}")
            input("Hit Enter to continue...")

if __name__ == '__main__':
    main()