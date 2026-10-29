#Module Import
import platform, os, socket, psutil, threading

#Variable Assignment
Platform = platform.system()
with open('WhitePorts.txt', 'r') as WhitelistedPortsFile:
    WhitelistedPortsList = [int(port.strip()) for port in WhitelistedPortsFile.readlines() if port.strip().isdigit()]

# Configurable Port Exposure Risk Mapping
PORT_EXPOSURE_RISK_MAP = {
    21: 'HIGH',      # FTP (cleartext)
    22: 'MEDIUM',    # SSH (remote administrative shell)
    23: 'HIGH',      # Telnet (cleartext remote shell)
    80: 'MEDIUM',    # HTTP (unencrypted web traffic)
    135: 'HIGH',     # MS RPC / EPMAP (frequently targeted)
    139: 'HIGH',     # NetBIOS Session Service
    443: 'LOW',      # HTTPS (standard encrypted web traffic)
    445: 'HIGH',     # SMB (frequently targeted for lateral movement)
    8080: 'MEDIUM',  # HTTP Alternate / Proxy
}

def get_port_exposure_risk(port: int) -> str:
    """
    Evaluates exposure risk tier for a given network port.
    Note: Indicates exposure risk, not confirmed vulnerability.
    """
    if port is None:
        return 'UNKNOWN'
    try:
        port_num = int(port)
        return PORT_EXPOSURE_RISK_MAP.get(port_num, 'MEDIUM')
    except (ValueError, TypeError):
        return 'UNKNOWN'

def get_port_process_info(port: int):
    """
    Safely correlates a local listening/active port to its owning PID and process name.
    Does NOT terminate or modify any processes.
    Returns: (pid, process_name) or (None, "Unknown")
    """
    if port is None:
        return (None, "Unknown")

    try:
        target_port = int(port)
    except (ValueError, TypeError):
        return (None, "Unknown")

    # Fast path: check current socket connections
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.laddr and conn.laddr.port == target_port:
                if conn.pid is not None and conn.pid > 0:
                    try:
                        proc = psutil.Process(conn.pid)
                        return (conn.pid, proc.name())
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        return (conn.pid, "Unknown")
    except (psutil.AccessDenied, psutil.Error):
        pass

    # Fallback path: iterate process table if net_connections was restricted
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            for conn in proc.connections(kind='inet'):
                if conn.laddr and conn.laddr.port == target_port:
                    return (proc.pid, proc.name())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue

    return (None, "Unknown")

def get_active_network_context():
    """
    Retrieves the most relevant active or established network connection context
    for real-time anomaly investigation.
    Prioritizes:
    1. Active ESTABLISHED non-localhost connections (with remote service port or local port)
    2. Any active ESTABLISHED connection
    3. Listening sockets with high exposure risk
    Returns dict: {'port': int or 'Unknown', 'pid': int or 'Unknown', 'process': str, 'port_risk': str}
    """
    default_context = {
        'port': 'Unknown',
        'pid': 'Unknown',
        'process': 'Unknown',
        'port_risk': 'Unknown'
    }

    try:
        conns = psutil.net_connections(kind='inet')
    except Exception:
        return default_context

    candidate = None

    # Priority 1: ESTABLISHED external connections
    for c in conns:
        if c.status == 'ESTABLISHED' and c.raddr:
            r_ip = c.raddr.ip if hasattr(c.raddr, 'ip') else c.raddr[0]
            if r_ip not in ('127.0.0.1', '::1', '0.0.0.0'):
                candidate = c
                break

    # Priority 2: Any ESTABLISHED connection
    if not candidate:
        for c in conns:
            if c.status == 'ESTABLISHED':
                candidate = c
                break

    # Priority 3: Any LISTEN socket
    if not candidate:
        for c in conns:
            if c.status == 'LISTEN':
                candidate = c
                break

    if not candidate:
        return default_context

    port = None
    if candidate.raddr and hasattr(candidate.raddr, 'port') and candidate.raddr.port:
        port = candidate.raddr.port
    elif candidate.laddr and hasattr(candidate.laddr, 'port') and candidate.laddr.port:
        port = candidate.laddr.port

    pid = candidate.pid if (candidate.pid and candidate.pid > 0) else None
    process_name = "Unknown"

    if pid:
        try:
            p = psutil.Process(pid)
            process_name = p.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            process_name = "Unknown"

    # If port has no process name, try fallback lookup
    if (not pid or process_name == "Unknown") and port:
        lookup_pid, lookup_proc = get_port_process_info(port)
        if lookup_pid:
            pid = lookup_pid
        if lookup_proc != "Unknown":
            process_name = lookup_proc

    port_risk = get_port_exposure_risk(port) if port else 'Unknown'

    return {
        'port': port if port is not None else 'Unknown',
        'pid': pid if pid is not None else 'Unknown',
        'process': process_name,
        'port_risk': port_risk
    }

#Function 1
def clear():
  if Platform == 'Linux' or Platform == 'Darwin':
    os.system("clear")

  elif Platform == 'Windows':
    os.system("cls")

#Function 2
OpenPorts = []
target = "127.0.0.1"
def singlePortScanner(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target, port))
        print(f"{port}")
        OpenPorts.append(port)
    except:
        pass

#Function 3
def multiPortScanner(startPort, endPort):
    threads = []
    for port in range(startPort, endPort):
        if port in WhitelistedPortsList:
            continue
        thread = threading.Thread(target=singlePortScanner, args=[port])
        thread.start()
        threads.append(thread)
    for t in threads:
        t.join()

#Function 4
def PortCloser(port):
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            for conns in proc.connections(kind='inet'):
                if conns.laddr.port == port:
                    print(f"Process {proc.name()} (PID {proc.pid}) is using port {port}")
                    proc.terminate()
                    print('Process terminated')
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass