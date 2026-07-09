import os
import json
import time
import psutil
from datetime import datetime

BASELINE_FILE = "baseline.json"
LOG_FILE = "jinda_siem.log"

def load_baseline() -> dict:
    """Reads our golden baseline configuration file."""
    try:
        with open(BASELINE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        # Safe fallback if file is missing or corrupted
        return {"authorized_ports": [8000, 22], "authorized_executables": []}

def write_siem_log(severity: str, event_id: str, port: int, pid: int, action: str):
    """Writes standardized, SIEM-ready log strings to our flat file."""
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    log_line = f"{timestamp} | {severity} | {event_id} | Port:{port} | PID:{pid} | Action:{action}\n"
    
    with open(LOG_FILE, "a") as f:
        f.write(log_line)

def scan_and_enforce() -> list:
    """
    Scans the Ubuntu kernel network tables, verifies active listening sockets 
    against the baseline, terminates non-compliant processes, and logs alerts.
    """
    baseline = load_baseline()
    alerts_triggered = []
    
    # Query the kernel for all active IPv4/IPv6 listening sockets
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == psutil.CONN_LISTEN:
            port = conn.laddr.port
            pid = conn.pid
            
            # If a socket is listening but has no bound PID (rare kernel state), skip it
            if not pid:
                continue
                
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                
                # EVALUATION MATRIX: Check if port or executable violates our baseline
                if port not in baseline["authorized_ports"] or proc_name not in baseline["authorized_executables"]:
                    
                    # 1. Compile the Alert Threat Data
                    alert_entry = {
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "port": port,
                        "pid": pid,
                        "proc_name": proc_name,
                        "status": "TERMINATED_BY_EDR"
                    }
                    alerts_triggered.append(alert_entry)
                    
                    # 2. Emit the SIEM Compliance Log Block
                    write_siem_log(
                        severity="CRITICAL", 
                        event_id="EVNT_042", 
                        port=port, 
                        pid=pid, 
                        action="TERMINATED_NON_COMPLIANT_PROCESS"
                    )
                    
                    # 3. KERNEL ENFORCEMENT: Kill the malicious process instantly
                    proc.terminate() 
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Handle processes that close out on their own before we can evaluate them
                continue
                
    return alerts_triggered