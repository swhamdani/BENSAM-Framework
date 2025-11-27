"""
bensam_integration.py
----------------------
Robust integration of BENSAM blockchain logging with Network Scanner.

- Dynamic import of BENSAM modules happens once.
- Parse ScanResult.txt safely and log to blockchain.
- Generate final JSON report.
"""

import os
import json
import importlib.util
import sys
import re
from datetime import datetime

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

BENSAM_PATH = r"D:\NetworkScanner\BENSAM-Framework"
bensam_collected_events = []  # global store of all scan events

# ---------------------------------------------------------------------------
# DYNAMIC MODULE LOADING
# ---------------------------------------------------------------------------

def load_module(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

try:
    audit = load_module("audit", os.path.join(BENSAM_PATH, "audit.py"))
    core_module = load_module("core", os.path.join(BENSAM_PATH, "core.py"))
    print("[BENSAM] Dynamic import successful: audit.py + core.py loaded.")
except Exception as e:
    print(f"[BENSAM] ERROR loading BENSAM modules: {e}")
    raise

# Initialize contract once
contract = audit.SmartContract()

# ---------------------------------------------------------------------------
# LOGGING FUNCTION
# ---------------------------------------------------------------------------

def log_scan_event(ip, status, ports=None, vulns=None):
    """
    Log a single host discovery result into the BENSAM ledger.
    """
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": ip,
        "status": status,
        "open_ports": ports if ports else [],
        "vulnerabilities": vulns if vulns else []
    }

    # Store in global list
    bensam_collected_events.append(event)

    # Safe blockchain logging
    try:
        audit.BlockchainAudit().log_event("HostScan", event)
    except Exception as e:
        print(f"[BENSAM] Blockchain logging failed for {ip}: {e}")

    return event

# ---------------------------------------------------------------------------
# SCANRESULT.TXT PARSER
# ---------------------------------------------------------------------------

def parse_scan_result(scan_file_path):
    """
    Parse ScanResult.txt and log all hosts to BENSAM safely.
    Deduplicates entries per host/IP.
    """

    if not os.path.exists(scan_file_path):
        print(f"[BENSAM] ScanResult.txt not found: {scan_file_path}")
        return

    print(f"[BENSAM] Parsing ScanResult.txt ...")

    hosts = {}
    current_ip = None
    current_ports = []
    current_vulns = []
    inside_host_script_block = False

    def flush_host():
        nonlocal current_ip, current_ports, current_vulns
        if not current_ip:
            return

        if current_ip not in hosts:
            hosts[current_ip] = {
                "status": "up",
                "open_ports": current_ports.copy(),
                "vulnerabilities": current_vulns.copy()
            }
        else:
            # merge lists without duplicates
            hosts[current_ip]["open_ports"].extend(
                p for p in current_ports if p not in hosts[current_ip]["open_ports"]
            )
            hosts[current_ip]["vulnerabilities"].extend(
                v for v in current_vulns if v not in hosts[current_ip]["vulnerabilities"]
            )

        current_ip = None
        current_ports.clear()
        current_vulns.clear()

    try:
        with open(scan_file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip().replace("\x00", "") for line in f]

        for line in lines:
            if line.startswith("Nmap scan report for"):
                flush_host()
                current_ip = line.split()[-1]
                continue

            # Ports
            if re.search(r"/tcp\s+open", line):
                current_ports.append(line)
                continue

            # Host script results
            if line.startswith("Host script results"):
                inside_host_script_block = True
                continue

            if inside_host_script_block:
                if line.startswith("|_"):
                    current_vulns.append(line[2:].strip())
                else:
                    inside_host_script_block = False
                continue

            if "CVE-" in line:
                current_vulns.append(line.strip())
                continue

        flush_host()

        # Log hosts safely
        for ip, info in hosts.items():
            try:
                log_scan_event(
                    ip,
                    info.get("status", "up"),
                    ports=info.get("open_ports", []),
                    vulns=info.get("vulnerabilities", [])
                )
                print(f"[Blockchain Log] HostScan: {ip} logged")
            except Exception as e:
                print(f"[BENSAM] Failed to log host {ip}: {e}")

        print(f"[BENSAM] Parsing complete. Hosts logged: {len(hosts)}")
    except Exception as e:
        print(f"[BENSAM] Error parsing ScanResult.txt: {e}")

# ---------------------------------------------------------------------------
# FINAL REPORT GENERATION
# ---------------------------------------------------------------------------

def finalize_bensam(output_folder="output"):
    """
    Generate final JSON report from collected events.
    """
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    filename = f"bensam_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    output_path = os.path.join(output_folder, filename)

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "entries": bensam_collected_events
                },
                f,
                indent=4
            )
        print(f"[BENSAM] Report written successfully → {output_path}")
    except Exception as e:
        print(f"[BENSAM] Failed to write report: {e}")

    return output_path
