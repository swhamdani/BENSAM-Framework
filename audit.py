"""
audit.py
─────────────────────────────────────────────────────────────────────────────
Concrete implementations for Phase 1 of BENSAM Framework.

"""

import hashlib
import json
import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional
from BENSAM_Framework.utils import is_internal_ip
from BENSAM_Framework.interfaces import IBlockchainLogger, IDatabase


# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────

_HERE = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(_HERE, "data")
os.makedirs(_DATA_DIR, exist_ok=True)

_DEVICES_FILE    = os.path.join(_DATA_DIR, "devices.json")
_LOGS_FILE       = os.path.join(_DATA_DIR, "traffic_logs.json")
_VIOLATIONS_FILE = os.path.join(_DATA_DIR, "violations.json")
_PAYLOADS_DIR    = os.path.join(_DATA_DIR, "payloads")
_LEDGER_FILE     = os.path.join(_DATA_DIR, "simulated_ledger.json")
_POLICY_FILE     = os.path.join(_HERE, "policy_rules.json")

os.makedirs(_PAYLOADS_DIR, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _read_json(path: str, default):
    """Read a JSON file, return default if missing or corrupt."""
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        print(f"[BENSAM][DB] Warning: could not read {path}: {e}")
    return default


def _write_json(path: str, data) -> None:
    """Write data to a JSON file atomically (write to temp then rename)."""
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, default=str)
        os.replace(tmp, path)
    except Exception as e:
        print(f"[BENSAM][DB] Warning: could not write {path}: {e}")


def _sha256(payload: Dict) -> str:
    """
    Compute SHA-256 hash of a dict.
    Keys are sorted for deterministic output — same data always produces
    the same hash regardless of insertion order.
    """
    serialized = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()

# ─────────────────────────────────────────────────────────────────────────────
# FIX 1 + 6: Persistent JSON File Database
# ─────────────────────────────────────────────────────────────────────────────

class JSONFileDatabase(IDatabase):
    """
    Persistent off-chain data store using local JSON files.

    File layout (all under BENSAM_Framework/data/):
        devices.json        — known devices
        traffic_logs.json   — traffic events
        violations.json     — policy violations
        payloads/<scan_id>.json — full scan payloads (off-chain store)
    """

    # --- Device management ---

    def add_device(self, device: Dict) -> None:
        devices = _read_json(_DEVICES_FILE, {})
        devices[device["name"]] = {
            "ip":        device.get("ip", "Unknown"),
            "type":      device.get("type", "Unknown"),
            "os":        device.get("os", "Unknown"),
            "mac":       device.get("mac", "Unknown"),
            "ports":     device.get("ports", []),
            "services":  device.get("services", []),
            "last_seen": datetime.utcnow().isoformat()
        }
        _write_json(_DEVICES_FILE, devices)

    def update_timestamp(self, name: str) -> None:
        devices = _read_json(_DEVICES_FILE, {})
        if name in devices:
            devices[name]["last_seen"] = datetime.utcnow().isoformat()
            _write_json(_DEVICES_FILE, devices)

    def get_devices(self) -> Dict:
        return _read_json(_DEVICES_FILE, {})

    def store_profile(self, profile: Dict) -> None:
        devices = _read_json(_DEVICES_FILE, {})
        name = profile.get("name")
        if name:
            if name not in devices:
                devices[name] = {}
            devices[name].update(profile)
            devices[name]["last_seen"] = datetime.utcnow().isoformat()
            _write_json(_DEVICES_FILE, devices)

    # --- Traffic logs ---

    def log_traffic(self, packet: Dict) -> None:
        logs = _read_json(_LOGS_FILE, [])
        packet["logged_at"] = datetime.utcnow().isoformat()
        logs.append(packet)
        _write_json(_LOGS_FILE, logs)

    def get_logs(self) -> List[Dict]:
        return _read_json(_LOGS_FILE, [])

    # --- Policy violations ---

    def log_violation(self, device: Dict, violation: str, severity: str = "Medium") -> None:
        violations = _read_json(_VIOLATIONS_FILE, [])
        entry = {
            "violation_id": str(uuid.uuid4()),
            "device":       device,
            "rule":         violation,
            "severity":     severity,
            "timestamp":    datetime.utcnow().isoformat()
        }
        violations.append(entry)
        _write_json(_VIOLATIONS_FILE, violations)

    def get_violations(self) -> List[Dict]:
        return _read_json(_VIOLATIONS_FILE, [])

    # --- Off-chain payload store (FIX 6) ---

    def store_payload(self, scan_id: str, payload: Dict) -> str:
        """
        Save full scan payload to data/payloads/<scan_id>.json
        Returns ref_id (= scan_id) for on-chain reference.
        """
        path = os.path.join(_PAYLOADS_DIR, f"{scan_id}.json")
        _write_json(path, payload)
        return scan_id   # ref_id == scan_id for simplicity in Phase 1

    def get_payload(self, ref_id: str) -> Optional[Dict]:
        """Retrieve a payload by ref_id (= scan_id in Phase 1)."""
        path = os.path.join(_PAYLOADS_DIR, f"{ref_id}.json")
        if not os.path.exists(path):
            return None
        return _read_json(path, None)


# Alias — bensam_integration.py and core.py import "Database"
Database = JSONFileDatabase


# ─────────────────────────────────────────────────────────────────────────────
# FIX 2 + 3: Simulated Blockchain Audit with real SHA-256 hashing
# ─────────────────────────────────────────────────────────────────────────────

class SimulatedBlockchainAudit(IBlockchainLogger):
    """
    Phase 1 blockchain implementation.

    Behaviour:
    - Computes SHA-256 hash of every payload
    - Writes hash + metadata to a local simulated_ledger.json
    - Prints structured blockchain log lines
    - verify_scan_integrity() recomputes hash and compares — WORKS end-to-end

    Phase 3 upgrade:
    - Replace this class with FabricBlockchainAudit(IBlockchainLogger)
    - Point it at a real Hyperledger Fabric Gateway endpoint
    - No other files need to change
    """

    def _read_ledger(self) -> Dict:
        return _read_json(_LEDGER_FILE, {})

    def _write_ledger(self, ledger: Dict) -> None:
        _write_json(_LEDGER_FILE, ledger)

    def _new_tx_id(self) -> str:
        """Generate a simulated transaction ID."""
        return "TX-" + uuid.uuid4().hex.upper()

    # --- Core interface methods ---

    def log_scan_record(self,
                        scan_id: str,
                        payload_hash: str,
                        scan_type: str,
                        target: str,
                        ref_id: str) -> str:
        tx_id = self._new_tx_id()
        record = {
            "scan_id":      scan_id,
            "hash":         payload_hash,
            "scan_type":    scan_type,
            "target":       target,
            "ref_id":       ref_id,
            "timestamp":    datetime.utcnow().isoformat() + "Z",
            "tx_id":        tx_id
        }
        ledger = self._read_ledger()
        ledger[scan_id] = record
        self._write_ledger(ledger)
        print(f"[Blockchain][TX:{tx_id}] LogScanRecord → "
              f"scan_id={scan_id} target={target} "
              f"scan_type={scan_type} hash={payload_hash[:16]}...")
        return tx_id

    def verify_scan_integrity(self, scan_id: str, recomputed_hash: str) -> str:
        ledger = self._read_ledger()
        if scan_id not in ledger:
            print(f"[Blockchain] VerifyIntegrity → NOT_FOUND: {scan_id}")
            return "NOT_FOUND"
        stored_hash = ledger[scan_id].get("hash", "")
        if stored_hash == recomputed_hash:
            print(f"[Blockchain] VerifyIntegrity → VERIFIED: {scan_id}")
            return "VERIFIED"
        print(f"[Blockchain] VerifyIntegrity → TAMPERED: {scan_id} "
              f"(stored={stored_hash[:16]}... recomputed={recomputed_hash[:16]}...)")
        return "TAMPERED"

    def get_scan_record(self, scan_id: str) -> Optional[Dict]:
        ledger = self._read_ledger()
        return ledger.get(scan_id)

    def log_policy_violation(self,
                              violation_id: str,
                              scan_id: str,
                              target: str,
                              rule: str,
                              severity: str) -> str:
        tx_id = self._new_tx_id()
        record = {
            "violation_id": violation_id,
            "scan_id":      scan_id,
            "target":       target,
            "rule":         rule,
            "severity":     severity,
            "timestamp":    datetime.utcnow().isoformat() + "Z",
            "tx_id":        tx_id
        }
        ledger = self._read_ledger()
        ledger["VIOLATION_" + violation_id] = record
        self._write_ledger(ledger)
        print(f"[Blockchain][TX:{tx_id}] LogPolicyViolation → "
              f"target={target} rule={rule} severity={severity}")
        return tx_id

    def get_all_scan_records(self) -> List[Dict]:
        ledger = self._read_ledger()
        return [v for k, v in ledger.items() if not k.startswith("VIOLATION_")]

    # --- Legacy compatibility: log_event used by older code ---
    def log_event(self, event_type: str, data: Dict) -> str:
        """
        Legacy method kept for backward compatibility with existing
        calls in core.py and bensam_integration.py.
        Computes hash of data and logs as a scan record.
        """
        scan_id = "EVT-" + uuid.uuid4().hex
        payload_hash = _sha256(data)
        return self.log_scan_record(
            scan_id=scan_id,
            payload_hash=payload_hash,
            scan_type=event_type,
            target=data.get("ip", data.get("target", "unknown")),
            ref_id=scan_id
        )


# Alias — existing code imports "BlockchainAudit"
BlockchainAudit = SimulatedBlockchainAudit


# ─────────────────────────────────────────────────────────────────────────────
# FIX 4: Smart Contract with externalized policy rules
# ─────────────────────────────────────────────────────────────────────────────

class SmartContract:
    """
    Phase 1 policy enforcement engine.

    Rules are loaded from policy_rules.json so they can be updated without
    code changes. In Phase 3 these rules move into the Hyperledger Fabric
    chaincode (bensam.go) for tamper-proof enforcement.

    Default policy_rules.json structure:
    {
        "blocked_ports": [23, 21, 445],
        "allowed_os": ["Windows 11", "Windows 10", "Ubuntu 22.04"],
        "internal_network_prefix": "192.168.",
        "iot_open_port_limit": 2
    }
    """

    DEFAULT_RULES = {
        "blocked_ports":            [23, 21, 445],
        "allowed_os":               ["Windows 11", "Windows 10", "Ubuntu 22.04", "Unknown"],
        "internal_network_prefix":  "192.168.",
        "iot_open_port_limit":      2
    }

    def __init__(self):
        self.rules = self._load_rules()

    def _load_rules(self) -> Dict:
        if os.path.exists(_POLICY_FILE):
            try:
                with open(_POLICY_FILE, "r", encoding="utf-8") as f:
                    rules = json.load(f)
                print(f"[SmartContract] Loaded policy rules from {_POLICY_FILE}")
                return rules
            except Exception as e:
                print(f"[SmartContract] Could not load policy_rules.json: {e}. Using defaults.")
        else:
            # Write defaults so user can see and edit the file
            _write_json(_POLICY_FILE, self.DEFAULT_RULES)
            print(f"[SmartContract] Created default policy_rules.json at {_POLICY_FILE}")
        return self.DEFAULT_RULES

    def check_policy(self, device: Dict) -> Dict:
        """
        Check a device against loaded policy rules.

        Returns:
            {
                "status":     "Compliant" | "Violation",
                "violations": [ list of violation strings ],
                "severity":   "Low" | "Medium" | "High"
            }
        """
        violations = []
        severity   = "Low"

        device_type = device.get("type", "Unknown")
        os_name     = device.get("os",   "Unknown")
        ip          = device.get("ip",   "")
        ports       = [int(p) for p in device.get("ports", []) if str(p).isdigit()]

        # Rule 1: Blocked ports
        blocked = self.rules.get("blocked_ports", [])
        for port in ports:
            if port in blocked:
                violations.append(f"Blocked port open: {port}")
                severity = "High"

        # Rule 2: OS compliance (only for Laptops/Workstations)
        if device_type in ("Laptop", "Workstation", "Desktop"):
            allowed = self.rules.get("allowed_os", [])
            if os_name not in allowed:
                violations.append(f"Non-compliant OS: {os_name}")
                if severity != "High":
                    severity = "Medium"

        # Rule 3: Network range (Routers must be internal)
        # Uses RFC-1918 check instead of a hardcoded prefix —
        # works on any private network (home 192.168.x.x, office 172.24.x.x, etc.)
        if device_type == "Router":
            if not is_internal_ip(ip):
                violations.append(f"Router outside internal range: {ip}")
                if severity != "High":
                    severity = "Medium"

        # Rule 4: IoT open port limit
        if device_type == "IoT":
            limit = self.rules.get("iot_open_port_limit", 2)
            if len(ports) > limit:
                violations.append(
                    f"IoT device has {len(ports)} open ports (limit: {limit})"
                )
                if severity != "High":
                    severity = "Medium"

        if violations:
            return {"status": "Violation", "violations": violations, "severity": severity}
        return {"status": "Compliant",  "violations": [],         "severity": "Low"}
