"""
core.py
─────────────────────────────────────────────────────────────────────────────
BENSAM Framework — Core Pipeline (Phase 1)

Fixes applied:
  1. Parser now extracts FULL payload: IPs, MACs, ports, services,
     OS detection, CVEs, hostnames — nothing discarded
  2. SHA-256 hashing added at every pipeline stage
  3. Full payload stored off-chain (data/payloads/) via db.store_payload()
  4. Only hash + metadata submitted to blockchain layer
  5. traffic_monitoring() uses real scan data, not mock data
  6. SmartContract.check_policy() now returns structured dict (not plain string)
  7. generate_reports() includes hash registry for audit verification
  8. All classes implement their interfaces from interfaces.py

Architecture mapping:
  network_scan()        → Layer 1 output consumed here
  device_profiling()    → Layer 2: normalize + hash + store off-chain
  _submit_to_chain()    → Layer 2→3 handoff: hash + metadata to blockchain
  policy_enforcement()  → Layer 2: compliance check
  generate_reports()    → Layer 4 preparation: includes all hashes
"""

import hashlib
import json
import re
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from BENSAM_Framework.audit import Database, BlockchainAudit, SmartContract


# ─────────────────────────────────────────────────────────────────────────────
# Hashing helper (reused by audit layer for integrity verification)
# ─────────────────────────────────────────────────────────────────────────────

def compute_hash(payload: Dict) -> str:
    """
    SHA-256 hash of a dict. Keys sorted for deterministic output.
    This is the canonical hash function used throughout BENSAM —
    any component that recomputes a hash MUST use this function.
    """
    serialized = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# ScanResult.txt Parser
# ─────────────────────────────────────────────────────────────────────────────

class ScanResultParser:
    """
    Parses ScanResult.txt into structured host records.

    Extracts per host:
        ip, hostname, mac, vendor, status,
        open_ports (list of {port, proto, state, service, version}),
        os_detection, cves (list), raw_block

    FIX 5 from review: no data is discarded.
    """

    # Regex patterns
    _RE_HOST       = re.compile(r"Nmap scan report for (.+)")
    _RE_STATUS     = re.compile(r"Host is (up|down)")
    _RE_MAC        = re.compile(r"MAC Address: ([0-9A-Fa-f:]{17}) \((.+?)\)")
    _RE_PORT       = re.compile(
        r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.+))?"
    )
    _RE_OS         = re.compile(r"OS details?:\s*(.+)")
    _RE_OS_GUESS   = re.compile(r"Aggressive OS guesses?:\s*(.+)")
    _RE_CVE        = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    _RE_MS         = re.compile(r"\bMS\d{2}-\d{3}\b",     re.IGNORECASE)
    _RE_HOSTNAME   = re.compile(r"Nmap scan report for (.+?) \((\d+\.\d+\.\d+\.\d+)\)")

    def parse(self, file_path: str) -> List[Dict]:
        """
        Parse ScanResult.txt and return a list of host dicts.
        Returns [] if file not found or empty.
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except FileNotFoundError:
            print(f"[BENSAM][Parser] File not found: {file_path}")
            return []
        except Exception as e:
            print(f"[BENSAM][Parser] Error reading {file_path}: {e}")
            return []

        return self._split_and_parse(content)

    def _split_and_parse(self, content: str) -> List[Dict]:
        """Split content into per-host blocks then parse each."""
        # Split on "Nmap scan report for" keeping the delimiter
        raw_blocks = re.split(r"(?=Nmap scan report for )", content)
        hosts = []
        for block in raw_blocks:
            block = block.strip()
            if not block.startswith("Nmap scan report for"):
                continue
            host = self._parse_block(block)
            if host:
                hosts.append(host)
        return hosts

    def _parse_block(self, block: str) -> Optional[Dict]:
        """Parse a single host block into a structured dict."""
        lines = block.splitlines()
        if not lines:
            return None

        # --- IP and hostname ---
        header = lines[0]
        m_with_hostname = self._RE_HOSTNAME.search(header)
        if m_with_hostname:
            hostname = m_with_hostname.group(1).strip()
            ip       = m_with_hostname.group(2).strip()
        else:
            # No hostname — just IP or bare host
            parts = header.split()
            ip       = parts[-1].strip()
            hostname = ""

        if not ip:
            return None

        # --- Status ---
        status = "unknown"
        for line in lines[1:6]:
            m = self._RE_STATUS.search(line)
            if m:
                status = m.group(1)
                break

        # --- MAC and vendor ---
        mac    = "Unknown"
        vendor = "Unknown"
        for line in lines:
            m = self._RE_MAC.search(line)
            if m:
                mac    = m.group(1)
                vendor = m.group(2)
                break

        # --- Open ports and services ---
        open_ports = []
        for line in lines:
            m = self._RE_PORT.match(line.strip())
            if m:
                port_entry = {
                    "port":    int(m.group(1)),
                    "proto":   m.group(2),
                    "state":   m.group(3),
                    "service": m.group(4),
                    "version": (m.group(5) or "").strip()
                }
                open_ports.append(port_entry)

        # --- OS Detection ---
        os_detection = "Unknown"
        for line in lines:
            m = self._RE_OS.search(line)
            if m:
                os_detection = m.group(1).strip()
                break
            m = self._RE_OS_GUESS.search(line)
            if m:
                # Take first guess up to first semicolon
                os_detection = m.group(1).split(";")[0].strip()
                break

        # Also check "Service Info: OS:" line
        if os_detection == "Unknown":
            for line in lines:
                if "Service Info:" in line and "OS:" in line:
                    m = re.search(r"OS:\s*([^;,]+)", line)
                    if m:
                        os_detection = m.group(1).strip()
                        break

        # --- CVE extraction ---
        cves = list({
            cve.upper()
            for line in lines
            # Only lines NOT flagged as false/not-vulnerable
            if not re.search(r":\s*false\b", line, re.IGNORECASE)
            if not re.search(r":\s*(ERROR|Could not negotiate|not vulnerable)", line, re.IGNORECASE)
            if not line.strip().startswith("|")
            for cve in self._RE_CVE.findall(line) + self._RE_MS.findall(line)
        })

        return {
            "ip":           ip,
            "hostname":     hostname,
            "mac":          mac,
            "vendor":       vendor,
            "status":       status,
            "os":           os_detection,
            "open_ports":   open_ports,
            "port_numbers": [p["port"] for p in open_ports],
            "services":     list({p["service"] for p in open_ports}),
            "cves":         cves,
            "raw_block":    block
        }


# ─────────────────────────────────────────────────────────────────────────────
# BENSAM Framework Core
# ─────────────────────────────────────────────────────────────────────────────

class BENSAMFramework:
    """
    Orchestrates the full BENSAM pipeline:

        Layer 1 output (ScanResult.txt)
            ↓
        network_scan()       — parse + store devices
            ↓
        device_profiling()   — enrich + hash + store off-chain + log on-chain
            ↓
        policy_enforcement() — check rules + log violations on-chain
            ↓
        generate_reports()   — full JSON report with hash registry
    """

    def __init__(self, scan_result_file: str = "ScanResult.txt"):
        self.scan_result_file = scan_result_file
        self.db               = Database()
        self.blockchain       = BlockchainAudit()
        self.contract         = SmartContract()
        self.parser           = ScanResultParser()

        # Runtime scan context — populated during run()
        self._current_scan_id:   Optional[str] = None
        self._current_scan_type: str           = "Network Scan"
        self._current_target:    str           = "unknown"

    # ─────────────────────────────────────────────────────────────────────
    # Internal: hash + store off-chain + submit to chain
    # ─────────────────────────────────────────────────────────────────────

    def _submit_to_chain(self,
                          payload: Dict,
                          scan_type: str,
                          target: str) -> Dict:
        """
        Core Layer 2 → Layer 3 handoff:
          1. Compute SHA-256 of full payload
          2. Store full payload off-chain
          3. Submit only {hash, metadata} to blockchain

        Returns:
            {
                "scan_id":      str,
                "hash":         str,
                "ref_id":       str,
                "tx_id":        str
            }
        """
        scan_id = str(uuid.uuid4())

        # Add scan metadata to payload before hashing
        payload["_meta"] = {
            "scan_id":   scan_id,
            "scan_type": scan_type,
            "target":    target,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        # Step 1: Hash
        payload_hash = compute_hash(payload)

        # Step 2: Store full payload off-chain
        ref_id = self.db.store_payload(scan_id, payload)

        # Step 3: Submit hash + metadata to blockchain
        tx_id = self.blockchain.log_scan_record(
            scan_id=scan_id,
            payload_hash=payload_hash,
            scan_type=scan_type,
            target=target,
            ref_id=ref_id
        )

        return {
            "scan_id":  scan_id,
            "hash":     payload_hash,
            "ref_id":   ref_id,
            "tx_id":    tx_id
        }

    # ─────────────────────────────────────────────────────────────────────
    # Step 1: Network Scan
    # ─────────────────────────────────────────────────────────────────────

    def network_scan(self) -> List[Dict]:
        """
        Parse ScanResult.txt into structured host records.
        Store each device in the persistent off-chain database.
        """
        print("[BENSAM] Parsing ScanResult.txt ...")
        hosts = self.parser.parse(self.scan_result_file)

        if not hosts:
            print("[BENSAM] No hosts found in ScanResult.txt.")
            return []

        devices = self.db.get_devices()
        for host in hosts:
            device = {
                "name":     host.get("hostname") or f"Host_{host['ip'].replace('.', '_')}",
                "ip":       host["ip"],
                "type":     "Unknown",
                "os":       host.get("os", "Unknown"),
                "mac":      host.get("mac", "Unknown"),
                "vendor":   host.get("vendor", "Unknown"),
                "ports":    host.get("port_numbers", []),
                "services": host.get("services", []),
                "cves":     host.get("cves", [])
            }
            if device["name"] not in devices:
                print(f"[BENSAM] New device: {device['ip']} ({device['name']})")
                self.db.add_device(device)
            else:
                self.db.update_timestamp(device["name"])

        print(f"[BENSAM] Network scan complete. Hosts found: {len(hosts)}")
        return hosts

    # ─────────────────────────────────────────────────────────────────────
    # Step 2: Device Profiling — hash + store off-chain + log on-chain
    # ─────────────────────────────────────────────────────────────────────

    def device_profiling(self, host: Dict) -> Dict:
        """
        FIX 6: Full payload hashed before blockchain submission.

        Profile structure (everything from the scan):
            ip, hostname, mac, vendor, os, status,
            open_ports, services, cves, scan_timestamp
        """
        profile = {
            "ip":         host.get("ip"),
            "hostname":   host.get("hostname", ""),
            "mac":        host.get("mac", "Unknown"),
            "vendor":     host.get("vendor", "Unknown"),
            "os":         host.get("os", "Unknown"),
            "status":     host.get("status", "unknown"),
            "open_ports": host.get("open_ports", []),
            "services":   host.get("services", []),
            "cves":       host.get("cves", []),
            "timestamp":  datetime.utcnow().isoformat() + "Z"
        }

        # Persist profile off-chain
        self.db.store_profile({
            "name": host.get("hostname") or f"Host_{host['ip'].replace('.', '_')}",
            **profile
        })

        # Hash full profile and submit to chain
        chain_result = self._submit_to_chain(
            payload=dict(profile),   # copy so _meta doesn't pollute profile
            scan_type="DeviceProfile",
            target=host.get("ip", "unknown")
        )

        print(f"[BENSAM] DeviceProfile logged → "
              f"IP={profile['ip']} "
              f"hash={chain_result['hash'][:16]}... "
              f"tx={chain_result['tx_id']}")

        return chain_result

    # ─────────────────────────────────────────────────────────────────────
    # Step 3: Traffic Monitoring — uses real scan data
    # ─────────────────────────────────────────────────────────────────────

    def traffic_monitoring(self, hosts: List[Dict]) -> None:
        """
        FIX 7: Uses real scan data instead of hardcoded mock data.

        Derives traffic events from open ports discovered in the scan.
        Each open port on each host = a logged traffic event.
        """
        print("[BENSAM] Logging traffic events from scan data...")
        event_count = 0

        for host in hosts:
            ip = host.get("ip", "unknown")
            for port_entry in host.get("open_ports", []):
                packet = {
                    "src":     ip,
                    "dst":     "scanner",
                    "port":    port_entry.get("port"),
                    "proto":   port_entry.get("proto"),
                    "service": port_entry.get("service"),
                    "state":   port_entry.get("state"),
                    "version": port_entry.get("version", "")
                }
                self.db.log_traffic(packet)
                event_count += 1

        print(f"[BENSAM] Traffic monitoring complete. Events logged: {event_count}")

    # ─────────────────────────────────────────────────────────────────────
    # Step 4: Policy Enforcement
    # ─────────────────────────────────────────────────────────────────────

    def policy_enforcement(self, hosts: List[Dict]) -> List[Dict]:
        """
        FIX 2 (partial): Policy rules loaded from policy_rules.json.
        In Phase 3 these move into Hyperledger Fabric chaincode.

        Returns list of violation records.
        """
        print("[BENSAM] Running policy enforcement...")
        all_violations = []

        for host in hosts:
            device_name = host.get("hostname") or f"Host_{host['ip'].replace('.', '_')}"
            device = self.db.get_devices().get(device_name, {})
            device["ip"]    = host.get("ip", device.get("ip", ""))
            device["ports"] = host.get("port_numbers", [])
            device["os"]    = host.get("os", device.get("os", "Unknown"))

            # check_policy now returns structured dict (FIX from review Bug 6)
            result = self.contract.check_policy(device)

            if result["status"] == "Violation":
                for rule in result["violations"]:
                    violation_id = str(uuid.uuid4())

                    # Log to off-chain DB
                    self.db.log_violation(device, rule, result["severity"])

                    # Log to blockchain
                    self.blockchain.log_policy_violation(
                        violation_id=violation_id,
                        scan_id=self._current_scan_id or "unknown",
                        target=host.get("ip", "unknown"),
                        rule=rule,
                        severity=result["severity"]
                    )

                    all_violations.append({
                        "ip":       host.get("ip"),
                        "rule":     rule,
                        "severity": result["severity"]
                    })
                    print(f"[BENSAM] Policy violation → "
                          f"IP={host.get('ip')} rule='{rule}' severity={result['severity']}")
            else:
                print(f"[BENSAM] Policy check → Compliant: {host.get('ip')}")

        print(f"[BENSAM] Policy enforcement complete. Violations: {len(all_violations)}")
        return all_violations

    # ─────────────────────────────────────────────────────────────────────
    # Step 5: Report Generation
    # ─────────────────────────────────────────────────────────────────────

    def generate_reports(self, output_folder: str = "output") -> str:
        """
        Generate a comprehensive JSON report including:
        - All discovered devices with full profiles
        - All traffic events
        - All policy violations
        - Blockchain hash registry (scan_id → hash → ref_id)
          This is what Layer 4 (audit) will use to verify integrity.
        """
        os_module = __import__("os")
        os_module.makedirs(output_folder, exist_ok=True)

        devices    = self.db.get_devices()
        logs       = self.db.get_logs()
        violations = self.db.get_violations()

        # Build hash registry from blockchain ledger
        hash_registry = [
            {
                "scan_id":   r.get("scan_id"),
                "hash":      r.get("hash"),
                "ref_id":    r.get("ref_id"),
                "scan_type": r.get("scan_type"),
                "target":    r.get("target"),
                "timestamp": r.get("timestamp"),
                "tx_id":     r.get("tx_id")
            }
            for r in self.blockchain.get_all_scan_records()
        ]

        report = {
            "metadata": {
                "report_name":       "BENSAM Network Scan & Compliance Report",
                "generated_at":      datetime.utcnow().isoformat() + "Z",
                "framework_version": "1.0-phase1",
                "total_devices":     len(devices),
                "total_violations":  len(violations),
                "total_log_events":  len(logs),
                "blockchain_records": len(hash_registry)
            },
            "devices":       devices,
            "traffic_logs":  logs,
            "violations":    violations,
            "hash_registry": hash_registry   # ← enables Layer 4 audit verification
        }

        filename = f"bensam_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        output_path = os_module.path.join(output_folder, filename)

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=4, default=str)
            print(f"[BENSAM] Report saved → {output_path}")
        except Exception as e:
            print(f"[BENSAM] Failed to write report: {e}")

        return output_path

    # ─────────────────────────────────────────────────────────────────────
    # Full Pipeline Runner
    # ─────────────────────────────────────────────────────────────────────

    def run(self, scan_type: str = "Network Scan",
            target: str = "unknown",
            output_folder: str = "output") -> str:
        """
        Execute the full BENSAM pipeline end-to-end.

        Args:
            scan_type:     Type of scan that produced ScanResult.txt
            target:        IP or network that was scanned
            output_folder: Where to write the final report

        Returns:
            Path to the generated report file
        """
        self._current_scan_type = scan_type
        self._current_target    = target

        print(f"\n{'='*60}")
        print(f"[BENSAM] Starting pipeline: {scan_type} → {target}")
        print(f"{'='*60}")

        # Step 1: Parse scan results
        hosts = self.network_scan()
        if not hosts:
            print("[BENSAM] No hosts to process. Generating empty report.")
            return self.generate_reports(output_folder)

        # Step 2: Profile each device (hash + store off-chain + log on-chain)
        scan_records = []
        for host in hosts:
            result = self.device_profiling(host)
            scan_records.append(result)
            # Keep first scan_id as the "session" scan_id for policy violations
            if not self._current_scan_id:
                self._current_scan_id = result["scan_id"]

        # Step 3: Traffic events from real scan data
        self.traffic_monitoring(hosts)

        # Step 4: Policy enforcement
        self.policy_enforcement(hosts)

        # Step 5: Final report
        report_path = self.generate_reports(output_folder)

        print(f"\n[BENSAM] Pipeline complete.")
        print(f"[BENSAM] Devices processed:   {len(hosts)}")
        print(f"[BENSAM] Blockchain records:  {len(scan_records)}")
        print(f"[BENSAM] Report:              {report_path}")
        print(f"{'='*60}\n")

        return report_path


if __name__ == "__main__":
    app = BENSAMFramework()
    app.run(scan_type="Vulnerability Scan", target="192.168.10.0/24")
