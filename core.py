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
  9. [FIX] network_scan() deduplicates hosts by IP address using seen_ips set,
     preventing the same IP from being treated as multiple devices when nmap
     emits repeated host blocks (e.g. across ping/port/script scan phases).
     - seen_ips guards the current parse pass (in-memory dedup)
     - db.get_devices() re-fetched each iteration (prevents stale dict miss)
     - Dedup key is IP (stable), not hostname (can vary or be empty)
     - Return value is the deduplicated unique_hosts list, so all downstream
       steps (device_profiling, traffic_monitoring, policy_enforcement) receive
       exactly one entry per IP — fixing cascading duplicate blockchain TXs,
       duplicate policy violations, and incorrect host counts.
 10. [FIX] device_profiling() signature restored to per-host (host: Dict)
     so it stays compatible with bensam_integration.py and run() callers.
     CVE enrichment and risk scoring are applied to the single host dict,
     then _submit_to_chain() is called — blockchain submission preserved.
     self.update_log() replaced with print() (no GUI dependency in core).
     Profiled host appended to self._profiled_hosts for report generation.
 11. [FIX] generate_reports() now calls ReportGenerator.generate_html() and
     generate_json() after the JSON blockchain report, producing three output
     files per scan:
       bensam_audit_<ts>.json   — blockchain audit trail
       bensam_report_<ts>.json  — structured host data  (ReportGenerator)
       bensam_report_<ts>.html  — human-readable report (ReportGenerator)

Architecture mapping:
  network_scan()        → Layer 1 output consumed here
  device_profiling()    → Layer 2: enrich CVEs + score risk + hash + store + log on-chain
  _submit_to_chain()    → Layer 2→3 handoff: hash + metadata to blockchain
  policy_enforcement()  → Layer 2: compliance check
  generate_reports()    → Layer 4: audit JSON + HTML/JSON via ReportGenerator
"""

import hashlib
import json
import re
import uuid
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional

from BENSAM_Framework.vuln_intel import VulnerabilityIntel
from BENSAM_Framework.risk_scoring import RiskScoring
from BENSAM_Framework.report_generator import ReportGenerator
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
# Network utility helpers
# ─────────────────────────────────────────────────────────────────────────────

def is_internal_ip(ip: str) -> bool:
    """
    Returns True if IP falls within any RFC-1918 private range:
        10.0.0.0/8
        172.16.0.0/12   (covers 172.16.x.x – 172.31.x.x, includes 172.24.x.x)
        192.168.0.0/16
    Works at home, office, lab — no config needed.
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Scan.xml Parser
# ─────────────────────────────────────────────────────────────────────────────

class ScanResultParser:
    """
    Parses Scan.xml into structured host records.

    Scan.xml stores nmap output as individual <Result> XML elements, one
    line of nmap output per element.  This parser:
      1. Reads the XML with ElementTree
      2. Extracts the text content of every <Result> element
         (skips bulk/multiline elements that are duplicate full-stdout dumps)
      3. Reconstructs per-host records by walking the line sequence

    Extracts per host:
        ip, hostname, mac, vendor, status, latency,
        open_ports (list of {port, proto, state, service, version}),
        os, cves (list), raw_lines (list of original text lines)
    """

    import xml.etree.ElementTree as _ET

    _RE_REPORT  = re.compile(r"^Nmap scan report for (.+?)(\s+\[host down\])?$")
    _RE_MAC     = re.compile(r"^MAC Address:\s*([0-9A-Fa-f:]{17})\s*\((.+?)\)")
    _RE_STATUS  = re.compile(r"^Host is (up|down)")
    _RE_PORT    = re.compile(
        r"^(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.+))?"
    )
    _RE_OS      = re.compile(r"^(?:OS details?|Aggressive OS guesses?):\s*(.+)")
    _RE_SVC_OS  = re.compile(r"Service Info:.*OS:\s*([^;,]+)")
    _RE_LATENCY = re.compile(r"\(([\d.]+s) latency\)")
    _RE_CVE     = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    _RE_MS      = re.compile(r"\bMS\d{2}-\d{3}\b",     re.IGNORECASE)
    _RE_HOSTNAME = re.compile(r"^Nmap scan report for (.+?) \((\d+\.\d+\.\d+\.\d+)\)$")

    def parse(self, file_path: str) -> list:
        """
        Parse Scan.xml and return a list of host dicts.
        Returns [] if file not found, empty, or not valid XML.
        """
        import xml.etree.ElementTree as ET

        try:
            tree = ET.parse(file_path)
            xml_root = tree.getroot()
        except FileNotFoundError:
            print(f"[BENSAM][Parser] File not found: {file_path}")
            return []
        except ET.ParseError as e:
            print(f"[BENSAM][Parser] XML parse error in {file_path}: {e}")
            return []
        except Exception as e:
            print(f"[BENSAM][Parser] Error reading {file_path}: {e}")
            return []

        # Extract per-line text from <Result> elements.
        # Skip bulk multiline elements (the final full-stdout callback dump
        # that NMapScanHandler emits — it contains \n and duplicates the lines).
        lines = []
        for elem in xml_root.findall("Result"):
            text = (elem.text or "").strip()
            if text and "\n" not in text:
                lines.append(text)

        if not lines:
            print(f"[BENSAM][Parser] No usable lines found in {file_path}")
            return []

        return self._parse_lines(lines)

    def _parse_lines(self, lines: list) -> list:
        """Walk extracted nmap output lines and build per-host dicts."""
        from collections import OrderedDict

        hosts      = OrderedDict()
        current_ip = None
        cve_pat    = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
        ms_pat     = re.compile(r"\bMS\d{2}-\d{3}\b",     re.IGNORECASE)

        for line in lines:
            line = line.strip()

            # ── New host block ────────────────────────────────────────────
            m = self._RE_REPORT.match(line)
            if m:
                addr    = m.group(1).strip()
                is_down = bool(m.group(2))

                # Separate optional hostname from IP
                hm = self._RE_HOSTNAME.match(line)
                if hm:
                    hostname = hm.group(1).strip()
                    ip       = hm.group(2).strip()
                else:
                    ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", addr)
                    ip       = ip_match.group(1) if ip_match else addr
                    hostname = addr.replace(ip, "").strip(" ()")

                current_ip = ip
                if ip not in hosts:
                    hosts[ip] = {
                        "ip":           ip,
                        "hostname":     hostname,
                        "mac":          "Unknown",
                        "vendor":       "Unknown",
                        "status":       "down" if is_down else "",
                        "latency":      "",
                        "os":           "Unknown",
                        "open_ports":   [],
                        "port_numbers": [],
                        "services":     set(),
                        "cves":         set(),
                        "raw_lines":    []
                    }
                hosts[ip]["raw_lines"].append(line)
                continue

            if current_ip is None:
                continue

            host = hosts[current_ip]
            host["raw_lines"].append(line)

            # ── Host status + latency ─────────────────────────────────────
            m = self._RE_STATUS.match(line)
            if m:
                if not host["status"]:
                    host["status"] = m.group(1)
                lat = self._RE_LATENCY.search(line)
                if lat:
                    host["latency"] = lat.group(1)
                continue

            # ── MAC address + vendor ──────────────────────────────────────
            m = self._RE_MAC.match(line)
            if m:
                host["mac"]    = m.group(1)
                host["vendor"] = m.group(2)
                continue

            # ── Open port ────────────────────────────────────────────────
            m = self._RE_PORT.match(line)
            if m:
                port_entry = {
                    "port":    int(m.group(1)),
                    "proto":   m.group(2),
                    "state":   m.group(3),
                    "service": m.group(4),
                    "version": (m.group(5) or "").strip()
                }
                host["open_ports"].append(port_entry)
                host["port_numbers"].append(port_entry["port"])
                host["services"].add(port_entry["service"])
                continue

            # ── OS detection ──────────────────────────────────────────────
            m = self._RE_OS.match(line)
            if m and host["os"] == "Unknown":
                host["os"] = m.group(1).split(";")[0].strip()
                continue

            m = self._RE_SVC_OS.search(line)
            if m and host["os"] == "Unknown":
                host["os"] = m.group(1).strip()
                continue

            # ── CVE extraction (skip false/not-vulnerable lines) ──────────
            if (not re.search(r":\s*false\b",                                    line, re.IGNORECASE)
                    and not re.search(r":\s*(ERROR|Could not negotiate|not vulnerable)", line, re.IGNORECASE)
                    and not line.startswith("|")):
                for cve in cve_pat.findall(line) + ms_pat.findall(line):
                    host["cves"].add(cve.upper())

        # Convert sets to sorted lists for JSON serialisation
        result = []
        for ip, h in hosts.items():
            h["services"]  = sorted(h["services"])
            h["cves"]      = sorted(h["cves"])
            h["raw_block"] = "\n".join(h.pop("raw_lines", []))
            result.append(h)

        return result


# ─────────────────────────────────────────────────────────────────────────────
# BENSAM Framework Core
# ─────────────────────────────────────────────────────────────────────────────

class BENSAMFramework:
    """
    Orchestrates the full BENSAM pipeline:

        Layer 1 output (Scan.xml)
            ↓
        network_scan()       — parse + deduplicate by IP + store devices
            ↓
        device_profiling()   — enrich CVEs + score risk + hash + store off-chain + log on-chain
            ↓
        policy_enforcement() — check rules + log violations on-chain
            ↓
        generate_reports()   — audit JSON + structured JSON + HTML via ReportGenerator
    """

    def __init__(self, scan_result_file: str = "Scan.xml"):
        self.scan_result_file = scan_result_file
        self.db               = Database()
        self.blockchain       = BlockchainAudit()
        self.contract         = SmartContract()
        self.parser           = ScanResultParser()

        # ReportGenerator used in generate_reports()
        self.report_generator = ReportGenerator(output_folder="output")

        # Accumulates enriched host dicts across device_profiling() calls
        # so generate_reports() can pass the full list to ReportGenerator
        self._profiled_hosts: List[Dict] = []

        # Runtime scan context
        self._current_scan_id:   Optional[str] = None
        self._current_scan_type: str           = "Network Scan"
        self._current_target:    str           = "unknown"

    # ─────────────────────────────────────────────────────────────────────
    # Internal: hash + store off-chain + submit to chain
    # ─────────────────────────────────────────────────────────────────────

    def _submit_to_chain(self, payload: Dict, scan_type: str, target: str) -> Dict:
        """
        Layer 2 → Layer 3 handoff:
          1. Compute SHA-256 of full payload
          2. Store full payload off-chain
          3. Submit only {hash, metadata} to blockchain

        Returns: { "scan_id", "hash", "ref_id", "tx_id" }
        """
        scan_id = str(uuid.uuid4())

        payload["_meta"] = {
            "scan_id":   scan_id,
            "scan_type": scan_type,
            "target":    target,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        payload_hash = compute_hash(payload)
        ref_id       = self.db.store_payload(scan_id, payload)
        tx_id        = self.blockchain.log_scan_record(
            scan_id=scan_id,
            payload_hash=payload_hash,
            scan_type=scan_type,
            target=target,
            ref_id=ref_id
        )

        return {"scan_id": scan_id, "hash": payload_hash, "ref_id": ref_id, "tx_id": tx_id}

    # ─────────────────────────────────────────────────────────────────────
    # Step 1: Network Scan
    # ─────────────────────────────────────────────────────────────────────

    def network_scan(self) -> List[Dict]:
        """
        Parse Scan.xml into structured host records.
        Store each unique device in the persistent off-chain database.
        Deduplication by IP prevents duplicate blockchain TXs and violations.
        """
        print(f"[BENSAM] Parsing scan results: {self.scan_result_file}")

        hosts = self.parser.parse(self.scan_result_file)
        if not hosts:
            print("[BENSAM] No hosts found in Scan.xml.")
            return []

        seen_ips     = set()
        unique_hosts = []

        for host in hosts:
            ip = host.get("ip")
            if not ip or ip in seen_ips:
                continue

            seen_ips.add(ip)
            unique_hosts.append(host)

            device = {
                "name":     host.get("hostname") or f"Host_{ip.replace('.', '_')}",
                "ip":       ip,
                "type":     "Unknown",
                "os":       host.get("os",      "Unknown"),
                "mac":      host.get("mac",     "Unknown"),
                "vendor":   host.get("vendor",  "Unknown"),
                "ports":    host.get("port_numbers", []),
                "services": host.get("services",     []),
                "cves":     host.get("cves",         [])
            }

            devices = self.db.get_devices()
            if device["name"] not in devices:
                print(f"[BENSAM] New device discovered → {device['ip']} ({device['name']})")
                self.db.add_device(device)
            else:
                self.db.update_timestamp(device["name"])

        print(f"[BENSAM] Network scan complete. Unique hosts found: {len(unique_hosts)}")
        return unique_hosts

    # ─────────────────────────────────────────────────────────────────────
    # Step 2: Device Profiling
    # Called once per host — enriches, scores, hashes, submits to chain
    # ─────────────────────────────────────────────────────────────────────

    def device_profiling(self, host: Dict) -> Dict:
        """
        Per-host pipeline step:

          1. Build base profile from scan data
          2. Enrich CVEs via VulnerabilityIntel
          3. Calculate risk score via RiskScoring
          4. Persist profile off-chain
          5. Hash full profile + submit to blockchain
          6. Append enriched host to self._profiled_hosts for ReportGenerator

        Args:
            host: Single host dict from network_scan()

        Returns:
            Chain result dict: { "scan_id", "hash", "ref_id", "tx_id" }
        """
        ip = host.get("ip", "unknown")

        # ── 1. Base profile ──────────────────────────────────────────────
        profile = {
            "ip":         ip,
            "hostname":   host.get("hostname",   ""),
            "mac":        host.get("mac",        "Unknown"),
            "vendor":     host.get("vendor",     "Unknown"),
            "os":         host.get("os",         "Unknown"),
            "status":     host.get("status",     "unknown"),
            "open_ports": host.get("open_ports", []),
            "services":   host.get("services",   []),
            "cves":       host.get("cves",       []),
            "timestamp":  datetime.utcnow().isoformat() + "Z"
        }

        # ── 2. CVE enrichment ────────────────────────────────────────────
        try:
            intel = VulnerabilityIntel()
            if profile["cves"]:
                enriched_cves = intel.enrich_cves(profile["cves"])
                profile["vulnerability_intel"] = enriched_cves
                print(f"[BENSAM] CVE enrichment → {ip}: {len(enriched_cves)} CVE(s) enriched")
            else:
                profile["vulnerability_intel"] = []
        except Exception as e:
            print(f"[BENSAM] CVE enrichment failed for {ip}: {e}")
            profile["vulnerability_intel"] = []

        # ── 3. Risk scoring ──────────────────────────────────────────────
        try:
            scorer                = RiskScoring()
            score                 = scorer.calculate(profile)
            level                 = scorer.classify(score)
            profile["risk_score"] = score
            profile["risk_level"] = level
            print(f"[BENSAM] Risk score → {ip}: {score} ({level})")
        except Exception as e:
            print(f"[BENSAM] Risk scoring failed for {ip}: {e}")
            profile["risk_score"] = 0
            profile["risk_level"] = "UNKNOWN"

        # ── 4. Persist profile off-chain ─────────────────────────────────
        self.db.store_profile({
            "name": host.get("hostname") or f"Host_{ip.replace('.', '_')}",
            **profile
        })

        # ── 5. Hash + submit to blockchain ───────────────────────────────
        chain_result = self._submit_to_chain(
            payload=dict(profile),   # copy so _meta doesn't pollute profile
            scan_type="DeviceProfile",
            target=ip
        )

        print(f"[BENSAM] DeviceProfile logged → "
              f"IP={ip} "
              f"hash={chain_result['hash'][:16]}... "
              f"tx={chain_result['tx_id']}")

        # ── 6. Accumulate for ReportGenerator ────────────────────────────
        self._profiled_hosts.append(dict(profile))

        return chain_result

    # ─────────────────────────────────────────────────────────────────────
    # Step 3: Traffic Monitoring
    # ─────────────────────────────────────────────────────────────────────

    def traffic_monitoring(self, hosts: List[Dict]) -> None:
        """Derives and logs one traffic event per open port per host."""
        print("[BENSAM] Logging traffic events from scan data...")
        event_count = 0

        for host in hosts:
            ip = host.get("ip", "unknown")
            for port_entry in host.get("open_ports", []):
                self.db.log_traffic({
                    "src":     ip,
                    "dst":     "scanner",
                    "port":    port_entry.get("port"),
                    "proto":   port_entry.get("proto"),
                    "service": port_entry.get("service"),
                    "state":   port_entry.get("state"),
                    "version": port_entry.get("version", "")
                })
                event_count += 1

        print(f"[BENSAM] Traffic monitoring complete. Events logged: {event_count}")

    # ─────────────────────────────────────────────────────────────────────
    # Step 4: Policy Enforcement
    # ─────────────────────────────────────────────────────────────────────

    def policy_enforcement(self, hosts: List[Dict]) -> List[Dict]:
        """
        Evaluates each host against policy_rules.json once.
        Returns list of violation records.
        """
        print("[BENSAM] Running policy enforcement...")
        all_violations = []

        for host in hosts:
            device_name = host.get("hostname") or f"Host_{host['ip'].replace('.', '_')}"
            device      = self.db.get_devices().get(device_name, {})
            device["ip"]    = host.get("ip",           device.get("ip", ""))
            device["ports"] = host.get("port_numbers", [])
            device["os"]    = host.get("os",           device.get("os", "Unknown"))

            result = self.contract.check_policy(device)

            if result["status"] == "Violation":
                for rule in result["violations"]:
                    violation_id = str(uuid.uuid4())
                    self.db.log_violation(device, rule, result["severity"])
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
    # Produces three output files per scan session:
    #   bensam_audit_<ts>.json   — blockchain audit trail
    #   bensam_report_<ts>.json  — structured host data  (ReportGenerator)
    #   bensam_report_<ts>.html  — human-readable report (ReportGenerator)
    # ─────────────────────────────────────────────────────────────────────

    def generate_reports(self, output_folder: str = "output") -> str:
        """
        Generate all BENSAM output files after a completed scan.

        Returns the path to the blockchain audit JSON (used by the GUI
        and bensam_integration.finalize_bensam()).
        """
        import os as os_module
        os_module.makedirs(output_folder, exist_ok=True)

        # Sync ReportGenerator to the requested output folder
        self.report_generator.output_folder = output_folder

        devices    = self.db.get_devices()
        logs       = self.db.get_logs()
        violations = self.db.get_violations()

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

        # ── File 1: Blockchain audit JSON ────────────────────────────────
        audit_report = {
            "metadata": {
                "report_name":        "BENSAM Network Scan & Compliance Report",
                "generated_at":       datetime.utcnow().isoformat() + "Z",
                "framework_version":  "1.0-phase1",
                "total_devices":      len(devices),
                "total_violations":   len(violations),
                "total_log_events":   len(logs),
                "blockchain_records": len(hash_registry)
            },
            "devices":       devices,
            "traffic_logs":  logs,
            "violations":    violations,
            "hash_registry": hash_registry
        }

        timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
        audit_path = os_module.path.join(output_folder, f"bensam_audit_{timestamp}.json")

        try:
            with open(audit_path, "w", encoding="utf-8") as f:
                json.dump(audit_report, f, indent=4, default=str)
            print(f"[BENSAM] Audit report saved  → {audit_path}")
        except Exception as e:
            print(f"[BENSAM] Failed to write audit report: {e}")

        # ── Files 2 & 3: ReportGenerator (structured JSON + HTML) ────────
        # self._profiled_hosts carries enriched CVE intel and risk scores
        # accumulated by device_profiling(). Falls back to flat device list
        # if called standalone (e.g. from __main__ without a full run()).
        profiled = self._profiled_hosts if self._profiled_hosts else list(devices.values())

        if profiled:
            try:
                rg_json = self.report_generator.generate_json(profiled)
                print(f"[BENSAM] Data report saved   → {rg_json}")
            except Exception as e:
                print(f"[BENSAM] ReportGenerator JSON failed: {e}")

            try:
                rg_html = self.report_generator.generate_html(profiled)
                print(f"[BENSAM] HTML report saved   → {rg_html}")
            except Exception as e:
                print(f"[BENSAM] ReportGenerator HTML failed: {e}")
        else:
            print("[BENSAM] No profiled hosts available — skipping ReportGenerator output.")

        return audit_path

    # ─────────────────────────────────────────────────────────────────────
    # Full Pipeline Runner
    # ─────────────────────────────────────────────────────────────────────

    def run(self, scan_type: str = "Network Scan",
            target: str = "unknown",
            output_folder: str = "output") -> str:
        """
        Execute the full BENSAM pipeline end-to-end.

        Args:
            scan_type:     Type of scan that produced Scan.xml
            target:        IP or network that was scanned
            output_folder: Where to write the final reports

        Returns:
            Path to the generated audit report file
        """
        self._current_scan_type = scan_type
        self._current_target    = target
        self._profiled_hosts    = []   # reset for fresh pipeline run

        print(f"\n{'='*60}")
        print(f"[BENSAM] Starting pipeline: {scan_type} → {target}")
        print(f"{'='*60}")

        # Step 1
        hosts = self.network_scan()
        if not hosts:
            print("[BENSAM] No hosts to process. Generating empty report.")
            return self.generate_reports(output_folder)

        # Step 2 — per-host enrichment + scoring + blockchain submission
        scan_records = []
        for host in hosts:
            result = self.device_profiling(host)
            scan_records.append(result)
            if not self._current_scan_id:
                self._current_scan_id = result["scan_id"]

        # Step 3
        self.traffic_monitoring(hosts)

        # Step 4
        self.policy_enforcement(hosts)

        # Step 5 — three output files
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