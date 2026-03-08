"""
bensam_integration.py
─────────────────────────────────────────────────────────────────────────────
Bridge between NetworkScannerGUI and BENSAM Framework.

Called from NetworkScannerGUI.py → on_scan_finished():
    from BENSAM_Framework.bensam_integration import parse_scan_result, finalize_bensam
    parse_scan_result(SCANRESULT_FILE)
    report_path = finalize_bensam(OUTPUT_FOLDER)

Fixes applied:
  1. No longer just logs host IPs — full payload passed to BENSAMFramework
  2. No module-level global event list — session state managed by framework
  3. Unused SmartContract() removed from module level
  4. Dynamic module loading replaced with direct imports
  5. parse_scan_result() now passes scan_type and target from GUI context
  6. finalize_bensam() returns report path for GUI to display
  7. Added verify_scan_integrity() for Layer 4 audit use
"""

import os
from datetime import datetime
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Module-level framework instance
# Created once, reused across calls within the same GUI session.
# ─────────────────────────────────────────────────────────────────────────────

_framework = None   # BENSAMFramework instance — lazy initialized


def _get_framework(scan_result_file: str = "ScanResult.txt"):
    """
    Return the module-level BENSAMFramework instance.
    Creates it on first call (lazy init) so import errors surface clearly.
    """
    global _framework
    if _framework is None or _framework.scan_result_file != scan_result_file:
        try:
            from BENSAM_Framework.core import BENSAMFramework
            _framework = BENSAMFramework(scan_result_file=scan_result_file)
            print("[BENSAM] Framework initialized.")
        except Exception as e:
            print(f"[BENSAM] ERROR: Could not initialize BENSAMFramework: {e}")
            raise
    return _framework


# ─────────────────────────────────────────────────────────────────────────────
# parse_scan_result
# Called by GUI immediately after a scan completes
# ─────────────────────────────────────────────────────────────────────────────

def parse_scan_result(scan_file_path: str,
                      scan_type: str = "Network Scan",
                      target: str = "unknown") -> int:
    """
    Parse ScanResult.txt and run the full BENSAM pipeline:
        parse → hash → store off-chain → log on-chain → enforce policy

    Args:
        scan_file_path: Absolute path to ScanResult.txt
        scan_type:      Type of scan (from GUI scantypeComboBox)
        target:         Target IP/network (from GUI targetComboBox)

    Returns:
        Number of hosts successfully processed (0 if file not found)

    Called from NetworkScannerGUI.on_scan_finished():
        parse_scan_result(SCANRESULT_FILE, scan_type, target)
    """
    if not os.path.exists(scan_file_path):
        print(f"[BENSAM] ScanResult.txt not found: {scan_file_path}")
        return 0

    print(f"[BENSAM] Processing scan results: {scan_type} → {target}")

    try:
        framework = _get_framework(scan_result_file=scan_file_path)

        # Run Steps 1-4 of the pipeline (not report generation yet)
        # report generation happens in finalize_bensam()
        hosts = framework.network_scan()

        if not hosts:
            print("[BENSAM] No hosts found in scan results.")
            return 0

        for host in hosts:
            framework.device_profiling(host)

        framework.traffic_monitoring(hosts)
        framework.policy_enforcement(hosts)

        print(f"[BENSAM] Processing complete. Hosts: {len(hosts)}")
        return len(hosts)

    except Exception as e:
        print(f"[BENSAM] Error in parse_scan_result: {e}")
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# finalize_bensam
# Called by GUI after parse_scan_result to generate the final report
# ─────────────────────────────────────────────────────────────────────────────

def finalize_bensam(output_folder: str = "output",
                    scan_file_path: str = "ScanResult.txt") -> str:
    """
    Generate the final BENSAM JSON report.

    Report includes:
        - All discovered devices with full profiles
        - All traffic events
        - All policy violations
        - Hash registry (scan_id → SHA-256 hash → ref_id)
          This is what Layer 4 audit uses to verify integrity.

    Args:
        output_folder:  Folder to write report into
        scan_file_path: Path to ScanResult.txt (to get correct framework instance)

    Returns:
        Absolute path to the generated report file.

    Called from NetworkScannerGUI.on_scan_finished():
        report_path = finalize_bensam(OUTPUT_FOLDER)
        self.win.textEdit.appendPlainText(f"[BENSAM] Report → {report_path}")
    """
    try:
        framework = _get_framework(scan_result_file=scan_file_path)
        report_path = framework.generate_reports(output_folder=output_folder)
        print(f"[BENSAM] Report generated → {report_path}")
        return report_path
    except Exception as e:
        print(f"[BENSAM] Error generating report: {e}")
        # Return a fallback path so GUI doesn't crash
        return os.path.join(output_folder, "bensam_report_ERROR.json")


# ─────────────────────────────────────────────────────────────────────────────
# verify_scan_integrity
# Layer 4 audit function — verifies a past scan was not tampered with
# ─────────────────────────────────────────────────────────────────────────────

def verify_scan_integrity(scan_id: str,
                          scan_file_path: str = "ScanResult.txt") -> dict:
    """
    Layer 4 audit: verify a previously logged scan has not been tampered with.

    Process:
        1. Retrieve on-chain hash by scan_id
        2. Retrieve off-chain payload by ref_id
        3. Recompute SHA-256 of the off-chain payload
        4. Compare recomputed hash with on-chain hash
        5. Return VERIFIED or TAMPERED

    Args:
        scan_id:        The scan_id from the hash_registry in a report
        scan_file_path: Path to locate the framework instance

    Returns:
        {
            "scan_id":         str,
            "status":          "VERIFIED" | "TAMPERED" | "NOT_FOUND" | "ERROR",
            "stored_hash":     str,
            "recomputed_hash": str,
            "match":           bool,
            "record":          dict   (on-chain metadata)
        }

    Called from GUI audit tab (to be built in Phase 4):
        result = verify_scan_integrity(scan_id)
        if result["status"] == "VERIFIED":
            self.update_log(f"✅ Integrity verified for {scan_id}")
        elif result["status"] == "TAMPERED":
            self.update_log(f"❌ TAMPER DETECTED for {scan_id}!")
    """
    try:
        from BENSAM_Framework.core import compute_hash
        framework = _get_framework(scan_result_file=scan_file_path)

        # Step 1: Get on-chain record
        record = framework.blockchain.get_scan_record(scan_id)
        if not record:
            return {
                "scan_id":         scan_id,
                "status":          "NOT_FOUND",
                "stored_hash":     "",
                "recomputed_hash": "",
                "match":           False,
                "record":          {}
            }

        stored_hash = record.get("hash", "")
        ref_id      = record.get("ref_id", "")

        # Step 2: Retrieve off-chain payload
        payload = framework.db.get_payload(ref_id)
        if not payload:
            return {
                "scan_id":         scan_id,
                "status":          "ERROR",
                "stored_hash":     stored_hash,
                "recomputed_hash": "",
                "match":           False,
                "record":          record,
                "error":           f"Off-chain payload not found for ref_id={ref_id}"
            }

        # Step 3: Recompute hash
        recomputed_hash = compute_hash(payload)

        # Step 4: Compare
        result_status = framework.blockchain.verify_scan_integrity(
            scan_id=scan_id,
            recomputed_hash=recomputed_hash
        )

        return {
            "scan_id":         scan_id,
            "status":          result_status,
            "stored_hash":     stored_hash,
            "recomputed_hash": recomputed_hash,
            "match":           (stored_hash == recomputed_hash),
            "record":          record
        }

    except Exception as e:
        print(f"[BENSAM] verify_scan_integrity error: {e}")
        return {
            "scan_id":         scan_id,
            "status":          "ERROR",
            "stored_hash":     "",
            "recomputed_hash": "",
            "match":           False,
            "record":          {},
            "error":           str(e)
        }


# ─────────────────────────────────────────────────────────────────────────────
# get_hash_registry
# Returns all blockchain records for display in GUI audit tab
# ─────────────────────────────────────────────────────────────────────────────

def get_hash_registry(scan_file_path: str = "ScanResult.txt") -> list:
    """
    Return all on-chain scan records for display in the audit dashboard.

    Each record contains:
        scan_id, hash, scan_type, target, timestamp, tx_id, ref_id

    Called from GUI audit tab:
        records = get_hash_registry()
        for r in records:
            self.update_log(f"{r['scan_id']} | {r['target']} | {r['hash'][:16]}...")
    """
    try:
        framework = _get_framework(scan_result_file=scan_file_path)
        return framework.blockchain.get_all_scan_records()
    except Exception as e:
        print(f"[BENSAM] get_hash_registry error: {e}")
        return []
