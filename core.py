# core.py
import json
from datetime import datetime
from audit import Database, BlockchainAudit, SmartContract
import re

class BENSAMFramework:
    def __init__(self, scan_result_file="ScanResult.txt"):
        self.db = Database()
        self.blockchain = BlockchainAudit()
        self.contract = SmartContract()
        self.scan_result_file = scan_result_file

    # Parse ScanResult.txt dynamically
    def parse_scan_result(self):
        devices = []
        try:
            with open(self.scan_result_file, "r") as f:
                content = f.read()
            # Extract IPs and MACs
            ip_matches = re.findall(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", content)
            mac_matches = re.findall(r"MAC Address: ([0-9A-Fa-f:]+) \((.*?)\)", content)
            for i, ip in enumerate(ip_matches):
                device = {
                    "name": f"Host_{i+1}",
                    "ip": ip,
                    "type": "Unknown",
                    "os": "Unknown",
                    "mac": mac_matches[i][0] if i < len(mac_matches) else "Unknown"
                }
                devices.append(device)
        except Exception as e:
            print(f"[BENSAM] Failed to parse scan results: {e}")
        return devices

    # Step 1: Network Scan
    def network_scan(self):
        print("[*] Parsing ScanResult.txt for devices...")
        detected_devices = self.parse_scan_result()

        for device in detected_devices:
            if device["name"] not in self.db.get_devices():
                print(f"[+] New device found: {device}")
                self.db.add_device(device)
            else:
                self.db.update_timestamp(device["name"])
        return detected_devices

    # Step 2: Device Profiling
    def device_profiling(self, device):
        profile = {
            "name": device["name"],
            "ip": device["ip"],
            "type": device.get("type", "Unknown"),
            "os": device.get("os", "Unknown"),
            "mac": device.get("mac", "Unknown")
        }
        self.db.store_profile(profile)
        self.blockchain.log_event("DeviceProfile", profile)

    # Step 3: Traffic Monitoring (simulated)
    def traffic_monitoring(self):
        print("[*] Simulated traffic monitoring...")
        mock_traffic = [
            {"src": "192.168.0.10", "dst": "8.8.8.8", "port": 443},
            {"src": "192.168.0.15", "dst": "192.168.0.1", "port": 80}
        ]
        for packet in mock_traffic:
            self.db.log_traffic(packet)
            self.blockchain.log_event("TrafficLog", packet)

    # Step 4: Policy Enforcement
    def policy_enforcement(self):
        print("[*] Running policy checks...")
        for device in self.db.get_devices().values():
            violation = self.contract.check_policy(device)
            if violation != "Compliant":
                self.db.log_violation(device, violation)
                self.blockchain.log_event("PolicyViolation", {"device": device, "rule": violation})

    # Step 5: Reporting
    def generate_reports(self):
        data = {
            "devices": self.db.get_devices(),
            "logs": self.db.get_logs(),
            "violations": self.db.get_violations()
        }
        self.blockchain.log_event("ReportGenerated", {"total_devices": len(data["devices"])})

        report = {
            "metadata": {
                "report_name": "BENSAM Network Scan & Compliance Report",
                "generated_at": datetime.now().isoformat(),
                "total_devices": len(data["devices"]),
                "total_violations": len(data["violations"])
            },
            "devices": data["devices"],
            "traffic_logs": data["logs"],
            "violations": data["violations"]
        }
        filename = f"bensam_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)
        print(f"[+] BENSAM report saved → {filename}")
        return filename

    # Runner
    def run(self):
        devices = self.network_scan()
        for device in devices:
            self.device_profiling(device)
        self.traffic_monitoring()
        self.policy_enforcement()
        return self.generate_reports()


if __name__ == "__main__":
    app = BENSAMFramework()
    app.run()
