import time
from audit import BlockchainAudit, Database, SmartContract

class BENSAMFramework:
    def __init__(self):
        self.db = Database()
        self.blockchain = BlockchainAudit()
        self.contract = SmartContract()

    # Step 1: Network Scan
    def network_scan(self):
        print("[*] Scanning network for active devices...")
        stored_devices = self.db.get_devices()
        detected_devices = [
            {"name": "HP_Elitebook", "ip": "192.168.0.10", "type": "Laptop"},
            {"name": "Office_Printer", "ip": "192.168.0.15", "type": "Printer"},
        ]

        for device in detected_devices:
            if device["name"] not in stored_devices:
                print(f"[+] New device found: {device}")
                self.db.add_device(device)
                self.device_profiling(device)
            else:
                self.db.update_timestamp(device["name"])
        return detected_devices

    # Step 2: Device Profiling
    def device_profiling(self, device):
        print(f"[*] Profiling device {device['ip']} ({device['name']})...")
        profile = {
            "name": device["name"],
            "ip": device["ip"],
            "type": device["type"],
            "os": "Windows 11" if device["type"] == "Laptop" else "Embedded OS"
        }
        self.db.store_profile(profile)
        self.blockchain.log_event("DeviceProfile", profile)

    # Step 3: Traffic Monitoring
    def traffic_monitoring(self):
        print("[*] Monitoring network traffic...")
        mock_traffic = [
            {"src": "192.168.0.10", "dst": "8.8.8.8", "port": 443},
            {"src": "192.168.0.15", "dst": "192.168.0.1", "port": 80}
        ]
        for packet in mock_traffic:
            self.db.log_traffic(packet)
            self.blockchain.log_event("TrafficLog", packet)

    # Step 4: Policy Enforcement
    def policy_enforcement(self):
        print("[*] Running smart contract policy checks...")
        for device in self.db.get_devices().values():
            violation = self.contract.check_policy(device)
            if violation:
                self.db.log_violation(device, violation)
                self.blockchain.log_event("PolicyViolation", {"device": device, "rule": violation})

    # Step 5: Reporting (JSON Export)
    def generate_reports(self):
        print("[*] Generating compliance and audit reports...")
        data = {
            "devices": self.db.get_devices(),
            "logs": self.db.get_logs(),
            "violations": self.db.get_violations(),
        }
        self.blockchain.log_event("ReportGenerated", {"count": len(data['devices'])})
        print("[Report] Devices:", len(data["devices"]))
        print("[Report] Violations:", len(data["violations"]))

        # === JSON Export ===
        import json
        from datetime import datetime

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

        print(f"[+] Report saved successfully → {filename}")

    # Runner
    def run(self):
        self.network_scan()
        self.traffic_monitoring()
        self.policy_enforcement()
        self.generate_reports()

if __name__ == "__main__":
    app = BENSAMFramework()
    app.run()
