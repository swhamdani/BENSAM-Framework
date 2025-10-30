import json
from datetime import datetime

class Database:
    def __init__(self):
        self.devices = {}
        self.logs = []
        self.violations = []

    def get_devices(self):
        return self.devices

    def add_device(self, device):
        self.devices[device["name"]] = {
            "ip": device["ip"],
            "type": device["type"],
            "last_seen": datetime.now().isoformat()
        }

    def update_timestamp(self, name):
        if name in self.devices:
            self.devices[name]["last_seen"] = datetime.now().isoformat()

    def store_profile(self, profile):
        self.devices[profile["name"]].update(profile)

    def log_traffic(self, packet):
        self.logs.append(packet)

    def log_violation(self, device, violation):
        entry = {"device": device, "violation": violation, "timestamp": datetime.now().isoformat()}
        self.violations.append(entry)

    def get_logs(self):
        return self.logs

    def get_violations(self):
        return self.violations


class BlockchainAudit:
    def log_event(self, event_type, data):
        print(f"[Blockchain Log] {event_type}: {json.dumps(data)}")


class SmartContract:
    def check_policy(self, device):
        # Simple mock rule: Printers cannot access external IPs
        if device.get("type") == "Printer":
            return "Unauthorized external communication"
        return None
