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
        """
        Simulates smart contract policy enforcement for different device types.
        device: dict with keys 'name', 'type', 'ip', 'os'
        Returns a string describing the policy status.
        """
        device_type = device.get("type")
        name = device.get("name")
        ip = device.get("ip")
        os_name = device.get("os")

        if device_type == "Printer":
            return "Unauthorized external communication"

        elif device_type == "Laptop":
            if os_name not in ["Windows 11", "Ubuntu 22.04"]:
                return "Outdated or unverified OS version"
            if name == "HP_Elitebook":
                return "Compliant"
            return "Unknown laptop device"

        elif device_type == "Router":
            if not ip.startswith("192.168"):
                return "Router outside internal network range"
            return "Compliant"

        elif device_type == "IoT":
            return "Open port detected on IoT device"

        else:
            return "Unknown device type or policy not defined"

