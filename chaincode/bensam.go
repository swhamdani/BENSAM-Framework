package main

import (
	"encoding/json"
	"fmt"
)

// Device represents a network device profile
type Device struct {
	Name string `json:"name"`
	Type string `json:"type"`
	IP   string `json:"ip"`
	OS   string `json:"os"`
}

// PolicyEnforcement applies simple rule-based checks to simulate smart contract behavior
func PolicyEnforcement(device Device) string {
	switch device.Type {

	case "Printer":
		// Example: Printers should not connect to external IPs
		return "Unauthorized external communication"

	case "Laptop":
		// Example: Laptops must run a secure OS version
		if device.OS != "Windows 11" && device.OS != "Ubuntu 22.04" {
			return "Outdated or unverified OS version"
		}
		// Example: Specific device name check
		if device.Name == "HP_Elitebook" {
			return "Compliant"
		}
		return "Unknown laptop device"

	case "Router":
		// Example: Routers must have internal IP range
		if device.IP[:7] != "192.168" {
			return "Router outside internal network range"
		}
		return "Compliant"

	case "IoT":
		// Example: IoT devices should not use open ports
		return "Open port detected on IoT device"

	default:
		return "Unknown device type or policy not defined"
	}
}

func main() {
	// Simulated test devices
	devices := []Device{
		{Name: "HP_Elitebook", Type: "Laptop", IP: "192.168.0.10", OS: "Windows 11"},
		{Name: "Office_Printer", Type: "Printer", IP: "192.168.0.15", OS: "Embedded OS"},
		{Name: "Main_Router", Type: "Router", IP: "192.168.0.1", OS: "RouterOS"},
		{Name: "Smart_Camera", Type: "IoT", IP: "192.168.0.25", OS: "TinyLinux"},
	}

	// Evaluate each device policy compliance
	for _, d := range devices {
		result := PolicyEnforcement(d)
		event := map[string]interface{}{
			"device": d,
			"policy": result,
		}
		resJSON, _ := json.MarshalIndent(event, "", "  ")
		fmt.Println(string(resJSON))
	}
}
