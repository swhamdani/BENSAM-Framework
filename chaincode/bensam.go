// chaincode/bensam.go
package main

import (
    "encoding/json"
    "fmt"
    "time"
)

// Device represents a network device
type Device struct {
    Name string `json:"name"`
    IP   string `json:"ip"`
    Type string `json:"type"`
    OS   string `json:"os"`
}

// LogEvent simulates a blockchain event
func LogEvent(eventType string, data interface{}) {
    timestamp := time.Now().Format(time.RFC3339)
    jsonData, _ := json.Marshal(data)
    fmt.Printf("[%s][Blockchain] %s: %s\n", timestamp, eventType, string(jsonData))
}

func main() {
    device := Device{Name: "Host_1", IP: "192.168.0.10", Type: "Laptop", OS: "Windows 11"}
    LogEvent("DeviceProfile", device)
    fmt.Println("BENSAM chaincode simulation complete")
}
