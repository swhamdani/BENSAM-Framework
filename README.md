
# Blockchain-Enhanced Network Scanning and Monitoring (BENSAM) Framework

The **Blockchain-Enhanced Network Scanning and Monitoring (BENSAM) Framework** is a conceptual, multi-layered system engineered for comprehensive, verifiable, and tamper-proof network security.

By leveraging blockchain technology, modular design, and object-oriented principles, BENSAM provides a scalable and auditable approach to network monitoring, traffic logging, device profiling, and compliance enforcement.

---

## 🚀 Key Features

- **Modular Architecture** – Breaks down complex tasks into reusable, manageable components.  
- **Object-Oriented Principles** – Applies the Single-Responsibility Principle (SRP) and Dependency Inversion Principle (DIP) for flexibility and loose coupling.  
- **Open-Closed Principle (OCP)** – Core logic interacts with abstract interfaces, making the system easily extensible without modifying existing code.  
- **Blockchain Integration** – Uses Hyperledger Fabric (simulated in prototype) for immutability, integrity verification, and auditable security events.  
- **Device & Traffic Policy Enforcement** – Smart contracts evaluate multiple device types (Laptop, Printer, Router, IoT) for compliance.  
- **Secure Data Flow** – Logs are hashed and stored off-chain; reference IDs recorded on-chain for verification.  
- **Automated Testing with pytest** – Simplifies test writing, encourages higher coverage, and ensures maintainability.  

---

## 🏛️ System Architecture

BENSAM follows a multi-layered architecture:

1. **Network Scanning Agents** – Generate raw device and traffic logs.  
2. **Logging & Event Aggregator Layer** – Processes, filters, and hashes payloads.  
   - Stores full payload in an Off-Chain Data Store.  
   - Generates a transaction proposal containing the hash, metadata, and reference ID.  
3. **Blockchain Layer (Hyperledger Fabric)** –  
   - Ordering Service packages transactions.  
   - Peer Nodes endorse and commit transactions.  
   - Chaincode (smart contracts) enforce compliance policies.  
4. **Monitoring & Audit Layer** – Queries on-chain hashes, retrieves off-chain logs, recomputes hashes, and verifies integrity.  

> This ensures tamper-proof, transparent, and auditable security monitoring.

---
📂 Project Structure
BENSAM-Framework/
│── core.py                # Core orchestration pipeline (scan, profile, traffic, policy, reporting)
│── audit.py               # Blockchain logging, SmartContract class, audit & compliance checks
│── chaincode/bensam.go    # Prototype Go chaincode for policy enforcement simulation
│── interfaces.py          # Abstract interfaces (Dependency Inversion Principle)
│── tests/
│    └── test_core.py      # pytest example with fixtures & parametrization
│── README.md              # Project documentation
│── requirements.txt       # Python dependencies

---

## 🧩 Core Components

### **interfaces.py**
- Defines abstract interfaces to decouple core logic from implementation.  
- Promotes loose coupling and flexibility.  
- Allows new modules to be added without modifying the core system.

### **core.py**
- Implements the orchestration pipeline: network scan → device profiling → traffic monitoring → policy enforcement → reporting.  
- Follows the **Open-Closed Principle (OCP)**.  
- Supports multi-device types: Laptop, Printer, Router, IoT.  
- Outputs JSON reports with device, traffic, and violation details.

### **audit.py**
- Simulates blockchain logging and SmartContract-based policy evaluation.  
- Policy enforcement rules now cover multiple device types and scenarios:
  - Printers: cannot access external IPs  
  - Laptops: OS compliance check (Windows 11 / Ubuntu 22.04)  
  - Routers: must have internal IP range  
  - IoT: simulated open port detection  

---

## ✅ Testing

The framework uses **pytest** for automated testing.

**Why pytest?**  
- Simple syntax with plain `assert` statements  
- Fixtures for reusable test setup/teardown  
- Parametrization for multiple inputs  
- Rich plugin ecosystem for flexibility

**Example Test File: `tests/test_core.py`**
```python
import pytest
from core import BENSAMFramework

@pytest.fixture
def sample_input():
    return {"event": "scan", "status": "success"}

@pytest.mark.parametrize("input_data", [
    {"event": "scan", "status": "success"},
    {"event": "monitor", "status": "failure"}
])
def test_core_processing(input_data):
    core = BENSAMFramework()
    result = core.run()  # runs scan, monitoring, and policy enforcement
    assert isinstance(result, type(None))  # basic placeholder assertion

Run tests:
pytest -v

🛠️ Installation & Usage

Clone the repository

git clone https://github.com/swhamdani/BENSAM-Framework.git
cd BENSAM-Framework


Install dependencies

pip install -r requirements.txt


Run tests

pytest

MVP Demo (mock ledger & policy enforcement)

1. Anchor a log

python - <<EOF
from core import BENSAMFramework
c = BENSAMFramework()
c.run()
EOF


2. Verify audit & policy

python audit.py <ref_id_from_step_1>


Output will show device profiles, traffic logs, policy violations, and a JSON report.

📖 Future Directions

Integration with real-world network scanning tools

Extended blockchain support beyond Hyperledger (e.g., Ethereum, Polygon)

Advanced AI/ML anomaly detection modules

Web-based dashboard for visualizing audit logs and compliance reports

📜 License

This project is licensed under the MIT License – free to use, modify, and distribute with attribution.
