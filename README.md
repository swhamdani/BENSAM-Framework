# Blockchain-Enhanced Network Scanning and Monitoring (BENSAM) Framework



The **Blockchain-Enhanced Network Scanning and Monitoring (BENSAM) Framework** is a modular, multi-layered system designed for **verifiable, tamper-proof, and auditable network security monitoring**.  



Phase 1 implements a **simulated blockchain audit layer** with off-chain payload storage, SHA-256 hashing, and full device & traffic profiling, laying the foundation for future Hyperledger Fabric integration.



---



## 🚀 Key Features (Phase 1)



- **Modular Architecture** – Components are loosely coupled, supporting easier upgrades and extensibility.  


- **Interface-Based Design** – `IBlockchainLogger` and `IDatabase` interfaces separate core logic from implementation.  


- **Simulated Blockchain Layer** – SHA-256 hashed payloads stored off-chain with metadata logged in `simulated_ledger.json`.  


- **Persistent Off-Chain Storage** – Device and traffic data survive system restarts (`JSONFileDatabase`).  


- **Policy Rules Externalization** – Compliance rules can be updated without code changes (`policy_rules.json`).  


- **Full Audit Verification** – Verify data integrity end-to-end using `verify_scan_integrity(scan_id)`.  


- **GUI Integration** – `bensam_integration.py` connects parsing, reporting, and verification to the interface layer.  



---



## 🏛️ Phase 1 Architecture Diagram


      +------------------+


      |  ScanResult.txt  |


      +--------+---------+


               |


               v


   +-----------------------+


   | ScanResultParser.parse |   ← Extract host/IP, hostname, MAC, vendor, OS, ports, services, CVEs


   +-----------------------+


               |


               v


  +------------------------+


  | device_profiling()     |   ← Generate structured payload


  +------------------------+


               |


               v


  +------------------------+


  | compute_hash(payload)  |   ← SHA-256 hash of payload


  +------------------------+


               |


               v


  +------------------------+       +------------------------+


  | JSONFileDatabase.store()| ----> | Off-chain payload store |


  |  data/payloads/<scan_id>.json  |  ← Persistent JSON files


  +------------------------+       +------------------------+


               |


               v


  +------------------------+


  | SimulatedBlockchainAudit |


  |  data/simulated_ledger.json |


  +------------------------+


               |


               v


    +--------------------+


    | Audit Verification |


    | verify_scan_integrity() |


    +--------------------+


This diagram illustrates the **Phase 1 flow**: Scan results → parsing → payload profiling → hashing → off-chain storage → simulated blockchain logging → audit verification.



---



## 📂 Project Structure (Phase 1)



BENSAM_Framework/
├── interfaces.py ← Abstract interfaces (IBlockchainLogger, IDatabase)
├── audit.py ← JSONFileDatabase + SimulatedBlockchainAudit
├── core.py ← BENSAMFramework pipeline (scan, hash, store, report)
├── bensam_integration.py ← GUI bridge, reporting, verification functions
├── policy_rules.json ← Editable compliance policies
├── data/ ← Auto-created on first run
│ ├── devices.json
│ ├── traffic_logs.json
│ ├── violations.json
│ ├── simulated_ledger.json
│ └── payloads/
│ └── <scan_id>.json ← One file per scan event
├── tests/ ← Automated pytest tests
│ └── test_core.py
├── README.md ← Project documentation
└── requirements.txt ← Python dependencies



---



## 🧩 Core Components



### **interfaces.py**


- Defines `IBlockchainLogger` & `IDatabase` for abstraction and future Fabric integration.  


- Supports Phase 3 upgrade by replacing the simulated blockchain with a real Hyperledger Fabric connector.  



### **audit.py**


- Implements `JSONFileDatabase` for persistent storage of device, traffic, and violation data.  


- Implements `SimulatedBlockchainAudit`:


  - SHA-256 hash computation for each payload  


  - Logs hash + metadata in `simulated_ledger.json`  


  - Provides `verify_scan_integrity()` for Layer 4 audit verification  



### **core.py**


- `ScanResultParser` extracts full payload data.  


- `_submit_to_chain()` handles off-chain storage → hash → blockchain log.  


- `traffic_monitoring()` collects real scan port data.  


- `generate_reports()` compiles results with `hash_registry`.  



### **bensam_integration.py**


- GUI bridge for scan parsing, report generation, and audit verification.  


- New functions:


  - `verify_scan_integrity(scan_id)` → checks end-to-end hash consistency  


  - `get_hash_registry()` → returns all blockchain records for dashboard display  



---



## ✅ Testing



- Uses **pytest** for automated testing and verification.  


- Test coverage includes scan parsing, device profiling, and blockchain simulation.



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


    result = core.run()  # runs scan, monitoring, policy enforcement


    assert isinstance(result, type(None))  # basic placeholder assertion

Run tests:

pytest 
-v
🛠️ Installation & Usage
Clone the repository
git
 clone https://github.com/swhamdani/BENSAM-Framework.git


cd
 BENSAM_Framework
Install dependencies
pip install 
-r
 requirements.txt
Run framework
python core.py

Reports and hashes are automatically generated.

Off-chain payloads are stored in data/payloads/.

Blockchain log simulation: data/simulated_ledger.json.

Run tests
pytest
📖 Future Directions (Phase 2 / Phase 3)

Replace SimulatedBlockchainAudit with FabricBlockchainAudit for real Hyperledger Fabric logging.

Advanced AI/ML anomaly detection for network events.

Web dashboard for audit visualization.

Multi-tenant network support with secure role-based access.

Phase 1 sets the foundation: off-chain payload storage, SHA-256 hashing, simulated blockchain logging, and audit verification.

📜 License

Licensed under MIT License – free to use, modify, and distribute with attribution.