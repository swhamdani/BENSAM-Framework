"""
interfaces.py
─────────────────────────────────────────────────────────────────────────────
Abstract base classes for BENSAM Framework.

All concrete implementations (Database, BlockchainAudit) MUST inherit from
these interfaces. This ensures Phase 3 (real Hyperledger Fabric connector)
can be swapped in without touching core.py or bensam_integration.py.

Phase 1:  SimulatedBlockchainAudit  → prints + writes to local JSON ledger
Phase 3:  FabricBlockchainAudit     → connects to real Hyperledger Fabric
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Blockchain Logger Interface
# ─────────────────────────────────────────────────────────────────────────────

class IBlockchainLogger(ABC):
    """
    Interface for blockchain audit logging.
    Phase 1: implemented by SimulatedBlockchainAudit (local JSON ledger)
    Phase 3: implemented by FabricBlockchainAudit (Hyperledger Fabric Gateway)
    """

    @abstractmethod
    def log_scan_record(self,
                        scan_id: str,
                        payload_hash: str,
                        scan_type: str,
                        target: str,
                        ref_id: str) -> str:
        """
        Store a scan hash on the blockchain.
        Returns the transaction ID (or simulated equivalent).

        Args:
            scan_id:      Unique ID for this scan (UUID)
            payload_hash: SHA-256 hex digest of the full scan payload
            scan_type:    e.g. 'Vulnerability Scan', 'Host Discovery'
            target:       IP address or network range scanned
            ref_id:       Reference to the off-chain payload file/record

        Returns:
            Transaction ID string
        """
        pass

    @abstractmethod
    def verify_scan_integrity(self, scan_id: str, recomputed_hash: str) -> str:
        """
        Compare recomputed_hash against the on-chain stored hash.

        Returns:
            'VERIFIED'  — hashes match, data is intact
            'TAMPERED'  — hashes differ, data was modified
            'NOT_FOUND' — scan_id not on chain
            'ERROR'     — could not complete verification
        """
        pass

    @abstractmethod
    def get_scan_record(self, scan_id: str) -> Optional[Dict]:
        """Retrieve a scan record by scan_id. Returns None if not found."""
        pass

    @abstractmethod
    def log_policy_violation(self,
                              violation_id: str,
                              scan_id: str,
                              target: str,
                              rule: str,
                              severity: str) -> str:
        """
        Store a compliance violation on the blockchain.
        Returns the transaction ID.
        """
        pass

    @abstractmethod
    def get_all_scan_records(self) -> List[Dict]:
        """Return all scan records (used by Layer 4 audit dashboard)."""
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Off-Chain Database Interface
# ─────────────────────────────────────────────────────────────────────────────

class IDatabase(ABC):
    """
    Interface for the off-chain persistent data store.
    Phase 1: implemented by JSONFileDatabase (local JSON files)
    Phase 3: can be swapped for MongoDB or PostgreSQL
    """

    # --- Device management ---
    @abstractmethod
    def add_device(self, device: Dict) -> None:
        """Add or update a device record."""
        pass

    @abstractmethod
    def update_timestamp(self, name: str) -> None:
        """Update the last_seen timestamp for a known device."""
        pass

    @abstractmethod
    def get_devices(self) -> Dict:
        """Return all known devices keyed by name."""
        pass

    # --- Profile storage ---
    @abstractmethod
    def store_profile(self, profile: Dict) -> None:
        """Store or update a full device profile."""
        pass

    # --- Traffic logs ---
    @abstractmethod
    def log_traffic(self, packet: Dict) -> None:
        """Append a traffic event to the log."""
        pass

    @abstractmethod
    def get_logs(self) -> List[Dict]:
        """Return all traffic log entries."""
        pass

    # --- Policy violations ---
    @abstractmethod
    def log_violation(self, device: Dict, violation: str, severity: str) -> None:
        """Record a policy violation."""
        pass

    @abstractmethod
    def get_violations(self) -> List[Dict]:
        """Return all recorded violations."""
        pass

    # --- Off-chain payload store ---
    @abstractmethod
    def store_payload(self, scan_id: str, payload: Dict) -> str:
        """
        Persist the full scan payload off-chain.
        Returns a ref_id that can be stored on-chain alongside the hash.
        """
        pass

    @abstractmethod
    def get_payload(self, ref_id: str) -> Optional[Dict]:
        """Retrieve a full scan payload by its ref_id."""
        pass
