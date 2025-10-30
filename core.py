# core.py
import json, hashlib, uuid, sqlite3
from datetime import datetime

# In-memory mock of the ledger (will be replaced by Fabric later)
LEDGER = {}

class BENSAMCore:
    def __init__(self):
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect("offchain_logs.db")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS logs
               (ref_id TEXT PRIMARY KEY, payload TEXT, ts TEXT)"""
        )
        conn.commit()
        conn.close()

    def process(self, raw_event: dict) -> dict:
        # 1. Build log payload
        log = {
            "event": raw_event["event"],
            "status": raw_event["status"],
            "src_ip": "192.168.1.10",
            "ts": datetime.utcnow().isoformat()
        }
        payload = json.dumps(log, sort_keys=True)
        log_hash = hashlib.sha256(payload.encode()).hexdigest()

        # 2. Off-chain store
        ref_id = str(uuid.uuid4())
        conn = sqlite3.connect("offchain_logs.db")
        conn.execute(
            "INSERT INTO logs VALUES (?, ?, ?)",
            (ref_id, payload, datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()

        # 3. Mock on-chain commit
        LEDGER[ref_id] = {"logHash": log_hash, "ts": int(datetime.utcnow().timestamp())}

        return {"ref_id": ref_id, "hash": log_hash, "status": "anchored"}
