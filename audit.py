import hashlib, json, sqlite3, sys
from core import LEDGER

def verify(ref_id):
    conn = sqlite3.connect("offchain_logs.db")
    cur = conn.execute("SELECT payload FROM logs WHERE ref_id = ?", (ref_id,))
    row = cur.fetchone(); conn.close()
    if not row: return {"error": "not found off-chain"}
    local_hash = hashlib.sha256(row[0].encode()).hexdigest()

    onchain = LEDGER.get(ref_id, {})
    if not onchain: return {"error": "not found on-chain"}

    return {
        "ref_id": ref_id,
        "match": local_hash == onchain["logHash"],
        "local_hash": local_hash,
        "onchain_hash": onchain["logHash"]
    }

if __name__ == "__main__":
    if len(sys.argv) != 2: print("Usage: python audit.py <ref_id>"); exit(1)
    print(json.dumps(verify(sys.argv[1]), indent=2))
