#!/usr/bin/env python3
"""
verify_rule_exists_via_put.py

Service-user tokens often have `cloudDetectionRulesCreateEdit` but lack
`cloudDetectionRulesView`. Result: POST/PUT/DELETE on a rule succeed,
but GET /rules and GET /rules/{id} silently filter the rule out. PUT
is the definitive existence test -- it returns 200/204 when the rule
exists and 404 when it does not.

Reads the (rule_id, pq_file) map produced by convert_test_deploy_sigma.py
in deployed_rule_ids.json next to this script.

Outputs:
  EXISTS / NOT_FOUND verdict per rule, plus a summary.
"""
from __future__ import annotations
import json
import os
import pathlib
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent

_CFG_PATH = os.environ.get("SIEM_TOOLKIT_CONFIG",
                           str(HERE / "tenant_config.json"))
CFG  = json.load(open(_CFG_PATH))
BASE = CFG["S1_CONSOLE_URL"].rstrip("/")
TOK  = CFG["S1_CONSOLE_API_TOKEN"].rstrip(".")

IDS_FILE = pathlib.Path(os.environ.get(
    "DEPLOYED_IDS_FILE", str(HERE / "deployed_rule_ids.json")))
ART_DIR  = pathlib.Path(os.environ.get(
    "SIGMA_OUT_DIR", "/tmp/sigma_converted_v4"))


def put_rule(site_id: str, rule_id: str, name: str,
             body: str) -> tuple[int, str]:
    payload = {
        "data": {"name": name,
                 "description": f"verify-by-PUT for {name}",
                 "severity": "Medium",
                 "expirationMode": "Permanent",
                 "queryType": "scheduled",
                 "queryLang": "2.0",
                 "status": "Draft",
                 "treatAsThreat": "UNDEFINED",
                 "networkQuarantine": False,
                 "coolOffSettings": {"renotifyMinutes": 60},
                 "scheduledParams": {"query": body,
                                     "lookbackWindowMinutes": 30,
                                     "runIntervalMinutes": 5,
                                     "threshold": {"value": 0,
                                                   "operator": "Greater"}}},
        "filter": {"siteIds": [site_id]}}
    req = urllib.request.Request(
        f"{BASE}/web/api/v2.1/cloud-detection/rules/{rule_id}",
        data=json.dumps(payload).encode(), method="PUT")
    req.add_header("Authorization", f"ApiToken {TOK}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode()[:240]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:240]


def main() -> int:
    print(f"\n{'='*78}\n  Verify rules via PUT-existence test\n{'='*78}")
    print(f"  Tenant   : {BASE}")
    print(f"  IDs file : {IDS_FILE}")
    print(f"  Artefacts: {ART_DIR}\n")

    if not IDS_FILE.exists():
        print(f"  FATAL: {IDS_FILE} not found.\n"
              f"  Run convert_test_deploy_sigma.py --deploy first.")
        return 1

    state = json.loads(IDS_FILE.read_text())
    rules = state.get("rules") or []
    site  = state.get("site_id") or os.environ.get("SITE_ID", "")
    if not site:
        print("  FATAL: site_id missing in deployed_rule_ids.json")
        return 1
    print(f"  Site     : {site}")
    print(f"  Rules    : {len(rules)} deployed entries\n")

    print(f"  {'#':>3}  {'rule':<32}{'id':<22}{'http':>5}  result")
    print("  " + "-" * 100)
    exists = gone = other = 0
    for i, r in enumerate(rules, 1):
        rid     = r["rule_id"]
        label   = f"{r['tactic']} {r['tech']}"
        pq_path = ART_DIR / r["pq_file"]
        if not pq_path.exists():
            print(f"  {i:>3}  {label[:32]:<32}{rid:<22}  --     "
                  f"pq file missing: {pq_path.name}")
            continue
        code, msg = put_rule(site, rid, f"[Sigma->PQ verify] {label}",
                             pq_path.read_text())
        if code in (200, 204):
            verdict = "EXISTS"; exists += 1
        elif code == 404:
            verdict = "NOT FOUND"; gone += 1
        else:
            verdict = f"HTTP {code}  {msg[:80]}"; other += 1
        print(f"  {i:>3}  {label[:32]:<32}{rid:<22}{code:>5}  {verdict}")

    print(f"\n  Summary:")
    print(f"    EXISTS (PUT 200/204)  : {exists}/{len(rules)}")
    print(f"    404 NOT FOUND         : {gone}/{len(rules)}")
    print(f"    Other (auth/RBAC)     : {other}/{len(rules)}")
    if exists > 0:
        print(f"\n  Rules ARE deployed. If GET /rules can't see them,")
        print(f"  the service-user role lacks `cloudDetectionRulesView`.")
        print(f"  Open the console UI (wider RBAC):")
        print(f"    {BASE}/#/cloud-detection/rules\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
