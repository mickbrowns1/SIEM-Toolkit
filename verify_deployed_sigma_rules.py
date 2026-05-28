#!/usr/bin/env python3
"""
verify_deployed_sigma_rules.py  (formerly _v3)

Diagnostic for the RBAC visibility quirk: when a service-user role has
`cloudDetectionRulesCreateEdit` but not `cloudDetectionRulesView`, POST
succeeds and returns rule IDs, but GET /rules silently hides those rules.

This script probes several scope-filter variants to characterise what
the token CAN see:
  - direct GET /rules/{id}
  - list with ?ids=<csv>
  - list with siteIds=, accountIds=, tenant=true, no scope
  - list with queryType= filter

Reads tenant credentials from tenant_config.json and the rule IDs from
deployed_rule_ids.json (both next to this script). Set SIEM_TOOLKIT_CONFIG
or DEPLOYED_IDS_FILE env vars to override.
"""
from __future__ import annotations
import json
import os
import pathlib
import urllib.error
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
_CFG_PATH = os.environ.get("SIEM_TOOLKIT_CONFIG",
                           str(HERE / "tenant_config.json"))
CFG  = json.load(open(_CFG_PATH))
BASE = CFG["S1_CONSOLE_URL"].rstrip("/")
TOK  = CFG["S1_CONSOLE_API_TOKEN"].rstrip(".")

_IDS_PATH = pathlib.Path(os.environ.get(
    "DEPLOYED_IDS_FILE", str(HERE / "deployed_rule_ids.json")))
if not _IDS_PATH.exists():
    raise SystemExit(f"{_IDS_PATH} not found. "
                     f"Run convert_test_deploy_sigma.py --deploy first.")
_STATE = json.loads(_IDS_PATH.read_text())
SITE = _STATE.get("site_id") or os.environ.get("SITE_ID") or ""
DEPLOYED_IDS = [r["rule_id"] for r in (_STATE.get("rules") or [])]


def get_json(path: str):
    req = urllib.request.Request(f"{BASE}{path}")
    req.add_header("Authorization", f"ApiToken {TOK}")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
        except Exception:
            body = {"_raw": "(non-json)"}
        return e.code, body


def main() -> int:
    print(f"\n{'='*78}\n  Verify deployed rules via `ids=` filter\n"
          f"{'='*78}\n  Tenant : {BASE}\n  Site   : {SITE or '(unset)'}\n"
          f"  IDs    : {len(DEPLOYED_IDS)} rules from {_IDS_PATH.name}\n")

    # --- 1. token / user identity -----------------------------------
    print("--- Step 1: token identity -------------------------------------")
    code, d = get_json("/web/api/v2.1/users/api-token-details")
    if code == 200:
        data = d.get("data") or {}
        print(f"  user        : {data.get('email') or data.get('fullName')}")
        print(f"  scope       : {data.get('scope')}")
        print(f"  scope id    : {data.get('scopeId')}")
        print(f"  expires     : {data.get('expiresAt') or 'never'}")
    else:
        # Service-user JWT often can't introspect itself
        code2, d2 = get_json("/web/api/v2.1/user")
        if code2 == 200:
            data = d2.get("data") or {}
            print(f"  user        : {data.get('email')}")
            print(f"  scope       : {data.get('scope')}")
        else:
            print(f"  HTTP {code} / {code2}  cannot introspect token "
                  "(common for service-user JWTs)")

    if not DEPLOYED_IDS:
        print("  No deployed rule IDs to verify.")
        return 0

    # --- 2. list with ids= filter, NO scope filter ------------------
    print("\n--- Step 2: list with `ids=<csv>` (no scope filter) -----------")
    ids = ",".join(DEPLOYED_IDS)
    code, d = get_json(f"/web/api/v2.1/cloud-detection/rules?ids={ids}")
    if code != 200:
        print(f"  HTTP {code}  {json.dumps(d)[:300]}")
    else:
        rules = d.get("data") or []
        print(f"  Returned : {len(rules)} of {len(DEPLOYED_IDS)} requested")
        for r in rules:
            scope = (((r.get("scope") or {})
                      or {}).get("scopeName") or
                     r.get("siteName") or r.get("accountName") or "?")
            print(f"    id={r.get('id')}  status={r.get('status'):<10}  "
                  f"scope={scope}  name={(r.get('name') or '')[:65]}")

    # --- 3. list ids= AND siteIds= ----------------------------------
    print("\n--- Step 3: list with `ids=` AND `siteIds=` -------------------")
    code, d = get_json(
        f"/web/api/v2.1/cloud-detection/rules?ids={ids}&siteIds={SITE}")
    if code != 200:
        print(f"  HTTP {code}  {json.dumps(d)[:300]}")
    else:
        print(f"  Returned : {len(d.get('data') or [])} of "
              f"{len(DEPLOYED_IDS)}")

    # --- 4. list all visible scheduled rules without scope ----------
    print("\n--- Step 4: list with queryType= filter ---------------------")
    code, d = get_json(
        "/web/api/v2.1/cloud-detection/rules"
        "?queryType=scheduled&limit=200")
    if code != 200:
        print(f"  HTTP {code}  {json.dumps(d)[:300]}")
    else:
        rules = d.get("data") or []
        sigma = [r for r in rules
                 if "[Sigma->PQ]" in (r.get("name") or "")]
        print(f"  visible scheduled rules : {len(rules)}")
        print(f"  of which [Sigma->PQ]    : {len(sigma)}")
        for r in sigma:
            print(f"    id={r.get('id')}  status={r.get('status'):<10}  "
                  f"{(r.get('name') or '')[:70]}")

    print(f"\n  Console:\n    {BASE}/#/cloud-detection/rules\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
