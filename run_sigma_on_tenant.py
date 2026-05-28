#!/usr/bin/env python3
"""
run_sigma_on_tenant.py

Re-runs the same 10 Sigma->PowerQuery rules against ANY tenant by
re-pointing the credentials. The 10 converted .pq bodies in
SIGMA_OUT_DIR (default /tmp/sigma_converted_v4) are tenant-agnostic --
they only depend on the SDL DV schema, not on the specific tenant URL.

Pipeline:

  Step 0  -- discover sites via /sites?limit=10 (token introspection)
  Step 1  -- probe tenant telemetry: last 24 h volume on the EDR/DV
             fields the converted rules query
             (event.type, endpoint.os, tgt.process.cmdline, ...)
  Step 2  -- smoke-test each of the 10 faithful .pq bodies against the
             tenant's /api/powerQuery
  Step 3  -- deploy each as an SDL Scheduled rule via the Mgmt API
             POST /web/api/v2.1/cloud-detection/rules
  Step 4  -- verify the deployed rules via PUT-existence test

Reads tenant credentials from tenant_config.json next to this script.
Override with the SIEM_TOOLKIT_CONFIG env var. Override the artefact
location with SIGMA_OUT_DIR. Override the target site with SITE_ID.
"""
from __future__ import annotations
import json
import os
import pathlib
import time
import urllib.error
import urllib.request
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
_CFG_PATH = os.environ.get("SIEM_TOOLKIT_CONFIG",
                           str(HERE / "tenant_config.json"))
CFG  = json.load(open(_CFG_PATH))
ART  = pathlib.Path(os.environ.get(
    "SIGMA_OUT_DIR", "/tmp/sigma_converted_v4"))

SDL_BASE = CFG["SDL_XDR_URL"].rstrip("/")
SDL_KEY  = CFG["SDL_LOG_READ_KEY"]
S1_CONS  = CFG["S1_CONSOLE_URL"].rstrip("/")
S1_TOK   = CFG["S1_CONSOLE_API_TOKEN"].rstrip(".")

RULES: list[tuple[str, str, str]] = [
    ("Lateral Movement",  "T1021.006 WinRM (evil-winrm)",
     "proc_creation_win_hktl_evil_winrm.pq"),
    ("Collection",        "T1113 Screen Capture (Psr.exe)",
     "proc_creation_win_psr_capture_screenshots.pq"),
    ("Collection",        "T1115 Clipboard (Get-Clipboard)",
     "proc_creation_win_powershell_get_clipboard.pq"),
    ("Exfiltration",      "T1560.001 RAR (.dmp files)",
     "proc_creation_win_winrar_exfil_dmp_files.pq"),
    ("Exfiltration",      "T1567.002 rclone",
     "proc_creation_win_pua_rclone_execution.pq"),
    ("Reconnaissance",    "T1016 netsh portproxy",
     "proc_creation_win_netsh_port_forwarding.pq"),
    ("Discovery",         "T1087/T1033 whoami /priv",
     "proc_creation_win_whoami_priv_discovery.pq"),
    ("Discovery",         "T1087/T1482 SharpHound",
     "proc_creation_win_hktl_bloodhound_sharphound.pq"),
    ("Credential Access", "T1003.001 Mimikatz cmd-line",
     "proc_creation_win_hktl_mimikatz_command_line.pq"),
    ("Credential Access", "T1003.001 ProcDump LSASS",
     "proc_creation_win_sysinternals_procdump_lsass.pq"),
]


# ----------------------------------------------------- helpers --------------
def pq(query: str, hours: int = 24) -> tuple[int, str, int]:
    end = int(time.time() * 1000); start = end - hours * 3600 * 1000
    body = {"token": SDL_KEY, "query": query,
            "startTime": str(start), "endTime": str(end)}
    req = urllib.request.Request(
        f"{SDL_BASE}/api/powerQuery",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            d = json.loads(r.read())
            return 200, "ok", len(d.get("values") or [])
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:250], 0


def pq_count(query: str) -> int:
    wrapped = f"{query} | group n=count() | limit 1"
    code, _, rows = pq(wrapped)
    if code != 200 or rows == 0:
        return 0
    end = int(time.time() * 1000); start = end - 24 * 3600 * 1000
    req = urllib.request.Request(
        f"{SDL_BASE}/api/powerQuery",
        data=json.dumps({"token": SDL_KEY, "query": wrapped,
                         "startTime": str(start),
                         "endTime": str(end)}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        d = json.loads(urllib.request.urlopen(req, timeout=60).read())
        v = (d.get("values") or [[None]])[0]
        return int(v[0]) if v and v[0] is not None else 0
    except Exception:
        return 0


def mgmt_get(path: str) -> tuple[int, dict]:
    req = urllib.request.Request(f"{S1_CONS}{path}")
    req.add_header("Authorization", f"ApiToken {S1_TOK}")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {"_body": "(non-json)"}


def deploy_rule(site_id: str, name: str, desc: str,
                body: str) -> tuple[int, str]:
    payload = {
        "data": {"name": name, "description": desc, "severity": "Medium",
                 "expirationMode": "Permanent", "queryType": "scheduled",
                 "queryLang": "2.0", "status": "Draft",
                 "treatAsThreat": "UNDEFINED", "networkQuarantine": False,
                 "coolOffSettings": {"renotifyMinutes": 60},
                 "scheduledParams": {"query": body,
                                     "lookbackWindowMinutes": 30,
                                     "runIntervalMinutes": 5,
                                     "threshold": {"value": 0,
                                                   "operator": "Greater"}}},
        "filter": {"siteIds": [site_id]}}
    req = urllib.request.Request(
        f"{S1_CONS}/web/api/v2.1/cloud-detection/rules",
        data=json.dumps(payload).encode(), method="POST")
    req.add_header("Authorization", f"ApiToken {S1_TOK}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.loads(r.read())
            return 200, str((d.get("data") or {}).get("id") or "?")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


def put_rule(site_id: str, rule_id: str, name: str,
             body: str) -> tuple[int, str]:
    payload = {
        "data": {"name": name, "description": f"verify-by-PUT for {name}",
                 "severity": "Medium", "expirationMode": "Permanent",
                 "queryType": "scheduled", "queryLang": "2.0",
                 "status": "Draft", "treatAsThreat": "UNDEFINED",
                 "networkQuarantine": False,
                 "coolOffSettings": {"renotifyMinutes": 60},
                 "scheduledParams": {"query": body,
                                     "lookbackWindowMinutes": 30,
                                     "runIntervalMinutes": 5,
                                     "threshold": {"value": 0,
                                                   "operator": "Greater"}}},
        "filter": {"siteIds": [site_id]}}
    req = urllib.request.Request(
        f"{S1_CONS}/web/api/v2.1/cloud-detection/rules/{rule_id}",
        data=json.dumps(payload).encode(), method="PUT")
    req.add_header("Authorization", f"ApiToken {S1_TOK}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, "ok"
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200]


# ----------------------------------------------------- main -----------------
def main() -> int:
    print(f"\n{'='*78}\n  Sigma -> PowerQuery -> SDL  on US tenant\n"
          f"{'='*78}")
    print(f"  Mgmt API : {S1_CONS}")
    print(f"  SDL      : {SDL_BASE}")
    print(f"  Artefact : {ART}\n")

    # --- 0. discover sites on US tenant ----------------------------------
    print("--- Step 0: discover sites + token identity ---------------------")
    code, d = mgmt_get("/web/api/v2.1/sites?limit=10")
    if code != 200:
        print(f"  HTTP {code}  {str(d)[:300]}")
        return 1
    sites = (d.get("data") or {}).get("sites") or []
    print(f"  Sites visible to token: {len(sites)}")
    for s in sites[:5]:
        print(f"    id={s.get('id')}  name={s.get('name')}  "
              f"state={s.get('state')}")
    if not sites:
        print("  FATAL: no sites visible -- token has no scope here")
        return 1
    site_id = sites[0]["id"]
    print(f"  --> deploying into site_id={site_id} "
          f"({sites[0].get('name')})\n")

    # --- 1. tenant schema probe ------------------------------------------
    print("--- Step 1: probe US tenant telemetry (last 24 h) --------------")
    probes = {
        "event.type='Process Creation'":
            "event.type='Process Creation'",
        "endpoint.os='windows'":
            "endpoint.os='windows'",
        "tgt.process.cmdline non-empty":
            "tgt.process.cmdline!=''",
        "src.process.image.path non-empty":
            "src.process.image.path!=''",
    }
    for label, q in probes.items():
        n = pq_count(q)
        print(f"  {label:<45}{n}")
    print()

    # --- 2. smoke-test 10 rules ------------------------------------------
    print("--- Step 2: smoke-test 10 faithful PQ bodies -------------------")
    test_results = []
    for i, (tactic, tech, fname) in enumerate(RULES, 1):
        pq_path = ART / fname
        if not pq_path.exists():
            print(f"  [{i:>2}] {tactic:<18}{tech:<32} MISSING {fname}")
            test_results.append((i, tactic, tech, fname, None, None))
            continue
        body = pq_path.read_text()
        code, msg, rows = pq(body)
        print(f"  [{i:>2}] {tactic:<18}{tech:<32} HTTP {code} rows={rows}")
        if code != 200:
            print(f"        err: {msg[:160]}")
        test_results.append((i, tactic, tech, fname, code, rows))
    print()

    # --- 3. deploy --------------------------------------------------------
    print("--- Step 3: deploy each valid PQ as SDL Scheduled rule ---------")
    deployed: list[tuple[int, str, str, str, str]] = []  # i, tactic, tech, fname, id
    for (i, tactic, tech, fname, code, rows) in test_results:
        if code != 200:
            print(f"  [{i:>2}] SKIP (smoke-test failed)")
            continue
        body = (ART / fname).read_text()
        name = f"[Sigma->PQ USEA1] {tactic} / {tech} ({pathlib.Path(fname).stem})"[:128]
        desc = (f"Auto-converted Sigma rule. "
                f"Source: /tmp/sigma_converted_v4/{fname}. "
                f"Faithful S1 DV schema.")
        dc, dmsg = deploy_rule(site_id, name, desc, body)
        verdict = (f"id={dmsg}" if dc == 200 else f"FAIL HTTP {dc} "
                                                  f"{dmsg[:160]}")
        print(f"  [{i:>2}] DEPLOY  HTTP {dc}  {verdict}")
        if dc == 200:
            deployed.append((i, tactic, tech, fname, dmsg))
    print()

    # --- 4. PUT verification ---------------------------------------------
    if deployed:
        print("--- Step 4: PUT-existence verification --------------------")
        exists = 0; gone = 0
        for (i, tactic, tech, fname, rid) in deployed:
            body = (ART / fname).read_text()
            name = f"[Sigma->PQ USEA1 verify] {tactic} / {tech}"[:128]
            pc, pmsg = put_rule(site_id, rid, name, body)
            verdict = ("EXISTS" if pc in (200, 204)
                       else "NOT FOUND" if pc == 404
                       else f"HTTP {pc} {pmsg[:80]}")
            print(f"  [{i:>2}] id={rid}  PUT HTTP {pc}  {verdict}")
            if pc in (200, 204):
                exists += 1
            elif pc == 404:
                gone += 1

    # --- summary ----------------------------------------------------------
    print(f"\n{'='*78}\n  SUMMARY\n{'='*78}")
    valid = sum(1 for (_, _, _, _, c, _) in test_results if c == 200)
    print(f"  Smoke-test passed   : {valid}/10")
    print(f"  Rules deployed      : {len(deployed)}/10")
    if deployed:
        ids_file = HERE / "deployed_rule_ids.json"
        ids_file.write_text(json.dumps(
            {"tenant": S1_CONS, "site_id": site_id,
             "rules": [{"rule_id": rid, "pq_file": fname,
                        "tactic": tactic, "tech": tech}
                       for (_, tactic, tech, fname, rid) in deployed]},
            indent=2))
        print(f"  Deployed IDs        : {ids_file}")
        print(f"  PUT-verified exists : (see Step 4 above)")
    print(f"\n  Console:  {S1_CONS}/#/cloud-detection/rules\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
