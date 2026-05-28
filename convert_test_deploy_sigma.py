#!/usr/bin/env python3
"""
convert_test_deploy_sigma.py  --  Sigma -> PowerQuery -> SDL Scheduled Rule.

Master pipeline that addresses every TODO from the v3 review:

  (a) Fixes rule #6 (netsh) by trying multiple candidate filenames AND by
      catching the pipeline error so the loop continues. Fixes rule #7
      (AdsiSearcher) by also searching rules/windows/powershell/.
  (b) Adds a WEL-mapping post-processor that rewrites the S1 EDR/DV PQ
      fields to the microsoft_windows_eventlog-latest parser schema so
      the queries can fire against Windows Event Log telemetry.
  (c) Deploys every PQ that passes the live /api/powerQuery smoke test
      as an SDL Scheduled rule via the S1 Mgmt API (POST
      /web/api/v2.1/cloud-detection/rules). Requires --deploy + a valid
      S1_CONSOLE_API_TOKEN in config.json.

For each rule we emit THREE PowerQuery variants and smoke-test each:

   <stem>.pq              -- faithful Sigma -> S1-PQ conversion (DV schema)
   <stem>.relaxed.pq      -- faithful minus the endpoint.os and event.type
                             clauses (DV schema but null-os-tolerant)
   <stem>.wel.pq          -- field-mapped onto microsoft_windows_eventlog-
                             latest (CommandLine, Image, ParentImage, ...)

Usage:
    python3 convert_test_deploy_sigma.py            # convert + test only
    python3 convert_test_deploy_sigma.py --deploy   # also create SDL rules
"""
from __future__ import annotations
import argparse
import json
import os
import pathlib
import re
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any

HERE     = pathlib.Path(__file__).resolve().parent
VENV_PY  = os.environ.get("SIGMA_VENV_PY", "/tmp/sigma_venv/bin/python3")
GH       = os.environ.get("GH_BIN", "gh")
OUT      = pathlib.Path(os.environ.get(
    "SIGMA_OUT_DIR", "/tmp/sigma_converted_v4")); OUT.mkdir(exist_ok=True)

_CFG_PATH = os.environ.get("SIEM_TOOLKIT_CONFIG",
                          str(HERE / "tenant_config.json"))
CFG      = json.load(open(_CFG_PATH))
SDL_BASE = CFG["SDL_XDR_URL"].rstrip("/")
SDL_KEY  = CFG["SDL_LOG_READ_KEY"]
S1_CONS  = CFG.get("S1_CONSOLE_URL", "").rstrip("/")
S1_TOK   = CFG.get("S1_CONSOLE_API_TOKEN", "").rstrip(".")
# Site id is discovered at runtime from /sites?limit=10 (first active site).
# Override with SITE_ID env var if you have multiple sites and want a
# specific one.
SITE_ID  = os.environ.get("SITE_ID", "")
SIGMA_RAW = "https://raw.githubusercontent.com/SigmaHQ/sigma/master"

# 10 desired (tactic, technique, keyword_list, allow_powershell_folder)
WANTED: list[tuple[str, str, list[str], bool]] = [
    ("Lateral Movement",  "T1021.006 WinRM",
     ["winrm", "winrs"], False),
    ("Collection",        "T1113 Screen Capture",
     ["screen_capture", "screencapture", "screenshot"], False),
    ("Collection",        "T1115 Clipboard Data",
     ["clipboard"], False),
    ("Exfiltration",      "T1560.001 Archive via RAR",
     ["winrar_compress", "winrar", "rar_compress"], False),
    ("Exfiltration",      "T1567.002 Exfil via rclone",
     ["rclone"], False),
    ("Reconnaissance",    "T1016 netsh port-fwd",
     ["netsh_allowed_ports", "netsh_port_proxy", "netsh_port_fwd",
      "netsh_fw", "netsh_portproxy"], False),
    ("Discovery",         "T1087.002 AdsiSearcher",
     ["adsisearcher", "adsi_searcher"], True),    # in powershell/
    ("Discovery",         "T1087/T1482 SharpHound",
     ["sharphound", "bloodhound"], False),
    ("Credential Access", "T1003.001 Mimikatz cmdline",
     ["mimikatz_command_line", "mimikatz_cli", "mimikatz"], False),
    ("Credential Access", "T1003.001 ProcDump LSASS",
     ["procdump_lsass", "procdump", "comsvcs_lsass"], False),
]


# ============================================================ helpers ======
def gh_api(path: str) -> Any:
    r = subprocess.run([GH, "api", path], capture_output=True, text=True,
                       timeout=60)
    if r.returncode != 0:
        raise RuntimeError(f"gh api {path}: {r.stderr.strip()[:300]}")
    return json.loads(r.stdout)


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "siem-toolkit"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def list_sigma_rules(allow_powershell: bool) -> list[str]:
    tree = gh_api("repos/SigmaHQ/sigma/git/trees/master?recursive=1")
    prefixes = ["rules/windows/process_creation/"]
    if allow_powershell:
        prefixes.append("rules/windows/powershell/")
    return sorted(
        e["path"] for e in tree.get("tree", [])
        if e.get("type") == "blob"
        and e.get("path", "").endswith(".yml")
        and any(e["path"].startswith(p) for p in prefixes)
    )


def pick(paths: list[str], keywords: list[str]) -> str | None:
    for kw in keywords:
        for p in paths:
            if kw in pathlib.Path(p).stem.lower():
                return p
    return None


def convert(yaml_text: str) -> str:
    code = (
        "import sys\n"
        "from sigma.rule import SigmaRule\n"
        "from sigma.backends.sentinelone_pq import SentinelOnePQBackend\n"
        "r = SigmaRule.from_yaml(sys.stdin.read())\n"
        "print(SentinelOnePQBackend().convert_rule(r)[0])\n")
    res = subprocess.run([VENV_PY, "-c", code], input=yaml_text, text=True,
                         capture_output=True, timeout=90)
    if res.returncode != 0:
        # last line of the trace is usually the most informative
        err = res.stderr.strip().splitlines()
        msg = err[-1] if err else "(no stderr)"
        raise RuntimeError(msg[:300])
    return res.stdout.strip()


def relax(pq_body: str) -> str:
    """Strip endpoint.os and event.type filter clauses."""
    body = pq_body
    body = re.sub(r'endpoint\.os\s*=\s*"[^"]*"\s+and\s+', '', body)
    body = re.sub(r'\s+and\s+endpoint\.os\s*=\s*"[^"]*"', '', body)
    body = re.sub(r'event\.type\s*=\s*"[^"]*"\s+and\s+', '', body)
    body = re.sub(r'\s+and\s+event\.type\s*=\s*"[^"]*"', '', body)
    body = re.sub(r'^\(\s*(.*)\s*\)$', r'\1', body.strip())
    return body.strip()


# DV schema  ->  WEL parser schema (microsoft_windows_eventlog-latest).
# Sysmon (EID=1) and Security (EID=4688) channels use slightly different
# field names; the WEL parser exposes Sysmon-style Image/ParentImage AND
# Security-style NewProcessName/ParentProcessName. We rewrite onto the
# more permissive Sysmon names because they're closer to S1 DV.
DV_TO_WEL = [
    (r'\btgt\.process\.cmdline\b',          'CommandLine'),
    (r'\btgt\.process\.image\.path\b',      'Image'),
    (r'\btgt\.process\.displayName\b',      'OriginalFileName'),
    (r'\btgt\.process\.publisher\b',        'Company'),
    (r'\bsrc\.process\.image\.path\b',      'ParentImage'),
    (r'\bsrc\.process\.cmdline\b',          'ParentCommandLine'),
    (r'\bsrc\.process\.user\.name\b',       'User'),
]


def wel_map(pq_body: str) -> str:
    """Rewrite a faithful DV-schema PQ body to query the
    microsoft_windows_eventlog-latest parser instead. Strategy:
       - replace tgt.process.* / src.process.* with WEL field names
       - replace `event.type="Process Creation"` with EID filter
       - replace `endpoint.os="windows"` with dataSource.name='Windows Event Logs'
       - prepend a parser-name pin so the filter narrows fast
    """
    body = pq_body
    for pat, repl in DV_TO_WEL:
        body = re.sub(pat, repl, body)
    body = re.sub(r'event\.type\s*=\s*"Process Creation"',
                  "(EventID=4688 or EventID=1)", body)
    body = re.sub(r'endpoint\.os\s*=\s*"windows"',
                  "dataSource.name='Windows Event Logs'", body)
    # Drop any leftover DV-only field comparisons that didn't map (would
    # otherwise null-filter every row). Only one we've seen: integrityLevel.
    body = re.sub(r'(?:\(\s*)?[\w.]+\.integrityLevel\s*=\s*"[^"]*"'
                  r'\s+(?:and|or)\s+', '', body)
    return body.strip()


def pq(query: str, hours: int = 24) -> tuple[int, str, int]:
    end = int(time.time() * 1000); start = end - hours * 3600 * 1000
    payload = {"token": SDL_KEY, "query": query,
               "startTime": str(start), "endTime": str(end)}
    req = urllib.request.Request(
        f"{SDL_BASE}/api/powerQuery",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            d = json.loads(r.read())
            return 200, "ok", len(d.get("values") or [])
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:250], 0


def deploy_rule(name: str, description: str, pq_body: str) -> tuple[int, str]:
    """POST a Scheduled-PQ rule to S1 Mgmt API."""
    if not (S1_CONS and S1_TOK):
        return 0, "no S1_CONSOLE_URL or S1_CONSOLE_API_TOKEN in config"
    payload = {
        "data": {
            "name": name,
            "description": description,
            "severity": "Medium",
            "expirationMode": "Permanent",
            "queryType": "scheduled",
            "queryLang": "2.0",
            "status": "Draft",
            "treatAsThreat": "UNDEFINED",
            "networkQuarantine": False,
            "coolOffSettings": {"renotifyMinutes": 60},
            "scheduledParams": {
                "query": pq_body,
                "lookbackWindowMinutes": 30,
                "runIntervalMinutes": 5,
                "threshold": {"value": 0, "operator": "Greater"},
            },
        },
        "filter": {"siteIds": [SITE_ID]},
    }
    req = urllib.request.Request(
        f"{S1_CONS}/web/api/v2.1/cloud-detection/rules",
        data=json.dumps(payload).encode(), method="POST")
    req.add_header("Authorization", f"ApiToken {S1_TOK}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.loads(r.read())
            rid = (d.get("data") or {}).get("id") or "?"
            return 200, f"created id={rid}"
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


# ============================================================ main =========
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--deploy", action="store_true",
                    help="Also create each valid PQ as an SDL Scheduled rule.")
    args = ap.parse_args()

    print(f"\n{'='*78}\n  Sigma -> PowerQuery  (faithful + relaxed + WEL) "
          f"-> SDL rule\n{'='*78}\n")
    print(f"  Backend         : pysigma-backend-sentinelone-pq")
    print(f"  Tenant SDL      : {SDL_BASE}")
    print(f"  Tenant Mgmt API : {S1_CONS}")
    print(f"  Deploy rules    : {'YES' if args.deploy else 'no (use --deploy)'}")
    print(f"  Output          : {OUT}\n")

    # Site-id auto-discovery (only needed for --deploy).
    global SITE_ID
    if args.deploy and not SITE_ID:
        try:
            req = urllib.request.Request(
                f"{S1_CONS}/web/api/v2.1/sites?limit=10")
            req.add_header("Authorization", f"ApiToken {S1_TOK}")
            req.add_header("Accept", "application/json")
            with urllib.request.urlopen(req, timeout=20) as r:
                sites = ((json.loads(r.read()).get("data") or {})
                         .get("sites") or [])
            if not sites:
                print("  FATAL: --deploy requested but no sites visible "
                      "to this token.")
                return 1
            SITE_ID = sites[0]["id"]
            print(f"  Site discovered : {SITE_ID} "
                  f"({sites[0].get('name')})\n")
        except urllib.error.HTTPError as e:
            print(f"  FATAL site discovery: HTTP {e.code} "
                  f"{e.read().decode()[:200]}")
            return 1

    # Pre-fetch the two relevant trees once
    print("--- listing sigmahq/sigma rule paths via gh api ---")
    pc_only        = list_sigma_rules(allow_powershell=False)
    pc_and_pwsh    = list_sigma_rules(allow_powershell=True)
    print(f"  process_creation/        : {len(pc_only)} rules")
    print(f"  process_creation/ + powershell/ : {len(pc_and_pwsh)} rules\n")

    summary: list[dict[str, Any]] = []
    for i, (tactic, tech, kws, allow_pwsh) in enumerate(WANTED, 1):
        paths = pc_and_pwsh if allow_pwsh else pc_only
        rec: dict[str, Any] = {"i": i, "tactic": tactic, "tech": tech}
        print(f"[{i:02d}/10] {tactic} :: {tech}")
        path = pick(paths, kws)
        if not path:
            print(f"    PICK    : no match for {kws}\n")
            rec["status"] = "no_match"; summary.append(rec); continue
        print(f"    PICK    : {path}")
        rec["path"] = path
        try:
            raw = fetch(f"{SIGMA_RAW}/{path}").decode("utf-8")
        except Exception as e:
            print(f"    FETCH   : FAIL {e}\n")
            rec["status"] = "fetch_failed"; summary.append(rec); continue
        stem = pathlib.Path(path).stem
        (OUT / f"{stem}.yml").write_text(raw)

        try:
            pq_body = convert(raw)
        except Exception as e:
            print(f"    CONVERT : FAIL  {e}\n")
            rec["status"] = "convert_failed"; rec["err"] = str(e)
            summary.append(rec); continue
        relaxed_body = relax(pq_body)
        wel_body     = wel_map(pq_body)
        (OUT / f"{stem}.pq").write_text(pq_body)
        (OUT / f"{stem}.relaxed.pq").write_text(relaxed_body)
        (OUT / f"{stem}.wel.pq").write_text(wel_body)
        rec["pq_chars"]      = len(pq_body)
        rec["relaxed_chars"] = len(relaxed_body)
        rec["wel_chars"]     = len(wel_body)
        print(f"    CONVERT : OK   faithful={len(pq_body)}c  "
              f"relaxed={len(relaxed_body)}c  wel={len(wel_body)}c")

        # smoke test all three
        c1, _, r1 = pq(pq_body)
        c2, _, r2 = pq(relaxed_body)
        c3, e3, r3 = pq(wel_body)
        rec.update({"fa_http": c1, "fa_rows": r1,
                    "re_http": c2, "re_rows": r2,
                    "wel_http": c3, "wel_rows": r3,
                    "wel_err": e3 if c3 != 200 else ""})
        print(f"    TEST FA : HTTP {c1}  rows={r1}")
        print(f"    TEST RE : HTTP {c2}  rows={r2}")
        print(f"    TEST WEL: HTTP {c3}  rows={r3}"
              f"{'  err=' + e3[:120] if c3 != 200 else ''}")

        valid = (c1 == 200) or (c3 == 200)
        rec["status"] = ("FIRES" if (r1 > 0 or r2 > 0 or r3 > 0)
                         else "valid_no_data" if valid
                         else "PQ_ERROR")

        # deploy faithful (only) if requested + valid
        if args.deploy and c1 == 200:
            rule_name = (f"[Sigma->PQ] {tactic} / {tech} "
                         f"({pathlib.Path(path).stem})")[:128]
            desc = (f"Auto-converted from SigmaHQ/sigma "
                    f"{path} via pysigma-backend-sentinelone-pq. "
                    f"Faithful S1 DV schema.")
            dc, dmsg = deploy_rule(rule_name, desc, pq_body)
            rec["deploy_http"] = dc; rec["deploy_msg"] = dmsg
            if dc == 200:
                # dmsg shape is "created id=<id>"; extract just the id
                rec["rule_id"] = dmsg.split("id=")[-1].strip()
                rec["pq_file"] = f"{pathlib.Path(path).stem}.pq"
            print(f"    DEPLOY  : HTTP {dc}  {dmsg[:160]}")
        print()
        summary.append(rec)

    # --- summary ---
    print(f"{'='*78}\n  SUMMARY  (rows = events matched in last 24 h)\n"
          f"{'='*78}")
    hdr = (f"  {'#':>3}  {'tactic':<18}{'technique':<26}"
           f"{'fa':>5}{'re':>5}{'wel':>5}  status")
    print(hdr); print("  " + "-" * (len(hdr) - 2))
    for s in summary:
        print(f"  {s['i']:>3}  {s['tactic']:<18}{s['tech']:<26}"
              f"{s.get('fa_rows','-')!s:>5}{s.get('re_rows','-')!s:>5}"
              f"{s.get('wel_rows','-')!s:>5}  {s.get('status','-')}")
    fires   = sum(1 for s in summary
                  if any(s.get(k, 0) and s[k] > 0
                         for k in ('fa_rows', 're_rows', 'wel_rows')))
    valid   = sum(1 for s in summary
                  if s.get('status') in ('valid_no_data', 'FIRES'))
    failed  = sum(1 for s in summary
                  if s.get('status') in ('no_match', 'fetch_failed',
                                         'convert_failed', 'PQ_ERROR'))
    print(f"\n  Rules with any matches : {fires}/10")
    print(f"  Syntactically valid     : {valid}/10")
    print(f"  Failed / not matched    : {failed}/10")
    if args.deploy:
        deployed = [s for s in summary if s.get('deploy_http') == 200]
        print(f"  SDL rules created       : {len(deployed)}/10")
        # Persist the (rule_id, pq_file) map for verify scripts.
        ids_file = HERE / "deployed_rule_ids.json"
        ids_file.write_text(json.dumps(
            {"tenant": S1_CONS,
             "site_id": SITE_ID,
             "rules": [{"rule_id":  s["rule_id"],
                        "pq_file":  s["pq_file"],
                        "tactic":   s["tactic"],
                        "tech":     s["tech"]}
                       for s in deployed]}, indent=2))
        print(f"  Deployed IDs            : {ids_file}")
    print(f"  Artefacts               : {OUT}/")
    print(f"\n  Next steps:")
    print(f"   - inspect {OUT}/*.wel.pq for WEL variants")
    print(f"   - re-run with --deploy to create SDL Scheduled rules")
    print(f"   - verify with verify_rule_exists_via_put.py")
    print(f"   - check console UI: {S1_CONS}/#/cloud-detection/rules\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
