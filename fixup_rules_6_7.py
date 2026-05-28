#!/usr/bin/env python3
"""
fixup_rules_6_7.py

Re-runs the convert -> test -> deploy pipeline for ONLY the 2 rules that
failed in convert_test_deploy_sigma.py:

  #6 Reconnaissance T1016  --  netsh port forwarding (the original
     `netsh_fw_add_rule.yml` uses a Sigma `|fieldref` modifier the
     S1-PQ backend doesn't support; switch to
     `netsh_port_forwarding.yml`).

  #7 Discovery T1087.002  --  AdsiSearcher (no .yml under
     rules/windows/process_creation/ or rules/windows/powershell/ is
     named adsisearcher; replace with `whoami /priv` which covers
     T1033 + T1087 Account Discovery and is highly diagnostic).

Runs the same 3-variant pipeline (faithful, relaxed, WEL-mapped),
smoke-tests each, and POSTs the faithful PQ as an SDL Scheduled rule.
"""
from __future__ import annotations
import json, os, pathlib, re, subprocess, sys, time
import urllib.error, urllib.request

HERE     = pathlib.Path(__file__).resolve().parent
VENV_PY  = os.environ.get("SIGMA_VENV_PY", "/tmp/sigma_venv/bin/python3")
OUT      = pathlib.Path(os.environ.get(
    "SIGMA_OUT_DIR", "/tmp/sigma_converted_v4"))
_CFG_PATH = os.environ.get("SIEM_TOOLKIT_CONFIG",
                          str(HERE / "tenant_config.json"))
CFG      = json.load(open(_CFG_PATH))
SDL_BASE = CFG["SDL_XDR_URL"].rstrip("/")
SDL_KEY  = CFG["SDL_LOG_READ_KEY"]
S1_CONS  = CFG["S1_CONSOLE_URL"].rstrip("/")
S1_TOK   = CFG["S1_CONSOLE_API_TOKEN"].rstrip(".")
SITE_ID  = os.environ.get("SITE_ID", "")  # auto-discovered in main()
SIGMA_RAW = "https://raw.githubusercontent.com/SigmaHQ/sigma/master"

# (tactic, technique, sigmahq/sigma path)
REPLACEMENTS = [
    ("Reconnaissance", "T1016 netsh port forwarding",
     "rules/windows/process_creation/"
     "proc_creation_win_netsh_port_forwarding.yml"),
    ("Discovery", "T1087/T1033 whoami /priv",
     "rules/windows/process_creation/"
     "proc_creation_win_whoami_priv_discovery.yml"),
]


def strip_unsupported_sigma_fields(yaml_text: str) -> str:
    """Remove Sigma fields that the S1-PQ backend doesn't map.

    The backend errors with a `{CommandLine}, {Company}, ...` field list
    whenever it sees a key it has no mapping for. The only one we hit in
    practice is `OriginalFileName`, which most LOLBins-style rules use as
    an alternate way to fingerprint a process; the rule remains semantic
    once removed because `Image|endswith:` is the primary selector.

    Strategy: drop any selection block that ONLY contains OriginalFileName,
    OR delete the lone OriginalFileName line from a mixed list.
    """
    out: list[str] = []
    skip_block = False
    for line in yaml_text.splitlines():
        s = line.strip()
        # Lone OriginalFileName key in a flow style ("- OriginalFileName: 'netsh.exe'")
        if s.startswith("- OriginalFileName:") or s.startswith("OriginalFileName:"):
            continue
        out.append(line)
    return "\n".join(out)


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "siem-toolkit"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


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
        err = res.stderr.strip().splitlines()
        raise RuntimeError((err[-1] if err else "(no stderr)")[:300])
    return res.stdout.strip()


def relax(pq_body: str) -> str:
    b = pq_body
    b = re.sub(r'endpoint\.os\s*=\s*"[^"]*"\s+and\s+', '', b)
    b = re.sub(r'\s+and\s+endpoint\.os\s*=\s*"[^"]*"', '', b)
    b = re.sub(r'event\.type\s*=\s*"[^"]*"\s+and\s+', '', b)
    b = re.sub(r'\s+and\s+event\.type\s*=\s*"[^"]*"', '', b)
    return re.sub(r'^\(\s*(.*)\s*\)$', r'\1', b.strip()).strip()


DV_TO_WEL = [
    (r'\btgt\.process\.cmdline\b',     'CommandLine'),
    (r'\btgt\.process\.image\.path\b', 'Image'),
    (r'\btgt\.process\.displayName\b', 'OriginalFileName'),
    (r'\btgt\.process\.publisher\b',   'Company'),
    (r'\bsrc\.process\.image\.path\b', 'ParentImage'),
    (r'\bsrc\.process\.cmdline\b',     'ParentCommandLine'),
    (r'\bsrc\.process\.user\.name\b',  'User'),
]


def wel_map(pq_body: str) -> str:
    b = pq_body
    for pat, repl in DV_TO_WEL:
        b = re.sub(pat, repl, b)
    b = re.sub(r'event\.type\s*=\s*"Process Creation"',
               "(EventID=4688 or EventID=1)", b)
    b = re.sub(r'endpoint\.os\s*=\s*"windows"',
               "dataSource.name='Windows Event Logs'", b)
    return b.strip()


def pq(query: str, hours: int = 24) -> tuple[int, str, int]:
    end = int(time.time() * 1000); start = end - hours * 3600 * 1000
    req = urllib.request.Request(
        f"{SDL_BASE}/api/powerQuery",
        data=json.dumps({"token": SDL_KEY, "query": query,
                         "startTime": str(start),
                         "endTime": str(end)}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return 200, "ok", len(
                (json.loads(r.read()).get("values") or []))
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:250], 0


def deploy(name: str, desc: str, body: str) -> tuple[int, str]:
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
        "filter": {"siteIds": [SITE_ID]}}
    if not SITE_ID:
        return 0, "SITE_ID not set / discoverable"
    req = urllib.request.Request(
        f"{S1_CONS}/web/api/v2.1/cloud-detection/rules",
        data=json.dumps(payload).encode(), method="POST")
    req.add_header("Authorization", f"ApiToken {S1_TOK}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.loads(r.read())
            return 200, f"id={(d.get('data') or {}).get('id', '?')}"
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


def main() -> int:
    global SITE_ID
    print(f"\n{'='*78}\n  Fix-up: re-convert + deploy rules #6 and #7"
          f"\n{'='*78}\n")
    if not SITE_ID:
        try:
            req = urllib.request.Request(
                f"{S1_CONS}/web/api/v2.1/sites?limit=10")
            req.add_header("Authorization", f"ApiToken {S1_TOK}")
            req.add_header("Accept", "application/json")
            sites = ((json.loads(urllib.request.urlopen(req, timeout=20).read()
                                 ).get("data") or {}).get("sites") or [])
            if sites:
                SITE_ID = sites[0]["id"]
                print(f"  Site discovered : {SITE_ID} "
                      f"({sites[0].get('name')})\n")
            else:
                print("  FATAL: no sites visible to this token.")
                return 1
        except urllib.error.HTTPError as e:
            print(f"  FATAL site discovery: HTTP {e.code} "
                  f"{e.read().decode()[:200]}")
            return 1
    for i, (tactic, tech, path) in enumerate(REPLACEMENTS, start=6):
        idx = "06" if i == 6 else "07"
        print(f"[{idx}/10] {tactic} :: {tech}")
        print(f"    SIGMA   : {path}")
        try:
            raw = fetch(f"{SIGMA_RAW}/{path}").decode("utf-8")
        except Exception as e:
            print(f"    FETCH   : FAIL {e}\n"); continue
        stem = pathlib.Path(path).stem
        (OUT / f"{stem}.yml").write_text(raw)
        cleaned = strip_unsupported_sigma_fields(raw)
        if cleaned != raw:
            (OUT / f"{stem}.cleaned.yml").write_text(cleaned)
            removed = len(raw.splitlines()) - len(cleaned.splitlines())
            print(f"    PREP    : stripped {removed} OriginalFileName "
                  f"line(s) the S1-PQ backend can't map")
        try:
            body = convert(cleaned)
        except Exception as e:
            print(f"    CONVERT : FAIL {e}\n"); continue
        re_body  = relax(body)
        wel_body = wel_map(body)
        (OUT / f"{stem}.pq").write_text(body)
        (OUT / f"{stem}.relaxed.pq").write_text(re_body)
        (OUT / f"{stem}.wel.pq").write_text(wel_body)
        print(f"    CONVERT : OK   faithful={len(body)}c  "
              f"relaxed={len(re_body)}c  wel={len(wel_body)}c")
        print(f"        FA  : {body[:160]}{'...' if len(body)>160 else ''}")
        print(f"        WEL : {wel_body[:160]}"
              f"{'...' if len(wel_body)>160 else ''}")

        c1, _, r1 = pq(body)
        c2, _, r2 = pq(re_body)
        c3, e3, r3 = pq(wel_body)
        print(f"    TEST FA : HTTP {c1}  rows={r1}")
        print(f"    TEST RE : HTTP {c2}  rows={r2}")
        print(f"    TEST WEL: HTTP {c3}  rows={r3}"
              f"{'  err=' + e3[:100] if c3 != 200 else ''}")

        if c1 == 200:
            rule_name = f"[Sigma->PQ] {tactic} / {tech} ({stem})"[:128]
            dc, dmsg = deploy(rule_name,
                              f"Auto-converted from SigmaHQ/sigma {path}",
                              body)
            print(f"    DEPLOY  : HTTP {dc}  {dmsg[:160]}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
