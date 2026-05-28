#!/usr/bin/env python3
"""
probe_wel_schema.py

Probe the tenant's Singularity Data Lake to discover what fields the
`microsoft_windows_eventlog-latest` parser emits. Output guides the WEL
mapping pipeline in convert_test_deploy_sigma.py.

Runs a series of read-only PowerQuery probes for the last 24 h. No state
changes -- safe to re-run.
"""
from __future__ import annotations
import json
import os
import pathlib
import time
import urllib.request
import urllib.error

HERE = pathlib.Path(__file__).resolve().parent
_CFG_PATH = os.environ.get("SIEM_TOOLKIT_CONFIG",
                           str(HERE / "tenant_config.json"))
CFG  = json.load(open(_CFG_PATH))
BASE = CFG["SDL_XDR_URL"].rstrip("/")
TOK  = CFG["SDL_LOG_READ_KEY"]


def pq(query: str, hours: int = 24) -> tuple[str, list, list[str]]:
    end = int(time.time() * 1000); start = end - hours * 3600 * 1000
    req = urllib.request.Request(
        f"{BASE}/api/powerQuery",
        data=json.dumps({"token": TOK, "query": query,
                         "startTime": str(start),
                         "endTime": str(end)}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        d = json.loads(urllib.request.urlopen(req, timeout=60).read())
        return ("OK", d.get("values") or [],
                [c.get("name") for c in (d.get("columns") or [])])
    except urllib.error.HTTPError as e:
        return (f"HTTP{e.code}", [e.read().decode()[:250]], [])
    except Exception as e:
        return (f"{type(e).__name__}", [str(e)], [])


PROBES: list[tuple[str, str]] = [
    ("WEL distribution by EventID",
     "parser.name='microsoft_windows_eventlog-latest' "
     "| group n=count() by EventID | sort -n | limit 20"),
    ("WEL channel / provider distribution",
     "parser.name='microsoft_windows_eventlog-latest' "
     "| group n=count() by Channel | sort -n | limit 15"),
    ("WEL ProviderName distribution",
     "parser.name='microsoft_windows_eventlog-latest' "
     "| group n=count() by ProviderName | sort -n | limit 15"),
    ("WEL EID=4688 row sample (Security: process creation)",
     "parser.name='microsoft_windows_eventlog-latest' EventID=4688 "
     "| columns CommandLine, NewProcessName, ParentProcessName, "
     "SubjectUserName, ProcessId | limit 3"),
    ("WEL EID=1 row sample (Sysmon: process creation)",
     "parser.name='microsoft_windows_eventlog-latest' EventID=1 "
     "| columns CommandLine, Image, ParentImage, User, ProcessGuid | limit 3"),
    ("Probe alternate camelCase fields on the WEL parser",
     "parser.name='microsoft_windows_eventlog-latest' "
     "| columns commandLine, image, parentImage, eventId | limit 3"),
    ("Probe nested process.* fields on the WEL parser",
     "parser.name='microsoft_windows_eventlog-latest' "
     "| columns process.cmdLine, process.image.path, "
     "process.parentImage.path, event.id | limit 3"),
    ("EID=4688 count alone (volume sanity)",
     "parser.name='microsoft_windows_eventlog-latest' EventID=4688 "
     "| group n=count() | limit 1"),
    ("EID=1 count alone",
     "parser.name='microsoft_windows_eventlog-latest' EventID=1 "
     "| group n=count() | limit 1"),
    ("Any cmdline-bearing record sample (raw)",
     "parser.name='microsoft_windows_eventlog-latest' "
     "| columns rawMessage | limit 1"),
]


def main() -> int:
    print(f"\n{'='*78}\n  WEL parser schema probe -- last 24 h\n  "
          f"endpoint: {BASE}/api/powerQuery\n{'='*78}")
    for label, query in PROBES:
        status, rows, cols = pq(query)
        oneline = query.replace("\n", " ")
        print(f"\n--- {label} ---")
        print(f"  query : {oneline[:160]}{'...' if len(oneline)>160 else ''}")
        print(f"  status: {status}   cols: {cols}")
        for r in rows[:10]:
            r_str = str(r)
            print(f"    {r_str[:240]}{'...' if len(r_str)>240 else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
