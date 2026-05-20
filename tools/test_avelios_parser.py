#!/usr/bin/env python3
import json, urllib.request
import os

log = '{"timestamp": "2026-05-14T00:24:41.969Z", "event_id": "d5c76dd2-5320-4b32-bd27-09acedfb5fdb", "event_type": "MALWARE_DETECTED", "event_category": "security", "severity": "CRITICAL", "source": {"application": "Avelios Medical", "module": "SecurityMonitor"}, "outcome": "detected", "details": {"malware_name": "Trojan.GenericKD"}}'

body = json.dumps({"parser_name": "Avelios-Medical-OCSF", "log_line": log}).encode()
req = urllib.request.Request(
    "http://localhost:8001/api/quality/test-parser",
    data=body, headers={"Content-Type": "application/json"})
r = json.loads(urllib.request.urlopen(req, timeout=30).read())

print(f"matched={r.get('matched')}  mode={r.get('mode')}  "
      f"extracted={r.get('extracted_count')}  derived={r.get('derived_count')}")
print()
print("json-extract fields (first 12):")
for f in [x for x in r.get("fields", []) if x.get("source") == "json-extract"][:12]:
    print(f"  {f['field']:<32} = {str(f['value'])[:50]}")
print()
print("rewrites applied:")
for rw in r.get("rewrites_applied", [])[:12]:
    print(f"  {rw['input']:<18} -> {rw['output']:<28} = {rw['result']!r}")
