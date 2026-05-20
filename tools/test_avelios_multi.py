#!/usr/bin/env python3
"""Verify the Parser Test Runner accepts multi-line NDJSON for JSON-mode parsers."""
import json, urllib.request
import os

LINES = [
    '{"timestamp":"2026-05-14T00:00:41.969Z","event_type":"DATA_IMPORT_COMPLETED","event_category":"data_transfer","severity":"INFO","outcome":"success","source":{"application":"Avelios Medical"}}',
    '{"timestamp":"2026-05-14T00:07:41.969Z","event_type":"PERFORMANCE_DEGRADATION","event_category":"system","severity":"MEDIUM","outcome":"success","source":{"application":"Avelios Medical"}}',
    '{"timestamp":"2026-05-14T00:24:41.969Z","event_type":"MALWARE_DETECTED","event_category":"security","severity":"CRITICAL","outcome":"detected","source":{"application":"Avelios Medical"},"details":{"malware_name":"Trojan.GenericKD"}}',
]

body = json.dumps({"parser_name": "Avelios-Medical-OCSF", "log_line": "\n".join(LINES)}).encode()
req = urllib.request.Request(
    "http://localhost:8001/api/quality/test-parser",
    data=body, headers={"Content-Type": "application/json"})
r = json.loads(urllib.request.urlopen(req, timeout=30).read())

print(f"matched      = {r.get('matched')}")
print(f"mode         = {r.get('mode')}")
print(f"payloads     = {r.get('payload_count')}  (showing {r.get('showing_payload')})")
print(f"extracted    = {r.get('extracted_count')}")
print(f"derived      = {r.get('derived_count')}")
print(f"parse_errors = {r.get('parse_errors')}")
print()
print("rewrites applied (first payload):")
for rw in r.get("rewrites_applied", [])[:10]:
    print(f"  {rw['input']:<18} -> {rw['output']:<28} = {rw['result']!r}")
