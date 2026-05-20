#!/usr/bin/env python3
"""Inspect Avelios Medical events: one query, full row dump, then field stats from Python."""
import json, time, urllib.request, collections
import os

def _load_sdl_cfg():
    import json as _j, os as _o, sys as _s
    here = _o.path.dirname(_o.path.abspath(__file__))
    candidates = [
        _o.environ.get("SDL_CONFIG"),
        _o.path.join(here, "sdl_config.json"),
        _o.path.join(here, "..", "sdl_config.json"),
    ]
    for p in candidates:
        if p and _o.path.exists(p):
            with open(p) as fh:
                return _j.load(fh)
    _s.stderr.write(
        "ERROR: no SDL config found. Set $SDL_CONFIG or create sdl_config.json "
        "(see sdl_config.example.json)\n")
    _s.exit(2)


CFG = _load_sdl_cfg()
BASE, KEY = CFG['base_url'].rstrip('/'), CFG['log_read_key']
NOW = int(time.time() * 1000)
START = NOW - 72 * 3600 * 1000          # last 3 days


def pq(query, mc=200):
    body = json.dumps({"token": KEY, "query": query,
                       "startTime": START, "endTime": NOW,
                       "maxCount": mc}).encode()
    req = urllib.request.Request(BASE + '/api/powerQuery', data=body,
                                 headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=60).read())


print("Fetching Avelios Medical sample (max 200, last 72h) ...")
d = pq("| filter dataSource.name == 'Avelios Medical' | limit 200")
cols = [c['name'] if isinstance(c, dict) else c for c in d.get('columns', [])]
vals = d.get('values', []) or []
print(f"Columns returned ({len(cols)}): {cols}")
print(f"Rows: {len(vals)}")
print()

# Tally non-null rate per returned column
counts = {c: 0 for c in cols}
for row in vals:
    for c, v in zip(cols, row):
        if v not in (None, '', 'null'):
            counts[c] += 1
print("=== Column populated-rate (out of returned columns) ===")
for c in cols:
    n = counts[c]
    pct = round(100 * n / max(1, len(vals)), 1)
    print(f"  {c:<35} {n:>4} / {len(vals)}   {pct:>5}%")

print()
print("=== First 2 events (pretty) ===")
for row in vals[:2]:
    print(json.dumps(dict(zip(cols, row)), indent=2, default=str)[:1500])
    print("---")

print()
print("=== Distinct fields IN the message body (if JSON) ===")
# If the events carry a structured body, peek inside it
field_freq = collections.Counter()
for row in vals:
    rd = dict(zip(cols, row))
    msg = rd.get('message') or rd.get('body') or rd.get('attributes')
    if isinstance(msg, str):
        try:
            j = json.loads(msg)
        except Exception:
            continue
    else:
        j = msg
    if isinstance(j, dict):
        def walk(obj, prefix=''):
            for k, v in obj.items():
                key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, dict):
                    walk(v, key)
                else:
                    field_freq[key] += 1
        walk(j)
for k, c in field_freq.most_common(40):
    print(f"  {k:<45} in {c:>3} events")
