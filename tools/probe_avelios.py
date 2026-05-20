#!/usr/bin/env python3
"""Probe the SDL tenant to understand why Avelios Medical field-population shows 0%."""
import json, time, urllib.request, urllib.error
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
BASE = CFG['base_url'].rstrip('/')
KEY  = CFG['log_read_key']
END_MS   = int(time.time() * 1000)
START_MS = END_MS - 24 * 3600 * 1000   # last 24h


def pq(query: str, max_count: int = 10) -> dict:
    body = json.dumps({
        "token": KEY, "query": query,
        "startTime": START_MS, "endTime": END_MS,
        "maxCount": max_count,
    }).encode()
    req = urllib.request.Request(BASE + '/api/powerQuery', data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        return json.loads(urllib.request.urlopen(req, timeout=30).read())
    except urllib.error.HTTPError as e:
        return {"_err": f"HTTP {e.code}: {e.read().decode()[:200]}"}
    except Exception as e:
        return {"_err": str(e)[:200]}


def show(label, d):
    if "_err" in d:
        print(f"[ERR] {label}: {d['_err']}"); return
    cols = [c['name'] if isinstance(c, dict) else c for c in d.get('columns', [])]
    vals = d.get('values', []) or d.get('matches', [])
    print(f"[OK ] {label}  cols={cols}  rows={len(vals)}")
    for v in vals[:8]:
        print(f"     {v}")


# 1. Distinct dataSource.name values containing 'velio'
print("=" * 70)
print("1. Source-name spellings containing 'velio'")
print("=" * 70)
show("by dataSource.name",
     pq("| group n=count() by dataSource.name | sort -n | limit 50", max_count=50))

# 2. Try a few candidate names
print()
print("=" * 70)
print("2. Try filtering by candidate names")
print("=" * 70)
for cand in ["Avelios Medical", "Avelios-Medical", "Avelios-Medical-OCSF",
             "avelios", "Avelios"]:
    d = pq(f"| filter dataSource.name == '{cand}' | group n=count()", max_count=1)
    n = (d.get('values') or [[None]])[0][0] if 'values' in d else d
    print(f"  {cand!r:<35}  -> {n}")
for cand in ["Avelios Medical", "Avelios-Medical-OCSF", "avelios"]:
    d = pq(f"| filter dataSource.name contains '{cand}' | group n=count()", max_count=1)
    n = (d.get('values') or [[None]])[0][0] if 'values' in d else d
    print(f"  contains {cand!r:<25}  -> {n}")

# 3. Sample one raw event to see what column names actually come back
print()
print("=" * 70)
print("3. Sample one event — what keys/columns are returned?")
print("=" * 70)
d = pq("| filter dataSource.name contains 'velio' | limit 1", max_count=1)
if "_err" in d:
    print("  ", d["_err"])
else:
    print("  columns:", [c['name'] if isinstance(c, dict) else c for c in d.get('columns', [])][:30])
    print("  first row sample:", str((d.get('values') or [None])[0])[:400])

# 4. If we got columns, check which OCSF fields exist
print()
print("=" * 70)
print("4. Field presence in last 24h for Avelios (using columns command)")
print("=" * 70)
d = pq("| filter dataSource.name contains 'velio' | "
       "columns dataSource.name, metadata.product.name, metadata.event_code, "
       "actor.user.name, src_endpoint.ip, dst_endpoint.ip | limit 5",
       max_count=5)
show("columns view", d)
