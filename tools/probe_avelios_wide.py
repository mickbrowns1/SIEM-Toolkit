#!/usr/bin/env python3
"""Search wider windows for Avelios Medical events."""
import json, time, urllib.request
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


def pq(query, start_ms, end_ms, mc=5):
    body = json.dumps({"token": KEY, "query": query,
                       "startTime": start_ms, "endTime": end_ms,
                       "maxCount": mc}).encode()
    req = urllib.request.Request(BASE + '/api/powerQuery', data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        return json.loads(urllib.request.urlopen(req, timeout=60).read())
    except Exception as e:
        return {"_err": str(e)[:200]}


for days in (1, 3, 7):
    start = NOW - days * 24 * 3600 * 1000
    print(f"\n=== last {days}d ===")
    d = pq("| group n=count() by dataSource.name | sort -n | limit 30", start, NOW, mc=30)
    if "_err" in d:
        print(d["_err"]); continue
    for row in d.get("values", []):
        name = row[0]
        if name and "velio" in name.lower():
            print(f"  HIT: {row}")
    # show top 10 in this window
    for row in (d.get("values", []) or [])[:10]:
        print(f"  {row}")
