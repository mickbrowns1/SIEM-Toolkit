#!/usr/bin/env python3
"""Probe what PowerQuery syntax this SDL tenant accepts."""
import json, time, urllib.request, urllib.error, sys
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
URL = CFG['base_url'].rstrip('/') + '/api/powerQuery'
END_MS = int(time.time() * 1000)
START_MS = END_MS - 3600 * 1000  # last hour


def run(label: str, query: str):
    body = json.dumps({
        "token":     CFG['log_read_key'],
        "query":     query,
        "startTime": START_MS,
        "endTime":   END_MS,
        "maxCount":  5,
    }).encode()
    req = urllib.request.Request(URL, data=body, headers={"Content-Type": "application/json"})
    try:
        resp = urllib.request.urlopen(req, timeout=30).read()
        d = json.loads(resp)
        st = d.get('status', '?')
        cols = d.get('columns') or []
        vals = d.get('values') or d.get('matches') or []
        print(f"[OK ] {label:<40} status={st} cols={len(cols)} rows={len(vals)}")
        if vals:
            print(f"      sample={str(vals[0])[:160]}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            j = json.loads(body)
            msg = j.get('message', body)[:200]
        except Exception:
            msg = body[:200]
        print(f"[ERR] {label:<40} HTTP {e.code}: {msg}")
    except Exception as e:
        print(f"[ERR] {label:<40} {type(e).__name__}: {str(e)[:160]}")


CASES = [
    ("leading-pipe single-stage",  "| group total=count()"),
    ("no-pipe single-stage",       "group total=count()"),
    ("leading-pipe multi-stage",   "| group events=count() by dataSource.name | sort -events | limit 5"),
    ("no-pipe multi-stage",        "group events=count() by dataSource.name | sort -events | limit 5"),
    ("no-pipe trim sort",          "group events=count() by dataSource.name | limit 5"),
    ("filter then group",          "dataSource.name=='SentinelOne' | group events=count()"),
    ("filter (modern keyword)",    "filter dataSource.name=='SentinelOne' | group events=count()"),
    ("dataset-style with sort",    "group events=count() by dataSource.name | sort events desc | limit 5"),
    ("count() as alias",           "| count() as events"),
    ("group by event.type",        "group events=count() by event.type | limit 5"),
]

print(f"URL: {URL}")
print(f"Window: last 1h ({START_MS}..{END_MS} ms)")
print()
for label, q in CASES:
    run(label, q)
