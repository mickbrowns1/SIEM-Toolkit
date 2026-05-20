#!/usr/bin/env python3
"""
Pull every parser under /logParsers/ from the SDL tenant and drop it into
./parsers/ so the SIEM-Toolkit Parser Test Runner can list it.

Auth: config_read_key from sentinelone-sdl-api/config.json
"""
from __future__ import annotations
import json
import os
import sys
import urllib.request
import urllib.parse
import urllib.error

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


SDL_CFG_PATH = os.environ.get('SDL_CONFIG')  # placeholder; cfg loaded below
DEST = os.environ.get('PARSERS_DIR', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'parsers'))
def call(base_url: str, token: str, path: str, params: dict) -> dict:
    """POST with JSON body — works for both listFiles and getFile on SDL."""
    url = f"{base_url.rstrip('/')}{path}"
    body = json.dumps({**params, "token": token}).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:300]
        raise RuntimeError(f"HTTP {e.code} {path}: {body}")


def main() -> int:
    cfg = _load_sdl_cfg()
    base = cfg["base_url"]
    # config_read_key first (per docs), fall back to console_api_token
    token = cfg.get("config_read_key") or cfg.get("console_api_token")
    if not token:
        print("No config_read_key or console_api_token in config.json", file=sys.stderr)
        return 2

    print(f"Listing /logParsers/ from {base} ...")
    res = call(base, token, "/api/listFiles", {"pathPrefix": "/logParsers/"})
    paths = res.get("paths", [])
    print(f"Found {len(paths)} files under /logParsers/")

    os.makedirs(DEST, exist_ok=True)
    fetched, skipped, failed = 0, 0, []

    for p in paths:
        # Strip leading /logParsers/, sanitize for filesystem
        name = p.rsplit("/", 1)[-1] or "_unnamed"
        # Avoid colliding with existing sample files? Always overwrite to keep fresh.
        try:
            r = call(base, token, "/api/getFile", {"path": p})
        except Exception as e:
            failed.append((p, str(e)))
            continue

        content = r.get("content")
        if content is None:
            failed.append((p, "no content"))
            continue

        out = os.path.join(DEST, name)
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(content)
        ver = r.get("version", "?")
        print(f"  + {name:<60} v{ver}  ({len(content)} bytes)")
        fetched += 1

    print()
    print(f"Done: fetched={fetched}, failed={len(failed)}")
    if failed:
        for p, err in failed[:10]:
            print(f"  ! {p}: {err}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
