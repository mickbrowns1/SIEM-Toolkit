import os
import re
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()

ENV_FILE = Path(os.environ.get("ENV_FILE_PATH", "/app/.env"))

# Fields we expose in the UI — order matters for display
FIELDS = [
    {"key": "S1_BASE_URL",          "label": "Console URL",                   "secret": False, "placeholder": "https://demo.sentinelone.net"},
    {"key": "S1_API_TOKEN",         "label": "Console API Token",             "secret": True,  "placeholder": "eyJ..."},
    {"key": "SDL_XDR_URL",          "label": "SDL XDR URL",                   "secret": False, "placeholder": "https://xdr.us1.sentinelone.net"},
    {"key": "SDL_LOG_READ_KEY",     "label": "SDL Log Read Key",              "secret": True,  "placeholder": "1DnK0Y4e..."},
    {"key": "ANTHROPIC_API_KEY",    "label": "Anthropic API Key",             "secret": True,  "placeholder": "sk-ant-..."},
    {"key": "STAR_LIBRARY_ONLY",    "label": "STAR Rules — Library Only",     "secret": False, "placeholder": "true",
     "type": "select", "options": ["true", "false"],
     "hint": "true = load only SentinelOne Library rules (@sentinelone.com creators). false = include custom tenant rules as well."},
]

FIELD_KEYS = {f["key"] for f in FIELDS}


def _read_env() -> dict[str, str]:
    """Read .env file into a dict."""
    vals: dict[str, str] = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                vals[k.strip()] = v.strip()
    return vals


def _write_env(updates: dict[str, str]) -> None:
    """Write updates into .env, preserving comments and unknown keys."""
    existing_lines: list[str] = []
    if ENV_FILE.exists():
        existing_lines = ENV_FILE.read_text().splitlines()

    written: set[str] = set()
    new_lines: list[str] = []

    for line in existing_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k, _, _ = stripped.partition("=")
            k = k.strip()
            if k in updates:
                new_lines.append(f"{k}={updates[k]}")
                written.add(k)
                continue
        new_lines.append(line)

    # Append any new keys not already in the file
    for k, v in updates.items():
        if k not in written:
            new_lines.append(f"{k}={v}")

    ENV_FILE.write_text("\n".join(new_lines) + "\n")


@router.get("/config")
async def get_config():
    """Return current config values. Secrets are masked."""
    env_vals = _read_env()
    result = []
    for f in FIELDS:
        key = f["key"]
        # Prefer live env var, fall back to .env file value
        raw = os.environ.get(key, env_vals.get(key, ""))
        if f["secret"] and raw:
            # Show first 6 + last 4 chars, mask middle
            masked = raw[:6] + "•" * max(4, len(raw) - 10) + raw[-4:] if len(raw) > 10 else "••••••••"
        else:
            masked = raw
        result.append({
            "key": key,
            "label": f["label"],
            "secret": f["secret"],
            "placeholder": f["placeholder"],
            "value": masked,
            "set": bool(raw),
        })
    env_file_exists = ENV_FILE.exists()
    return {"fields": result, "env_file_exists": env_file_exists, "env_file_path": str(ENV_FILE)}


class ConfigUpdate(BaseModel):
    updates: dict[str, str]


@router.post("/config")
async def save_config(body: ConfigUpdate):
    """Save config values to .env file. Only known keys accepted."""
    bad = [k for k in body.updates if k not in FIELD_KEYS]
    if bad:
        raise HTTPException(400, f"Unknown keys: {bad}")
    if not ENV_FILE.parent.exists():
        raise HTTPException(503, f"Cannot write to {ENV_FILE} — check Docker volume mount")
    try:
        _write_env(body.updates)
    except Exception as e:
        raise HTTPException(500, f"Failed to write .env: {e}")
    return {"saved": list(body.updates.keys()), "restart_required": True}
