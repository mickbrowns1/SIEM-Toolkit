import os
import asyncio
import httpx
from datetime import datetime, timezone

BASE_URL = os.environ.get("S1_BASE_URL", "https://demo.sentinelone.net").rstrip("/")
TOKEN = os.environ.get("S1_API_TOKEN", "")

# Configurable PowerQuery timeout — SDL queries on large tenants can exceed 2 min.
# Set SDL_PQ_TIMEOUT in .env (seconds). Default: 600.
SDL_PQ_TIMEOUT = int(os.environ.get("SDL_PQ_TIMEOUT", "600"))
# How many times to retry on ReadTimeout before giving up. Default: 1 (one retry).
SDL_PQ_TIMEOUT_RETRIES = int(os.environ.get("SDL_PQ_TIMEOUT_RETRIES", "1"))

# Scalyr/XDR PowerQuery credentials — from SDL_XDR_URL + SDL_LOG_READ_KEY
# in the SentinelOne console: Settings → Integrations → Data Lake API Keys
SDL_XDR_URL = os.environ.get("SDL_XDR_URL", "https://xdr.us1.sentinelone.net").rstrip("/")
SDL_LOG_READ_KEY = os.environ.get("SDL_LOG_READ_KEY", "")

# SDL Configuration Read Key — used to list/fetch parser files under /logParsers/
# (separate from SDL_LOG_READ_KEY which is for querying events only).
# Find it in the S1 console: Settings → Integrations → Data Lake API Keys → Configuration Read.
SDL_CONFIG_READ_KEY = os.environ.get("SDL_CONFIG_READ_KEY", "")

# Management Console API uses ApiToken auth
HEADERS = {
    "Authorization": f"ApiToken {TOKEN}",
    "Content-Type": "application/json",
}


def _iso_to_epoch_ms(iso_str: str) -> int:
    """Convert ISO-8601 UTC string to epoch milliseconds for Scalyr API."""
    dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    return int(dt.timestamp() * 1000)


async def get_star_rules(page_size: int = 100) -> list:
    """Fetch custom STAR rules from /cloud-detection/rules, paginating via cursor."""
    all_rules = []
    cursor = None
    async with httpx.AsyncClient(timeout=30) as client:
        while True:
            params = {"limit": page_size}
            if cursor:
                params["cursor"] = cursor
            resp = await client.get(
                f"{BASE_URL}/web/api/v2.1/cloud-detection/rules",
                headers=HEADERS,
                params=params,
            )
            resp.raise_for_status()
            body = resp.json()
            all_rules.extend(body.get("data", []))
            cursor = body.get("pagination", {}).get("nextCursor")
            if not cursor:
                break
    return all_rules


async def get_library_rules(page_size: int = 100) -> list:
    """
    Fetch Detection Library (OOTB/Platform) rules from /web/api/v2.1/detection-library/rules.
    Requires an account-level or higher API token — site-scoped tokens will receive a 400.
    Returns an empty list gracefully if the token lacks sufficient scope.
    """
    all_rules = []
    cursor = None
    async with httpx.AsyncClient(timeout=60) as client:
        while True:
            params: dict = {"limit": page_size}
            if cursor:
                params["cursor"] = cursor
            resp = await client.get(
                f"{BASE_URL}/web/api/v2.1/detection-library/rules",
                headers=HEADERS,
                params=params,
            )
            # 400 typically means site-scoped token — return empty rather than crash
            if resp.status_code == 400:
                return []
            resp.raise_for_status()
            body = resp.json()
            batch = body.get("data", [])
            all_rules.extend(batch)
            cursor = body.get("pagination", {}).get("nextCursor")
            if not cursor:
                break

    results = []
    for rule in all_rules:
        results.append({
            "id": str(rule.get("id", "")),
            "name": rule.get("name", "unnamed"),
            "s1ql": rule.get("s1ql") or rule.get("query", ""),
            "queryType": rule.get("queryType", "events"),
            "severity": rule.get("severity", ""),
            "description": rule.get("description", ""),
            "gdlRuleId": rule.get("id", ""),
            "creator": "SentinelOne",
            "expirationMode": rule.get("expirationMode", "Permanent"),
        })
    return results


async def run_powerquery(query: str, from_date: str, to_date: str, max_count: int = 1000) -> dict:
    """
    Run a PowerQuery against the Singularity Data Lake via the Scalyr XDR API.
    Uses SDL_XDR_URL + SDL_LOG_READ_KEY (Scalyr readlog token).
    The Scalyr PowerQuery API is synchronous — results return in one request.
    """
    if not SDL_LOG_READ_KEY:
        return {"events": [], "error": "SDL_LOG_READ_KEY not configured — add it to .env"}

    start_ms = _iso_to_epoch_ms(from_date)
    end_ms = _iso_to_epoch_ms(to_date)

    payload = {
        "token": SDL_LOG_READ_KEY,
        "query": query,
        "startTime": start_ms,
        "endTime": end_ms,
        "maxCount": max_count,
    }

    # Use a generous read timeout for PowerQuery — large SDL scans can be slow.
    pq_timeout = httpx.Timeout(connect=15.0, read=SDL_PQ_TIMEOUT, write=30.0, pool=15.0)
    max_attempts = 2 + SDL_PQ_TIMEOUT_RETRIES  # base 2 (rate-limit) + timeout retries

    async with httpx.AsyncClient(timeout=pq_timeout) as client:
        for attempt in range(max_attempts):
            try:
                resp = await client.post(
                    f"{SDL_XDR_URL}/api/powerQuery",
                    json=payload,
                )
                resp.raise_for_status()
                break
            except httpx.ReadTimeout:
                if attempt < max_attempts - 1:
                    await asyncio.sleep(5)
                    continue
                raise RuntimeError(
                    f"PowerQuery timed out after {SDL_PQ_TIMEOUT}s "
                    f"(increase SDL_PQ_TIMEOUT in .env). Query: {query[:200]}"
                )
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429 and attempt < max_attempts - 1:
                    await asyncio.sleep(10 * (attempt + 1))
                    continue
                try:
                    detail = e.response.json()
                except Exception:
                    detail = e.response.text[:500]
                raise RuntimeError(
                    f"HTTP {e.response.status_code} from {e.request.url}: {detail}"
                ) from e

        data = resp.json()
        status = data.get("status", "")

        if status != "success":
            # Return full response as error detail for debugging
            return {"events": [], "error": f"PowerQuery status={status}: {str(data)[:400]}"}

        # Scalyr PowerQuery returns: {"status":"success","columns":[{"name":"..."},...], "values":[[...],...],...}
        raw_cols = data.get("columns", [])
        values = data.get("values", [])

        if raw_cols and values:
            # columns may be list of strings or list of {"name":...} dicts
            col_names = [
                c["name"] if isinstance(c, dict) else c
                for c in raw_cols
            ]
            rows = [dict(zip(col_names, row)) for row in values]
            return {"events": rows}

        # Fallback: return raw matches array
        matches = data.get("matches", [])
        return {"events": matches}


def _sdl_config_headers() -> dict:
    """Auth headers for the SDL Configuration File API (uses POST /api/listFiles,
    POST /api/getFile, etc.). Falls back to SDL_LOG_READ_KEY if no dedicated
    Configuration Read key is set — that won't work for all endpoints, but lets
    callers fail with a meaningful 401 instead of crashing."""
    key = SDL_CONFIG_READ_KEY or SDL_LOG_READ_KEY
    return {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }


async def list_sdl_parsers() -> list[str]:
    """List parser paths under /logParsers/ via the SDL Configuration File API.

    Requires SDL_CONFIG_READ_KEY (or higher) in .env. The endpoint is
    POST <SDL_XDR_URL>/api/listFiles with {"pathPrefix": "/logParsers/"}.
    Returns names without the /logParsers/ prefix, suitable for use as
    filenames in the local parsers/ directory.
    """
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{SDL_XDR_URL}/api/listFiles",
            headers=_sdl_config_headers(),
            json={"pathPrefix": "/logParsers/"},
        )
        resp.raise_for_status()
        data = resp.json()
        paths = data.get("paths") or data.get("files") or []
        # Normalize: strip leading /logParsers/ and ignore anything that isn't there
        names: list[str] = []
        for p in paths:
            if isinstance(p, dict):
                p = p.get("path") or p.get("name") or ""
            if isinstance(p, str) and p.startswith("/logParsers/"):
                names.append(p[len("/logParsers/"):])
        return names


async def list_sdl_parsers_legacy() -> list[str]:
    """[Deprecated] Legacy management-console path — kept for reference but unused."""
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{BASE_URL}/api/v1/files/logParsers",
            headers=HEADERS,
        )
        resp.raise_for_status()
        data = resp.json()
        # Response is a list of file objects or a dict with 'files' key
        if isinstance(data, list):
            return [f.get("name") or f.get("path", "") for f in data if isinstance(f, dict)]
        return [f.get("name") or f.get("path", "") for f in data.get("files", [])]


async def get_sdl_parser(filename: str) -> dict:
    """Fetch a single SDL parser file by name via POST /api/getFile.

    Returns the raw SDL response dict, e.g.
    {"status": "success", "path": "/logParsers/Foo", "content": "...", "version": 3, ...}
    """
    path = filename if filename.startswith("/logParsers/") else f"/logParsers/{filename}"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{SDL_XDR_URL}/api/getFile",
            headers=_sdl_config_headers(),
            json={"path": path},
        )
        resp.raise_for_status()
        return resp.json()


async def get_account_id() -> str | None:
    """Return the first account ID visible to the current token.

    Tries /accounts first (works for account-scoped or higher tokens). If that
    returns 403 (site-scoped token), falls back to /sites and reads accountId
    from the first site.
    """
    async with httpx.AsyncClient(timeout=15) as client:
        # Path 1: account-scoped token
        resp = await client.get(
            f"{BASE_URL}/web/api/v2.1/accounts",
            headers=HEADERS,
            params={"limit": 1},
        )
        if resp.status_code == 200:
            accounts = resp.json().get("data", [])
            if accounts:
                return str(accounts[0]["id"])
        # Path 2: site-scoped token — accountId is embedded in sites payload
        if resp.status_code in (401, 403):
            sresp = await client.get(
                f"{BASE_URL}/web/api/v2.1/sites",
                headers=HEADERS,
                params={"limit": 1},
            )
            if sresp.status_code == 200:
                data = sresp.json().get("data", {})
                sites = data.get("sites") if isinstance(data, dict) else data
                if sites:
                    return str(sites[0].get("accountId") or "") or None
        return None


async def get_scope_for_platform_rules() -> tuple[str, str] | None:
    """Pick the best scope for /detection-library/platform-rules.

    Returns (scopeLevel, scopeId). Tries account first, then site — site-scoped
    tokens cannot list accounts but CAN query platform-rules with site scope.
    """
    async with httpx.AsyncClient(timeout=15) as client:
        # Prefer account scope (broadest)
        a = await client.get(
            f"{BASE_URL}/web/api/v2.1/accounts",
            headers=HEADERS,
            params={"limit": 1},
        )
        if a.status_code == 200:
            accounts = a.json().get("data", [])
            if accounts:
                return ("account", str(accounts[0]["id"]))
        # Fall back to site scope (site-scoped tokens land here)
        s = await client.get(
            f"{BASE_URL}/web/api/v2.1/sites",
            headers=HEADERS,
            params={"limit": 1},
        )
        if s.status_code == 200:
            data = s.json().get("data", {})
            sites = data.get("sites") if isinstance(data, dict) else data
            if sites:
                sid = sites[0].get("id")
                if sid:
                    return ("site", str(sid))
        return None


async def get_platform_rules(page_size: int = 1000) -> list:
    """
    Fetch all Detection Library platform rules from /detection-library/platform-rules.
    Requires scopeLevel + scopeId. Tries account scope first, then site scope so
    site-scoped tokens also work.
    """
    scope = await get_scope_for_platform_rules()
    if not scope:
        return []
    scope_level, scope_id = scope

    all_rules: list = []
    cursor: str = ""
    async with httpx.AsyncClient(timeout=60) as client:
        while True:
            params: dict = {
                "scopeLevel": scope_level,
                "scopeId": scope_id,
                "limit": page_size,
                "cursor": cursor,
            }
            resp = await client.get(
                f"{BASE_URL}/web/api/v2.1/detection-library/platform-rules",
                headers=HEADERS,
                params=params,
            )
            if resp.status_code == 400:
                return []
            resp.raise_for_status()
            body = resp.json()
            all_rules.extend(body.get("data", []))
            cursor = body.get("pagination", {}).get("nextCursor") or ""
            if not cursor:
                break
    return all_rules


async def get_sites() -> list:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{BASE_URL}/web/api/v2.1/sites",
            headers=HEADERS,
            params={"limit": 100},
        )
        resp.raise_for_status()
        return resp.json().get("data", {}).get("sites", [])
