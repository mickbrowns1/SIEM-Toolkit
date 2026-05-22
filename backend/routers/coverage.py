import json
import os
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime
from db import get_db, ParsedRule, ParserField, ActiveSource, RuleFiringCache, CoverageSnapshot
from services import s1_client, rule_parser

DETECTIONS_FILE = os.environ.get("DETECTIONS_FILE", "/app/data/detections.json")

router = APIRouter()


def _extract_mitre(rule: dict) -> tuple[list[str], list[dict]]:
    """Extract (tactics, techniques) from a raw S1 rule dict.

    Primary format (platform-rules API):
      rule["mitre"] = [
        {"tactic": "Execution", "techniques": [{"id": "T1204", "title": "User Execution"}]},
        ...
      ]
    Falls back to flat field names used by older API versions / STAR rules.
    """
    tactics: list[str] = []
    techniques: list[dict] = []

    # ── Primary: structured mitre array (platform-rules API) ──────────────────
    mitre_list = rule.get("mitre")
    if isinstance(mitre_list, list):
        for item in mitre_list:
            if not isinstance(item, dict):
                continue
            tac = item.get("tactic")
            if isinstance(tac, str) and tac.strip():
                tactics.append(tac.strip())
            for tech in item.get("techniques", []):
                if isinstance(tech, dict):
                    tid   = str(tech.get("id",    "") or "").strip()
                    tname = str(tech.get("title") or tech.get("name") or tid).strip()
                    if tid or tname:
                        techniques.append({"id": tid, "name": tname})

    # ── Fallback: flat field names (STAR rules / older API versions) ──────────
    if not tactics:
        for key in ("tactic", "tactics", "mitreTactic", "mitreTactics"):
            val = rule.get(key)
            if isinstance(val, str) and val:
                tactics.extend(v.strip() for v in val.split(",") if v.strip())
            elif isinstance(val, list):
                for v in val:
                    if isinstance(v, str) and v:
                        tactics.append(v.strip())
                    elif isinstance(v, dict):
                        n = v.get("name") or v.get("tactic") or ""
                        if n:
                            tactics.append(n.strip())

    if not techniques:
        for key in ("technique", "techniques", "mitreTechnique", "mitreTechniques", "mitreAttack"):
            val = rule.get(key)
            if isinstance(val, list):
                for v in val:
                    if isinstance(v, str) and v.strip():
                        techniques.append({"id": v.strip(), "name": v.strip()})
                    elif isinstance(v, dict):
                        tid   = str(v.get("id") or v.get("techniqueId") or "").strip()
                        tname = str(v.get("name") or v.get("title") or v.get("technique") or tid).strip()
                        if tid or tname:
                            techniques.append({"id": tid, "name": tname})

    # Deduplicate
    seen_ids: set = set()
    unique_techniques = []
    for t in techniques:
        key_t = t["id"] or t["name"]
        if key_t not in seen_ids:
            seen_ids.add(key_t)
            unique_techniques.append(t)

    return list(dict.fromkeys(tactics)), unique_techniques


def _product_from_data_sources(data_sources: list) -> str:
    """Derive a product label from a rule's data_sources list.
    Prefers the first non-SentinelOne entry (e.g. 'AWS CloudTrail', 'Okta'),
    falls back to 'SentinelOne' for generic endpoint rules.
    """
    if not data_sources:
        return "SentinelOne"
    non_s1 = [d for d in data_sources if d.lower() not in ("sentinelone", "s1")]
    return non_s1[0] if non_s1 else data_sources[0]


def _star_query_texts(rule: dict) -> list[str]:
    """
    Extract all PowerQuery/filter strings from a STAR rule.
    Handles simple rules (s1ql) and correlation rules (subQueries[].subQuery).
    """
    texts = []

    # Simple rules
    for field in ("s1ql", "queryLang", "query", "powerQuery"):
        v = rule.get(field)
        # queryLang "2.0" is a version string, not a query — skip short strings
        if v and isinstance(v, str) and len(v) > 5:
            texts.append(v)

    # Correlation rules: subQueries[].subQuery
    cp = rule.get("correlationParams") or {}
    for sq in cp.get("subQueries", []):
        v = sq.get("subQuery")
        if v and isinstance(v, str):
            texts.append(v)
    # Also handle older conditions[] format
    for cond in cp.get("conditions", []):
        for key in ("filter", "query", "subQuery"):
            v = cond.get(key)
            if v and isinstance(v, str):
                texts.append(v)

    return texts


@router.post("/load-star-rules")
async def load_star_rules(db: Session = Depends(get_db)):
    """Fetch all STAR rules from the Management Console API and index their fields."""
    try:
        rules = await s1_client.get_star_rules()
    except Exception as e:
        raise HTTPException(502, f"S1 API error: {type(e).__name__}: {e}")

    # Replace all existing STAR rules cleanly to avoid duplicate key errors
    db.query(ParsedRule).filter_by(rule_type="star").delete()
    db.flush()

    loaded = []
    for rule in rules:
        all_fields: set = set()
        for qt in _star_query_texts(rule):
            all_fields |= rule_parser.extract_star_fields(qt)
        fields = list(all_fields)
        record = ParsedRule(
            rule_id=str(rule.get("id", "")),
            name=rule.get("name", "unnamed"),
            rule_type="star",
            fields_used=fields,
            raw=json.dumps(rule),
        )
        db.add(record)
        loaded.append({"id": record.rule_id, "name": record.name, "fields": fields})

    db.commit()
    return {"loaded": len(loaded), "rules": loaded}


_EXCLUDED_PATHS = ("/rules/silent/", "/rules/dev/")


def _import_from_api_rules(db, rules: list) -> int:
    """
    Import platform rules fetched directly from the S1 API into the database.
    Each rule has a 'sources' list — the authoritative dataSource.name values.
    """
    db.query(ParsedRule).filter_by(rule_type="library").delete()
    db.commit()

    loaded = 0
    seen_ids: set = set()
    for rule in rules:
        rule_id = str(rule.get("id", f"lib_{loaded}"))
        if rule_id in seen_ids:
            continue
        seen_ids.add(rule_id)

        sources = rule.get("sources") or []
        tactics, techniques = _extract_mitre(rule)
        # generatedAlerts is returned directly by the platform-rules API
        generated_alerts = rule.get("generatedAlerts")
        db.add(ParsedRule(
            rule_id=rule_id,
            name=rule.get("name", "unnamed"),
            rule_type="library",
            fields_used=[],          # API rules don't expose field-level info
            raw=json.dumps({
                "data_sources": sources,
                "tactics": tactics,
                "techniques": techniques,
                "generated_alerts": generated_alerts,
            }),
        ))
        loaded += 1
        if loaded % 500 == 0:
            db.flush()

    db.commit()
    return loaded


def _import_detections(db, detections_file: str) -> int:
    """
    Import library detection rules from extracted.json into the database.
    Replaces any existing library rules. Returns the count of rules loaded.
    """
    with open(detections_file, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    results = data.get("results", [])
    results = [r for r in results if not any(r.get("file", "").startswith(p) for p in _EXCLUDED_PATHS)]

    db.query(ParsedRule).filter_by(rule_type="library").delete()
    db.commit()

    loaded = 0
    seen_ids: set = set()
    for rule in results:
        all_fields: set = set()
        data_sources: list[str] = []
        for q in rule.get("queries", []):
            all_fields.update(q.get("keys", []))
            ds_vals = q.get("pairs", {}).get("dataSource.name", [])
            for v in ds_vals:
                if isinstance(v, str):
                    data_sources.append(v)
                elif isinstance(v, list):
                    data_sources.extend(str(x) for x in v)

        rule_id = str(rule.get("id", f"lib_{loaded}"))
        if rule_id in seen_ids:
            continue
        seen_ids.add(rule_id)

        tactics, techniques = _extract_mitre(rule)
        db.add(ParsedRule(
            rule_id=rule_id,
            name=rule.get("name", "unnamed"),
            rule_type="library",
            fields_used=list(all_fields),
            raw=json.dumps({
                "data_sources": list(set(data_sources)),
                "tactics": tactics,
                "techniques": techniques,
            }),
        ))
        loaded += 1
        if loaded % 500 == 0:
            db.flush()

    db.commit()
    return loaded


@router.post("/load-detections")
async def load_detections(db: Session = Depends(get_db)):
    """
    Reload detection library rules.
    Tries the live S1 API first (platform-rules endpoint); falls back to extracted.json.
    """
    # Prefer the live API — gives accurate 'sources' and is always up to date
    try:
        rules = await s1_client.get_platform_rules()
        if rules:
            loaded = _import_from_api_rules(db, rules)
            return {"loaded": loaded, "source": "api"}
    except Exception:
        pass

    # Fall back to local extracted.json
    if not os.path.exists(DETECTIONS_FILE):
        raise HTTPException(
            404,
            "S1 API unavailable and no detections file found — "
            "ensure the data/ volume is mounted with detections.json"
        )
    try:
        loaded = _import_detections(db, DETECTIONS_FILE)
    except Exception as e:
        raise HTTPException(500, f"Failed to import detections: {e}")
    return {"loaded": loaded, "source": "file"}


@router.post("/upload-sigma")
async def upload_sigma(files: list[UploadFile] = File(...), db: Session = Depends(get_db)):
    """Upload one or more Sigma YAML files and index their fields."""
    loaded = []
    for file in files:
        content = (await file.read()).decode("utf-8", errors="replace")
        fields = list(rule_parser.extract_sigma_fields(content))
        record = ParsedRule(
            rule_id=f"sigma_{file.filename}",
            name=file.filename or "unnamed",
            rule_type="sigma",
            fields_used=fields,
            raw=content,
        )
        db.merge(record)
        loaded.append({"name": file.filename, "fields": fields})

    db.commit()
    return {"loaded": len(loaded), "rules": loaded}


def _fetch_parsers_from_console(parsers_dir: str) -> dict:
    """
    Fetch every parser under /logParsers/ from the SDL console and write them
    to parsers_dir.  Uses SDL_CONFIG_READ_KEY (needs 'Manage config files' permission)
    and SDL_XDR_URL from the environment.

    Returns {"fetched": N, "failed": [...], "skipped": reason_or_None}
    """
    import urllib.request, urllib.error, json as _json, os as _os

    # Read live from .env file so Settings-page saves are picked up without restart
    def _env_val(key: str) -> str:
        val = _os.environ.get(key, "")
        if not val:
            env_path = _os.environ.get("ENV_FILE_PATH", "/app/.env")
            try:
                for line in open(env_path).read().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, _, v = line.partition("=")
                        if k.strip() == key:
                            val = v.strip()
                            break
            except Exception:
                pass
        return val

    config_key = _env_val("SDL_CONFIG_READ_KEY")
    base_url    = _env_val("SDL_XDR_URL").rstrip("/")

    if not config_key:
        return {"fetched": 0, "failed": [], "skipped": "SDL_CONFIG_READ_KEY not set"}
    if not base_url:
        return {"fetched": 0, "failed": [], "skipped": "SDL_XDR_URL not set"}

    def _post(path: str, params: dict) -> dict:
        url  = f"{base_url}{path}"
        body = _json.dumps({**params, "token": config_key}).encode()
        req  = urllib.request.Request(url, data=body, headers={
            "Authorization": f"Bearer {config_key}",
            "Content-Type":  "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return _json.loads(r.read())
        except urllib.error.HTTPError as e:
            err_body = e.read().decode(errors="replace")[:300]
            raise RuntimeError(f"HTTP {e.code} {path}: {err_body}")

    # List all parser paths
    res   = _post("/api/listFiles", {"pathPrefix": "/logParsers/"})

    # Support multiple response shapes: {"paths": [...]} or {"files": [...]}
    raw_paths = res.get("paths") or res.get("files") or []

    # Each element may be a plain string or a dict with a "path"/"name" key
    paths = []
    for p in raw_paths:
        if isinstance(p, dict):
            p = p.get("path") or p.get("name") or ""
        if isinstance(p, str) and p.startswith("/logParsers/"):
            paths.append(p)

    _os.makedirs(parsers_dir, exist_ok=True)
    fetched, failed = 0, []

    for p in paths:
        name = p.rsplit("/", 1)[-1] or "_unnamed"
        try:
            r       = _post("/api/getFile", {"path": p})
            content = r.get("content")
            if content is None:
                failed.append({"path": p, "error": "no content", "raw": r})
                continue
            with open(_os.path.join(parsers_dir, name), "w", encoding="utf-8") as fh:
                fh.write(content)
            fetched += 1
        except Exception as e:
            failed.append({"path": p, "error": str(e)})

    # Surface the raw API response so callers can see exactly what was returned.
    # Truncate paths list so the response stays readable (first 200).
    debug_info = {
        "response_keys": list(res.keys()),
        "paths_found": len(paths),
        "paths_listed": paths[:200],
    }
    return {"fetched": fetched, "failed": failed, "skipped": None, "debug": debug_info}


@router.post("/load-parsers-from-sdl")
async def load_parsers_from_sdl(db: Session = Depends(get_db)):
    """
    Sync SDL parsers from the console (if SDL_CONFIG_READ_KEY is set) then index
    every file in the local /app/parsers directory into the DB.
    """
    import os
    parsers_dir = "/app/parsers"

    # ── Step 1: fetch from console (best-effort) ────────────────────────────
    fetch_result = _fetch_parsers_from_console(parsers_dir)

    # ── Step 2: load whatever is on disk into the DB ─────────────────────────
    try:
        entries = [
            e for e in os.scandir(parsers_dir)
            if e.is_file() and not e.name.startswith(".")
        ]
    except FileNotFoundError:
        raise HTTPException(503, "parsers/ directory not found — check Docker volume mount")

    if not entries and fetch_result["skipped"]:
        raise HTTPException(
            422,
            f"No parser files found in parsers/ directory and console sync was skipped "
            f"({fetch_result['skipped']}). "
            "Add SDL_CONFIG_READ_KEY in Settings (needs 'Manage config files' permission) "
            "or upload a parser file manually."
        )
    if not entries:
        raise HTTPException(
            422,
            "No parser files found in parsers/ directory after console sync. "
            "Check SDL_CONFIG_READ_KEY permissions ('Manage config files' required)."
        )

    loaded = []
    errors = []
    for entry in entries:
        try:
            with open(entry.path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()

            fields: set = set()
            try:
                import json as _json
                parser_data = _json.loads(content)
                fields = rule_parser.extract_parser_fields(parser_data)
            except Exception:
                pass
            fields |= rule_parser.extract_parser_fields_from_content(content)

            name = entry.name
            db.query(ParserField).filter_by(parser_name=name).delete()
            for f in fields:
                db.add(ParserField(parser_name=name, field_name=f, field_type="string"))
            loaded.append({"parser": name, "fields": list(fields), "field_count": len(fields)})
        except Exception as e:
            errors.append({"parser": entry.name, "error": str(e)})

    db.commit()
    return {
        "loaded": len(loaded),
        "parsers": loaded,
        "errors": errors,
        "console_fetch": fetch_result,
    }


@router.post("/upload-parser")
async def upload_parser(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Upload an SDL parser JSON file and index its output fields."""
    raw_bytes = await file.read()
    content_str = raw_bytes.decode("utf-8", errors="replace")

    # Try structured JSON extraction first, fall back to content-string extraction
    fields: set = set()
    try:
        parser_data = json.loads(content_str)
        fields = rule_parser.extract_parser_fields(parser_data)
    except json.JSONDecodeError:
        pass

    # Always also run content-string extraction (catches $field$ SDL format strings)
    fields |= rule_parser.extract_parser_fields_from_content(content_str)

    db.query(ParserField).filter_by(parser_name=file.filename).delete()
    for f in fields:
        db.add(ParserField(parser_name=file.filename, field_name=f, field_type="string"))

    db.commit()
    return {"parser": file.filename, "fields": list(fields)}


class ParserContentPayload(BaseModel):
    parser_name: str
    content: str  # raw SDL parser file content as string


@router.post("/load-parser-content")
async def load_parser_content(payload: ParserContentPayload, db: Session = Depends(get_db)):
    """
    Accept raw SDL parser content (as a string) and index its output fields.
    Used by MCP-based loader scripts since the SDL HTTP API endpoint is not
    accessible from inside Docker with standard API token auth.
    """
    fields: set = set()

    # Try JSON parsing first (structured attributes/fields/mappings)
    try:
        parser_data = json.loads(payload.content)
        fields = rule_parser.extract_parser_fields(parser_data)
    except (json.JSONDecodeError, Exception):
        pass

    # Always run SDL format-string extraction ($field.name$ patterns)
    fields |= rule_parser.extract_parser_fields_from_content(payload.content)

    if not fields:
        raise HTTPException(422, "No fields could be extracted from the parser content")

    db.query(ParserField).filter_by(parser_name=payload.parser_name).delete()
    for f in fields:
        db.add(ParserField(parser_name=payload.parser_name, field_name=f, field_type="string"))

    db.commit()
    return {"parser": payload.parser_name, "fields": list(fields), "field_count": len(fields)}


# Native SentinelOne platform sources — parsed by the system, not by SDL parsers.
# Excluded from the coverage map as they do not require custom parser coverage.
_S1_NATIVE_SOURCES = {
    "SentinelOne", "asset", "alert", "vulnerability",
    "ActivityFeed", "indicator", "misconfiguration",
    "SentinelOne Ranger AD",
}

# Cached count of events with no dataSource.name — updated on each sync
_unlabelled_event_count: int = -1  # -1 = not yet queried


@router.post("/sync-sources")
async def sync_sources(days: int = 7, db: Session = Depends(get_db)):
    """Pull active dataSource.names from the SDL and store them.
    Also detects whether a parser is already producing structured fields
    for each source by checking if event.type is populated in the data lake.
    Native S1 platform sources are excluded as they do not require SDL parsers.
    """
    import asyncio
    from datetime import datetime, timedelta
    now = datetime.utcnow()
    from_dt = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    to_dt = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    try:
        volume_result, parsed_result = await asyncio.gather(
            s1_client.run_powerquery(
                "| group events=count() by dataSource.name | sort -events | limit 200",
                from_dt, to_dt
            ),
            s1_client.run_powerquery(
                "| filter event.type != '' | group parsed=count() by dataSource.name | limit 200",
                from_dt, to_dt
            ),
        )
    except Exception as e:
        raise HTTPException(502, f"PowerQuery error: {e}")

    # Build lookup: source_name → count of parsed events seen
    parsed_by_source: dict[str, int] = {}
    for row in parsed_result.get("events", []):
        name = row.get("dataSource.name")
        if name:
            parsed_by_source[name] = row.get("parsed", 0)

    # Preserve existing parser_detected values so a source once confirmed as
    # parsed never loses its "Covered" status due to a sampling gap or timeout.
    existing_detected: dict[str, int] = {
        s.source_name: (s.parser_detected or 0)
        for s in db.query(ActiveSource).all()
    }

    rows = volume_result.get("events", [])
    db.query(ActiveSource).delete()
    synced_at = datetime.utcnow()
    seen = 0
    for row in rows:
        name = row.get("dataSource.name")
        if name and name not in _S1_NATIVE_SOURCES:
            # Keep the highest parser_detected ever seen for this source
            new_detected = parsed_by_source.get(name, 0)
            prev_detected = existing_detected.get(name, 0)
            db.add(ActiveSource(
                source_name=name,
                event_count=row.get("events", 0),
                synced_at=synced_at,
                parser_detected=max(new_detected, prev_detected),
            ))
            seen += 1

    db.commit()
    synced_names = [r["dataSource.name"] for r in rows if r.get("dataSource.name") and r["dataSource.name"] not in _S1_NATIVE_SOURCES]

    # Auto-record a coverage snapshot after every live-sources sync
    try:
        h = _compute_health(db)
        db.add(CoverageSnapshot(
            health_score=h["health_score"],
            parser_pct=h["parser_pct"],
            mitre_pct=h["mitre_pct"],
            firing_pct=h["firing_pct"] or 0.0,
            active_sources=h["active_sources"],
            covered_sources=h["covered_sources"],
            rules_loaded=h["rules_loaded"],
            tactics_covered=h["tactics_covered"],
            techniques_covered=h["techniques_covered"],
            rules_with_mitre=h["rules_with_mitre"],
            rules_fired=h["rules_fired"],
        ))
        db.commit()
    except Exception:
        pass  # snapshot failure should never break sync

    return {"synced": seen, "sources": synced_names}


def _build_parser_ds_index() -> tuple[dict[str, dict], list[dict]]:
    """
    Read all parser files from /app/parsers/ and build:
      - index: dataSource.name → {parser_name, format_type}  (complete parsers)
      - stubs:  list of {parser_name} for files with no dataSource.name attribute

    Format type is "grok", "dottedJson", or "custom".
    Sources with grok/dottedJson parsers are flagged as needing a proper parser.
    """
    import os, re
    parsers_dir = "/app/parsers"
    _DS_NAME_RE = re.compile(r'"?dataSource\.name"?\s*:\s*"([^"]+)"')
    _FORMAT_TYPE_RE = re.compile(r'"type"\s*:\s*"([^"]+)"')
    # Only treat a file as a parser if it has a formats section — rules out dashboards/saved-searches
    _HAS_FORMATS_RE = re.compile(r'\bformats\s*:', re.IGNORECASE)

    index: dict[str, dict] = {}
    stubs: list[dict] = []
    try:
        entries = [e for e in os.scandir(parsers_dir) if e.is_file() and not e.name.startswith(".")]
    except FileNotFoundError:
        return index, stubs

    for entry in entries:
        try:
            with open(entry.path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue

        # Skip files that have no formats section — they're dashboards/queries, not parsers
        if not _HAS_FORMATS_RE.search(content):
            continue

        # Extract dataSource.name (may appear multiple times — take first)
        ds_match = _DS_NAME_RE.search(content)
        if not ds_match:
            # Has formats but no dataSource.name — genuine stub parser
            stubs.append({"parser_name": entry.name})
            continue
        ds_name = ds_match.group(1).strip()

        # Determine format type — look for grok/dottedJson/custom in "type" values
        format_types = {m.group(1).lower() for m in _FORMAT_TYPE_RE.finditer(content)}
        if "grok" in format_types:
            fmt = "grok"
        elif "dottedjson" in format_types:
            fmt = "dottedJson"
        else:
            fmt = "custom"

        index[ds_name] = {"parser_name": entry.name, "format_type": fmt}

    return index, stubs


@router.get("/map")
def get_coverage_map(db: Session = Depends(get_db)):
    """
    Source-centric coverage map.
    For each active dataSource.name in the SDL:
      - covered       = a custom parser is loaded for it (dataSource.name matches)
      - parser_needed = no parser, OR parser uses grok/dottedJson format
    Also surfaces which STAR rules reference each source.
    """
    active_sources = db.query(ActiveSource).order_by(ActiveSource.event_count.desc()).all()
    parser_fields_rows = db.query(ParserField).all()
    rules = db.query(ParsedRule).all()

    firing_cache: dict[str, int] = {
        row.rule_name: row.alert_count
        for row in db.query(RuleFiringCache).all()
    }
    firing_cache_populated = len(firing_cache) > 0

    # parser_name → set of field names (for field count display)
    parser_index: dict[str, set] = {}
    for pf in parser_fields_rows:
        parser_index.setdefault(pf.parser_name, set()).add(pf.field_name)

    # Build dataSource.name → {parser_name, format_type} index from parser files
    ds_index, stub_parsers = _build_parser_ds_index()

    def _normalize(s: str) -> str:
        return s.lower().replace(" ", "").replace("-", "").replace("_", "").replace(".", "")

    def _find_stub_match(source_name: str) -> dict | None:
        """Return stub parser info if a stub filename fuzzy-matches this source name."""
        sn = _normalize(source_name)
        for stub in stub_parsers:
            fn = _normalize(stub["parser_name"])
            if fn in sn or sn in fn:
                return stub
        return None

    def _find_parser_info(source_name: str) -> dict | None:
        """
        Match priority:
          1. Exact dataSource.name match
          2. Normalized substring: active source name ↔ parser dataSource.name
          3. Normalized substring: active source name ↔ parser filename
             (catches cases where the parser file has a wrong dataSource.name)
        """
        # 1. Exact match on dataSource.name
        if source_name in ds_index:
            return ds_index[source_name]
        sn = _normalize(source_name)
        # 2. Normalized ds_name substring
        for ds_name, info in ds_index.items():
            if _normalize(ds_name) in sn or sn in _normalize(ds_name):
                return info
        # 3. Normalized filename substring
        for info in ds_index.values():
            if _normalize(info["parser_name"]) in sn or sn in _normalize(info["parser_name"]):
                return info
        return None

    # Fields each rule needs: rule.name → set of field names
    rule_fields_index: dict[str, set] = {
        rule.name: set(rule.fields_used or []) for rule in rules
    }

    # Build rule index: source_name → rules that reference it
    rule_by_source: dict[str, list] = {}
    for rule in rules:
        try:
            raw_data = json.loads(rule.raw) if rule.raw else {}
        except Exception:
            raw_data = {}

        if rule.rule_type == "library":
            # Library rules store pre-extracted data_sources list in raw
            data_sources = raw_data.get("data_sources", [])
        else:
            query_texts = _star_query_texts(raw_data)
            data_sources = rule_parser.extract_data_sources(query_texts)

        product = _product_from_data_sources(data_sources)

        for ds in data_sources:
            rule_by_source.setdefault(ds, []).append({"rule": rule.name, "type": rule.rule_type, "product": product})

    # Fields to ignore when computing "missing" — these are metadata/schema fields
    # always present in events regardless of the parser
    _SCHEMA_FIELDS = {
        "dataSource.name", "dataSource.vendor", "dataSource.category",
        "event.type", "timestamp", "src.endpoint.ip", "src.endpoint.name",
        # Endpoint agent fields — populated by the SentinelOne agent, not by SDL parsers
        "cmdScript.content", "endpoint.os", "endpoint.name", "endpoint.uid",
    }

    sources_out = []
    covered_count = 0
    needed_count = 0

    for src in active_sources:
        parser_info = _find_parser_info(src.source_name)
        parser_in_data = (src.parser_detected or 0) > 0

        stub_info = _find_stub_match(src.source_name) if not parser_info else None

        if parser_info and parser_info["format_type"] == "custom":
            status = "covered"
            matched_parser = parser_info["parser_name"]
            format_type = "custom"
        elif parser_info and parser_info["format_type"] in ("grok", "dottedJson") and not parser_in_data:
            # Known parser but primitive format and no evidence of parsing in data
            status = "parser_needed"
            matched_parser = parser_info["parser_name"]
            format_type = parser_info["format_type"]
        elif parser_in_data:
            # Parsed fields detected in the data lake — a parser is running
            status = "covered"
            matched_parser = parser_info["parser_name"] if parser_info else "detected in data"
            format_type = parser_info["format_type"] if parser_info else "unknown"
        elif stub_info:
            # A parser file exists but has no dataSource.name — it's a stub/incomplete
            status = "stub_parser"
            matched_parser = stub_info["parser_name"]
            format_type = None
            stub_info["suggested_ds_name"] = src.source_name
        else:
            status = "parser_needed"
            matched_parser = None
            format_type = None

        if status == "covered":
            covered_count += 1
        else:
            needed_count += 1  # stub_parser and parser_needed both count as needing work

        rules_for_src: list = [
            {**r, "alert_count": firing_cache.get(r["rule"], 0)}
            for r in rule_by_source.get(src.source_name, [])
            if r["type"] == "library"
        ]
        # Sort rules so grouped-by-product rendering is stable
        rules_for_src.sort(key=lambda r: (r.get("product", ""), r["rule"]))

        # Close-match suggestions — shown when there are no library rules for this source.
        close_matches: list = []
        if not rules_for_src:
            import re as _re

            def _word_tokens(s: str) -> set:
                """Split on non-alphanumeric boundaries, lowercase, drop single chars."""
                return {t for t in _re.split(r"[^a-z0-9]+", s.lower()) if len(t) >= 2}

            def _is_close(a: str, b: str) -> bool:
                na, nb = _normalize(a), _normalize(b)
                # 1. Simple substring match
                if na in nb or nb in na:
                    return True
                # 2. Token-level: handles "Microsoft 365 Collaboration" vs "Microsoft O365"
                #    — "365" is inside "o365", and they share "microsoft"
                ta, tb = _word_tokens(a), _word_tokens(b)
                shared_exact = ta & tb
                if not shared_exact:
                    return False  # Must share at least one word exactly
                # Check that a DISTINCTIVE (non-shared) token from one name
                # appears as a substring inside a token from the other.
                # This avoids matching "Azure AD" to "Azure Platform" on "azure" alone.
                unique_a = ta - shared_exact
                unique_b = tb - shared_exact
                return any(
                    ua in ub or ub in ua
                    for ua in unique_a for ub in unique_b
                    if len(ua) >= 2 and len(ub) >= 2
                )

            sn = _normalize(src.source_name)
            for lib_ds, lib_rules in rule_by_source.items():
                lib_only = [r for r in lib_rules if r["type"] == "library"]
                if not lib_only:
                    continue
                if _is_close(src.source_name, lib_ds):
                    close_matches.append({
                        "library_name": lib_ds,
                        "rule_count": len(lib_only),
                    })
            close_matches.sort(key=lambda x: x["rule_count"], reverse=True)
            close_matches = close_matches[:3]

        # Count how many rules reference each field (frequency)
        field_freq: dict[str, int] = {}
        for r in rules_for_src:
            for f in rule_fields_index.get(r["rule"], set()):
                field_freq[f] = field_freq.get(f, 0) + 1

        # Fields the parser provides
        parser_provides = parser_index.get(matched_parser, set()) if matched_parser and matched_parser != "detected in data" else set()

        # Minimum number of rules that must reference a field before we flag it.
        # Scales with rule count so single-rule oddities don't dominate.
        rule_count = len(rules_for_src)
        min_rules = max(2, round(rule_count * 0.05)) if rule_count >= 10 else 2

        # Missing = dotted-path fields needed by >= min_rules rules,
        # not in schema constants, not provided by the parser.
        missing_fields = sorted(
            f for f, count in field_freq.items()
            if count >= min_rules
            and "." in f
            and f not in _SCHEMA_FIELDS
            and f not in parser_provides
        )

        sources_out.append({
            "source_name": src.source_name,
            "event_count": src.event_count,
            "status": status,
            "parser": matched_parser,
            "format_type": format_type,
            "unlabelled": bool(src.unlabelled),
            "stub_suggested_ds_name": stub_info.get("suggested_ds_name") if stub_info and status == "stub_parser" else None,
            "parser_fields": len(parser_provides),
            "parser_detected": src.parser_detected or 0,
            "rules": rules_for_src,
            "rule_count": len(rules_for_src),
            "close_matches": close_matches,
            "missing_fields": missing_fields,
            "missing_fields_count": len(missing_fields),
            "synced_at": src.synced_at.isoformat() if src.synced_at else None,
        })

    # Only surface stub parsers that matched an active source with real events —
    # unmatched stubs with zero events are noise and are suppressed.

    synced_at = active_sources[0].synced_at.isoformat() if active_sources else None

    # stub_parsers = total parser FILES missing dataSource.name (independent of active sources)
    stub_file_count = len(stub_parsers)

    return {
        "summary": {
            "active_sources": len(active_sources),
            "covered": covered_count,
            "parser_needed": needed_count,
            "stub_parsers": stub_file_count,
            "unlabelled_events": _unlabelled_event_count,
            "parsers_loaded": len(parser_index),
            "rules_loaded": len(rules),
            "firing_cache_populated": firing_cache_populated,
        },
        "sources": sources_out,
        "synced_at": synced_at,
        "has_sources": len(active_sources) > 0,
    }


@router.get("/stub-parsers")
def get_stub_parsers():
    """Return all parser files that have a formats: section but no dataSource.name attribute.
    Used by Parser Quality — Attributes Missing section. Independent of active sources."""
    _, stubs = _build_parser_ds_index()
    return {"stubs": stubs, "count": len(stubs)}


@router.get("/mitre")
def get_mitre_coverage(db: Session = Depends(get_db)):
    rules = db.query(ParsedRule).filter_by(rule_type="library").all()

    TACTIC_ORDER = [
        "Reconnaissance", "Resource Development", "Initial Access", "Execution",
        "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact", "Uncategorized",
    ]

    tactic_map: dict[str, dict] = {}
    no_mitre_count = 0

    for rule in rules:
        try:
            raw_data = json.loads(rule.raw) if rule.raw else {}
        except Exception:
            raw_data = {}
        tactics = raw_data.get("tactics", [])
        techniques = raw_data.get("techniques", [])
        if not tactics and not techniques:
            no_mitre_count += 1
            continue
        if not tactics:
            tactics = ["Uncategorized"]
        for tactic in tactics:
            tactic = _normalise_tactic(tactic)
            if tactic not in tactic_map:
                tactic_map[tactic] = {"techniques": {}, "rule_count": 0}
            tactic_map[tactic]["rule_count"] += 1
            for tech in techniques:
                key_t = tech["id"] or tech["name"]
                if key_t:
                    tactic_map[tactic]["techniques"][key_t] = tech["name"] or key_t

    def _tactic_sort_key(name: str) -> int:
        try:
            return TACTIC_ORDER.index(name)
        except ValueError:
            return len(TACTIC_ORDER)

    tactics_out = []
    total_techniques = 0
    for tactic_name in sorted(tactic_map.keys(), key=_tactic_sort_key):
        tech_dict = tactic_map[tactic_name]["techniques"]
        techniques_list = [
            {"id": k if (k.startswith("T") and len(k) >= 4) else "", "name": v}
            for k, v in sorted(tech_dict.items())
        ]
        total_techniques += len(techniques_list)
        tactics_out.append({
            "tactic": tactic_name,
            "rule_count": tactic_map[tactic_name]["rule_count"],
            "technique_count": len(techniques_list),
            "techniques": techniques_list,
        })

    return {
        "tactics": tactics_out,
        "total_rules": len(rules),
        "rules_with_mitre": len(rules) - no_mitre_count,
        "rules_without_mitre": no_mitre_count,
        "total_techniques": total_techniques,
        "tactic_count": len(tactics_out),
    }


@router.post("/sync-rule-firing")
async def sync_rule_firing(period_days: int = 30, db: Session = Depends(get_db)):
    """Populate rule firing cache from the generatedAlerts field stored during
    the last Detection Library sync (platform-rules API).  This is instant and
    requires no SDL PowerQuery.  Falls back to SDL PowerQuery if the stored data
    is missing (e.g. rules were imported from the detections.json file fallback)."""
    from datetime import datetime

    checked_at = datetime.utcnow()
    result_rows = []
    source = "api"

    # ── Fast path: use generatedAlerts stored in ParsedRule.raw ───────────────
    rules = db.query(ParsedRule).filter_by(rule_type="library").all()
    for rule in rules:
        try:
            raw_data = json.loads(rule.raw) if rule.raw else {}
        except Exception:
            raw_data = {}
        ga = raw_data.get("generated_alerts")
        if ga is not None:  # present means rule was imported from the live API
            result_rows.append({"rule_name": rule.name, "alerts": int(ga)})

    # ── Fallback: SDL PowerQuery (rules imported from detections.json) ─────────
    if not result_rows:
        source = "powerquery"
        from datetime import timedelta
        now = datetime.utcnow()
        from_dt = (now - timedelta(days=period_days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        to_dt = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        FIRING_QUERIES = [
            ("| filter ruleName != '' | group alerts=count() by ruleName | sort -alerts | limit 2000", "ruleName"),
            ("| filter threatInfo.detectionEngineRule.name != '' | group alerts=count() by threatInfo.detectionEngineRule.name | sort -alerts | limit 2000", "threatInfo.detectionEngineRule.name"),
        ]
        for query, name_field in FIRING_QUERIES:
            try:
                result = await s1_client.run_powerquery(query, from_dt, to_dt, max_count=10_000_000)
                rows = result.get("events", []) if isinstance(result, dict) else []
                if rows:
                    result_rows = [
                        {"rule_name": r.get(name_field, ""), "alerts": r.get("alerts", 0)}
                        for r in rows if r.get(name_field)
                    ]
                    if result_rows:
                        break
            except Exception:
                continue

    if not result_rows:
        return {
            "synced": 0,
            "rules_with_alerts": 0,
            "source": source,
            "message": "No alert data found. Run Sync Detection Library first to import generatedAlerts from the S1 API.",
        }

    # Upsert into cache
    db.query(RuleFiringCache).delete()
    for row in result_rows:
        db.add(RuleFiringCache(
            rule_name=row["rule_name"],
            alert_count=row["alerts"],
            period_days=period_days,
            checked_at=checked_at,
        ))
    db.commit()

    fired = sum(1 for r in result_rows if r["alerts"] > 0)
    return {
        "synced": len(result_rows),
        "rules_with_alerts": fired,
        "rules_never_fired": len(result_rows) - fired,
        "source": source,
        "period_days": period_days,
    }


@router.get("/rule-firing-cache")
def get_rule_firing_cache(db: Session = Depends(get_db)):
    """Return all cached rule firing data sorted by alert count descending."""
    rows = db.query(RuleFiringCache).order_by(RuleFiringCache.alert_count.desc()).all()
    total_rules = db.query(ParsedRule).filter_by(rule_type="library").count()
    fired = [r for r in rows if r.alert_count > 0]
    never_fired_count = total_rules - len(fired)
    period_days = rows[0].period_days if rows else 30
    checked_at = rows[0].checked_at.isoformat() if rows and rows[0].checked_at else None

    # Build rule_name → product lookup from ParsedRule raw JSON
    rule_product: dict[str, str] = {}
    for rule in db.query(ParsedRule).filter_by(rule_type="library").all():
        try:
            raw_data = json.loads(rule.raw) if rule.raw else {}
        except Exception:
            raw_data = {}
        rule_product[rule.name] = _product_from_data_sources(raw_data.get("data_sources", []))

    return {
        "rules": [
            {
                "rule_name": r.rule_name,
                "alert_count": r.alert_count,
                "period_days": r.period_days,
                "checked_at": r.checked_at.isoformat() if r.checked_at else None,
                "product": rule_product.get(r.rule_name, "SentinelOne"),
            }
            for r in rows
        ],
        "summary": {
            "rules_monitored": len(rows),
            "fired_in_period": len(fired),
            "never_fired": never_fired_count,
            "period_days": period_days,
            "checked_at": checked_at,
        },
    }


# SentinelOne uses non-standard tactic names in some rules.
# Map them to the closest standard ATT&CK Enterprise tactic.
_TACTIC_NORMALISE: dict[str, str] = {
    "defense impairment": "Defense Evasion",
    "stealth":            "Defense Evasion",
    "evasion":            "Defense Evasion",
    "c2":                 "Command and Control",
    "c&c":                "Command and Control",
}

_ATTACK_TACTICS = {
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
}


def _normalise_tactic(tactic: str) -> str:
    """Return the canonical ATT&CK Enterprise tactic name."""
    return _TACTIC_NORMALISE.get(tactic.strip().lower(), tactic.strip())


def _compute_health(db) -> dict:
    """Compute current health score from DB state.

    Weights:
      40% parser coverage  — what % of active sources have a working parser
      35% MITRE coverage   — what % of the 14 standard ATT&CK tactics are covered
      25% rule firing      — what % of library rules have fired (0 if cache empty)
    """
    # --- Parser coverage ---
    all_sources = db.query(ActiveSource).all()
    total_sources = len(all_sources)
    # "covered" = parser_detected > 0 (parser running in data lake)
    covered_sources = sum(1 for s in all_sources if (s.parser_detected or 0) > 0)
    parser_pct = round((covered_sources / total_sources * 100) if total_sources else 0.0, 1)

    # --- MITRE coverage ---
    TOTAL_TACTICS = 14  # standard ATT&CK Enterprise tactic count
    rules = db.query(ParsedRule).filter_by(rule_type="library").all()
    total_rules = len(rules)
    covered_tactics: set = set()
    covered_techniques: set = set()
    rules_with_mitre = 0
    for rule in rules:
        try:
            raw = json.loads(rule.raw) if rule.raw else {}
        except Exception:
            raw = {}
        tactics = raw.get("tactics", [])
        techniques = raw.get("techniques", [])
        if tactics or techniques:
            rules_with_mitre += 1
        for t in tactics:
            if t and t.lower() != "uncategorized":
                covered_tactics.add(_normalise_tactic(t))
        for tech in techniques:
            k = tech.get("id") or tech.get("name")
            if k:
                covered_techniques.add(k)
    # Only count tactics that are actual ATT&CK Enterprise tactics
    recognised_tactics = covered_tactics & _ATTACK_TACTICS
    tactics_covered = len(recognised_tactics)
    techniques_covered = len(covered_techniques)
    mitre_pct = round(min(tactics_covered / TOTAL_TACTICS * 100, 100.0), 1)

    # --- Rule firing ---
    firing_rows = db.query(RuleFiringCache).all()
    cache_populated = len(firing_rows) > 0
    rules_fired = sum(1 for r in firing_rows if r.alert_count > 0)
    if cache_populated and total_rules > 0:
        firing_pct = round(rules_fired / total_rules * 100, 1)
    else:
        firing_pct = 0.0

    # --- Weighted health score ---
    if cache_populated:
        score = round(0.40 * parser_pct + 0.35 * mitre_pct + 0.25 * firing_pct, 1)
    else:
        # Without firing data, reweight between parser + MITRE
        score = round(0.55 * parser_pct + 0.45 * mitre_pct, 1)

    return {
        "health_score": score,
        "parser_pct": parser_pct,
        "mitre_pct": mitre_pct,
        "firing_pct": firing_pct if cache_populated else None,
        "active_sources": total_sources,
        "covered_sources": covered_sources,
        "rules_loaded": total_rules,
        "tactics_covered": tactics_covered,
        "techniques_covered": techniques_covered,
        "rules_with_mitre": rules_with_mitre,
        "rules_fired": rules_fired,
        "firing_cache_populated": cache_populated,
        "components": {
            "parser_coverage": {"value": parser_pct, "weight": 0.40 if cache_populated else 0.55, "label": "Parser Coverage"},
            "mitre_coverage":  {"value": mitre_pct,  "weight": 0.35 if cache_populated else 0.45, "label": "MITRE Coverage"},
            "rule_firing":     {"value": firing_pct if cache_populated else None, "weight": 0.25 if cache_populated else 0.0, "label": "Rule Firing Rate"},
        }
    }


@router.get("/health")
def get_health_score(db: Session = Depends(get_db)):
    """Return the current tenant health score and component breakdown."""
    h = _compute_health(db)
    # Most recent snapshot for trend comparison
    prev = db.query(CoverageSnapshot).order_by(CoverageSnapshot.recorded_at.desc()).offset(1).first()
    delta = None
    if prev:
        delta = round(h["health_score"] - prev.health_score, 1)
    h["delta_from_previous"] = delta
    return h


@router.post("/snapshot")
def record_snapshot(db: Session = Depends(get_db)):
    """Record a coverage snapshot. Called automatically at end of sync-sources."""
    h = _compute_health(db)
    snap = CoverageSnapshot(
        health_score=h["health_score"],
        parser_pct=h["parser_pct"],
        mitre_pct=h["mitre_pct"],
        firing_pct=h["firing_pct"] or 0.0,
        active_sources=h["active_sources"],
        covered_sources=h["covered_sources"],
        rules_loaded=h["rules_loaded"],
        tactics_covered=h["tactics_covered"],
        techniques_covered=h["techniques_covered"],
        rules_with_mitre=h["rules_with_mitre"],
        rules_fired=h["rules_fired"],
    )
    db.add(snap)
    db.commit()
    return {"recorded": True, "health_score": h["health_score"]}


@router.get("/snapshots")
def get_snapshots(limit: int = 30, db: Session = Depends(get_db)):
    """Return the last N daily snapshots for sparkline charts."""
    rows = (
        db.query(CoverageSnapshot)
        .order_by(CoverageSnapshot.recorded_at.desc())
        .limit(limit)
        .all()
    )
    return {
        "snapshots": [
            {
                "date": r.recorded_at.strftime("%Y-%m-%d"),
                "health_score": r.health_score,
                "parser_pct": r.parser_pct,
                "mitre_pct": r.mitre_pct,
                "firing_pct": r.firing_pct,
                "active_sources": r.active_sources,
                "covered_sources": r.covered_sources,
            }
            for r in reversed(rows)  # chronological order
        ]
    }


@router.get("/dependency-map")
def get_dependency_map(db: Session = Depends(get_db)):
    """
    Flip of the coverage map: for each detection library rule, show which
    data sources it requires. Flags rules as 'at_risk' if any required
    source has no parser or has zero recent events.
    """
    rules = db.query(ParsedRule).filter_by(rule_type="library").all()
    active_sources = {s.source_name: s for s in db.query(ActiveSource).all()}
    ds_index, _ = _build_parser_ds_index()

    # Build set of source names that are "healthy" (have events + parser)
    healthy_sources: set = set()
    for name, src in active_sources.items():
        has_parser = name in ds_index or (src.parser_detected or 0) > 0
        if has_parser and (src.event_count or 0) > 0:
            healthy_sources.add(name)

    out = []
    for rule in rules:
        try:
            raw_data = json.loads(rule.raw) if rule.raw else {}
        except Exception:
            raw_data = {}

        data_sources = raw_data.get("data_sources", [])
        tactics = raw_data.get("tactics", [])
        techniques = raw_data.get("techniques", [])
        generated_alerts = raw_data.get("generated_alerts")

        source_statuses = []
        at_risk = False
        for ds in data_sources:
            src = active_sources.get(ds)
            if src is None:
                status = "inactive"
                at_risk = True
            elif ds not in healthy_sources:
                status = "no_parser"
                at_risk = True
            else:
                status = "healthy"
            source_statuses.append({"source": ds, "status": status})

        # Rules with no source requirements are not "at risk" (platform-wide rules)
        if not data_sources:
            at_risk = False

        out.append({
            "rule": rule.name,
            "rule_id": rule.rule_id,
            "sources": source_statuses,
            "source_count": len(data_sources),
            "tactics": tactics,
            "techniques": [t.get("id", "") for t in techniques if t.get("id")],
            "generated_alerts": generated_alerts,
            "at_risk": at_risk,
            "no_sources": len(data_sources) == 0,
            "product": _product_from_data_sources(data_sources),
        })

    # Sort: at-risk first, then by source count desc, then alphabetical
    out.sort(key=lambda r: (not r["at_risk"], -r["source_count"], r["rule"]))

    at_risk_count = sum(1 for r in out if r["at_risk"])
    healthy_count = sum(1 for r in out if not r["at_risk"] and not r["no_sources"])

    return {
        "rules": out,
        "total": len(out),
        "at_risk": at_risk_count,
        "healthy": healthy_count,
        "no_source_requirements": sum(1 for r in out if r["no_sources"]),
    }


@router.get("/onboarding-status")
def get_onboarding_status(db: Session = Depends(get_db)):
    """
    Pipeline status for each active source across 6 lifecycle stages.
    Returns per-source progress for the onboarding tracker view.
    """
    import re as _re
    active_sources = db.query(ActiveSource).order_by(ActiveSource.event_count.desc()).all()
    ds_index, stub_parsers = _build_parser_ds_index()
    stub_names = {s["parser_name"] for s in stub_parsers}
    firing_cache = {r.rule_name: r.alert_count for r in db.query(RuleFiringCache).all()}

    # rule_by_source: source_name → list of rule names
    rules = db.query(ParsedRule).filter_by(rule_type="library").all()
    rule_by_source: dict = {}
    for rule in rules:
        try:
            raw_data = json.loads(rule.raw) if rule.raw else {}
        except Exception:
            raw_data = {}
        for ds in raw_data.get("data_sources", []):
            rule_by_source.setdefault(ds, []).append(rule.name)

    def _normalize(s):
        return _re.sub(r"[^a-z0-9]", "", s.lower())

    def _find_parser(source_name):
        if source_name in ds_index:
            return ds_index[source_name]
        sn = _normalize(source_name)
        for ds_name, info in ds_index.items():
            if _normalize(ds_name) in sn or sn in _normalize(ds_name):
                return info
        return None

    out = []
    for src in active_sources:
        parser_info = _find_parser(src.source_name)
        parser_active = (src.parser_detected or 0) > 0
        has_ds_name = parser_info is not None and parser_info.get("parser_name") not in stub_names
        rules_for_src = rule_by_source.get(src.source_name, [])
        rules_firing = any(firing_cache.get(r, 0) > 0 for r in rules_for_src)

        has_detection_rules = len(rules_for_src) > 0

        # Core stages (apply to every source)
        core_stages = [
            {"stage": "Data Received",      "done": (src.event_count or 0) > 0},
            {"stage": "Parser File Exists", "done": parser_info is not None},
            {"stage": "Parser Active",      "done": parser_active},
            {"stage": "Source Labeled",     "done": has_ds_name and parser_active},
        ]
        # Detection stages (only meaningful when detection rules exist)
        detection_stages = [
            {"stage": "Detection Rules",    "done": has_detection_rules, "na": False},
            {"stage": "Rules Firing",       "done": rules_firing,        "na": False},
        ]

        if has_detection_rules:
            stages = core_stages + detection_stages
            total = 6
        else:
            # Mark detection stages as N/A — don't count against progress
            stages = core_stages + [
                {"stage": "Detection Rules", "done": False, "na": True},
                {"stage": "Rules Firing",    "done": False, "na": True},
            ]
            total = 4  # progress calculated over core stages only

        completed = sum(1 for s in stages if s.get("done") and not s.get("na"))
        out.append({
            "source": src.source_name,
            "event_count": src.event_count,
            "stages": stages,
            "completed": completed,
            "total": total,
            "has_detection_rules": has_detection_rules,
            "pct": round(completed / total * 100) if total else 0,
        })

    # Sort: incomplete first, then by event volume
    out.sort(key=lambda x: (x["completed"] == x["total"], -x["event_count"]))

    return {
        "sources": out,
        "fully_onboarded": sum(1 for s in out if s["completed"] == s["total"]),
        "in_progress": sum(1 for s in out if 0 < s["completed"] < s["total"]),
        "not_started": sum(1 for s in out if s["completed"] == 0),
    }


@router.delete("/reset")
def reset_data(db: Session = Depends(get_db)):
    db.query(ParsedRule).delete()
    db.query(ParserField).delete()
    db.query(ActiveSource).delete()
    db.commit()
    global _unlabelled_event_count
    _unlabelled_event_count = -1
    return {"cleared": True}
