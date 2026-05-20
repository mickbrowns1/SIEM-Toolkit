import json
import os
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime
from db import get_db, ParsedRule, ParserField, ActiveSource
from services import s1_client, rule_parser

DETECTIONS_FILE = os.environ.get("DETECTIONS_FILE", "/app/data/detections.json")

router = APIRouter()


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
        db.add(ParsedRule(
            rule_id=rule_id,
            name=rule.get("name", "unnamed"),
            rule_type="library",
            fields_used=[],          # API rules don't expose field-level info
            raw=json.dumps({"data_sources": sources}),
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

        db.add(ParsedRule(
            rule_id=rule_id,
            name=rule.get("name", "unnamed"),
            rule_type="library",
            fields_used=list(all_fields),
            raw=json.dumps({"data_sources": list(set(data_sources))}),
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


@router.post("/load-parsers-from-sdl")
async def load_parsers_from_sdl(db: Session = Depends(get_db)):
    """
    Load SDL parsers from the local /app/parsers directory (mounted from ./parsers/).
    Files are placed there by the MCP-based loader or by manual copy.
    Falls back to a clear error if the directory is empty.
    """
    import os
    parsers_dir = "/app/parsers"

    try:
        entries = [
            e for e in os.scandir(parsers_dir)
            if e.is_file() and not e.name.startswith(".")
        ]
    except FileNotFoundError:
        raise HTTPException(503, "parsers/ directory not found — check Docker volume mount")

    if not entries:
        raise HTTPException(
            422,
            "No parser files found in parsers/ directory. "
            "Use 'Load SDL Parsers via MCP' in Claude Code to populate it, "
            "or upload a parser file manually."
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
    return {"loaded": len(loaded), "parsers": loaded, "errors": errors}


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

    rows = volume_result.get("events", [])
    db.query(ActiveSource).delete()
    synced_at = datetime.utcnow()
    seen = 0
    for row in rows:
        name = row.get("dataSource.name")
        if name and name not in _S1_NATIVE_SOURCES:
            db.add(ActiveSource(
                source_name=name,
                event_count=row.get("events", 0),
                synced_at=synced_at,
                parser_detected=parsed_by_source.get(name, 0),
            ))
            seen += 1
    db.commit()
    return {"synced": seen, "sources": [r["dataSource.name"] for r in rows if r.get("dataSource.name") and r["dataSource.name"] not in _S1_NATIVE_SOURCES]}


def _build_parser_ds_index() -> dict[str, dict]:
    """
    Read all parser files from /app/parsers/ and build an index:
      dataSource.name (exact, from parser attributes) → {parser_name, format_type}

    Format type is "grok", "dottedJson", or "custom".
    Sources with grok/dottedJson parsers are flagged as needing a proper parser.
    """
    import os, re
    parsers_dir = "/app/parsers"
    _DS_NAME_RE = re.compile(r'"dataSource\.name"\s*:\s*"([^"]+)"')
    _FORMAT_TYPE_RE = re.compile(r'"type"\s*:\s*"([^"]+)"')

    index: dict[str, dict] = {}
    try:
        entries = [e for e in os.scandir(parsers_dir) if e.is_file() and not e.name.startswith(".")]
    except FileNotFoundError:
        return index

    for entry in entries:
        try:
            with open(entry.path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception:
            continue

        # Extract dataSource.name (may appear multiple times — take first)
        ds_match = _DS_NAME_RE.search(content)
        if not ds_match:
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

    return index


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

    # parser_name → set of field names (for field count display)
    parser_index: dict[str, set] = {}
    for pf in parser_fields_rows:
        parser_index.setdefault(pf.parser_name, set()).add(pf.field_name)

    # Build dataSource.name → {parser_name, format_type} index from parser files
    ds_index = _build_parser_ds_index()

    def _normalize(s: str) -> str:
        return s.lower().replace(" ", "").replace("-", "").replace("_", "").replace(".", "")

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

        for ds in data_sources:
            rule_by_source.setdefault(ds, []).append({"rule": rule.name, "type": rule.rule_type})

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
        else:
            status = "parser_needed"
            matched_parser = None
            format_type = None

        if status == "covered":
            covered_count += 1
        else:
            needed_count += 1

        rules_for_src: list = [r for r in rule_by_source.get(src.source_name, []) if r["type"] == "library"]

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
            "parser_fields": len(parser_provides),
            "parser_detected": src.parser_detected or 0,
            "rules": rules_for_src,
            "rule_count": len(rules_for_src),
            "close_matches": close_matches,
            "missing_fields": missing_fields,
            "missing_fields_count": len(missing_fields),
            "synced_at": src.synced_at.isoformat() if src.synced_at else None,
        })

    synced_at = active_sources[0].synced_at.isoformat() if active_sources else None

    return {
        "summary": {
            "active_sources": len(active_sources),
            "covered": covered_count,
            "parser_needed": needed_count,
            "parsers_loaded": len(parser_index),
            "rules_loaded": len(rules),
        },
        "sources": sources_out,
        "synced_at": synced_at,
        "has_sources": len(active_sources) > 0,
    }


@router.delete("/reset")
def reset_data(db: Session = Depends(get_db)):
    db.query(ParsedRule).delete()
    db.query(ParserField).delete()
    db.commit()
    return {"cleared": True}
