import json
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime
from db import get_db, ParsedRule, ParserField, ActiveSource
from services import s1_client, rule_parser

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
    """Fetch STAR rules from SentinelOne and index their fields."""
    try:
        rules = await s1_client.get_star_rules()
    except Exception as e:
        raise HTTPException(502, f"S1 API error: {e}")

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


@router.post("/sync-sources")
async def sync_sources(days: int = 7, db: Session = Depends(get_db)):
    """Pull active dataSource.names from the SDL and store them."""
    from datetime import datetime, timedelta
    now = datetime.utcnow()
    from_dt = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    to_dt = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    try:
        result = await s1_client.run_powerquery(
            "| group events=count() by dataSource.name | sort -events | limit 200",
            from_dt, to_dt
        )
    except Exception as e:
        raise HTTPException(502, f"PowerQuery error: {e}")

    rows = result.get("events", [])
    # Clear old and insert fresh
    db.query(ActiveSource).delete()
    synced_at = datetime.utcnow()
    seen = 0
    for row in rows:
        name = row.get("dataSource.name")
        if name:
            db.add(ActiveSource(
                source_name=name,
                event_count=row.get("events", 0),
                synced_at=synced_at,
            ))
            seen += 1
    db.commit()
    return {"synced": seen, "sources": [r["dataSource.name"] for r in rows if r.get("dataSource.name")]}


@router.get("/map")
def get_coverage_map(db: Session = Depends(get_db)):
    """
    Source-centric coverage map.
    For each active dataSource.name in the SDL:
      - covered       = a parser is loaded for it
      - parser_needed = no parser loaded
    Also surfaces which STAR rules reference each source.
    """
    active_sources = db.query(ActiveSource).order_by(ActiveSource.event_count.desc()).all()
    parser_fields_rows = db.query(ParserField).all()
    rules = db.query(ParsedRule).all()

    # parser_name → set of field names
    parser_index: dict[str, set] = {}
    for pf in parser_fields_rows:
        parser_index.setdefault(pf.parser_name, set()).add(pf.field_name)

    # Build a fuzzy match: dataSource.name → parser_name
    # Parser names like "paloalto", "palo", "okta_authentication-latest" need to match
    # "Palo Alto Networks Firewall", "Okta", etc.
    def _find_parser(source_name: str) -> str | None:
        sn = source_name.lower().replace(" ", "").replace("-", "").replace("_", "")
        for pname in parser_index:
            pn = pname.lower().replace(" ", "").replace("-", "").replace("_", "")
            # Direct substring match in either direction
            if pn in sn or sn in pn:
                return pname
        return None

    # Build rule index: source_name → rules that reference it
    rule_by_source: dict[str, list] = {}
    for rule in rules:
        query_texts = _star_query_texts(json.loads(rule.raw)) if rule.rule_type == "star" else []
        data_sources = rule_parser.extract_data_sources(query_texts)
        for ds in data_sources:
            rule_by_source.setdefault(ds, []).append({"rule": rule.name, "type": rule.rule_type})
        if not data_sources:
            # Rule with no explicit source filter — applies to all
            rule_by_source.setdefault("__any__", []).append({"rule": rule.name, "type": rule.rule_type})

    sources_out = []
    covered_count = 0
    needed_count = 0

    for src in active_sources:
        matched_parser = _find_parser(src.source_name)
        status = "covered" if matched_parser else "parser_needed"
        if status == "covered":
            covered_count += 1
        else:
            needed_count += 1

        rules_for_src = rule_by_source.get(src.source_name, []) + rule_by_source.get("__any__", [])

        sources_out.append({
            "source_name": src.source_name,
            "event_count": src.event_count,
            "status": status,
            "parser": matched_parser,
            "parser_fields": len(parser_index.get(matched_parser, set())) if matched_parser else 0,
            "rules": rules_for_src,
            "rule_count": len(rules_for_src),
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
