import json
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from db import get_db, ParsedRule, ParserField
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


@router.get("/map")
def get_coverage_map(db: Session = Depends(get_db)):
    """Return coverage analysis: parser fields vs rule fields."""
    rules = db.query(ParsedRule).all()
    parser_fields_rows = db.query(ParserField).all()

    # field → list of rules using it + data sources referenced by those rules
    rule_field_index: dict[str, list] = {}
    rule_ds_index: dict[str, set] = {}  # field → set of dataSource.name values
    for rule in rules:
        query_texts = _star_query_texts(json.loads(rule.raw)) if rule.rule_type == "star" else []
        data_sources = rule_parser.extract_data_sources(query_texts)
        for field in rule.fields_used or []:
            rule_field_index.setdefault(field, []).append(
                {"rule": rule.name, "type": rule.rule_type}
            )
            rule_ds_index.setdefault(field, set()).update(data_sources)

    # field → parser name
    parser_field_index: dict[str, str] = {
        pf.field_name: pf.parser_name for pf in parser_fields_rows
    }

    all_fields = set(rule_field_index) | set(parser_field_index)

    detail = {}
    for f in all_fields:
        in_parser = f in parser_field_index
        in_rules = f in rule_field_index
        detail[f] = {
            "in_parser": in_parser,
            "parser_name": parser_field_index.get(f),
            "data_sources": sorted(rule_ds_index.get(f, set())),
            "rule_count": len(rule_field_index.get(f, [])),
            "rules": rule_field_index.get(f, []),
            "status": (
                "covered" if in_parser and in_rules
                else "unused" if in_parser and not in_rules
                else "missing_parser"
            ),
        }

    parsed_unused = [f for f, d in detail.items() if d["status"] == "unused"]
    missing_parser = [f for f, d in detail.items() if d["status"] == "missing_parser"]
    covered = [f for f, d in detail.items() if d["status"] == "covered"]

    return {
        "summary": {
            "total_parser_fields": len(parser_field_index),
            "total_rule_fields": len(rule_field_index),
            "covered": len(covered),
            "parsed_but_unused": len(parsed_unused),
            "rules_missing_parser": len(missing_parser),
        },
        "parsed_but_unused": parsed_unused,
        "rules_missing_parser": missing_parser,
        "fields": detail,
    }


@router.delete("/reset")
def reset_data(db: Session = Depends(get_db)):
    db.query(ParsedRule).delete()
    db.query(ParserField).delete()
    db.commit()
    return {"cleared": True}
