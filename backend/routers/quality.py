from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta
from services import s1_client
import os
import re

router = APIRouter()


PARSERS_DIR = "/app/parsers"


@router.get("/parsers")
def list_parser_files():
    """List parser filenames available under /app/parsers/ for the Test Runner."""
    try:
        names = sorted(
            e.name for e in os.scandir(PARSERS_DIR)
            if e.is_file() and not e.name.startswith(".")
        )
    except FileNotFoundError:
        names = []
    return {"parsers": names, "count": len(names)}


@router.post("/sync-from-sdl")
async def sync_parsers_from_sdl():
    """Download every parser file under /logParsers/ on the SDL tenant into
    /app/parsers/. After this call returns, the Parser Test Runner dropdown
    will include all tenant parsers (including custom ones).

    Requires SDL_CONFIG_READ_KEY in .env (Configuration Read scope on the
    Data Lake API key).
    """
    if not s1_client.SDL_CONFIG_READ_KEY:
        raise HTTPException(
            400,
            "SDL_CONFIG_READ_KEY is not set in .env. Generate a Data Lake API key "
            "with 'Configuration Read' scope in the S1 console and add it to .env."
        )

    try:
        names = await s1_client.list_sdl_parsers()
    except Exception as e:
        raise HTTPException(502, f"SDL listFiles failed: {e}")

    os.makedirs(PARSERS_DIR, exist_ok=True)
    downloaded: list[str] = []
    errors: list[dict] = []

    for name in names:
        # The path on SDL is /logParsers/<name>; we write to /app/parsers/<sanitized-name>.
        safe_name = name.replace("/", "_")
        try:
            resp = await s1_client.get_sdl_parser(name)
            content = resp.get("content")
            if content is None:
                errors.append({"parser": name, "error": "no content field in response"})
                continue
            with open(os.path.join(PARSERS_DIR, safe_name), "w", encoding="utf-8") as fh:
                fh.write(content)
            downloaded.append(safe_name)
        except Exception as e:
            errors.append({"parser": name, "error": str(e) or e.__class__.__name__})

    return {
        "downloaded": len(downloaded),
        "parsers": downloaded,
        "errors": errors,
        "directory": PARSERS_DIR,
    }


def _date_range_hours(hours: int) -> tuple[str, str]:
    now = datetime.utcnow()
    return (
        (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    )


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class SampleEventsRequest(BaseModel):
    source: str
    limit: int = 20
    hours: int = 1


class FieldPopulationRequest(BaseModel):
    source: str
    hours: int = 24
    fields: list[str] = [
        "src.ip",
        "src.port",
        "dst.ip",
        "dst.port",
        "user.name",
        "event.type",
        "src.process.name",
        "src.process.cmdline",
        "tgt.file.path",
        "network.direction",
        "dataSource.name",
    ]


class TestParserRequest(BaseModel):
    parser_name: str
    log_line: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flatten_dict(d: dict, prefix: str = "", out: dict | None = None) -> dict:
    """Recursively flatten a nested dict into dotted keys."""
    if out is None:
        out = {}
    if not isinstance(d, dict):
        return out
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            _flatten_dict(v, key, out)
        else:
            out[key] = v
    return out


def _flatten_event(event: dict) -> dict:
    """Return a flat field→value dict from a PowerQuery result row.

    If the row only carries a JSON-stringified payload in `message` (i.e. the
    parser wasn't applied at query time), parse and flatten it inline so the
    UI can measure field population accurately. The original raw `message`
    is preserved under its own key.
    """
    if not isinstance(event, dict):
        return {}
    flat = dict(event)
    msg = flat.get("message")
    if isinstance(msg, str) and msg.startswith("{") and msg.endswith("}"):
        try:
            parsed = __import__("json").loads(msg)
            if isinstance(parsed, dict):
                flat.update(_flatten_dict(parsed))
        except Exception:
            pass
    return flat


def _extract_format_strings(content: str) -> list[str]:
    """
    Extract SDL format string values from augmented-JSON parser content.
    Matches:  "format": "..."  (double-quoted value, supports escaped quotes).
    """
    pattern = re.compile(r'"format"\s*:\s*"((?:[^"\\]|\\.)*)"')
    return pattern.findall(content)


def _sdl_format_to_regex(fmt: str) -> tuple[re.Pattern, dict[str, str]]:
    """
    Convert an SDL format string to a compiled Python regex.

    Returns (compiled_pattern, py_group_to_sdl_field) mapping so callers can
    translate group names back to the original SDL field names.

    Raises re.error if the resulting pattern cannot be compiled.
    """
    # Split on $...$ tokens
    token_pattern = re.compile(r'\$([^$]+)\$')
    parts = token_pattern.split(fmt)
    # parts alternates: literal, token, literal, token, ...

    regex_parts: list[str] = []
    py_group_to_sdl: dict[str, str] = {}
    seen_groups: dict[str, int] = {}

    for i, part in enumerate(parts):
        if i % 2 == 0:
            # Literal text
            regex_parts.append(re.escape(part))
        else:
            # Token: either "field.name=PATTERN" or just "field.name"
            if '=' in part:
                field_name, pattern = part.split('=', 1)
            else:
                field_name = part
                pattern = r'[^\s]+'

            # Build a valid Python group name
            safe = re.sub(r'[.\-]', '_', field_name)
            if safe in seen_groups:
                seen_groups[safe] += 1
                safe = f"{safe}_{seen_groups[safe]}"
            else:
                seen_groups[safe] = 0

            py_group_to_sdl[safe] = field_name
            regex_parts.append(f'(?P<{safe}>{pattern})')

    compiled = re.compile(''.join(regex_parts), re.IGNORECASE)
    return compiled, py_group_to_sdl


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/sample-events")
async def sample_events(req: SampleEventsRequest):
    """Return a sample of raw events from a given data source."""
    query = f'| filter dataSource.name = "{req.source}" | limit {req.limit}'
    from_dt, to_dt = _date_range_hours(req.hours)

    result = await s1_client.run_powerquery(query, from_dt, to_dt)

    rows = result if isinstance(result, list) else (result.get("rows") or result.get("events") or [])
    events = [_flatten_event(row) for row in rows]

    return {
        "source": req.source,
        "events": events,
        "count": len(events),
        "hours": req.hours,
    }


@router.post("/field-population")
async def field_population(req: FieldPopulationRequest):
    """
    Analyse how consistently each requested field is populated across a sample
    of events from a data source.
    """
    query = f'| filter dataSource.name = "{req.source}" | limit 500'
    from_dt, to_dt = _date_range_hours(req.hours)

    result = await s1_client.run_powerquery(query, from_dt, to_dt)

    rows = result if isinstance(result, list) else (result.get("rows") or result.get("events") or [])
    events = [_flatten_event(row) for row in rows]

    if not events:
        raise HTTPException(status_code=404, detail=f"No events found for source '{req.source}' in the last {req.hours} hours.")

    total = len(events)
    _empty = {None, "", "null"}

    # Collect all field names seen across the sample (useful for surfacing what IS there)
    all_seen_fields = sorted({k for ev in events for k in ev})

    field_stats = []
    for field in req.fields:
        # dataSource.name is always 100% — we filtered by it; Scalyr just doesn't echo it back
        if field == "dataSource.name":
            populated = total
        else:
            populated = sum(1 for ev in events if ev.get(field) not in _empty)
        rate = round((populated / total) * 100, 1)
        field_stats.append({
            "field": field,
            "populated": populated,
            "total": total,
            "rate": rate,
        })

    # Sort ascending by rate (worst coverage first)
    field_stats.sort(key=lambda x: x["rate"])

    return {
        "source": req.source,
        "total_sampled": total,
        "hours": req.hours,
        "fields": field_stats,
        "fields_seen_in_sample": all_seen_fields,
    }


@router.post("/test-parser")
async def test_parser(req: TestParserRequest):
    """
    Test a parser against a raw log line by extracting and matching SDL format
    strings found in the parser file.
    """
    parser_path = f"/app/parsers/{req.parser_name}"

    try:
        with open(parser_path, "r", encoding="utf-8") as fh:
            content = fh.read()
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Parser file not found: {req.parser_name}")
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not read parser file: {exc}")

    format_strings = _extract_format_strings(content)

    # ── JSON auto-extract path ──────────────────────────────────────────────
    # SDL parsers that use `$=json{parse=json}$` (or any format containing
    # `parse=json`) auto-extract every top-level JSON key as an attribute.
    # The regex-based path can't model that — handle it explicitly so users
    # can test JSON-shaped logs against JSON-mode parsers.
    log_input = req.log_line.strip()
    is_json_mode = any("parse=json" in f for f in format_strings) or log_input.startswith("{")
    if is_json_mode:
        import json as _json
        # Support multi-line input (one JSON object per line, or a JSON array)
        lines = [ln for ln in (l.strip() for l in log_input.splitlines()) if ln]
        payloads: list[dict] = []
        parse_errors: list[str] = []
        # Single line: try direct parse; if it's a JSON array, expand.
        if len(lines) == 1:
            try:
                obj = _json.loads(lines[0])
            except Exception as e:
                return {
                    "parser_name": req.parser_name,
                    "matched": False,
                    "message": f"Parser expects JSON but log line could not be parsed as JSON: {e}",
                    "fields": [],
                }
            if isinstance(obj, list):
                payloads = [x for x in obj if isinstance(x, dict)]
            elif isinstance(obj, dict):
                payloads = [obj]
            else:
                return {
                    "parser_name": req.parser_name,
                    "matched": False,
                    "message": "Parser expects a JSON object (got scalar).",
                    "fields": [],
                }
        else:
            # Multi-line: one JSON object per line (NDJSON)
            for i, ln in enumerate(lines, 1):
                try:
                    obj = _json.loads(ln)
                    if isinstance(obj, dict):
                        payloads.append(obj)
                    else:
                        parse_errors.append(f"line {i}: not a JSON object")
                except Exception as e:
                    parse_errors.append(f"line {i}: {e}")

        if not payloads:
            return {
                "parser_name": req.parser_name,
                "matched": False,
                "message": "No valid JSON objects found. " + " | ".join(parse_errors[:3]),
                "fields": [],
            }

        # Use the first payload for the detail table; report totals.
        payload = payloads[0]
        extracted = _flatten_dict(payload)
        # Apply lightweight rewrites if present (input/output/match/replace blocks).
        # We only handle simple literal/regex matches with $0 or string replacements;
        # this is best-effort, intended for quick visual verification.
        rewrites_applied = []
        rewrite_re = re.compile(
            r'\{\s*input:\s*"([^"]+)"\s*,\s*output:\s*"([^"]+)"\s*,\s*match:\s*"((?:[^"\\]|\\.)*)"\s*,\s*replace:\s*"((?:[^"\\]|\\.)*)"\s*\}',
            re.DOTALL,
        )
        derived: dict[str, str] = {}
        for m in rewrite_re.finditer(content):
            in_field, out_field, match_pat, replace_val = m.group(1), m.group(2), m.group(3), m.group(4)
            src_val = extracted.get(in_field)
            if src_val is None:
                continue
            try:
                m2 = re.search(match_pat, str(src_val))
            except re.error:
                continue
            if not m2:
                continue
            # SDL uses $0 for whole match, $1.. for groups. Translate to Python
            # \g<0>, \g<1>, ... so re.sub doesn't read \0 as a null byte.
            def _to_py_backref(s: str) -> str:
                return re.sub(r"\$(\d+)", lambda mm: f"\\g<{mm.group(1)}>", s)
            try:
                val = re.sub(match_pat, _to_py_backref(replace_val), str(src_val), count=1)
            except re.error:
                val = replace_val
            derived[out_field] = val
            rewrites_applied.append({
                "input": in_field, "input_value": src_val,
                "output": out_field, "matched_on": match_pat, "result": val,
            })

        fields = (
            [{"field": k, "value": v, "source": "json-extract"} for k, v in sorted(extracted.items())]
            + [{"field": k, "value": v, "source": "rewrite"}     for k, v in sorted(derived.items())]
        )
        return {
            "parser_name": req.parser_name,
            "matched": True,
            "mode": "json",
            "format_matched": "$=json{parse=json}$",
            "fields": fields,
            "rewrites_applied": rewrites_applied,
            "extracted_count": len(extracted),
            "derived_count": len(derived),
            "payload_count": len(payloads),
            "parse_errors": parse_errors,
            "showing_payload": 1,
        }

    # ── Regex format-string path (original) ─────────────────────────────────
    for fmt in format_strings:
        try:
            compiled, py_to_sdl = _sdl_format_to_regex(fmt)
        except re.error:
            # Skip unparseable format strings
            continue

        match = compiled.search(req.log_line)
        if match:
            fields = [
                {"field": py_to_sdl.get(group, group), "value": value}
                for group, value in match.groupdict().items()
                if value is not None
            ]
            return {
                "parser_name": req.parser_name,
                "matched": True,
                "mode": "regex",
                "format_matched": fmt,
                "fields": fields,
            }

    return {
        "parser_name": req.parser_name,
        "matched": False,
        "message": "No format pattern matched",
        "fields": [],
    }
