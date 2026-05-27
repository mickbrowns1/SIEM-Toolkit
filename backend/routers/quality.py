from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta
from services import s1_client
import os
import re

router = APIRouter()


PARSERS_DIR = "/app/parsers"

# Files under PARSERS_DIR are populated by syncing from the SDL
# /api/listFiles + /api/getFile endpoints. SDL stores more than just parsers
# in the same directory: UEBA analytics tables, saved searches, dashboard
# configs and a few other types. Showing those in the Parser Test Runner
# dropdown is confusing and selecting them produces errors.
#
# Identify real parsers in two tiers:
#   1) reject names matching well-known non-parser SDL artefact patterns
#   2) accept only files whose first 4 KB contains a parser-config marker
#      (attributes:, patterns:, formats:, patternRefs:, rewrites:, parser:)

_PARSER_MARKER_RE = re.compile(
    r"^\s*(attributes|patterns|formats|patternRefs|rewrites|parser)\s*[:=]",
    re.MULTILINE,
)
_PARSER_NAME_DENYLIST = re.compile(
    r"^(ueba[_\-]|searches$|alerts$|.*_baselines?_|.*_features?_|.*_scores?_|"
    r"bsi[_\-]|.*-overview$|.*[_\-]membership$|.*[_\-]risk$|.*[_\-]smoke[_\-]test$|"
    r".*[_\-]test[_\-](default|merge|replace|same))",
    re.IGNORECASE,
)


def _looks_like_parser(path: str, name: str) -> bool:
    """Return True if a file under PARSERS_DIR is actually a parser config."""
    if _PARSER_NAME_DENYLIST.match(name):
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    return bool(_PARSER_MARKER_RE.search(head))


@router.get("/parsers")
def list_parser_files():
    """List parser filenames available under PARSERS_DIR for the Test Runner.

    Filters out non-parser SDL artefacts (UEBA tables, saved searches,
    dashboards, etc.) so the dropdown only contains files that the Test
    Runner can actually use.
    """
    try:
        entries = [e for e in os.scandir(PARSERS_DIR)
                   if e.is_file() and not e.name.startswith(".")]
    except FileNotFoundError:
        return {"parsers": [], "count": 0}
    names = sorted(
        e.name for e in entries
        if _looks_like_parser(e.path, e.name)
    )
    return {"parsers": names, "count": len(names)}


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
    filter_mode: str = "broad"  # reserved for future use


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
    Handles both:
      - quoted keys:   "format": "..."   (valid JSON)
      - unquoted keys:  format: "..."    (SDL augmented-JSON)
    Skips commented-out lines (// ...).
    """
    pattern = re.compile(r'(?<!//)\"?format\"?\s*:\s*"((?:[^"\\]|\\.)*)"')
    results = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        results.extend(pattern.findall(line))
    return results


def _sdl_format_to_regex(fmt: str) -> tuple[re.Pattern, dict[str, str]]:
    """
    Convert an SDL format string to a compiled Python regex.

    SDL format strings may start with '.*,' to absorb a syslog header.  When
    used with re.search that prefix is redundant AND harmful (it forces a comma
    before the first named field, which won't exist when the log starts with
    the field directly).  We strip the leading '.*,' so re.search can anchor
    to the first real field at any position in the line.

    Internal '.*' wildcards (field separators for skipped fields) are kept as
    non-greedy '.*?' so they don't consume adjacent named-field values.

    Returns (compiled_pattern, py_group_to_sdl_field).
    Raises re.error if the resulting pattern cannot be compiled.
    """
    # Strip leading/trailing .* wildcards — re.search handles positioning
    fmt = re.sub(r'^(\.\*,?)+', '', fmt)
    fmt = re.sub(r'(,?\.\*)+$', '', fmt)

    # Split on $...$ tokens
    token_pattern = re.compile(r'\$([^$]+)\$')
    parts = token_pattern.split(fmt)
    # parts alternates: literal, token, literal, token, ...

    regex_parts: list[str] = []
    py_group_to_sdl: dict[str, str] = {}
    seen_groups: dict[str, int] = {}

    def _escape_literal(s: str) -> str:
        """Escape literal text but keep internal .* as non-greedy wildcards."""
        segments = re.split(r'(\.\*)', s)
        return ''.join(r'.*?' if seg == '.*' else re.escape(seg) for seg in segments)

    for i, part in enumerate(parts):
        if i % 2 == 0:
            # Literal text (possibly containing .* wildcards)
            regex_parts.append(_escape_literal(part))
        else:
            # Token: either "field.name=PATTERN" or just "field.name"
            if '=' in part:
                field_name, pattern = part.split('=', 1)
            else:
                field_name = part
                # Default: match any non-comma chars (SDL CSV fields)
                pattern = r'[^,]*'

            # Build a valid Python named-group identifier
            safe = re.sub(r'[.\-]', '_', field_name)
            if safe in seen_groups:
                seen_groups[safe] += 1
                safe = f"{safe}_{seen_groups[safe]}"
            else:
                seen_groups[safe] = 0

            py_group_to_sdl[safe] = field_name
            regex_parts.append(f'(?P<{safe}>{pattern})')

    compiled = re.compile(''.join(regex_parts), re.IGNORECASE | re.DOTALL)
    return compiled, py_group_to_sdl


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/sample-unlabelled")
async def sample_unlabelled(req: SampleEventsRequest):
    """Return a sample of events that have no dataSource.name — these need parsers.
    Also runs a count query so the caller can update the banner with the real total.
    """
    import asyncio
    from routers import coverage as _coverage

    filter_expr = "!(dataSource.name = *) !(source = 'scalyr')"
    from_dt, to_dt = _date_range_hours(req.hours)

    sample_result, count_result = await asyncio.gather(
        s1_client.run_powerquery(f"{filter_expr} | limit {req.limit}", from_dt, to_dt),
        s1_client.run_powerquery(f"{filter_expr} | group events=count()", from_dt, to_dt, max_count=50_000_000),
    )

    rows = sample_result if isinstance(sample_result, list) else (sample_result.get("rows") or sample_result.get("events") or [])

    events = [_flatten_event(row) for row in rows]
    non_empty_keys: set = set()
    for ev in events:
        for k, v in ev.items():
            if v is not None and v != "" and v != "null":
                non_empty_keys.add(k)
    events = [{k: v for k, v in ev.items() if k in non_empty_keys} for ev in events]

    count_rows = count_result.get("events", []) if isinstance(count_result, dict) else []
    total = count_rows[0].get("events", 0) if count_rows else 0
    _coverage._unlabelled_event_count = total

    return {
        "events": events,
        "count": len(events),
        "total": total,
        "hours": req.hours,
        "columns_seen": sorted(non_empty_keys),
    }


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
        return {
            "source": req.source,
            "total_sampled": 0,
            "hours": req.hours,
            "fields": [],
            "fields_seen_in_sample": [],
            "message": f"No events found for source '{req.source}' in the last {req.hours} hours.",
        }

    total = len(events)
    _empty_scalars = {None, "", "null"}

    def _is_empty(val):
        """Return True if the value counts as unpopulated."""
        if val is None:
            return True
        if isinstance(val, list):
            return len(val) == 0
        if isinstance(val, dict):
            return len(val) == 0
        return val in _empty_scalars

    # Collect all field names seen across the sample (useful for surfacing what IS there)
    all_seen_fields = sorted({k for ev in events for k in ev})

    all_seen_fields_set = set(all_seen_fields)

    field_stats = []
    for field in req.fields:
        # Skip fields that don't appear anywhere in the sample
        if field not in all_seen_fields_set:
            continue
        populated = sum(1 for ev in events if not _is_empty(ev.get(field)))
        rate = round((populated / total) * 100, 1)
        field_stats.append({
            "field": field,
            "populated": populated,
            "total": total,
            "rate": rate,
        })

    # Sort descending by rate (best coverage first)
    field_stats.sort(key=lambda x: x["rate"], reverse=True)

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
    # Only enter JSON mode if the log content actually looks like JSON.
    # Don't force it based on the parser type alone — a JSON-capable parser
    # should still fall through to regex matching for non-JSON inputs.
    is_json_mode = log_input.startswith("{") or log_input.startswith("[")
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
        # SDL's parse=json puts all keys into unmapped.* namespace first, then
        # rewrites map unmapped.X -> ocsf.field.  Mirror that so rewrites fire.
        unmapped_aliases = {f"unmapped.{k}": v for k, v in extracted.items()}
        extracted_with_unmapped = {**extracted, **unmapped_aliases}

        # Apply lightweight rewrites if present (input/output/match/replace blocks).
        # We only handle simple literal/regex matches with $0 or string replacements;
        # this is best-effort, intended for quick visual verification.
        rewrites_applied = []
        # Handle both quoted keys ("input":) and unquoted keys (input:)
        rewrite_re = re.compile(
            r'\{\s*"?input"?\s*:\s*"([^"]+)"\s*,\s*"?output"?\s*:\s*"([^"]+)"\s*,\s*"?match"?\s*:\s*"((?:[^"\\]|\\.)*)"\s*,\s*"?replace"?\s*:\s*"((?:[^"\\]|\\.)*)"\s*\}',
            re.DOTALL,
        )
        derived: dict[str, str] = {}
        for m in rewrite_re.finditer(content):
            in_field, out_field, match_pat, replace_val = m.group(1), m.group(2), m.group(3), m.group(4)
            src_val = extracted_with_unmapped.get(in_field)
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

    # ── Regex format-string path ─────────────────────────────────────────────
    def _try_prefix_match(compiled: re.Pattern, py_to_sdl: dict, log_line: str):
        """
        Try the full pattern; if it doesn't match, progressively shorten from
        the right (group by group) until we get a match.  This handles logs
        that don't include all the trailing optional fields the parser defines.
        Returns (match, truncated) or (None, False).
        """
        m = compiled.search(log_line)
        if m:
            return m, False

        # Shorten pattern by removing trailing named groups one at a time
        p = compiled.pattern
        # Find all (?P<name>...) group end positions (right to left)
        group_ends = [m2.end() for m2 in re.finditer(r'\(\?P<[^>]+>[^)]*\)', p)]
        for end in reversed(group_ends[1:]):   # keep at least 1 group
            try:
                shorter = re.compile(p[:end], re.IGNORECASE | re.DOTALL)
                m2 = shorter.search(log_line)
                if m2:
                    return m2, True
            except re.error:
                continue
        return None, False

    for fmt in format_strings:
        try:
            compiled, py_to_sdl = _sdl_format_to_regex(fmt)
        except re.error:
            continue

        match, truncated = _try_prefix_match(compiled, py_to_sdl, req.log_line)
        if match:
            fields = [
                {"field": py_to_sdl.get(group, group), "value": value}
                for group, value in match.groupdict().items()
                if value is not None and value != ""
            ]
            return {
                "parser_name": req.parser_name,
                "matched": True,
                "mode": "regex",
                "format_matched": fmt[:120] + ("…" if len(fmt) > 120 else ""),
                "fields": fields,
                "note": "Partial match — log has fewer fields than the full parser format" if truncated else None,
            }

    return {
        "parser_name": req.parser_name,
        "matched": False,
        "message": "No format pattern matched. Check that the log includes the log-type keyword (e.g. TRAFFIC, THREAT) and enough comma-separated fields.",
        "fields": [],
    }
