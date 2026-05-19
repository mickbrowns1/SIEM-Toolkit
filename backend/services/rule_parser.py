import re
import json
import yaml
from typing import Set, List

_DS_PATTERN = re.compile(
    r"dataSource\.name\s*[=in]+\s*[\('\"]([^'\"),]+)['\")]",
    re.IGNORECASE,
)


# STAR PowerQuery operators that follow a field name
_STAR_OPS = [
    "ContainsCIS", "NotContainsCIS", "Contains", "NotContains",
    "StartsWith", "EndsWith", "In", "NotIn",
    "IsEmpty", "IsNotEmpty", "Matches", "NotMatches",
    "GreaterOrEqual", "LessOrEqual", "GreaterThan", "LessThan",
    "Between", "=", "!=",
]
_STAR_KEYWORD = {"and", "or", "not", "true", "false", "null"}
_OP_PATTERN = re.compile(
    r"([\w.]+)\s*(?:" + "|".join(re.escape(op) for op in _STAR_OPS) + r")\b"
    r"|([\w.]+)\s*=",   # also catch field= (no-space form used in subQuery strings)
    re.IGNORECASE,
)


def extract_star_fields(query: str) -> Set[str]:
    """Extract field names referenced in a STAR PowerQuery/subQuery string."""
    fields: Set[str] = set()
    for match in _OP_PATTERN.finditer(query):
        field = match.group(1) or match.group(2)
        if field and field.lower() not in _STAR_KEYWORD and not field[0].isdigit():
            fields.add(field)
    return fields


def extract_sigma_fields(sigma_content: str) -> Set[str]:
    """Extract field names from a Sigma rule YAML."""
    try:
        rule = yaml.safe_load(sigma_content)
    except Exception:
        return set()

    fields: Set[str] = set()
    detection = rule.get("detection", {}) if isinstance(rule, dict) else {}

    def _walk(node):
        if isinstance(node, dict):
            for key, val in node.items():
                if key == "condition":
                    continue
                # Strip pipe modifiers: CommandLine|contains → CommandLine
                clean = key.split("|")[0]
                if clean and clean not in ("keywords",):
                    fields.add(clean)
                _walk(val)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(detection)
    return fields


def extract_data_sources(texts: List[str]) -> List[str]:
    """Extract dataSource.name values from a list of query strings."""
    sources: Set[str] = set()
    for text in texts:
        for match in _DS_PATTERN.finditer(text):
            sources.add(match.group(1).strip())
    return sorted(sources)


_SDL_FIELD_PAT = re.compile(r'\$([a-zA-Z][a-zA-Z0-9._]*)(?:=[^$]*)?\$')
_SDL_ATTR_KEY_PAT = re.compile(r'"([a-zA-Z][a-zA-Z0-9._]+)"\s*:')
# Matches both quoted and unquoted output/to keys in rewrites:
#   output: "user.name"  OR  "output": "user.name"
#   "to": "src_endpoint.ip"
_SDL_REWRITE_OUT_PAT = re.compile(
    r'(?:"output"|output|"to"|"replace")\s*:\s*"([a-zA-Z][a-zA-Z0-9._]+)"'
)


def extract_parser_fields_from_content(content: str) -> Set[str]:
    """
    Extract output field names from SDL augmented-JSON parser content string.
    Handles:
    - $field.name$ and $field.name=pattern$ from format strings
    - "output": "field.name" and output: "field.name" from rewrites
    - quoted attribute keys from attributes{} blocks
    """
    fields: Set[str] = set()

    # Fields from format strings: $field.name$ or $field.name=pattern_var$
    for match in _SDL_FIELD_PAT.finditer(content):
        field = match.group(1)
        # Skip pattern variable names (no dot, short, all lowercase)
        if "." in field or field[0].isupper() or len(field) > 6:
            fields.add(field)

    # Rewrite output targets: output: "field.name" / "output": "field.name"
    _skip_values = {"$0", "1", "2", "3", "4", "99"}
    for match in _SDL_REWRITE_OUT_PAT.finditer(content):
        val = match.group(1)
        if val not in _skip_values and "." in val:
            fields.add(val)

    # Quoted attribute keys (skip single-word SDL builtins)
    _skip_keys = {"id", "format", "halt", "input", "output", "match", "replace",
                  "timezone", "attribute", "attributes", "patterns", "formats",
                  "rewrites", "type", "version"}
    for match in _SDL_ATTR_KEY_PAT.finditer(content):
        key = match.group(1)
        if key not in _skip_keys and ("." in key or len(key) > 8):
            fields.add(key)

    return fields


_SKIP_FIELD_NAMES = {
    "id", "format", "halt", "input", "output", "match", "replace",
    "timezone", "attribute", "attributes", "patterns", "formats",
    "rewrites", "type", "version", "source", "dataset", "predicate",
    "transformations", "mappings", "observables", "fields", "constant",
    "copy", "from", "to", "value", "field", "name",
}


def _extract_rewrite_fields(rewrites) -> Set[str]:
    """Extract 'output' field names from a rewrites list."""
    fields: Set[str] = set()
    if not isinstance(rewrites, list):
        return fields
    for rw in rewrites:
        if not isinstance(rw, dict):
            continue
        # Standard SDL rewrite: {"input": "...", "output": "field.name"}
        out = rw.get("output") or rw.get("to")
        if out and isinstance(out, str) and "." in out and out not in _SKIP_FIELD_NAMES:
            fields.add(out)
    return fields


def _walk_mappings(node) -> Set[str]:
    """Recursively extract copy.to and constant.field from SDL mappings blocks."""
    fields: Set[str] = set()
    if isinstance(node, dict):
        # transformations copy: {"copy": {"from": "...", "to": "field.name"}}
        if "copy" in node and isinstance(node["copy"], dict):
            to = node["copy"].get("to")
            if to and isinstance(to, str) and "." in to:
                fields.add(to)
        # transformations constant: {"constant": {"value": ..., "field": "field.name"}}
        if "constant" in node and isinstance(node["constant"], dict):
            f = node["constant"].get("field")
            if f and isinstance(f, str) and "." in f:
                fields.add(f)
        for v in node.values():
            fields |= _walk_mappings(v)
    elif isinstance(node, list):
        for item in node:
            fields |= _walk_mappings(item)
    return fields


def extract_parser_fields(parser_json: dict) -> Set[str]:
    """
    Extract output field names from an SDL parser JSON dict.
    Handles: attributes lists, fields lists, mappings targets,
    rewrites[].output, rewrites[].to, copy.to, constant.field.
    """
    fields: Set[str] = set()

    # Legacy: attributes as list of {name: ...}
    for attr in parser_json.get("attributes", []):
        if isinstance(attr, dict) and "name" in attr:
            fields.add(attr["name"])

    # Legacy: fields list
    for field in parser_json.get("fields", []):
        if isinstance(field, str):
            fields.add(field)
        elif isinstance(field, dict) and "name" in field:
            fields.add(field["name"])

    # Legacy: flat mappings list with "target"
    for mapping in parser_json.get("mappings", []):
        if isinstance(mapping, dict) and "target" in mapping:
            fields.add(mapping["target"])

    # SDL rewrites[].output in top-level formats[]
    for fmt in parser_json.get("formats", []):
        if isinstance(fmt, dict):
            fields |= _extract_rewrite_fields(fmt.get("rewrites", []))

    # SDL mappings block (nested transformations with copy.to / constant.field)
    mappings_block = parser_json.get("mappings", {})
    if isinstance(mappings_block, dict):
        fields |= _walk_mappings(mappings_block)

    # observables[].name
    for obs in parser_json.get("observables", {}).get("fields", []):
        if isinstance(obs, dict) and "name" in obs:
            n = obs["name"]
            if "." in n:
                fields.add(n)

    return fields
