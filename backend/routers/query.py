from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta
from services import s1_client

router = APIRouter()


def _date_range(hours: int | None = None, days: int | None = None) -> tuple[str, str]:
    now = datetime.utcnow()
    if hours:
        delta = timedelta(hours=hours)
    else:
        delta = timedelta(days=days or 1)
    return (
        (now - delta).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    )


PRESET_QUERIES = [
    {"label": "Top sources by volume",       "query": "| group events=count() by dataSource.name | sort -events | limit 25"},
    {"label": "Unlabelled events",            "query": "!(dataSource.name = *) !(source = 'scalyr') | group events=count() by source | sort -events | limit 25"},
    {"label": "Events by type",               "query": "| group events=count() by dataSource.name, event.type | sort -events | limit 50"},
    {"label": "Failed logins",                "query": "| filter event.type = 'Logon' | filter event.outcome = 'FAILED' | group count() by user.name, src.ip | sort -count() | limit 25"},
    {"label": "Process executions",           "query": "| filter event.type = 'Process Creation' | group count() by src.process.name | sort -count() | limit 25"},
    {"label": "Network connections by dest",  "query": "| filter event.type = 'IP Connect' | group count() by dst.ip | sort -count() | limit 25"},
    {"label": "Rules firing (30d)",           "query": "| filter ruleName != '' | group alerts=count() by ruleName | sort -alerts | limit 50"},
]


class QueryRequest(BaseModel):
    query: str
    hours: int | None = None
    days: int | None = None
    max_count: int = 1000


@router.get("/presets")
def get_presets():
    return {"presets": PRESET_QUERIES}


@router.post("/run")
async def run_query(req: QueryRequest):
    """Run a PowerQuery against the Singularity Data Lake."""
    if not req.query.strip():
        raise HTTPException(400, "Query cannot be empty")
    if req.max_count > 10_000:
        req.max_count = 10_000

    from_dt, to_dt = _date_range(hours=req.hours, days=req.days)

    try:
        result = await s1_client.run_powerquery(req.query, from_dt, to_dt, max_count=req.max_count)
    except Exception as e:
        raise HTTPException(502, f"PowerQuery error: {e}")

    err = result.get("error") if isinstance(result, dict) else None
    if err:
        raise HTTPException(502, f"PowerQuery error: {err}")

    events = result.get("events", [])
    columns = sorted({k for row in events for k in row.keys()}) if events else []

    return {
        "rows": len(events),
        "columns": columns,
        "events": events,
        "from": from_dt,
        "to": to_dt,
        "query": req.query,
    }
