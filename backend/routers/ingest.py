from datetime import datetime, timedelta
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel
from services import s1_client

router = APIRouter()


def _date_range(days: int) -> tuple[str, str]:
    now = datetime.utcnow()
    return (
        (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    )


def _date_range_hours(hours: int) -> tuple[str, str]:
    now = datetime.utcnow()
    return (
        (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    )


@router.get("/top-sources")
async def get_top_sources(
    days: int = Query(None, ge=1, le=90),
    hours: int = Query(None, ge=1, le=24),
):
    """Top log sources by event count over the given period."""
    if hours is not None:
        from_dt, to_dt = _date_range_hours(hours)
        period_label = f"{hours}h"
    else:
        from_dt, to_dt = _date_range(days or 7)
        period_label = f"{days or 7}d"
    query = "| group events=count() by dataSource.name | sort -events | limit 25"
    try:
        result = await s1_client.run_powerquery(query, from_dt, to_dt)
    except Exception as e:
        raise HTTPException(502, f"PowerQuery error: {e}")
    return {"period": period_label, "data": result.get("events", [])}


@router.get("/by-event-type")
async def get_by_event_type(days: int = Query(7, ge=1, le=90)):
    """Event counts grouped by source and event type."""
    from_dt, to_dt = _date_range(days)
    query = "| group events=count() by dataSource.name, event.type | sort -events | limit 100"
    try:
        result = await s1_client.run_powerquery(query, from_dt, to_dt)
    except Exception as e:
        raise HTTPException(502, f"PowerQuery error: {e}")
    return {"period_days": days, "data": result.get("events", [])}


@router.get("/daily-volume")
async def get_daily_volume(days: int = Query(5, ge=1, le=7)):
    """Total event count per day — queries run in parallel."""
    import asyncio

    now = datetime.utcnow()
    points = min(days, 7)

    async def _fetch_day(i: int) -> dict:
        day_from = (now - timedelta(days=i + 1)).strftime("%Y-%m-%dT00:00:00.000Z")
        day_to   = (now - timedelta(days=i)).strftime("%Y-%m-%dT00:00:00.000Z")
        label    = (now - timedelta(days=i + 1)).strftime("%Y-%m-%d")
        try:
            result = await s1_client.run_powerquery("| group total=count()", day_from, day_to)
            events_list = result.get("events", []) if isinstance(result, dict) else []
            count = events_list[0].get("total", 0) if events_list else 0
        except Exception:
            count = 0
        return {"date": label, "events": count}

    results = await asyncio.gather(*[_fetch_day(i) for i in range(points)])
    return list(reversed(results))


class FilterRule(BaseModel):
    source: str = ""
    event_type: str = ""
    days: int = 7
    gb_per_million_events: float = 0.5


@router.post("/simulate-filter")
async def simulate_filter(rule: FilterRule):
    """Estimate how many events and GB would be eliminated by an exclusion filter."""
    from_dt, to_dt = _date_range(rule.days)

    clauses = []
    if rule.source:
        clauses.append(f"dataSource.name=='{rule.source}'")
    if rule.event_type:
        clauses.append(f"event.type=='{rule.event_type}'")

    if clauses:
        filter_expr = " and ".join(clauses)
        query = f"| filter {filter_expr} | group events=count()"
    else:
        query = "| group events=count()"

    try:
        result = await s1_client.run_powerquery(query, from_dt, to_dt)
        events = (result.get("events") or [{}])[0].get("events", 0) if isinstance(result.get("events"), list) else 0
    except Exception as e:
        raise HTTPException(502, f"PowerQuery error: {e}")

    estimated_gb = round(events / 1_000_000 * rule.gb_per_million_events, 3)
    monthly_events = int(events / rule.days * 30)
    monthly_gb = round(monthly_events / 1_000_000 * rule.gb_per_million_events, 2)

    return {
        "period_days": rule.days,
        "matched_events": events,
        "estimated_gb_period": estimated_gb,
        "projected_monthly_events": monthly_events,
        "projected_monthly_gb": monthly_gb,
        "filter": {"source": rule.source, "event_type": rule.event_type},
    }
