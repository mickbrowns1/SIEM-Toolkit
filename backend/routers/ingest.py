from datetime import datetime, timedelta
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel
from services import s1_client
from services.async_cache import async_ttl_cache, cache_stats, cache_clear

router = APIRouter()

# Dashboard endpoints can be expensive on busy tenants. Cache results in-process
# for a short TTL so reloads and parallel widgets are instant. Pass ?nocache=1
# to bypass for a forced refresh.
_DASHBOARD_TTL_SECONDS = 300


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


@async_ttl_cache(ttl_seconds=_DASHBOARD_TTL_SECONDS)
async def _top_sources_cached(hours: int) -> dict:
    """Cache key: hours only. days is normalised to hours upstream."""
    from_dt, to_dt = _date_range_hours(hours)
    query = "| group events=count() by dataSource.name | sort -events | limit 25"
    result = await s1_client.run_powerquery(query, from_dt, to_dt)
    return {"data": result.get("events", [])}


@router.get("/top-sources")
async def get_top_sources(
    days: int = Query(None, ge=1, le=90),
    hours: int = Query(None, ge=1, le=720),
    nocache: bool = Query(False, description="Bypass dashboard cache"),
):
    """Top log sources by event count.

    Note: SDL returns 'internal Scalyr error' when this query uses day-scale
    timestamps on busy tenants, but the same window expressed in hours runs
    fine. We normalise days -> hours internally for stability.
    """
    if hours is None and days is None:
        days = 7
    if hours is None:
        hours = days * 24
        period_label = f"{days}d"
    else:
        period_label = f"{hours}h"
    try:
        cached = await _top_sources_cached(hours, nocache=nocache)
    except Exception as e:
        raise HTTPException(502, f"PowerQuery error: {e}")
    return {"period": period_label, "data": cached["data"]}


@async_ttl_cache(ttl_seconds=_DASHBOARD_TTL_SECONDS)
async def _by_event_type_cached(days: int) -> dict:
    # Same days->hours normalisation as top-sources for tenant stability.
    from_dt, to_dt = _date_range_hours(days * 24)
    query = "| group events=count() by dataSource.name, event.type | sort -events | limit 100"
    result = await s1_client.run_powerquery(query, from_dt, to_dt)
    return {"data": result.get("events", [])}


@router.get("/by-event-type")
async def get_by_event_type(
    days: int = Query(7, ge=1, le=90),
    nocache: bool = Query(False),
):
    """Event counts grouped by source and event type."""
    try:
        cached = await _by_event_type_cached(days, nocache=nocache)
    except Exception as e:
        raise HTTPException(502, f"PowerQuery error: {e}")
    return {"period_days": days, "data": cached["data"]}


@async_ttl_cache(ttl_seconds=_DASHBOARD_TTL_SECONDS)
async def _daily_volume_cached(days: int) -> list:
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


@router.get("/daily-volume")
async def get_daily_volume(
    days: int = Query(5, ge=1, le=7),
    nocache: bool = Query(False),
):
    """Total event count per day — queries run in parallel."""
    return await _daily_volume_cached(days, nocache=nocache)


@router.get("/cache-stats")
def ingest_cache_stats():
    """Inspect dashboard cache (entry count + TTL remaining per key)."""
    return cache_stats()


@router.delete("/cache")
def ingest_cache_clear():
    """Forcefully wipe the dashboard cache (next call refetches from SDL)."""
    return {"cleared": cache_clear()}


class FilterRule(BaseModel):
    source: str = ""
    event_type: str = ""
    days: int = 7
    gb_per_million_events: float = 0.5


@router.post("/simulate-filter")
async def simulate_filter(rule: FilterRule):
    """Estimate how many events and GB would be eliminated by an exclusion filter."""
    from_dt, to_dt = _date_range(rule.days)

    # Build Scalyr filter expression clauses (uses = not ==, SDL syntax)
    clauses = []
    if rule.source:
        clauses.append(f"dataSource.name = '{rule.source}'")
    if rule.event_type:
        clauses.append(f"event.type = '{rule.event_type}'")

    if clauses:
        filter_expr = " ".join(clauses)
        query = f"{filter_expr} | group events=count()"
    else:
        query = "dataSource.name != '' | group events=count()"

    try:
        result = await s1_client.run_powerquery(query, from_dt, to_dt)
        err = result.get("error") if isinstance(result, dict) else None
        if err:
            raise HTTPException(502, f"PowerQuery error: {err}")
        rows = result.get("events") or []
        events = rows[0].get("events", 0) if rows else 0
    except HTTPException:
        raise
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
