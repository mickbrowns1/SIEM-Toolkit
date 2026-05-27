from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from db import engine, Base, get_db, ParsedRule, RuleFiringCache, CoverageSnapshot
from routers import coverage, ingest, settings, quality, query

Base.metadata.create_all(bind=engine)

# Runtime migration: add columns that didn't exist in earlier schema versions
from sqlalchemy import text
with engine.connect() as _conn:
    _conn.execute(text(
        "ALTER TABLE active_sources ADD COLUMN IF NOT EXISTS parser_detected INTEGER DEFAULT 0"
    ))
    _conn.execute(text(
        "ALTER TABLE active_sources ADD COLUMN IF NOT EXISTS unlabelled BOOLEAN DEFAULT FALSE"
    ))
    _conn.execute(text(
        "CREATE TABLE IF NOT EXISTS rule_firing_cache ("
        "id SERIAL PRIMARY KEY, "
        "rule_name VARCHAR UNIQUE, "
        "alert_count INTEGER DEFAULT 0, "
        "period_days INTEGER DEFAULT 30, "
        "checked_at TIMESTAMP"
        ")"
    ))
    _conn.execute(text(
        "CREATE TABLE IF NOT EXISTS coverage_snapshots ("
        "id SERIAL PRIMARY KEY, "
        "recorded_at TIMESTAMP, "
        "health_score FLOAT DEFAULT 0, "
        "parser_pct FLOAT DEFAULT 0, "
        "mitre_pct FLOAT DEFAULT 0, "
        "firing_pct FLOAT DEFAULT 0, "
        "active_sources INTEGER DEFAULT 0, "
        "covered_sources INTEGER DEFAULT 0, "
        "rules_loaded INTEGER DEFAULT 0, "
        "tactics_covered INTEGER DEFAULT 0, "
        "techniques_covered INTEGER DEFAULT 0, "
        "rules_with_mitre INTEGER DEFAULT 0, "
        "rules_fired INTEGER DEFAULT 0"
        ")"
    ))
    _conn.commit()

app = FastAPI(title="Parallax", version="1.0.0")


@app.on_event("startup")
async def start_ingest_prewarmer():
    """Start optional background pre-warmer for the Ingest Dashboard cache.
    Opt-in via INGEST_PREWARM=1. See backend/services/prewarmer.py."""
    from services import prewarmer
    prewarmer.start_if_enabled()


@app.on_event("startup")
async def auto_load_detections():
    """
    Auto-load detection library rules on startup.
    Tries the live S1 API first (accurate 'sources' field); falls back to extracted.json.
    Skips if rules are already loaded — use the 'Sync Library' button to force a refresh.
    """
    import os
    from sqlalchemy.orm import Session
    from services import s1_client

    db: Session = next(get_db())
    try:
        existing = db.query(ParsedRule).filter_by(rule_type="library").count()
        if existing > 0:
            return  # Already loaded — skip until user manually refreshes

        # Try live API first
        try:
            rules = await s1_client.get_platform_rules()
            if rules:
                coverage._import_from_api_rules(db, rules)
                return
        except Exception:
            pass

        # Fall back to local file
        detections_file = os.environ.get("DETECTIONS_FILE", "/app/data/detections.json")
        if os.path.exists(detections_file):
            coverage._import_detections(db, detections_file)
    finally:
        db.close()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(coverage.router, prefix="/api/coverage", tags=["Coverage"])
app.include_router(ingest.router,   prefix="/api/ingest",   tags=["Ingest"])
app.include_router(settings.router, prefix="/api/settings", tags=["Settings"])
app.include_router(quality.router,  prefix="/api/quality",  tags=["Quality"])
app.include_router(query.router,    prefix="/api/query",    tags=["Query"])


@app.get("/health")
def health():
    return {"status": "ok"}
