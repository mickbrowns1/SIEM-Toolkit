from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from db import engine, Base, get_db, ParsedRule
from routers import coverage, ingest, settings, quality

Base.metadata.create_all(bind=engine)

# Runtime migration: add columns that didn't exist in earlier schema versions
from sqlalchemy import text
with engine.connect() as _conn:
    _conn.execute(text(
        "ALTER TABLE active_sources ADD COLUMN IF NOT EXISTS parser_detected INTEGER DEFAULT 0"
    ))
    _conn.commit()

app = FastAPI(title="SIEM Toolkit", version="1.0.0")


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


@app.get("/health")
def health():
    return {"status": "ok"}
