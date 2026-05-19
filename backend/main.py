from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from db import engine, Base
from routers import coverage, ingest

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SIEM Toolkit", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(coverage.router, prefix="/api/coverage", tags=["Coverage"])
app.include_router(ingest.router, prefix="/api/ingest", tags=["Ingest"])


@app.get("/health")
def health():
    return {"status": "ok"}
