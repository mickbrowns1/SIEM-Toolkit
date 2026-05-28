import os, shutil
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db import get_db, ConsoleConfig, ActiveSource, ParserField, ParsedRule, RuleFiringCache
from services import s1_client

PARSERS_DIR = "/app/parsers"


def _clear_console_data(db: Session) -> dict:
    """Wipe all sync data that is specific to a console (sources, parsers, rules, firing cache)
    and delete fetched parser files from disk. Called when switching active console."""
    sources_deleted  = db.query(ActiveSource).delete()
    fields_deleted   = db.query(ParserField).delete()
    rules_deleted    = db.query(ParsedRule).delete()
    firing_deleted   = db.query(RuleFiringCache).delete()
    db.commit()

    # Remove fetched parser files (keep directory itself)
    files_deleted = 0
    try:
        for entry in os.scandir(PARSERS_DIR):
            if entry.is_file() and not entry.name.startswith("."):
                os.remove(entry.path)
                files_deleted += 1
    except FileNotFoundError:
        pass

    return {
        "sources": sources_deleted,
        "parser_fields": fields_deleted,
        "rules": rules_deleted,
        "firing_cache": firing_deleted,
        "parser_files": files_deleted,
    }

router = APIRouter()


def _mask(token: str) -> str:
    """Return the last 6 characters of a token, padded with bullets."""
    if not token:
        return ""
    return "••••••" + token[-6:] if len(token) > 6 else "••••••"


def _console_out(c: ConsoleConfig) -> dict:
    return {
        "id": c.id,
        "name": c.name,
        "s1_base_url": c.s1_base_url,
        "s1_api_token": _mask(c.s1_api_token or ""),
        "sdl_xdr_url": c.sdl_xdr_url,
        "sdl_log_read_key": _mask(c.sdl_log_read_key or ""),
        "sdl_config_read_key": _mask(c.sdl_config_read_key or ""),
        "sdl_pq_timeout": c.sdl_pq_timeout,
        "is_active": c.is_active,
        "created_at": c.created_at.isoformat() if c.created_at else None,
    }


@router.get("/list")
def list_consoles(db: Session = Depends(get_db)):
    """Return all configured consoles with masked tokens."""
    consoles = db.query(ConsoleConfig).order_by(ConsoleConfig.id).all()
    return {"consoles": [_console_out(c) for c in consoles]}


@router.get("/active")
def get_active(db: Session = Depends(get_db)):
    """Return the currently active console (masked), or null if none."""
    c = db.query(ConsoleConfig).filter_by(is_active=True).first()
    return {"console": _console_out(c) if c else None}


class AddConsoleBody(BaseModel):
    name: str
    s1_base_url: str
    s1_api_token: str
    sdl_xdr_url: str
    sdl_log_read_key: str
    sdl_config_read_key: str = ""
    sdl_pq_timeout: int = 600


@router.post("/add")
def add_console(body: AddConsoleBody, db: Session = Depends(get_db)):
    """Create a new console entry. First console is automatically made active."""
    existing = db.query(ConsoleConfig).filter_by(name=body.name).first()
    if existing:
        raise HTTPException(400, f"A console named '{body.name}' already exists")

    is_first = db.query(ConsoleConfig).count() == 0

    c = ConsoleConfig(
        name=body.name,
        s1_base_url=body.s1_base_url.rstrip("/"),
        s1_api_token=body.s1_api_token,
        sdl_xdr_url=body.sdl_xdr_url.rstrip("/"),
        sdl_log_read_key=body.sdl_log_read_key,
        sdl_config_read_key=body.sdl_config_read_key,
        sdl_pq_timeout=body.sdl_pq_timeout,
        is_active=is_first,
    )
    db.add(c)
    db.commit()
    db.refresh(c)

    if is_first:
        s1_client.set_active_console({
            "s1_base_url": c.s1_base_url,
            "s1_api_token": c.s1_api_token,
            "sdl_xdr_url": c.sdl_xdr_url,
            "sdl_log_read_key": c.sdl_log_read_key,
            "sdl_config_read_key": c.sdl_config_read_key,
            "sdl_pq_timeout": c.sdl_pq_timeout,
        })

    return {"console": _console_out(c)}


@router.post("/{console_id}/activate")
def activate_console(console_id: int, db: Session = Depends(get_db)):
    """Set this console as active, update s1_client credentials, and clear stale sync data."""
    c = db.query(ConsoleConfig).filter_by(id=console_id).first()
    if not c:
        raise HTTPException(404, "Console not found")

    # Check if we're actually switching (not re-activating the same one)
    currently_active = db.query(ConsoleConfig).filter_by(is_active=True).first()
    is_switch = currently_active is None or currently_active.id != console_id

    # Deactivate all others, activate this one
    db.query(ConsoleConfig).update({"is_active": False})
    c.is_active = True
    db.commit()
    db.refresh(c)

    s1_client.set_active_console({
        "s1_base_url": c.s1_base_url,
        "s1_api_token": c.s1_api_token,
        "sdl_xdr_url": c.sdl_xdr_url,
        "sdl_log_read_key": c.sdl_log_read_key,
        "sdl_config_read_key": c.sdl_config_read_key,
        "sdl_pq_timeout": c.sdl_pq_timeout,
    })

    cleared = None
    if is_switch:
        cleared = _clear_console_data(db)

    return {"console": _console_out(c), "cleared": cleared, "needs_sync": is_switch}


@router.delete("/{console_id}")
def delete_console(console_id: int, db: Session = Depends(get_db)):
    """Delete a console. Cannot delete the currently active console."""
    c = db.query(ConsoleConfig).filter_by(id=console_id).first()
    if not c:
        raise HTTPException(404, "Console not found")
    if c.is_active:
        raise HTTPException(400, "Cannot delete the active console — activate another console first")
    db.delete(c)
    db.commit()
    return {"deleted": console_id}
