"""Tiny in-process async TTL cache for backend endpoints.

Two-fold benefit:
  * Identical concurrent calls share one upstream PowerQuery (single-flight).
  * Repeat reads within TTL return instantly (no SDL round-trip).

Designed for read-only dashboard endpoints. Keep it stdlib-only so it adds
no dependency. Caches live until the process restarts.

Usage:
    @async_ttl_cache(ttl_seconds=300)
    async def get_top_sources(...): ...
"""

from __future__ import annotations
import asyncio
import functools
import time
from typing import Any, Awaitable, Callable, Tuple


# Maps cache-key -> (expires_at, value)
_STORE: dict[Tuple[str, Tuple[Any, ...], Tuple[Tuple[str, Any], ...]], Tuple[float, Any]] = {}
# Maps cache-key -> asyncio.Lock for single-flight
_LOCKS: dict[Tuple[str, Tuple[Any, ...], Tuple[Tuple[str, Any], ...]], asyncio.Lock] = {}


def _make_key(name: str, args: tuple, kwargs: dict) -> Tuple[str, Tuple[Any, ...], Tuple[Tuple[str, Any], ...]]:
    # Skip the special "nocache" kwarg so it doesn't fragment the cache.
    kw = tuple(sorted((k, v) for k, v in kwargs.items() if k != "nocache"))
    return (name, args, kw)


def async_ttl_cache(ttl_seconds: int = 300) -> Callable:
    """Decorator: cache an async function's result for ttl_seconds.

    The wrapped function may accept an optional `nocache=True` kwarg to
    bypass + refresh the cache for that call.
    """
    def decorator(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            nocache = bool(kwargs.pop("nocache", False))
            key = _make_key(fn.__qualname__, args, kwargs)

            if not nocache:
                hit = _STORE.get(key)
                if hit and hit[0] > time.monotonic():
                    return hit[1]

            lock = _LOCKS.setdefault(key, asyncio.Lock())
            async with lock:
                # Re-check after acquiring lock — another caller may have populated.
                if not nocache:
                    hit = _STORE.get(key)
                    if hit and hit[0] > time.monotonic():
                        return hit[1]

                value = await fn(*args, **kwargs)
                _STORE[key] = (time.monotonic() + ttl_seconds, value)
                return value

        return wrapper
    return decorator


def cache_stats() -> dict:
    """Debug helper: return current cache entries (no values)."""
    now = time.monotonic()
    return {
        "entries": len(_STORE),
        "live": [
            {"key": str(k), "ttl_remaining_s": round(v[0] - now, 1)}
            for k, v in _STORE.items()
            if v[0] > now
        ],
    }


def cache_clear() -> int:
    """Wipe the cache; returns the number of entries removed."""
    n = len(_STORE)
    _STORE.clear()
    return n
