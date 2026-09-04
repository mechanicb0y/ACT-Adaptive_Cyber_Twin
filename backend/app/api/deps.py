"""Shared FastAPI dependencies for the route modules.

The API keeps one :class:`AnalysisEngine` for the whole process. It used to be a
module global in ``main.py``; it lives here now so the versioned route modules
can reach it without importing ``main`` (which would be circular).
"""

from __future__ import annotations

from app.api.engine import AnalysisEngine

_engine: AnalysisEngine | None = None


def get_engine() -> AnalysisEngine:
    global _engine
    if _engine is None:
        _engine = AnalysisEngine()
    return _engine


def reset_engine_singleton() -> None:
    """Drop the cached engine (tests that need a clean pipeline call this)."""
    global _engine
    _engine = None
