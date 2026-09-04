"""Cross-cutting infrastructure for the production build.

Nothing in here touches the detection pipeline. ``app/core`` holds the pieces a
long-running service needs that a one-shot CLI run does not: typed settings read
from the environment, structured logging, and (in later phases) metrics.

The detection core still imports nothing from this package - it stays framework
free and deterministic. These modules are wired in only by ``app/api`` and the
service entry point.
"""

from app.core.settings import Settings, get_settings

__all__ = ["Settings", "get_settings"]
