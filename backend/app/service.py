"""Run the ACT API as a long-lived service.

``python -m app.main --mode service`` (or the ``act --mode service`` console
script) lands here. It configures logging, optionally resolves a TLS
certificate, and hands control to uvicorn. Everything is driven by the
environment (``ACT_HOST``, ``ACT_PORT``, ``ACT_SSL_*``, ``ACT_LOG_FORMAT`` …) so
the systemd unit / Windows service / container all start it the same way.

The process is meant to be supervised (systemd ``Restart=on-failure``, Docker
``restart: unless-stopped``, NSSM). It does not daemonise itself.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from app.config import env as _env  # noqa: F401  (loads backend/.env)
from app.core.logging import configure_logging
from app.core.settings import Settings, get_settings

log = logging.getLogger("app.service")


@dataclass(slots=True)
class ServeOptions:
    host: str
    port: int
    workers: int
    reload: bool
    ssl_certfile: Optional[str]
    ssl_keyfile: Optional[str]

    @property
    def scheme(self) -> str:
        return "https" if self.ssl_certfile else "http"


def build_options(
    settings: Optional[Settings] = None,
    *,
    host: Optional[str] = None,
    port: Optional[int] = None,
    workers: int = 1,
    reload: bool = False,
) -> ServeOptions:
    settings = settings or get_settings()

    ssl_cert = ssl_key = None
    if settings.ssl_enabled:
        from app.core.tls import resolve_cert_pair
        ssl_cert, ssl_key = resolve_cert_pair(settings)

    return ServeOptions(
        host=host or settings.host,
        port=port or settings.port,
        workers=max(1, workers),
        reload=reload,
        ssl_certfile=ssl_cert,
        ssl_keyfile=ssl_key,
    )


def run_service(
    *,
    host: Optional[str] = None,
    port: Optional[int] = None,
    workers: int = 1,
    reload: bool = False,
) -> int:
    """Blocking. Returns an exit code when uvicorn stops."""
    import uvicorn

    settings = get_settings()
    configure_logging(settings)

    opts = build_options(settings, host=host, port=port, workers=workers,
                         reload=reload)

    # Only rewrite request.client.host from X-Forwarded-For when the operator
    # has said this process sits behind a trusted proxy. Otherwise a direct
    # client could spoof its address for rate limiting and the audit log.
    forwarded_allow_ips = "*" if settings.trust_forwarded_for else "127.0.0.1"

    log.info(
        "starting ACT service",
        extra={"bind": f"{opts.scheme}://{opts.host}:{opts.port}",
               "workers": opts.workers, "env": settings.env,
               "auth": settings.auth_enabled,
               "trust_proxy": settings.trust_forwarded_for},
    )

    uvicorn.run(
        "app.api.main:app",
        host=opts.host,
        port=opts.port,
        workers=opts.workers if not opts.reload else 1,
        reload=opts.reload,
        ssl_certfile=opts.ssl_certfile,
        ssl_keyfile=opts.ssl_keyfile,
        log_config=None,          # our configure_logging owns the handlers
        access_log=True,
        proxy_headers=settings.trust_forwarded_for,
        forwarded_allow_ips=forwarded_allow_ips,
    )
    return 0
