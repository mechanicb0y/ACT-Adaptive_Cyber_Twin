"""Development TLS certificates.

Production certificates come from Let's Encrypt / your PKI and are pointed at by
``ACT_SSL_CERT`` / ``ACT_SSL_KEY``. For local HTTPS this generates a throwaway
self-signed pair with ``openssl`` (already present on virtually every dev box and
in the backend image). It refuses to run when ``ACT_ENV`` is production - a
self-signed cert there is a mistake, not a convenience.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Tuple

from app.core.settings import Settings, get_settings

log = logging.getLogger("app.core.tls")

DEFAULT_DIR = Path(__file__).resolve().parents[2] / "data" / "tls"
DEFAULT_CERT = DEFAULT_DIR / "dev-cert.pem"
DEFAULT_KEY = DEFAULT_DIR / "dev-key.pem"


class CertError(RuntimeError):
    pass


def generate_self_signed(
    cert_path: Path = DEFAULT_CERT,
    key_path: Path = DEFAULT_KEY,
    *,
    common_name: str = "localhost",
    days: int = 825,
    force: bool = False,
) -> Tuple[Path, Path]:
    """Create a self-signed cert/key pair (idempotent unless ``force``)."""
    cert_path = Path(cert_path)
    key_path = Path(key_path)

    if cert_path.exists() and key_path.exists() and not force:
        return cert_path, key_path

    if shutil.which("openssl") is None:
        raise CertError(
            "openssl is not on PATH - install it, or point ACT_SSL_CERT / "
            "ACT_SSL_KEY at an existing certificate."
        )

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key_path), "-out", str(cert_path),
        "-days", str(days), "-subj", f"/CN={common_name}",
        "-addext", f"subjectAltName=DNS:{common_name},DNS:localhost,IP:127.0.0.1",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise CertError(f"openssl failed: {result.stderr.strip()}")

    try:
        key_path.chmod(0o600)
    except OSError:
        pass
    log.warning("generated self-signed dev certificate at %s (browsers will warn)",
                cert_path)
    return cert_path, key_path


def resolve_cert_pair(settings: Settings | None = None) -> Tuple[str, str]:
    """The cert/key uvicorn should use. Generates a dev pair if none is set."""
    settings = settings or get_settings()

    if settings.ssl_cert and settings.ssl_key:
        cert, key = Path(settings.ssl_cert), Path(settings.ssl_key)
        if not cert.exists() or not key.exists():
            raise CertError(
                f"ACT_SSL_CERT / ACT_SSL_KEY point at missing files: {cert}, {key}"
            )
        return str(cert), str(key)

    if settings.is_production:
        raise CertError(
            "ACT_SSL_ENABLED is on in production but ACT_SSL_CERT / ACT_SSL_KEY "
            "are not set. Point them at your real certificate."
        )

    cert, key = generate_self_signed()
    return str(cert), str(key)
