"""Phase 4: dev self-signed cert generation + cert resolution rules."""

from __future__ import annotations

import shutil

import pytest

from app.core import tls
from app.core.tls import CertError

_HAS_OPENSSL = shutil.which("openssl") is not None


@pytest.mark.skipif(not _HAS_OPENSSL, reason="openssl not on PATH")
def test_generate_self_signed_creates_a_usable_pair(tmp_path):
    cert = tmp_path / "c.pem"
    key = tmp_path / "k.pem"
    out_cert, out_key = tls.generate_self_signed(cert, key, common_name="localhost")
    assert out_cert.exists() and out_key.exists()
    body = out_cert.read_text()
    assert "BEGIN CERTIFICATE" in body

    # idempotent: a second call does not error and keeps the file
    mtime = out_cert.stat().st_mtime
    tls.generate_self_signed(cert, key)
    assert out_cert.stat().st_mtime == mtime


def test_resolve_uses_explicit_paths_when_present(monkeypatch, tmp_path):
    cert = tmp_path / "c.pem"; cert.write_text("x")
    key = tmp_path / "k.pem"; key.write_text("y")
    monkeypatch.setenv("ACT_SSL_CERT", str(cert))
    monkeypatch.setenv("ACT_SSL_KEY", str(key))
    from app.core.settings import reload_settings
    reload_settings()

    assert tls.resolve_cert_pair() == (str(cert), str(key))


def test_resolve_errors_when_explicit_paths_are_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("ACT_SSL_CERT", str(tmp_path / "nope.pem"))
    monkeypatch.setenv("ACT_SSL_KEY", str(tmp_path / "nope.key"))
    from app.core.settings import reload_settings
    reload_settings()
    with pytest.raises(CertError):
        tls.resolve_cert_pair()


def test_resolve_refuses_selfsigned_in_production(monkeypatch):
    monkeypatch.delenv("ACT_SSL_CERT", raising=False)
    monkeypatch.delenv("ACT_SSL_KEY", raising=False)
    monkeypatch.setenv("ACT_ENV", "production")
    from app.core.settings import reload_settings
    reload_settings()
    with pytest.raises(CertError):
        tls.resolve_cert_pair()
