"""Phase 4: `--mode service` / run_service / uvicorn option wiring."""

from __future__ import annotations

import sys
import types

import pytest


@pytest.fixture
def fake_uvicorn(monkeypatch):
    calls = {}
    mod = types.ModuleType("uvicorn")

    def run(app, **kwargs):
        calls["app"] = app
        calls["kwargs"] = kwargs

    mod.run = run
    monkeypatch.setitem(sys.modules, "uvicorn", mod)
    return calls


def _reload():
    from app.core.settings import reload_settings
    reload_settings()


def test_mode_service_dispatches_to_run_service(monkeypatch, fake_uvicorn):
    monkeypatch.setenv("ACT_HOST", "0.0.0.0")
    monkeypatch.setenv("ACT_PORT", "9100")
    _reload()

    from app.main import run
    rc = run(["--mode", "service"])
    assert rc == 0
    assert fake_uvicorn["app"] == "app.api.main:app"
    assert fake_uvicorn["kwargs"]["host"] == "0.0.0.0"
    assert fake_uvicorn["kwargs"]["port"] == 9100
    assert fake_uvicorn["kwargs"]["ssl_certfile"] is None


def test_cli_flags_override_env(monkeypatch, fake_uvicorn):
    monkeypatch.setenv("ACT_PORT", "8000")
    _reload()
    from app.main import run
    run(["--mode", "service", "--bind-host", "127.0.0.1", "--bind-port", "8123",
         "--workers", "4"])
    kw = fake_uvicorn["kwargs"]
    assert kw["host"] == "127.0.0.1" and kw["port"] == 8123 and kw["workers"] == 4


def test_reload_forces_single_worker(monkeypatch, fake_uvicorn):
    _reload()
    from app.main import run
    run(["--mode", "service", "--workers", "8", "--reload"])
    assert fake_uvicorn["kwargs"]["reload"] is True
    assert fake_uvicorn["kwargs"]["workers"] == 1


def test_build_options_wires_ssl_when_enabled(monkeypatch, tmp_path):
    cert = tmp_path / "c.pem"; cert.write_text("x")
    key = tmp_path / "k.pem"; key.write_text("y")
    monkeypatch.setenv("ACT_SSL_ENABLED", "true")
    monkeypatch.setenv("ACT_SSL_CERT", str(cert))
    monkeypatch.setenv("ACT_SSL_KEY", str(key))
    _reload()

    from app.service import build_options
    opts = build_options()
    assert opts.ssl_certfile == str(cert)
    assert opts.ssl_keyfile == str(key)
    assert opts.scheme == "https"


def test_build_options_plain_by_default(monkeypatch):
    monkeypatch.delenv("ACT_SSL_ENABLED", raising=False)
    _reload()
    from app.service import build_options
    opts = build_options()
    assert opts.ssl_certfile is None and opts.scheme == "http"


def test_mode_defaults_to_cli(monkeypatch):
    # a parse of the ingestion path still works and does not touch uvicorn
    from app.main import build_parser_arguments
    args = build_parser_arguments().parse_args(["--file", "x.log"])
    assert args.mode == "cli"
