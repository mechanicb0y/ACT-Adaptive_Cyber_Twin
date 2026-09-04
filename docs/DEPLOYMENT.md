# Deploying ACT

Four ways to run ACT as a long-lived service. All of them start the same
process — `python -m app.main --mode service` (or `act --mode service`) — which
runs uvicorn in the foreground and is supervised by systemd / Docker / NSSM.

Config always comes from the environment (`backend/.env`, or the container's
env). The two variables you must set for any real deployment:

| Variable | Why |
| --- | --- |
| `ACT_JWT_SECRET` | Without it sessions die on restart and cannot be shared across workers. `python -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `DATABASE_URL` | `postgresql+psycopg://user:pass@host:5432/act` for production. Unset = local SQLite. |

Run `alembic upgrade head` before first start (the container and the systemd
unit do this for you).

---

## 1. Docker Compose (recommended)

```bash
cp .env.docker.example .env          # set POSTGRES_PASSWORD, ACT_JWT_SECRET
docker compose up -d --build         # backend + frontend + postgres
docker compose --profile tools up -d # + pgAdmin on :5050
docker compose --profile ai    up -d # + Ollama (set OLLAMA_HOST=http://ollama:11434)
```

- Dashboard: <http://localhost:8080> · API docs: <http://localhost:8080/docs>
- The **frontend** container (nginx) serves the static dashboard and proxies
  `/api`, `/docs`, `/openapi.json` (and the `/api/stream` websocket) to the
  **backend** container.
- Migrations run automatically (`docker-entrypoint.sh` waits for Postgres, then
  `alembic upgrade head`).
- Health checks are defined for every service; `depends_on … condition:
  service_healthy` orders startup.
- Persistent volumes: `pgdata`, `act-data` (SQLite/RAG/TLS), `act-logs`,
  `ollama`, `pgadmin`.
- First admin: set `ACT_ADMIN_PASSWORD` in `.env`, or leave it blank and read the
  generated one from `docker compose logs act-backend`.

**Development**: `cp docker-compose.override.yml.example docker-compose.override.yml`
for source bind-mounts + `--reload` + the API exposed directly on `:8000`.

### TLS with Compose

Terminate TLS at the nginx frontend (add a `443` listener + `ssl_certificate`
lines and mount your certs), or put a proxy (Caddy, Traefik) in front. The
backend can also do TLS itself — set `ACT_SSL_ENABLED=true` and mount the cert,
then publish `8000`.

---

## 2. systemd (Linux, bare-metal or VM)

```bash
sudo useradd --system --home /opt/act --shell /usr/sbin/nologin act
sudo cp -r . /opt/act && sudo chown -R act:act /opt/act
sudo python3 -m venv /opt/act/backend/.venv
sudo /opt/act/backend/.venv/bin/pip install -r /opt/act/backend/requirements.txt psycopg[binary]
sudo install -m0640 -o act -g act /opt/act/backend/.env.example /opt/act/backend/.env
sudo -e /opt/act/backend/.env          # set ACT_JWT_SECRET, DATABASE_URL

sudo cp systemd/act.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now act
journalctl -u act -f
```

- `Restart=on-failure`, `RestartSec=3`; `ExecStartPre` runs the migrations.
- Logs go to the journal. `ACT_LOG_FORMAT=json` (set in the unit) makes each line
  structured — ship with `journalctl -u act -o cat | …`.
- The unit is hardened (`ProtectSystem=strict`, `NoNewPrivileges`, empty
  capability set, `ReadWritePaths` limited to `data/` and `logs/`).

### HTTPS without a reverse proxy

```bash
sudo scripts/letsencrypt.sh act.example.com you@example.com
sudo mkdir -p /etc/systemd/system/act.service.d
sudo cp systemd/act-https.conf /etc/systemd/system/act.service.d/https.conf   # edit the domain
sudo systemctl daemon-reload && sudo systemctl restart act
```

`act-https.conf` sets `ACT_SSL_ENABLED`, the cert paths, `ACT_FORCE_HTTPS=true`,
`ACT_PORT=443` and grants `CAP_NET_BIND_SERVICE`. certbot's deploy hook
(`systemctl try-restart act`) picks up renewals.

---

## 3. Windows service

No systemd; use the helper script (elevated PowerShell, from the repo root):

```powershell
# real Windows service via NSSM  (winget install NSSM.NSSM)
.\windows\Install-ActService.ps1 -Method NSSM

# or, no extra software: a Scheduled Task that runs at boot as SYSTEM
.\windows\Install-ActService.ps1 -Method Task

.\windows\Install-ActService.ps1 -Uninstall
```

- NSSM: auto-start, restart-on-exit (3 s delay), stdout/stderr rotated in
  `backend\logs\`.
- Config from `backend\.env`. For structured logs the script sets
  `ACT_LOG_FORMAT=json`.

---

## 4. Plain uvicorn (quick / debugging)

```bash
cd backend
python -m app.main --mode service            # reads ACT_HOST / ACT_PORT / ACT_SSL_*
python -m app.main --mode service --reload --bind-port 8001
# equivalent to the historical:
python -m uvicorn app.api.main:app --reload
```

---

## SSL / HTTPS reference

| Variable | Meaning |
| --- | --- |
| `ACT_SSL_ENABLED` | `true` makes `--mode service` start uvicorn with TLS. |
| `ACT_SSL_CERT` / `ACT_SSL_KEY` | PEM paths. If unset **and not production**, ACT generates a self-signed pair in `backend/data/tls/` (needs `openssl`). In production, unset = refuse to start. |
| `ACT_FORCE_HTTPS` | Redirect any plaintext request to `https://` (honours `X-Forwarded-Proto`; never redirects `/api/health`). Use it behind a TLS-terminating proxy too. |

Dev certificate by hand: `scripts/gen-dev-cert.sh` (Linux/macOS/Git-Bash) or
`windows\gen-dev-cert.ps1`.
