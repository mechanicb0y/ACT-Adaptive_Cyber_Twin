# ACT — Adaptive Cyber Twin

ACT reads a Linux machine's security logs, understands them the way an analyst
would, and — when you let it — defends the machine on its own.

It ingests real `sshd` / `sudo` / `useradd` activity, correlates isolated events
into **behaviours** (brute force, user enumeration, privilege escalation,
credential theft, persistence), scores each one, joins them into **attack paths**
per attacker, maps everything to **MITRE ATT&CK** and the kill chain, predicts
the attacker's next move, decides whether to **BLOCK / ALERT / do nothing**, and
(when armed against a machine over SSH) carries the block out autonomously.

A local LLM (Ollama) is a genuine participant: it contributes an independent
risk judgment and confidence that are blended into the decision, and it writes
the incident narrative. Everything degrades gracefully — no Ollama, no API key,
no internet, and ACT still runs on its deterministic core.

```
logs ─▶ parse ─▶ normalise ─▶ correlate ─▶ risk score ─▶ MITRE + kill chain
                                                              │
                                             attack graph (one path per attacker)
                                                              │
                    predict next move ─▶ decide (stats + local AI) ─▶ respond
                                                              │
                             narrate (Ollama + RAG) ─▶ dashboard / API / report / alerts
```

---

## Table of contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Repository layout](#repository-layout)
4. [Setup from scratch](#setup-from-scratch)
   - [Windows (dashboard + API)](#a-windows--the-act-host)
   - [Kali / Linux (the target)](#b-kali--linux--the-monitored-machine)
   - [Ollama (local AI, optional)](#c-ollama--local-ai-optional)
5. [Running ACT](#running-act)
6. [Incident reports](#incident-reports)
7. [Alerts (Telegram / Slack)](#alerts--telegram--slack)
8. [Attack simulations](#attack-simulations)
9. [Testing](#testing)
10. [Configuration reference](#configuration-reference)
11. [Troubleshooting](#troubleshooting)
12. [Contributing](#contributing)

---

## Features

| Area | What it does |
| --- | --- |
| **Ingestion** | File replay, local `journalctl`, or a **remote machine over SSH** — each is one small reader class. Follows live. |
| **Correlation** | Time-windowed rules turn raw events into behaviours: `brute-force`, `distributed-brute-force`, `successful-brute-force`, `user-enumeration`, `privilege-escalation`, `sensitive-file-access`, `persistence`. |
| **Risk engine** | 0–100 score from explainable factors (volume, rate, privileged target, external source, compromise, night hours, …). Every point is justified. |
| **MITRE ATT&CK** | Offline technique + tactic + kill-chain-stage mapping (`data/mitre_attack.json`). |
| **Attack graph** | Connects behaviours into one path per attacker; splits unrelated attackers apart; orders by kill-chain stage. |
| **Prediction** | Kill-chain transition model + ML anomaly score ⇒ ranked "next move" guesses. |
| **Decision engine** | Deterministic policy (BLOCK / ALERT / MONITOR) **blended with the local AI's independent vote**. The AI can raise confidence, tip a borderline block, or escalate a MONITOR to ALERT — it can never invent a block on its own. |
| **Autonomous response** | When armed against an SSH host, ACT runs a reversible `iptables` block itself above its confidence threshold. Account lock / host isolation are advisory only. Off by default (simulation mode). |
| **Local AI narrator** | Ollama (preferred) / Gemini / Anthropic / built-in template, grounded in a local RAG knowledge base. |
| **Incident reports** | Per-attacker **HTML** (preview) and **PDF** (download): MITRE techniques, kill-chain stages, event timeline, risk, confidence, AI contribution, actions taken. PDF needs no third-party library. |
| **Alerts** | Instant **Telegram** and/or **Slack** notification when a critical attack is detected (risk ≥ threshold). |
| **Dashboard** | Single-file dark ops console at `/`, live WebSocket event feed. |
| **REST API** | Everything the dashboard uses, documented at `/docs`. |

---

## Architecture

ACT is a pipeline of small, single-purpose stages. Each stage is deterministic
and independently testable; only the narrator and (optionally) the anomaly score
touch a model, and both have fallbacks.

```
backend/app/
├── ingestion/          readers (file / journald / ssh) + parsers → raw events
│   ├── readers/        one class per source; adding a source = one file
│   └── parsers/        syslog envelope split + per-line rules
├── analyzer/           the "understanding" layer
│   ├── normalizer      raw dict → SecurityEvent
│   ├── correlation/    time-window rules → Behavior
│   ├── risk_engine     Behavior → 0–100 score + reasons
│   ├── mitre_mapper    Behavior → ATT&CK techniques + kill-chain stage
│   └── attack_graph_builder   Behaviors → AttackGraph (paths per attacker)
├── intelligence/       the "decision" layer
│   ├── prediction_engine   AttackPath → next-move ranking
│   ├── llm_analyst         Ollama/Gemini/Anthropic: risk judgment + narrative
│   ├── decision_engine     stats ⊕ AI vote → Decision (block/alert/monitor)
│   ├── cognitive_twin      predict → decide → respond → explain, per attacker
│   ├── notifier            Telegram / Slack critical alerts
│   ├── response/           reversible commands + dry-run / SSH responder
│   └── rag/                local embeddings + vector store for grounding
├── reporting/          AttackPath + assessment → HTML / PDF incident report
├── api/
│   ├── engine.py       AnalysisEngine: the whole pipeline, no web framework
│   ├── serializers.py  hand-written JSON contract with the dashboard
│   └── main.py         thin FastAPI routes
└── models/             plain dataclasses shared by every layer

frontend/index.html     the dashboard (no build step)
scripts/attacks/        end-to-end attack simulations
```

**Design rules that never change:**

- The pipeline core is deterministic and explainable. A model may *inform* a
  decision; it never *is* the decision.
- Every response command is reversible and printed before it runs.
- ACT never touches a machine until you point it at one over SSH **and** it
  clears its own confidence gate.
- Missing model / key / internet / RAG index ⇒ graceful fallback, never a crash.

---

## Repository layout

```
ACT/
├── backend/            Python: pipeline, API, tests
│   ├── app/            source (see Architecture)
│   ├── config/detection.json   thresholds, windows, response & alert settings
│   ├── data/           offline MITRE KB + generated RAG index
│   ├── tests/          pytest suite + sample logs
│   ├── requirements.txt
│   └── .env            local secrets (git-ignored) — see below
├── frontend/index.html the dashboard
├── scripts/attacks/    lateral-movement & other simulations
├── docs/               setup guides + the weekly design write-ups
└── docker-compose.yml
```

---

## Setup from scratch

Prerequisites: **Python 3.11+** (3.13 tested), **git**. A Linux target with
`systemd` (a Kali VM is ideal) if you want live monitoring. Ollama is optional.

### A. Windows — the ACT host

```powershell
git clone <repo-url> ACT
cd ACT\backend

python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

`requirements.txt` is small on purpose. `scikit-learn` / `numpy` are optional
(they upgrade the anomaly score and RAG search; pure-Python fallbacks are used
if absent). The LLM and embeddings are called over plain HTTP — no SDK.

Create `backend\.env` (git-ignored) for any secrets you use:

```ini
# --- Local AI (optional) ---
OLLAMA_MODEL=llama3.2
# OLLAMA_PATH=C:\Users\you\AppData\Local\Programs\Ollama   # if `ollama` isn't on PATH
# ACT_LLM_PROVIDER=ollama            # force a provider (ollama|gemini|anthropic|none)
# GEMINI_API_KEY=...                 # cloud fallback
# ANTHROPIC_API_KEY=...

# --- Critical alerts (optional) ---
# TELEGRAM_BOT_TOKEN=123456:AA...
# TELEGRAM_CHAT_ID=123456789
# SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../xxxx
```

Verify:

```powershell
python -m pytest -q
python -m app.main --file tests/logs/auth_bruteforce.log
```

### B. Kali / Linux — the monitored machine

You have two options (full detail in [`docs/KALI_SETUP.md`](docs/KALI_SETUP.md)):

**Option A (recommended): ACT on Windows, pulls logs from Kali over SSH.**
On Kali:

```bash
sudo systemctl enable --now ssh
# let your user read the journal (or ACT can use sudo journalctl)
sudo usermod -aG systemd-journal,adm "$USER"
ip addr        # note the VM's address, e.g. 192.168.10.139
```

From Windows, test the path:

```powershell
python -m app.main --ssh kali@192.168.10.139 --since=-1h
```

**Option B: run ACT inside Kali.** Copy `backend/` over, `pip install -r
requirements.txt`, and use `--journal` instead of `--ssh`.

### C. Ollama — local AI (optional)

Full guide: [`docs/OLLAMA_RAG_SETUP.md`](docs/OLLAMA_RAG_SETUP.md).

```bash
# install from https://ollama.com, then:
ollama pull llama3.2
ollama pull nomic-embed-text     # embeddings for RAG
ollama serve                     # usually already running
```

ACT auto-detects a reachable Ollama on `http://localhost:11434`. With it, the
decision confidence is blended with the model's own judgment and the narrative
becomes context-aware. Without it, ACT uses its deterministic path and a
built-in template — nothing breaks.

---

## Running ACT

### Dashboard + API

```bash
cd backend
python -m uvicorn app.api.main:app --reload
```

- Dashboard: <http://127.0.0.1:8000/>
- API docs: <http://127.0.0.1:8000/docs>

In the dashboard: put `kali@<vm-ip>` in the **Kali VM** box, then **Go live**
(follow the journal) or **Pull 1h** (one-shot). Or pick a bundled log and
**Replay**. Attack paths, the Cognitive Twin panel, MITRE techniques and the
live feed populate within a second or two.

Connecting a VM over SSH **arms** ACT: a block decision above the confidence
threshold is executed on that VM automatically. Toggle simulation-only from the
dashboard, or `POST /api/disarm`.

### CLI

```bash
python -m app.main --file tests/logs/two_attackers.log        # replay
python -m app.main --journal --since=-1h                       # this machine
python -m app.main --ssh kali@192.168.10.139 --follow          # remote, live
python -m app.main --file tests/logs/auth_bruteforce.log --json
```

### Docker

```bash
docker compose up --build      # serves the API + dashboard on :8000
```

---

## Incident reports

Every attack path can be exported as an analyst-ready report containing MITRE
ATT&CK techniques, kill-chain progression, the full event timeline, risk score,
decision confidence, the **local AI's contribution**, and the action ACT took.

- **Dashboard:** *Export Report* (HTML preview) and *PDF* buttons on the
  Cognitive Twin panel and on each attack path.
- **API:**
  ```
  GET /api/report/{attacker}?format=html    # standalone page, print-friendly
  GET /api/report/{attacker}?format=pdf      # downloadable PDF
  ```

The PDF is produced by a tiny built-in writer (standard PDF fonts, no
`reportlab` / `weasyprint` to install). The HTML version is the rich one and
also prints cleanly to PDF from the browser.

---

## Alerts — Telegram / Slack

ACT can fire an instant notification the moment a **critical** attack is
detected (decision risk ≥ `risk_threshold`, default **90**). The message
includes the attacker address, the target, the attack type, the risk score and
a short summary. Each attacker is alerted once per session.

1. **Configure a transport** in `backend/.env`:
   - Telegram: `TELEGRAM_BOT_TOKEN` (from [@BotFather](https://t.me/BotFather))
     and `TELEGRAM_CHAT_ID` (your chat/channel id).
   - Slack: `SLACK_WEBHOOK_URL` (an Incoming Webhook).
2. **Enable** in `backend/config/detection.json` → `notifications` (`enabled`,
   `platform`: `telegram` / `slack` / `both`, `risk_threshold`), or at runtime
   from the dashboard's **Critical Alerts** panel, or:
   ```
   POST /api/notifications/config?enabled=true&platform=both
   POST /api/notifications/test        # send a test on every configured transport
   GET  /api/notifications             # status
   ```

Secrets are read from the environment first and are never committed.

---

## Attack simulations

[`scripts/attacks/`](scripts/attacks/) drives ACT end to end.

**Lateral movement / internal attack** — an external breach of `web-01`, an
SSH hop to `db-01` (privilege escalation + `cat /etc/shadow` + a backdoor
account), then a second hop to `app-02`. Three hosts, three source addresses.

```bash
# safe replay (no network traffic) — feed the committed scenario to ACT:
curl -X POST "http://127.0.0.1:8000/api/ingest/file?path=lateral_movement.log"

# or regenerate it with a live clock:
python scripts/attacks/lateral_movement.py --out backend/tests/logs/act_lab.log

# or, against your OWN lab VMs, perform the real SSH hops:
scripts/attacks/lateral_movement.sh --live --web deploy@10.0.5.11 --web-pass ... \
    --db dbadmin@10.0.5.20 --db-pass ... --app svc@10.0.5.30 --app-pass ...
```

Expect ~3 attack paths, most ending in compromise, one reaching kill-chain
stage 6 (Persistence), BLOCK decisions for the deeper pivots, and a critical
alert per source address. See [`scripts/attacks/README.md`](scripts/attacks/README.md).

> Only run the `--live` paths against machines you are authorised to test.

---

## Testing

```bash
cd backend
python -m pytest -q              # full suite
python -m pytest -q tests/test_lateral_movement.py     # one file
python -m pytest -q -k decision                        # by keyword
```

The suite is **hermetic**: `conftest.py` forces `ACT_LLM_PROVIDER=none` so tests
never reach a real model. Key files:

| File | Covers |
| --- | --- |
| `test_api_contract.py` | the JSON shape the dashboard depends on |
| `test_decision_and_response.py` | the BLOCK / ALERT / MONITOR policy + responders |
| `test_decision_ai.py` | the local AI's influence on the decision |
| `test_lateral_movement.py` | multi-stage internal attack detection |
| `test_reporting.py` | HTML + PDF report generation |
| `test_notifier.py` | Telegram / Slack alerting (HTTP mocked) |
| `test_correlation_rules.py`, `test_risk_engine.py`, `test_attack_graph.py`, … | each pipeline stage |

Adding a feature means adding a test in the matching file.

---

## Configuration reference

`backend/config/detection.json` (edit this, not the code):

| Key | Meaning |
| --- | --- |
| `graph.max_gap_seconds` | two behaviours join in the attack graph only if closer than this |
| `response.block_threshold` | risk at/above which a matched attack pattern becomes block-eligible |
| `response.alert_threshold` | risk at/above which a non-pattern is still worth an alert |
| `response.auto_execute_confidence` | confidence bar to recommend **and** (armed) carry out a block |
| `response.allow_account_lock` | let the armed responder also lock accounts |
| `notifications.enabled` / `platform` / `risk_threshold` | critical-alert transport and trigger |
| `rules.<name>.enabled` / `threshold` / `window_seconds` | per-correlation-rule tuning |

Environment (`backend/.env`): `OLLAMA_MODEL`, `OLLAMA_PATH`, `ACT_LLM_PROVIDER`,
`GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `ACT_LLM_TIMEOUT`, `TELEGRAM_BOT_TOKEN`,
`TELEGRAM_CHAT_ID`, `SLACK_WEBHOOK_URL`, `ACT_NOTIFY_TIMEOUT`.

---

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Dashboard shows **API offline** | Start `uvicorn` in `backend/`. Check nothing else holds port 8000. |
| `pip install` fails on `requirements.txt` | Save the file as UTF-8 (some Windows editors write UTF-16). Upgrade `pip`. |
| SSH ingest: **"could not read the remote journal"** | Use the dashboard's *Test connection*. Usually key auth or journal permissions — `sudo usermod -aG systemd-journal $USER` on the target, or pass `sudo=true`. See `docs/KALI_SETUP.md`. |
| No attack paths after replaying a log | Confirm events were created (`/api/stats`). Very old timestamps still work; too few events for a rule's `threshold` won't correlate. |
| Narrative says **"built-in"** | No model reachable. Start `ollama serve` / `ollama pull llama3.2`, or set `GEMINI_API_KEY`. ACT still works without one. |
| AI never influences the decision | Expected without a model. With Ollama running, check `intelligence.provider` in `/api/stats`. |
| Blocks don't execute | ACT must be **armed** (a VM connected over SSH) and the decision must clear `auto_execute_confidence`. Account lock / isolation are advisory by design. |
| PDF report won't open | It's a minimal PDF — try a real reader (Acrobat, Chrome, Edge), not a thumbnailer. The HTML report is the rich version. |
| Telegram/Slack test fails | `GET /api/notifications` shows `*_ready`. Re-check the token / webhook in `.env` and restart. `last_error` carries the transport error. |
| `ollama` not found though installed | Set `OLLAMA_PATH` in `.env` to its install dir, or open a fresh terminal. |

---

## Contributing

1. **Branch** from `develop`. Keep changes focused.
2. **Match the codebase style**: small single-purpose modules, plain dataclasses
   in `models/`, detection logic in `analyzer/correlation/`, "what to do" in
   `intelligence/`. Config goes in `detection.json`, never hard-coded.
3. **Preserve the invariants**: deterministic core, reversible responses,
   graceful degradation, nothing touches a machine unless armed + confident.
4. **Test** — add/extend the test in the matching `backend/tests/test_*.py`.
   `python -m pytest -q` must stay green. Tests must not require a network or a
   model (`conftest.py` enforces `ACT_LLM_PROVIDER=none`).
5. **API changes** must update `app/api/serializers.py` **and**
   `tests/test_api_contract.py` (that test is the dashboard's contract).
6. **New log source** = one reader in `ingestion/readers/`.
   **New detection** = one rule in `analyzer/correlation/` + its MITRE mapping in
   `data/mitre_attack.json`.
7. Open the PR against `develop` with a short "why", the test output, and a note
   on any config or contract change.

The `docs/WEEK_0*.md` files record why each layer is shaped the way it is —
worth reading before a larger change.
