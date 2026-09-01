# ACT — Week 4: API, Dashboard and Defense

**Goal:** everything the command line can do, available over HTTP and drawn in a browser.

**Status:** done. 176 tests passing.

---

## 1. Start it

```bash
cd backend
python -m pip install fastapi uvicorn
python -m uvicorn app.api.main:app --reload
```

Then open:

- **http://127.0.0.1:8000** — the dashboard
- **http://127.0.0.1:8000/docs** — API documentation, generated automatically

---

## 2. Where the logic lives

The most important decision this week was **not** putting the logic in the routes.

```
app/api/engine.py        AnalysisEngine, no web framework anywhere in it
app/api/serializers.py   ACT objects -> plain JSON dictionaries
app/api/main.py          FastAPI routes, three or four lines each
```

`AnalysisEngine` owns the event store, the ingestion pipeline, the correlator
and the graph builder. Every route reads a query, calls the engine, and
serializes. That means:

- the whole API is tested **without starting a server** (`tests/test_api_engine.py`)
- the JSON shape is a written contract, tested separately (`tests/test_api_contract.py`)
- swapping FastAPI for anything else would not touch a line of logic

The engine also **caches**. Detection only re-runs when the number of stored
events changes, so a dashboard polling every second does not re-correlate
thousands of events each time.

---

## 3. The endpoints

| Method | Path | What it does |
|---|---|---|
| GET | `/api/events` | filter by `user`, `ip`, `type`, `search`, with `limit` and `offset` |
| GET | `/api/behaviors` | filter by `min_risk`, `rule`, `severity` |
| GET | `/api/behaviors/{id}` | one behavior with all its evidence |
| GET | `/api/attack-graph` | nodes and edges, ready to draw |
| GET | `/api/stats` | everything the dashboard header needs |
| GET | `/api/logs` | sample logs available to replay |
| POST | `/api/ingest/file?path=` | replay a captured log |
| POST | `/api/ingest/journal?since=` | read this machine |
| POST | `/api/live/start` | follow the journal or a file in the background |
| POST | `/api/live/stop` | stop following |
| POST | `/api/reset` | clear everything |
| WS | `/api/stream` | every new event, the moment it is ingested |

Example:

```bash
curl -X POST "http://127.0.0.1:8000/api/ingest/file?path=auth_bruteforce.log"
curl "http://127.0.0.1:8000/api/behaviors?min_risk=80"
curl "http://127.0.0.1:8000/api/attack-graph"
```

---

## 4. The live stream

`WS /api/stream` pushes each new event as it arrives.

It **polls the engine once a second** rather than being pushed to by a callback.
That is deliberate: ingestion runs in its own thread, and reading a growing list
from the event loop is far easier to reason about than pushing objects across
threads. A dropped socket cannot take the server down.

The `on_event` callback designed back in Week 1 is what makes live ingestion
possible at all — the hook was already there, it just had nothing listening.

---

## 5. The dashboard

`frontend/index.html` — one file, no framework, no build step.

- **Header stats** — events, coverage, behaviors, highest risk, attack paths,
  kill chain completeness, technique count
- **Behavior cards** — coloured by severity, each one opens to show *why this
  score is 100* and the evidence behind it
- **Attack paths** — the chain drawn stage by stage, with the reason on every
  link and a live link to each ATT&CK page
- **Events table** — everything ingested, newest first
- **Live feed** — websocket, updates as the attack happens
- **Top sources and techniques** — sidebar summary

Controls across the top: replay a sample log, read this machine, start/stop the
live monitor, clear.

The dashboard uses the same colour palette the CLI output implies, and the deck
uses it too — so the demo looks like one product rather than three tools.

---

## 6. A bug this week caught

Loading two log files into one store merged two unrelated attackers into a
single attack path. Both had attacked `root`, five hours apart, and the shared
username was enough to link them.

Fix: edges in the attack graph now have a **time limit**.

```json
"graph": { "max_gap_seconds": 3600 }
```

Two behaviors are joined only if the gap between their time spans is under an
hour. Same reasoning as the correlation windows in Week 2 — things far apart in
time are not one session. It is in the config file, not the code.

---

## 7. Files

**Added**

| File | Purpose |
|---|---|
| `app/api/engine.py` | AnalysisEngine, all API logic, framework free |
| `app/api/serializers.py` | the JSON contract |
| `frontend/index.html` | the dashboard |
| `tests/test_api_engine.py` | ingestion, filtering, caching, stats, reset |
| `tests/test_api_contract.py` | every key the dashboard reads |
| `docs/ACT_Defense_Deck.pptx` | 16 slide defense presentation |
| `docs/DEMO_RUNBOOK.md` | what to type on the day |

**Modified**

| File | Change |
|---|---|
| `app/api/main.py` | replaced the placeholder with the full API |
| `app/analyzer/attack_graph_builder.py` | time limit on edges |
| `app/config/detection_config.py` | non-rule config sections |
| `config/detection.json` | added the `graph` block |

---

## 8. Where the project ended up

| | |
|---|---|
| Tests | 176, all passing |
| Detection rules | 13 — 6 parsing, 7 correlation |
| ATT&CK techniques | 6 |
| Log coverage | 77.1% of a real auth log |
| Kill chain stages | 6, detected end to end |
| Lines of production code | roughly 2,500 |

**Still not built, on purpose:** prediction, automatic response, Windows and
Wazuh ingestion, a real database, and machine learning of any kind. The four
weeks built the foundation those would need — a prediction engine has to learn
from a clean history of correlated, timestamped, labelled behaviors, and that
history is exactly what did not exist a month ago.
