# ACT — Four Week Plan

Target: a working end-to-end demo, a REST API + dashboard, and a defense deck.

The rule for all four weeks: **no AI, no machine learning.** Every stage below
is deterministic and explainable. The intelligence comes from correlation,
scoring and graph structure — which is exactly what makes it defensible in a
viva, and exactly what an ML layer would need as a foundation later.

---

## Week 1 — Real log ingestion ✅ DONE

Readers (file + journald), syslog framing, six parsing rules, ingestion
pipeline, CLI, real timestamps, 58 tests.

See `WEEK_01_REAL_LOG_INGESTION.md`.

---

## Week 2 — Correlation and risk

The correlator is currently one hard-coded method with a magic number
(`>= 5`). It becomes a real engine.

**Correlation rule plugins.** Same pattern as the parsing rules: a
`BaseCorrelationRule`, a registry, one file per behavior. `BehaviorCorrelator`
loops over them and stops containing detection logic itself.

**Time windows.** `5 failures ever` is not brute force — `5 failures in 60
seconds` is. Every rule gets a configurable window, which is only possible
because Week 1 fixed the timestamps.

**New behaviors beyond brute force:**

| Behavior | Built from |
|---|---|
| Successful Brute Force / Account Compromise | failures then `SUCCESSFUL_LOGIN`, same IP+user |
| SSH User Enumeration | many distinct usernames, one IP |
| Distributed Brute Force | one username, many IPs |
| Privilege Escalation Attempt | `SUDO_FAILURE` after a login |
| Suspicious Persistence | `ACCOUNT_CREATED` shortly after compromise |
| Sensitive File Access | `SUDO_COMMAND` touching `/etc/shadow`, `/etc/passwd` |

**Risk scoring engine.** `Behavior.confidence = 0.9` is currently a constant
someone typed. Replace it with a scored value built from real indicators:
attempt volume, attempt rate, distinct usernames, whether the target account
exists, whether it is `root`, time of day, whether the IP is internal or
external, whether the attempt eventually succeeded. Output: a 0–100 risk
score with the contributing factors listed, so the dashboard can explain
*why* something scored 87.

**Config file.** Thresholds and windows move out of the code into
`config/detection.yaml`. Tuning detection should not require editing Python.

Deliverable: the sample attack log produces 5–6 distinct scored behaviors
instead of 2 identical ones.

---

## Week 3 — MITRE ATT&CK and the attack graph

**MITRE mapper.** A `MitreMapper` converts each behavior into tactics and
techniques from a local JSON knowledge base (no network dependency in the
demo):

| Behavior | Technique |
|---|---|
| SSH Brute Force | T1110.001 — Password Guessing (Credential Access) |
| User Enumeration | T1087 — Account Discovery (Discovery) |
| Account Compromise | T1078 — Valid Accounts (Initial Access) |
| Privilege Escalation Attempt | T1548.003 — Sudo and Sudo Caching |
| Sensitive File Access | T1003.008 — /etc/passwd and /etc/shadow |
| Backdoor Account | T1136.001 — Create Local Account (Persistence) |

This is the single highest-value feature for the defense. It turns "5 failed
logins" into industry-standard language every examiner recognises.

**Attack graph.** Nodes are behaviors, edges are relationships (same IP, same
user, same host, temporal order). The sample log stops being a list and
becomes a path:

```
Discovery → Credential Access → Initial Access → Privilege Escalation → Persistence
```

Plus a **kill-chain completeness score**: how far along the chain did this
attacker get? That is the number that makes the whole project feel like a
product rather than an exercise.

Deliverable: `python -m app.main --file ... --graph` prints the attack path
with MITRE IDs, and the graph is exportable as JSON for the dashboard.

---

## Week 4 — API, dashboard, presentation

**REST API** (`app/api/`, FastAPI is already a dependency):

```
GET  /events                  filter by user, ip, type, time
GET  /behaviors               scored, with MITRE mapping
GET  /attack-graph            nodes + edges for the frontend
GET  /stats                   ingestion coverage, counts, top attackers
POST /ingest/file             replay a log file
WS   /stream                  live events as they are ingested
```

The `on_event` callback built in Week 1 is what feeds the websocket — the
hook is already there.

**Dashboard** (`frontend/`): live event feed, behavior cards with risk score
and MITRE technique, the attack graph visualised, top attacker IPs. Kept
deliberately simple — one page, no framework ceremony.

**Presentation deck:** the vision, the architecture diagram, the four layers,
the SOLID justification, a live demo (start the API, brute-force the Kali VM
from another terminal, watch the dashboard light up), and an honest "what is
not built yet" slide. Examiners reward that slide.

---

## Risk notes

- **Week 3 is the heaviest.** If time gets tight, ship the MITRE mapper and
  cut the attack graph down to a simple ordered chain rather than a full
  graph. MITRE mapping alone carries the defense.
- **Do the demo recording early.** A recorded backup of the live demo, made in
  week 3, saves the presentation if the VM misbehaves on the day.
- **Keep the scope closed.** No ML, no Windows parser, no Wazuh integration
  before the deadline. They belong in the "future work" slide, where they
  make the project look ambitious instead of unfinished.
