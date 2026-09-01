# ACT — Week 5: The AI Layer (Cyber Cognitive Twin)

**Goal:** the leap from *detecting* attacks to *understanding, predicting, and
acting on* them. This is the Cyber Cognitive Twin from the original vision.

**Status:** done. 216 tests passing.

---

## 1. What changed

Everything before this week answered **"what happened."** Week 5 adds four new
questions, which were the whole point of the project:

| Question | Engine |
|---|---|
| What will the attacker do next? | **Prediction engine** (ML + kill-chain model) |
| What should we do about it? | **Decision engine** |
| Can ACT act on its own? | **Response engine** (real, but safely gated) |
| Can it explain itself to a human? | **LLM analyst** |

The `CognitiveTwin` ties them together: for every attacker it runs
**predict → decide → respond → explain**.

```bash
python -m app.main --file tests/logs/auth_bruteforce.log --twin
```

```
1. 192.168.1.50   100% of kill chain, compromised
    PREDICT   now at Persistence, anomaly 63% (model: statistical)
        next -> Lateral Movement / Exfiltration  82%
    DECIDE    block_ip -> 192.168.1.50   urgency Critical, confidence 0.95
        Block 192.168.1.50: the host is compromised, and account 'kali' should also be locked.
    RESPOND   dry_run   sudo iptables -A INPUT -s 192.168.1.50 -j DROP
    EXPLAIN   (built-in)
        192.168.1.50 reached Persistence with a risk of 100/100... the most
        likely next move is Lateral Movement / Exfiltration...
```

---

## 2. Prediction — what happens next

`app/intelligence/prediction_engine.py`, `feature_extractor.py`, `anomaly_model.py`

Two signals combine:

**A kill-chain transition model.** Attacks move through stages in a fairly fixed
order (discovery → guess passwords → get in → escalate → steal credentials →
persist → spread). Given the deepest stage reached, the model ranks what usually
comes next, and even flags a *skipped* stage that may still happen. This is
deterministic and explainable — every prediction can be justified out loud.

**A machine-learning anomaly score.** How far this activity is from a normal,
quiet host. Two implementations behind one interface:

- `IsolationForestScorer` — real scikit-learn. Trains on a baseline of normal
  traffic and flags outliers.
- `StatisticalScorer` — pure Python, deviation-from-baseline, no dependency.

`build_anomaly_scorer()` uses the scikit-learn one **if the library is
installed**, and the pure-Python one otherwise. So ACT runs everywhere and gets
smarter when scikit-learn is present. Install it with `pip install scikit-learn`.

The features the model reads (`FeatureExtractor`) are volume, failure count,
distinct users, distinct IPs, speed, off-hours, external source, whether root
was targeted, whether it succeeded, and how deep the attack went.

---

## 3. Decision — what to do

`app/intelligence/decision_engine.py`

A clear policy turns understanding into one recommended action:

| Situation | Action |
|---|---|
| Host compromised, or risk ≥ block threshold | **BLOCK_IP** (+ note to lock the account) |
| Risk ≥ alert threshold | **ALERT** a human |
| Otherwise | **MONITOR** |

Thresholds live in `config/detection.json` under `response`, so how aggressive
ACT is can be tuned without touching code. The engine only **decides** — it
never runs anything. That separation is what makes an autonomous system safe to
reason about.

---

## 4. Response — acting on it, safely

`app/intelligence/response/`

This is what makes ACT autonomous: when **armed**, it really runs
`iptables ... DROP` on the Kali VM over SSH to block an attacker in real time.
It reuses the same SSH identity as the log reader, so **the machine ACT watches
is the machine ACT defends.**

Three safety rails, by design:

1. **Off by default.** ACT uses `DryRunResponder` until you explicitly arm it.
   A dry run logs the exact command but never runs it.
2. **Allow-list.** Even when armed, only blocking an IP is permitted unless you
   turn on account locking in config. Anything else is refused.
3. **Reversible only.** Every command has an undo (`iptables -D`, `passwd -u`).
   An autonomous system must never take an action it cannot take back.

```
DryRunResponder   →   logs "would run: iptables ... DROP", never executes
SSHResponder      →   runs it on the VM, but only when armed and allow-listed
```

---

## 5. Explanation — the LLM analyst

`app/intelligence/llm_analyst.py`

The language model turns ACT's structured findings into a short, analyst-style
incident report in plain English. Two deliberate choices:

- **The LLM only explains. It never decides and never acts.** Those stay in the
  deterministic engines, so the system's behaviour is never at the mercy of a
  model. The LLM makes the *output* readable, not the *decisions*.
- **It is fully optional.** Set `ANTHROPIC_API_KEY` (and optionally
  `ANTHROPIC_MODEL`) and ACT uses the real model. No key, or no internet, and it
  falls back to a built-in template. The pipeline never depends on an external
  service, so the demo can never break because the network hiccuped.

That design is also the honest answer to "is this just calling ChatGPT?" — no.
The intelligence (prediction, scoring, decision, response) is ACT's own
engineered logic. The LLM is an optional narrator on top.

---

## 6. On the dashboard

A new **Cognitive Twin** panel sits above the tabs, showing the worst attacker's
Predict / Decide / Respond at a glance, plus the narrative. Two buttons:

- **Arm response** — switches ACT from dry-run to a live SSH responder aimed at
  the VM. Turns red when armed.
- **Execute / Dry run** — carries out the decision (only really executes when
  armed).

---

## 7. Running it

```bash
cd backend

# optional, makes the anomaly score use real ML
python -m pip install scikit-learn

# optional, turns on the LLM narrator
setx ANTHROPIC_API_KEY "sk-ant-..."     # Windows, then reopen the terminal

# the AI layer on a sample attack
python -m app.main --file tests/logs/auth_bruteforce.log --twin

# on the live Kali VM
python -m app.main --ssh kali@192.168.10.139 --since=-1h --twin

# in the dashboard: read the VM, then use the Cognitive Twin panel
python -m uvicorn app.api.main:app --reload
```

API: `GET /api/intelligence`, `POST /api/arm`, `POST /api/disarm`,
`POST /api/respond?actor=<ip>`.

---

## 8. Files

**Added**

| File | Purpose |
|---|---|
| `models/prediction.py`, `decision.py`, `response.py`, `twin.py` | the new data shapes |
| `intelligence/feature_extractor.py` | events → numeric features |
| `intelligence/anomaly_model.py` | IsolationForest + pure-Python fallback |
| `intelligence/prediction_engine.py` | next-move prediction |
| `intelligence/decision_engine.py` | choose the defensive action |
| `intelligence/response/` | commands, base, dry-run, SSH responders |
| `intelligence/llm_analyst.py` | optional plain-English narrative |
| `intelligence/cognitive_twin.py` | the orchestrator |
| 4 new test files | prediction, decision+response, twin, API intelligence |

**Modified**

| File | Change |
|---|---|
| `api/engine.py` | runs the twin, arm/disarm/respond, intelligence in stats |
| `api/main.py` | `/api/intelligence`, `/api/arm`, `/api/disarm`, `/api/respond` |
| `api/serializers.py` | prediction/decision/response/assessment JSON |
| `app/main.py`, `utils/report_printer.py` | `--twin` CLI view |
| `frontend/index.html` | Cognitive Twin panel + arm/execute |
| `config/detection.json` | `response` thresholds |

---

## 9. Where the project stands

| | |
|---|---|
| Tests | 216, all passing |
| Detection rules | 13 (6 parsing, 7 correlation) |
| AI engines | prediction, decision, response, LLM analyst |
| Real-time | reads and defends a live Kali VM over SSH |
| Still deterministic | every decision is explainable; the LLM only narrates |

**Two sentences for the defense:** ACT now reads a real machine, understands the
attack in MITRE terms, predicts the attacker's next move with a machine-learning
anomaly score, decides the best defensive action, and — when armed — blocks the
attacker on the machine itself in real time, all explained in plain language by
an optional AI narrator. The intelligence is ACT's own engineered logic and
stays fully explainable; the language model is an optional layer on top, never
in control of what the system does.
