# ACT — Week 2: Correlation and Risk

**Goal:** stop detecting one thing with one hard coded number. Detect the whole
attack, and give every finding a score that can be explained.

---

## 1. The two problems Week 1 left behind

**Problem 1. The correlator had one method and a magic number.**

```python
if len(events) >= 5:      # 5 what? in how long? decided by who?
```

Five failed logins spread over three months looked exactly like five failed
logins in ten seconds. One is a user who forgot his password. The other is an
attack.

**Problem 2. The score was typed by hand.**

```python
confidence = 0.90         # always, for everything
severity  = "High"        # always, for everything
```

Every finding looked equally dangerous, so the number meant nothing.

---

## 2. What ACT finds now

Same log file as last week. Week 1 found 2 identical behaviors. Week 2 finds 7,
scored and sorted:

```
7 behaviors detected

1. Account Compromise After Brute Force   risk 100/100   Critical
2. Suspicious Account Creation            risk  85/100   Critical
3. Sensitive File Access                  risk  80/100   Critical
4. Possible Brute Force Attack (root)     risk  73/100   High
5. SSH User Enumeration                   risk  68/100   High
6. Possible Brute Force Attack (kali)     risk  58/100   Medium
7. Privilege Escalation Attempt           risk  45/100   Medium
```

The same 19 failed logins appear in three different findings, which is correct
and worth explaining if asked: enumeration is *which accounts he looked for*,
brute force is *which password he guessed*, and compromise is *that he
succeeded*. Three questions about the same evidence.

That list is the whole attack story, in order of danger.

---

## 3. Time windows

`app/analyzer/correlation/time_window.py`

This is the core of the week. It uses a **sliding window with two pointers**:
`right` walks forward through the events, `left` is pushed forward until the two
fit inside the window. Whenever the window holds enough events, that is a burst.
Overlapping bursts are merged, so one attack is reported once instead of fifty
times.

```
events:   x  x  x  x  x            x        x
          |--- 5 in 15s ---|                      -> attack
                                   |-- 2 in 1h --| -> not an attack
```

Two helpers matter:

- `find_bursts()` counts **events** — "5 failures for the same user".
- `find_distinct_burst()` counts **distinct values** — "3 different usernames".

Ten failures for one username is password guessing. Ten failures for ten
usernames is someone hunting for accounts that exist. Both are ten events, so
counting events alone cannot tell them apart.

There is also `is_remote_ip()` and `is_external_ip()`, which answer two
different questions. `192.168.1.50` is remote (another machine) but not external
(still inside the network). Mixing those up is a common mistake.

---

## 4. Correlation rules, one file each

`app/analyzer/correlation/`

Same pattern as the parsing rules from Week 1. A parsing rule says what one log
line means. A correlation rule says what several events mean **together**.

| Rule | What it looks for | Base |
|---|---|---|
| `brute-force` | many failures, same user + same ip, one window | 45 |
| `user-enumeration` | one ip, many different usernames | 40 |
| `distributed-brute-force` | one username, many different ips | 55 |
| `successful-brute-force` | a success right after many failures | 85 |
| `privilege-escalation` | failed sudo, worse if a remote login came first | 30 |
| `sensitive-file-access` | sudo touching /etc/shadow, /etc/passwd, ssh keys | 70 |
| `persistence` | a new account created, worse if just after a login | 60 |

The two worth explaining in the defense:

**`successful-brute-force`** is the most important rule in ACT so far. Neither
half is suspicious alone — failures happen, logins happen. Only the *order and
the timing* make it a breach. This is exactly what a signature based IDS cannot
do and what correlation exists for.

**`distributed-brute-force`** groups by username instead of by ip. Attackers
spread attempts across many machines precisely so that a per-ip counter never
reaches its threshold. Changing the grouping key catches that.

All seven are registered in one list in `correlation/__init__.py`. Adding an
eighth is one new file plus one line.

---

## 5. The risk engine

`app/analyzer/risk_engine.py`

The rules decide **what** happened. The risk engine decides **how dangerous** it
is, from 0 to 100, and keeps the reasons.

| Indicator | Points | Why |
|---|---|---|
| rule base score | 30–85 | some attacks are worse than others |
| volume | +5 / +10 / +15 | more attempts means more determination |
| speed | +8 / +15 | a human types slowly, a script does not |
| privileged target | +15 | root is worth more than a normal user |
| external source | +10 | from the internet, not the office |
| many usernames | +5 / +10 | wide search, not a typo |
| spread over many ips | +10 | deliberately evading per-ip limits |
| the attack worked | +20 | a breach, not an attempt |
| credential files read | +10 | credential theft |
| account created | +10 | persistence |
| right after a remote login | +15 | context makes a normal action suspicious |
| outside working hours | +5 | nobody legitimate at 03:00 |

Score to severity: 80+ Critical, 60+ High, 35+ Medium, below that Low.

**The key design choice: the reasons are kept, not just the number.** Every
behavior carries its `risk_factors`, so ACT can print why:

```
1. Account Compromise After Brute Force   risk 100/100   Critical
    User 'kali' logged in successfully from 192.168.1.50 after 19 failed attempts
    why this score
        +85 Account Compromise After Brute Force base risk
        +15 20 events
        +8 automated speed, 23 events per minute
        +20 the attacker successfully logged in
```

A score with no explanation is a number nobody trusts. This one can always be
defended.

---

## 6. Thresholds moved out of the code

`config/detection.json`

```json
"brute-force": {
    "enabled": true,
    "threshold": 5,
    "window_seconds": 120
}
```

Tuning detection should not mean editing Python. Rules can also be switched off
here. JSON was chosen instead of YAML on purpose, so there is no extra package
to install. A missing or broken config file does not stop ACT — every rule keeps
its own defaults.

---

## 7. The correlator itself

`app/analyzer/behavior_correlator.py` no longer contains any detection logic. It
runs each enabled rule, scores what comes back, and sorts by risk. Detection
lives in the rules, danger lives in the risk engine, and this file only puts the
two together.

`detect_brute_force()` is kept as a thin wrapper so older code and tests still
work.

---

## 8. Files

**Added**

| File | Purpose |
|---|---|
| `app/models/severity.py` | Low / Medium / High / Critical, chosen from the score |
| `app/models/risk_factor.py` | one reason a behavior got its points |
| `app/config/detection_config.py` | loads thresholds from JSON, safe defaults |
| `config/detection.json` | the actual thresholds and windows |
| `app/analyzer/correlation/time_window.py` | sliding windows, grouping, ip checks |
| `app/analyzer/correlation/base_correlation_rule.py` | the rule contract |
| `app/analyzer/correlation/__init__.py` | rule registry |
| 7 rule files | one detection each |
| `app/analyzer/risk_engine.py` | 0–100 score plus reasons |
| `tests/test_time_window.py` | window maths |
| `tests/test_correlation_rules.py` | one test per rule |
| `tests/test_risk_engine.py` | scoring behaviour |
| `tests/test_detection_config.py` | config loading and failure |
| `tests/test_attack_chain.py` | full attack, end to end |

**Modified**

| File | Change |
|---|---|
| `app/models/behavior.py` | added `risk_score`, `risk_factors`, `rule`, `first_seen`, `last_seen`, `attributes` |
| `app/analyzer/behavior_correlator.py` | rewritten as a rule runner |
| `app/utils/report_printer.py` | prints the score and the reasons |
| `app/main.py` | runs all rules, new flags `--config`, `--min-risk`, `--no-factors` |
| `tests/test_behavior_correlator.py` | rewritten for windows and scoring |

---

## 9. Running it

```bash
cd backend

# first time only
python -m pip install pytest

# everything
python -m app.main --file tests/logs/auth_bruteforce.log

# only serious findings
python -m app.main --file tests/logs/auth_bruteforce.log --min-risk 70

# shorter output
python -m app.main --file tests/logs/auth_bruteforce.log --no-factors --evidence 3

# different thresholds without touching the code
python -m app.main --file tests/logs/auth_bruteforce.log --config my_rules.json

# tests (use python -m, the pytest command is not on PATH on Windows)
python -m pytest
```

---

## 10. Next week

MITRE ATT&CK mapping (turning each behavior into a technique ID like T1110.001)
and the attack graph that links the seven behaviors into one attack path with a
kill chain completeness score.
