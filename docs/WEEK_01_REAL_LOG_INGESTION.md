# ACT — Week 1: Real Log Ingestion

**Goal of this week:** stop feeding ACT hand-written Python dictionaries.
Make it read real Linux logs, from a real machine, automatically.

**Status:** done. 58 tests passing. Live streaming verified.

---

## 1. What changed, in one picture

**Before this week**

```
   me, typing a dict by hand
              ↓
        EventNormalizer
              ↓
         SecurityEvent
              ↓
          EventStore
              ↓
      BehaviorCorrelator
```

The parser existed but was not connected to anything. Nothing read a file.
Nothing read the operating system.

**After this week**

```
  journalctl -f          /var/log/auth.log
        │                       │
        └───────┬───────────────┘
                ↓
          BaseLogReader          "where do lines come from?"
                ↓
           SyslogRecord          splits time / host / process / message
                ↓
            LinuxParser          "which rule understands this line?"
                ↓
        6 parsing rules          "what does this line mean?"
                ↓
         EventNormalizer         → SecurityEvent
                ↓
             EventStore
                ↓
        BehaviorCorrelator       → Behavior
```

Everything between `journalctl` and `Behavior` now runs by itself.

---

## 2. Run it

From the `backend/` folder:

```bash
# Replay the captured attack log (works on Windows, Linux, anywhere)
python -m app.main --file tests/logs/auth_bruteforce.log

# Read the real machine — Kali, last hour
sudo python -m app.main --journal --since "-1h"

# Watch the machine live; new attacks print as they happen
sudo python -m app.main --journal --follow

# Show every normalized event, not only the behaviors
python -m app.main --file tests/logs/auth_bruteforce.log --show-events

# Show all evidence events, with the original log line under each one
python -m app.main --file tests/logs/auth_bruteforce.log --evidence 0 --raw

# JSON output (this is what the REST API will return in Week 4)
python -m app.main --file tests/logs/auth_bruteforce.log --json

# Tests
pytest
```

Current output of the demo run:

```
ACT ingestion from file tests/logs/auth_bruteforce.log

35 lines read, 27 events created, 8 skipped, 0 parse errors, coverage 77.1%

2 behaviors detected

1. Possible Brute Force Attack [High]
    Detected 6 failed login attempts from 192.168.1.50
    confidence 0.9, evidence 6 events
        2026-08-06 21:11:09  FAILED_LOGIN  SSH authentication failed for user 'root' from 192.168.1.50
        2026-08-06 21:11:12  FAILED_LOGIN  SSH authentication failed for user 'root' from 192.168.1.50
        2026-08-06 21:11:15  FAILED_LOGIN  SSH authentication failed for user 'root' from 192.168.1.50
        2026-08-06 21:11:18  FAILED_LOGIN  SSH authentication failed for user 'root' from 192.168.1.50
        2026-08-06 21:11:21  FAILED_LOGIN  SSH authentication failed for user 'root' from 192.168.1.50
        2026-08-06 21:11:24  FAILED_LOGIN  SSH authentication failed for user 'root' from 192.168.1.50

2. Possible Brute Force Attack [High]
    Detected 7 failed login attempts from 192.168.1.50
    confidence 0.9, evidence 7 events
        2026-08-06 21:11:29  FAILED_LOGIN  SSH authentication failed for user 'kali' from 192.168.1.50
        ...
```

Every behavior now prints the events that prove it. `--evidence 0` prints all
of them, `--raw` adds the original log line under each one.

---

## 3. The new layers, and why each one exists

### 3.1 Readers — `app/ingestion/readers/`

**The question a reader answers: "where do the raw lines come from?"**

| File | What it does |
|---|---|
| `base_reader.py` | The contract. One method: `read()` yields lines. |
| `file_log_reader.py` | Reads a log file. `follow=True` behaves like `tail -f`. |
| `journald_reader.py` | Runs `journalctl` as a subprocess and streams its output. |

Two design decisions worth defending:

**Readers are generators, not functions that return a list.**
`read()` yields one line at a time. This is what makes a finished file and an
infinite live stream look *identical* to the rest of ACT. The pipeline does
`for line in reader.read()` and never learns whether that loop will end.
It also means ACT never loads a 2 GB log into RAM.

**`JournaldReader` uses `-o short-iso`, not the default output.**
Classic syslog prints `Aug 6 21:11:09` — with no year. `short-iso` prints
`2026-08-06T21:11:09+0300`. On a real machine we should never have to guess
which year a security event belongs to.

Modern Kali/Debian have no `/var/log/auth.log` by default — authentication
events only exist in the journal. So `JournaldReader` is the *primary* Linux
source, and `FileLogReader` is for replaying captured logs and for tests.

`FileLogReader` in follow mode also survives **log rotation**: if the file is
truncated or replaced (inode changes), it reopens instead of going silently
deaf. That is a real bug in a lot of student log collectors.

### 3.2 Syslog framing — `app/ingestion/parsers/syslog_record.py`

Every Linux log line has two halves:

```
Aug  6 21:11:09 kali sshd-session[7611]: Failed password for root from 192.168.1.50
|------------- envelope -------------| |--------- message --------------------|
```

The envelope is the same for sshd, sudo, cron and systemd. Only the message
differs.

So the envelope is parsed **exactly once**, here, into a `SyslogRecord`
(timestamp, host, process, pid, message, raw_line). Rules then receive a
ready-made record and only have to understand their own message text.

That is the single-responsibility split: **framing lives here, meaning lives
in the rules.** Before this week, `SSHFailedLoginRule` hard-coded
`"host": "kali"` because it had no way to know the real hostname. Now it
reads it from the envelope, so ACT works on any machine.

If a line has no recognisable envelope, the record is still built with
`envelope_parsed=False` and the whole line as the message — so rules can
still try. Nothing crashes.

### 3.3 Parsing rules — `app/ingestion/parsers/rules/`

**The question a rule answers: "what does this line mean?"**

Six rules now, up from one:

| Rule | Event type | Attack stage it reveals |
|---|---|---|
| `SSHFailedLoginRule` | `FAILED_LOGIN` | brute force |
| `SSHInvalidUserRule` | `FAILED_LOGIN` | user enumeration |
| `SSHAcceptedLoginRule` | `SUCCESSFUL_LOGIN` | **successful compromise** |
| `SudoAuthFailureRule` | `SUDO_FAILURE` | privilege escalation attempt |
| `SudoCommandRule` | `SUDO_COMMAND` | what the attacker actually ran |
| `UserAddedRule` | `ACCOUNT_CREATED` | persistence (backdoor account) |

`SSHAcceptedLoginRule` is the important addition. A successful login on its
own is normal. A successful login *directly after twenty failures from the
same IP* is a breach. The correlator can only see that if ACT ingests both
halves of the story — which, until this week, it did not.

The rules are registered in one place, `rules/__init__.py`:

```python
def default_linux_rules() -> list[BaseRule]:
    return [
        SSHFailedLoginRule(),
        SSHInvalidUserRule(),
        SSHAcceptedLoginRule(),
        SudoAuthFailureRule(),
        SudoCommandRule(),
        UserAddedRule(),
    ]
```

**Adding support for a new Linux event = adding one file and one line here.
No existing file is edited.** That is the Open/Closed Principle, and it is
the concrete thing to point at when the examiners ask what "modular" means.

Each rule also has a `process_hint` (`"sshd"`, `"sudo"`, `"useradd"`), used
as a cheap pre-filter so ACT does not run six regexes against every cron line.

### 3.4 The pipeline — `app/ingestion/pipeline.py`

```
reader → parser → normalizer → event store → (optional callback)
```

`IngestionPipeline` owns the **order** of the stages and nothing else. No
regex, no file handling, no detection logic. Every stage is injected through
the constructor, so any of them can be swapped without editing this file:

```
FileLogReader  →  JournaldReader   (live machine instead of a file)
LinuxParser    →  WindowsParser    (new operating system, Week 5+)
EventStore     →  PostgresStore    (real database instead of memory)
```

It returns an `IngestionStats` object:

```
read=35 events=27 unmatched=8 errors=0 coverage=77.1%
```

`coverage` is genuinely useful in the defense: it is the honest answer to
"how much of a real log does your system understand?"

The `on_event` callback lets a live stream react to each event as it arrives
(print it, run the correlator, later push it to the dashboard over a
websocket) without the pipeline ever learning what a `Behavior` is.

### 3.5 Two bugs that had to be fixed first

**Bug 1 — the normalizer threw away real time.**

```python
timestamp=datetime.now()     # old
```

Every event was stamped with the moment ACT read it. Replay a log file from
last Tuesday and all 500 events land in the same millisecond. Every
time-window rule we build in Week 2 would have been meaningless.

Now the parser extracts the real time from the log and the normalizer keeps
it. `SecurityEvent` carries **two** clocks, on purpose:

- `timestamp` — when it happened on the monitored host
- `ingested_at` — when ACT saw it

Getting a syslog timestamp right is fiddly, so it lives in its own tested
module, `app/utils/time_parser.py`. `Aug 6 21:11:09` has no year: ACT assumes
the current year, and rolls back one year if that would put the log in the
future (parsing a December log in January). ISO strings and Unix epochs are
handled too, and anything unparseable falls back to ingestion time rather
than raising — one weird date must never stop ingestion.

**Bug 2 — an unknown line was treated as an error.**

```python
raise ValueError("No parser rule matched this log.")   # old
```

A real `auth.log` is mostly lines ACT does not care about: session opened,
session closed, cron, systemd. In this week's 35-line sample, **8 lines are
noise**. Raising on them means ingestion dies on line 1.

`parse()` now returns `None` for "I don't recognise this", which the pipeline
counts as `lines_unmatched`. Only a genuinely broken rule counts as an error.
"I don't understand this line" is normal operation, not a failure.

### 3.6 Small things that also got fixed

- `app/models/event_types.py` — event types are constants now. Previously
  one file wrote `"FAILED_LOGIN"` and a test wrote `"SUCCESS_LOGIN"` while the
  correlator looked for something else. Free-text strings silently break
  correlation; constants make that a crash instead of a wrong answer.
- `SecurityEvent.metadata` — a dict for source-specific detail (ssh port, sudo
  command, failure reason, pid). New parsers stay expressive without the model
  growing a new field per log source.
- `SecurityEvent.raw_log` — the original line, kept as forensic evidence.
- `requirements.txt` — was a full `pip freeze` of the global environment
  (pygame, matplotlib, Flask, scikit-learn) saved by PowerShell as UTF-16,
  which `pip install -r` cannot even read. Replaced with the real four
  dependencies.
- `.gitignore` — `*.log` was silently excluding the test log files the whole
  test suite depends on. Added an exception.

---

## 4. Tests — 58, all passing

| File | Covers |
|---|---|
| `test_time_parser.py` | year inference, ISO offsets, safe fallback |
| `test_syslog_record.py` | envelope splitting, both formats, unframed lines |
| `test_parser_rules.py` | one test per rule + noise lines must return `None` |
| `test_readers.py` | file reading, `follow` mode, journalctl command building |
| `test_ingestion_pipeline.py` | file → events → behavior, end to end |
| `test_normalizer.py` | defaults, timestamp preservation, metadata |
| `test_linux_parser.py` | rule injection, rule registry, matched-rule reporting |
| `test_event_store*.py` | add / query by user, ip, type, recency |
| `test_behavior_correlator.py` | threshold, grouping, ignoring success |
| `test_behavior_extractor.py` | single-event behaviors |

The tests were rewritten from print-and-look-at-it scripts into real
assertions. A test that only prints cannot fail, so it protects nothing.

The one to show in the defense:

```python
def test_events_keep_the_real_log_timestamp_not_ingestion_time(bruteforce_log):
    ...
    assert all(e.timestamp.hour == 21 for e in attack_events)
```

With the old `datetime.now()` normalizer, that assertion fails on every day
except the day of the attack. It is proof the pipeline preserves real time.

`tests/logs/auth_bruteforce.log` is a realistic 35-line Kali `auth.log`
containing a full attack chain:

```
21:10  user enumeration     admin, administrator, test  → invalid user
21:11  brute force          6× root, 7× kali            → failed password
21:11  COMPROMISE           kali                        → accepted password
21:12  privilege escalation                             → sudo auth failure
21:12  credential access    sudo cat /etc/shadow
21:12  persistence          useradd backdoor + usermod -aG sudo
```

ACT currently detects **stage 2 only** (the brute force). Weeks 2–3 are about
seeing the other five stages and connecting them into one attack.

---

## 5. Reproducing it on your Kali box

```bash
sudo systemctl start ssh

# from another terminal / another machine
for i in $(seq 1 10); do ssh baduser@<kali-ip>; done

# then, on the Kali box
cd backend
sudo python -m app.main --journal --since "-10min"
```

To capture a log file you can commit and replay later:

```bash
sudo journalctl -t sshd -t sshd-session -t sudo -t useradd \
     --since "-1h" -o short-iso --no-pager > backend/tests/logs/my_attack.log
```

---

## 6. What is still missing (and when it lands)

| Component | Week |
|---|---|
| Time-window correlation, multi-behavior detection | 2 |
| Risk scoring engine | 2 |
| MITRE ATT&CK mapper | 3 |
| Attack graph | 3 |
| REST API + dashboard | 4 |
| Prediction / decision / response / Cyber Cognitive Twin | after the project |

---

## 7. Three sentences for the supervisor

> This week ACT stopped being a set of unit-tested classes and became a system
> that reads a real operating system. It ingests systemd's journal live,
> understands six classes of Linux security event, and preserves the real
> event time so that time-based correlation is possible at all. The ingestion
> layer is fully injectable: adding Windows or Wazuh next semester means
> writing one reader and one parser, and changing nothing else.
