# Week 1 — File by File Changes

Short version of every file that was added or modified, and why.

Totals: **18 files added**, **10 files modified**, **58 tests passing**.

---

## Added — new code

### `app/models/event_types.py`
Constants for event types (`FAILED_LOGIN`, `SUCCESSFUL_LOGIN`, `SUDO_FAILURE`,
`SUDO_COMMAND`, `ACCOUNT_CREATED`) and failure reasons.

Before, event types were free-text strings written by hand in each file. One
file wrote `"FAILED_LOGIN"`, a test wrote `"SUCCESS_LOGIN"`, and the mismatch
broke correlation silently. Constants turn a typo into an import error.

### `app/utils/time_parser.py`
Turns any timestamp format into a real `datetime`.

Handles three formats. Traditional syslog `Aug 6 21:11:09` has **no year**, so
it assumes the current year and rolls back one year if that puts the log in the
future. ISO `2026-08-06T21:11:09+0300` (what journald prints) is converted to
naive local time. Unix epoch numbers work too. Anything unparseable returns a
fallback instead of raising, because one bad date must not stop ingestion.

### `app/ingestion/parsers/syslog_record.py`
Splits a log line into envelope and message.

```
Aug  6 21:11:09 kali sshd-session[7611]: Failed password for root from 10.0.0.5
|------------- envelope -------------| |----------- message -----------------|
```

One regex, run once per line, producing a `SyslogRecord` with `timestamp`,
`host`, `process`, `pid`, `message`, `raw_line`. The envelope is identical for
sshd, sudo, cron and systemd, so parsing it once means the rules only deal with
the message. If the line has no envelope, the record is still built with
`envelope_parsed=False` and the whole line as message.

### `app/ingestion/parsers/rules/__init__.py`
The rule registry. One function, `default_linux_rules()`, returning the list of
rules in priority order. The only place that knows the full rule list — adding
a rule means adding one line here.

### `app/ingestion/parsers/rules/ssh_invalid_user_rule.py`
Parses `Invalid user admin from 192.168.1.50 port 51402`. Produces a
`FAILED_LOGIN` with `failure_reason = invalid_user`. Signals user enumeration:
a real user typing their password wrong does not invent new account names.

### `app/ingestion/parsers/rules/ssh_accepted_login_rule.py`
Parses `Accepted password for kali from 192.168.1.50 port 51432 ssh2`.
Produces `SUCCESSFUL_LOGIN`.

The most important new rule. A successful login on its own is normal; a
successful login directly after twenty failures from the same IP is a breach.
The correlator can only see that if ACT ingests both halves of the story.

### `app/ingestion/parsers/rules/sudo_auth_failure_rule.py`
Parses `pam_unix(sudo:auth): authentication failure; ... user=kali`.
Produces `SUDO_FAILURE`. A privilege escalation attempt.

### `app/ingestion/parsers/rules/sudo_command_rule.py`
Parses `kali : TTY=pts/1 ; PWD=/home/kali ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow`.
Produces `SUDO_COMMAND` and keeps the command in `metadata`. Which command was
run is the interesting part.

### `app/ingestion/parsers/rules/user_added_rule.py`
Parses `new user: name=backdoor, UID=1001, home=..., shell=/bin/bash`.
Produces `ACCOUNT_CREATED`. Classic persistence: the attacker makes their own
account so they can come back after the password is changed.

### `app/ingestion/readers/base_reader.py`
Abstract class for every log source. One method, `read()`, which **yields**
lines instead of returning a list.

Yielding is the key decision. It makes a finished file and an infinite live
stream look identical to the pipeline, and it means ACT never loads a 2 GB log
into memory.

### `app/ingestion/readers/file_log_reader.py`
Reads a log file. `follow=True` behaves like `tail -f`, waiting for new lines.

Also handles log rotation: if the file is truncated or replaced (inode
changes), it reopens instead of going silently deaf, which is a common bug in
log collectors.

### `app/ingestion/readers/journald_reader.py`
Runs `journalctl -o short-iso --no-pager [-u unit] [-t identifier] [--since ...] [-f]`
as a subprocess and streams stdout line by line.

This is what makes ACT read a real machine. `-o short-iso` is deliberate: it
prints a full ISO timestamp with a year, so ACT never guesses. Modern Kali has
no `/var/log/auth.log`, so the journal is the primary Linux source and
`FileLogReader` is for replay and tests. Reports a clear error when journalctl
is missing or permission is denied.

### `app/ingestion/pipeline.py`
`IngestionPipeline` and `IngestionStats`.

```
reader -> parser -> normalizer -> event store -> optional callback
```

It owns the **order** of the stages and nothing else. No regex, no file
handling, no detection. Every stage is injected through the constructor, so
`FileLogReader → JournaldReader` or `EventStore → PostgresStore` needs zero
edits here.

`IngestionStats` counts lines read, events created, unmatched lines, parse
errors, and computes coverage — the honest answer to "how much of a real log
does your system understand?". The `on_event` callback lets a live stream react
per event without the pipeline knowing what a `Behavior` is.

### `app/main.py`
Command line entry point. Wires reader, parser, normalizer, store and
correlator together and prints the result.

```
python -m app.main --file tests/logs/auth_bruteforce.log
python -m app.main --journal --since "-1h"
python -m app.main --journal --follow
```

Flags: `--file`, `--journal`, `--unit`, `--since`, `--follow`, `--tail`,
`--host`, `--json`, `--show-events`, `--evidence N`, `--raw`.

### `app/utils/report_printer.py`
All console formatting, kept out of `main.py` so it can be reused later.

Plain lines only, no banner characters, no aligned key/value columns.
Indentation carries the structure. Every behavior prints the events that prove
it; `--evidence 0` prints all of them and `--raw` adds the original log line
under each event.

### `tests/conftest.py`
Shared pytest fixtures (`parser`, `normalizer`, `store`, `logs_dir`,
`bruteforce_log`) and the `sys.path` setup that makes `from app...` imports work
no matter which directory pytest runs from.

### `pytest.ini`
Pytest configuration. `pytest` with no arguments now runs the whole suite.

### `tests/logs/auth_bruteforce.log`
A realistic 35-line Kali `auth.log` containing a full attack chain: user
enumeration, brute force on two accounts, successful compromise, sudo failure,
`sudo cat /etc/shadow`, `useradd backdoor`. It also contains 8 lines of normal
noise (cron, systemd, session open/close) that ACT must correctly ignore.

### New test files
`test_time_parser.py`, `test_syslog_record.py`, `test_parser_rules.py`,
`test_readers.py`, `test_ingestion_pipeline.py`.

### Package `__init__.py` files
Added to `app/` and every subpackage. Makes the packages explicit instead of
relying on implicit namespace packages.

---

## Modified — existing code

### `app/models/security_event.py`
Added three fields.

- `metadata: dict` — source-specific detail (ssh port, sudo command, failure
  reason, pid). Lets new parsers stay expressive without the model growing a
  new field for every log source.
- `raw_log: str` — the original line, kept as forensic evidence.
- `ingested_at: datetime` — when ACT saw the event, kept separate from
  `timestamp`, which is when it happened on the monitored host.

### `app/analyzer/normalizer.py`
**Bug fix.** It used `timestamp=datetime.now()`, so every event was stamped
with the moment ACT read it. Replaying a log file put 500 events in the same
millisecond, which would have made every time-window rule in Week 2
meaningless.

Now it parses the real timestamp from the raw dictionary via `time_parser`, and
records `ingested_at` separately. It also sweeps any unknown key a parser
returns into `metadata` instead of dropping it.

### `app/ingestion/parsers/base_parser.py`
`parse()` now returns `Optional[dict]` — `None` means "no rule matched".

**Bug fix.** It used to raise `ValueError` on an unrecognised line. A real
`auth.log` is mostly lines ACT does not care about (8 out of 35 in the sample),
so raising means ingestion dies on line 1. "I do not understand this line" is
normal operation, not an error.

### `app/ingestion/parsers/rules/base_rule.py`
`matches()` and `parse()` now take a `SyslogRecord` instead of a raw string.
Added `name` (used in output and tests) and `process_hint` (`"sshd"`,
`"sudo"`, `"useradd"`), a cheap pre-filter so ACT does not run six regexes
against every cron line.

### `app/ingestion/parsers/rules/ssh_failed_login_rule.py`
Rewritten for the record-based interface. It also now:

- handles `Failed password for invalid user admin from ...`, not only the
  plain form
- reads host, process, pid and timestamp from the envelope instead of
  hard-coding `"host": "kali"` — so it works on any machine
- puts port, auth method and failure reason in `metadata`
- keeps the original line in `raw_log`

### `app/ingestion/parsers/linux_parser.py`
Rules are now **injected** through the constructor (defaulting to the registry)
instead of being hard-coded, so tests can run one rule in isolation. It frames
the line into a `SyslogRecord` first, then asks each rule in turn. Returns
`None` when nothing matches, and records which rule matched in `matched_rule`.

It still contains no parsing logic of its own, which is the point.

### `requirements.txt`
Was a full `pip freeze` of the global environment — pygame, matplotlib, Flask,
scikit-learn — saved by PowerShell as UTF-16, which `pip install -r` cannot
even read. Replaced with the four real backend dependencies.

### `.gitignore`
`*.log` was silently excluding `tests/logs/*.log`, the files the whole test
suite depends on. Added an exception, plus `.venv/` and `.pytest_cache/`.

### Rewritten tests
`test_normalizer.py`, `test_linux_parser.py`, `test_event_store.py`,
`test_event_store_queries.py`, `test_behavior_correlator.py`,
`test_behavior_extractor.py`.

They were print-and-look-at-it scripts. A test that only prints cannot fail, so
it protects nothing. They are now pytest functions with real assertions.

---

## Not touched

`app/models/behavior.py`, `app/analyzer/behavior_correlator.py`,
`app/analyzer/behavior_extractor.py`, `app/storage/event_store.py`,
`app/utils/json_printer.py`, `app/api/main.py`.

The correlator is Week 2's job.
