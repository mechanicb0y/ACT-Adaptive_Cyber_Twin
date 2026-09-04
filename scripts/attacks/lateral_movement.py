#!/usr/bin/env python3
"""Generate a syslog stream for a multi-stage INTERNAL (lateral movement) attack.

The scenario, three machines, three source addresses:

    1. External attacker 203.0.113.66 brute-forces `deploy` on web-01 and gets in.
    2. `deploy` does host recon and fails sudo (privilege escalation) on web-01.
    3. From web-01's internal address (10.0.5.11) the attacker SSH-hops to db-01,
       brute-forces `dbadmin` and gets in  -- lateral movement, hop 1.
    4. On db-01: failed sudo (priv-esc), `sudo cat /etc/shadow` (credential
       theft) and `useradd svc-monitor` + `usermod -aG sudo` (persistence).
    5. From db-01's internal address (10.0.5.20) the attacker hops again to
       app-02, brute-forces `svc` and gets in  -- lateral movement, hop 2.

Feeding this to ACT should produce several separate attack paths (one per
pivoted host), most of them ending in a successful compromise, with
privilege-escalation / sensitive-file-access / persistence behaviours and a
BLOCK decision for the source addresses.

Usage:
    python lateral_movement.py                 # print to stdout
    python lateral_movement.py --out lm.log    # write a file
    python lateral_movement.py --out /var/log/act_lab.log --start "now"

`--start` accepts "now" or a "Mon D HH:MM:SS" syslog timestamp. The default is
fixed so the output is reproducible (the committed test fixture is this file's
default output).
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta

DEFAULT_START = "Sep  3 01:12:03"
SYSLOG_FMT = "%b %d %H:%M:%S"


def _parse_start(value: str) -> datetime:
    if value.strip().lower() == "now":
        return datetime.now().replace(microsecond=0)
    #syslog has no year; anchor to this year for arithmetic only
    parsed = datetime.strptime(" ".join(value.split()), SYSLOG_FMT)
    return parsed.replace(year=datetime.now().year)


def _ts(base: datetime, offset: int) -> str:
    #syslog day is space-padded to width 2
    stamp = (base + timedelta(seconds=offset)).strftime(SYSLOG_FMT)
    parts = stamp.split()
    parts[1] = parts[1].rjust(2)
    return " ".join(parts)


# (offset_seconds, host, "process[pid]: message")
EVENTS: list[tuple[int, str, str]] = [
    # ---- 1. external brute force into web-01, user `deploy` -------------------
    (0,   "web-01", "sshd-session[2001]: Invalid user admin from 203.0.113.66 port 40001"),
    (0,   "web-01", "sshd-session[2001]: Failed password for invalid user admin from 203.0.113.66 port 40001 ssh2"),
    (3,   "web-01", "sshd-session[2003]: Invalid user deploy from 203.0.113.66 port 40005"),
    (3,   "web-01", "sshd-session[2003]: Failed password for invalid user deploy from 203.0.113.66 port 40005 ssh2"),
    (6,   "web-01", "sshd-session[2005]: Failed password for deploy from 203.0.113.66 port 40009 ssh2"),
    (9,   "web-01", "sshd-session[2005]: Failed password for deploy from 203.0.113.66 port 40009 ssh2"),
    (12,  "web-01", "sshd-session[2005]: Failed password for deploy from 203.0.113.66 port 40009 ssh2"),
    (15,  "web-01", "sshd-session[2007]: Failed password for deploy from 203.0.113.66 port 40013 ssh2"),
    (18,  "web-01", "sshd-session[2007]: Failed password for deploy from 203.0.113.66 port 40013 ssh2"),
    (21,  "web-01", "sshd-session[2009]: Accepted password for deploy from 203.0.113.66 port 40017 ssh2"),
    (21,  "web-01", "sshd-session[2009]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by deploy(uid=0)"),

    # ---- 2. recon + failed privilege escalation on web-01 --------------------
    (97,  "web-01", "sudo[2050]: pam_unix(sudo:auth): authentication failure; logname=deploy uid=1001 euid=0 tty=/dev/pts/0 ruser=deploy rhost=  user=deploy"),
    (112, "web-01", "sudo[2052]:     deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/passwd"),

    # ---- 3. lateral movement hop 1: web-01 (10.0.5.11) -> db-01 -------------
    (179, "db-01",  "sshd-session[3001]: Failed password for postgres from 10.0.5.11 port 51002 ssh2"),
    (182, "db-01",  "sshd-session[3001]: Failed password for postgres from 10.0.5.11 port 51002 ssh2"),
    (185, "db-01",  "sshd-session[3003]: Failed password for postgres from 10.0.5.11 port 51006 ssh2"),
    (188, "db-01",  "sshd-session[3003]: Failed password for postgres from 10.0.5.11 port 51006 ssh2"),
    (191, "db-01",  "sshd-session[3005]: Failed password for postgres from 10.0.5.11 port 51010 ssh2"),
    (194, "db-01",  "sshd-session[3007]: Failed password for dbadmin from 10.0.5.11 port 51014 ssh2"),
    (197, "db-01",  "sshd-session[3007]: Failed password for dbadmin from 10.0.5.11 port 51014 ssh2"),
    (200, "db-01",  "sshd-session[3009]: Failed password for dbadmin from 10.0.5.11 port 51018 ssh2"),
    (203, "db-01",  "sshd-session[3011]: Accepted password for dbadmin from 10.0.5.11 port 51022 ssh2"),
    (203, "db-01",  "sshd-session[3011]: pam_unix(sshd:session): session opened for user dbadmin(uid=1002) by dbadmin(uid=0)"),

    # ---- 4. priv-esc + credential theft + persistence on db-01 --------------
    (250, "db-01",  "sudo[3050]: pam_unix(sudo:auth): authentication failure; logname=dbadmin uid=1002 euid=0 tty=/dev/pts/1 ruser=dbadmin rhost=  user=dbadmin"),
    (265, "db-01",  "sudo[3052]: pam_unix(sudo:auth): authentication failure; logname=dbadmin uid=1002 euid=0 tty=/dev/pts/1 ruser=dbadmin rhost=  user=dbadmin"),
    (284, "db-01",  "sudo[3060]:     dbadmin : TTY=pts/1 ; PWD=/home/dbadmin ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"),
    (303, "db-01",  "sudo[3066]:     dbadmin : TTY=pts/1 ; PWD=/home/dbadmin ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash svc-monitor"),
    (303, "db-01",  "useradd[3068]: new user: name=svc-monitor, UID=1099, GID=1099, home=/home/svc-monitor, shell=/bin/bash, from=/dev/pts/1"),
    (311, "db-01",  "sudo[3072]:     dbadmin : TTY=pts/1 ; PWD=/home/dbadmin ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo svc-monitor"),

    # ---- 5. lateral movement hop 2: db-01 (10.0.5.20) -> app-02 ------------
    (447, "app-02", "sshd-session[4001]: Failed password for svc from 10.0.5.20 port 33001 ssh2"),
    (450, "app-02", "sshd-session[4001]: Failed password for svc from 10.0.5.20 port 33001 ssh2"),
    (453, "app-02", "sshd-session[4003]: Failed password for svc from 10.0.5.20 port 33005 ssh2"),
    (456, "app-02", "sshd-session[4003]: Failed password for svc from 10.0.5.20 port 33005 ssh2"),
    (459, "app-02", "sshd-session[4005]: Failed password for svc from 10.0.5.20 port 33009 ssh2"),
    (462, "app-02", "sshd-session[4007]: Accepted password for svc from 10.0.5.20 port 33013 ssh2"),
    (462, "app-02", "sshd-session[4007]: pam_unix(sshd:session): session opened for user svc(uid=1003) by svc(uid=0)"),
]


def render(start: datetime) -> str:
    lines = [f"{_ts(start, off)} {host} {msg}" for off, host, msg in EVENTS]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", help="write here instead of stdout")
    ap.add_argument("--start", default=DEFAULT_START,
                    help='"now" or a "Mon D HH:MM:SS" syslog timestamp (default: %(default)s)')
    args = ap.parse_args(argv)

    text = render(_parse_start(args.start))

    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        print(f"wrote {len(EVENTS)} lines -> {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
