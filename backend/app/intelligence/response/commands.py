#Builds the exact shell command for each defensive action.
#
#Kept in one small file so that "what command does ACT run to block an IP" has
#a single, auditable answer. Every command here is reversible on purpose: a
#blocked address can be unblocked, a locked account can be unlocked. An
#autonomous system must never take an action it cannot undo.
#
#The command runs on the VM through the remote login shell, so `target` is
#validated hard before it is ever interpolated: an IP for BLOCK_IP, a POSIX
#user name for LOCK_ACCOUNT. Anything else returns None and the responder
#reports "nothing to do" instead of running a crafted string.

import ipaddress
import re
from typing import Optional

from app.models.decision import Action

_USERNAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")


def _safe_ip(target: Optional[str]) -> Optional[str]:
    if not target:
        return None
    try:
        return str(ipaddress.ip_address(target.strip()))
    except ValueError:
        return None


def _safe_user(target: Optional[str]) -> Optional[str]:
    if not target:
        return None
    name = target.strip()
    return name if _USERNAME.match(name) else None


def build_command(action: str, target: Optional[str]) -> Optional[str]:
    """The command that carries out `action` against `target`, or None."""

    #`sudo -n` (non-interactive): if passwordless sudo for iptables is not set
    #up on the VM, sudo fails in under a second with a clear message instead of
    #hanging on a password prompt until the SSH call times out.
    if action == Action.BLOCK_IP:
        ip = _safe_ip(target)
        if ip is None:
            return None
        #drop every packet from this source address. Idempotent: check first so
        #a retry (or an already-applied rule) is a success, not a duplicate.
        return (
            f"sudo -n iptables -C INPUT -s {ip} -j DROP 2>/dev/null "
            f"|| sudo -n iptables -A INPUT -s {ip} -j DROP"
        )

    if action == Action.LOCK_ACCOUNT:
        user = _safe_user(target)
        if user is None:
            return None
        #disable the account's password so it cannot log in
        return f"sudo -n passwd -l {user}"

    if action == Action.ISOLATE_HOST:
        #cut all inbound traffic except an existing SSH session
        return "sudo -n iptables -I INPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT && sudo -n iptables -A INPUT -j DROP"

    return None


def build_undo_command(action: str, target: Optional[str]) -> Optional[str]:
    """The command that REVERSES `action`, so a mistake is one step from undone."""

    if action == Action.BLOCK_IP:
        ip = _safe_ip(target)
        return f"sudo iptables -D INPUT -s {ip} -j DROP" if ip else None

    if action == Action.LOCK_ACCOUNT:
        user = _safe_user(target)
        return f"sudo passwd -u {user}" if user else None

    if action == Action.ISOLATE_HOST:
        return "sudo iptables -D INPUT -j DROP"

    return None
