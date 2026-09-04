#Executes a defensive action on the Kali VM over SSH.
#
#This is the part that makes ACT autonomous: when armed, it really runs
#`iptables ... DROP` on the machine to block an attacker in real time. It reuses
#the same SSH settings as the log reader, so the machine ACT watches is the
#machine ACT defends.
#
#Three safety rails are built in:
#  * it only runs when explicitly armed (handled by BaseResponder)
#  * it only runs actions on its allow-list
#  * every command it runs is reversible (see commands.build_undo_command)

import shlex
import subprocess
from datetime import datetime
from typing import List, Optional, Sequence

from app.intelligence.response.base_responder import BaseResponder
from app.intelligence.response.commands import build_undo_command
from app.models.decision import Action, Decision
from app.models.response import ResponseResult, ResponseStatus

SSH_OPTIONS = [
    "-n",                              # never read local stdin...
    "-T",                              # ...and never ask for a pseudo-tty, so a
                                       # remote `sudo` that wants a password
                                       # fails at once instead of hanging
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "ConnectTimeout=8",
    "-o", "ServerAliveInterval=5",     # give up on a hung session fast
    "-o", "ServerAliveCountMax=2",
]


class SSHResponder(BaseResponder):

    name = "ssh"

    def __init__(
        self,
        host: str,
        user: Optional[str] = None,
        port: int = 22,
        key_file: Optional[str] = None,
        ssh_path: str = "ssh",
        allowed_actions: Optional[Sequence[str]] = None,
        timeout: int = 20,
    ):
        self.host = host
        self.user = user
        self.port = port
        self.key_file = key_file
        self.ssh_path = ssh_path
        self.timeout = timeout

        #by default only blocking an IP is allowed to execute. Locking accounts
        #and isolating the host must be turned on deliberately in config.
        self.allowed_actions = set(allowed_actions or {Action.BLOCK_IP})

    @property
    def target_host(self) -> str:
        return f"{self.user}@{self.host}" if self.user else self.host

    def ssh_command(self, remote: str) -> List[str]:

        command = [self.ssh_path, *SSH_OPTIONS]

        if self.port and self.port != 22:
            command += ["-p", str(self.port)]

        if self.key_file:
            command += ["-i", self.key_file]

        command += [self.target_host, remote]
        return command

    def execute(self, decision: Decision, command: str) -> ResponseResult:

        now = datetime.now()
        undo = build_undo_command(decision.action, decision.target)

        try:
            result = subprocess.run(
                self.ssh_command(command),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                stdin=subprocess.DEVNULL,   # nothing to type a password into
            )
        except subprocess.TimeoutExpired:
            #the SSH call ran long: the VM may just be slow. Worth another go.
            return ResponseResult(
                action=decision.action,
                target=decision.target,
                status=ResponseStatus.FAILED,
                command=command,
                armed=True,
                detail=f"{self.target_host} did not answer within {self.timeout}s",
                retryable=True,
                at=now,
            )
        except Exception as error:                          # noqa: BLE001
            return ResponseResult(
                action=decision.action,
                target=decision.target,
                status=ResponseStatus.FAILED,
                command=command,
                armed=True,
                detail=f"Could not reach {self.target_host}: {error}",
                retryable=True,
                at=now,
            )

        if result.returncode == 0:
            detail = f"Executed on {self.target_host}."
            if undo:
                detail += f" Undo with: {undo}"

            return ResponseResult(
                action=decision.action,
                target=decision.target,
                status=ResponseStatus.EXECUTED,
                command=command,
                armed=True,
                detail=detail,
                at=now,
            )

        detail = (result.stderr or result.stdout or "command failed").strip()
        low = detail.lower()

        #a config / auth problem that retrying cannot fix: surface it now.
        #Network conditions (refused, unreachable, timed out) are left retryable
        #because the VM may just be booting or briefly offline.
        hard = any(s in low for s in (
            "permission denied", "not in the sudoers", "a password is required",
            "a terminal is required", "host key verification failed",
            "name or service not known", "could not resolve hostname",
        ))
        sudo_hint = "sudo" in low and ("password" in low or "terminal" in low or "sudoers" in low)
        if sudo_hint:
            detail += (
                f"  [fix: give {self.user or 'the SSH user'} passwordless sudo for "
                f"iptables on the VM, e.g. `echo '{self.user or '<user>'} ALL=(root) "
                f"NOPASSWD: /usr/sbin/iptables' | sudo tee /etc/sudoers.d/act`]"
            )

        return ResponseResult(
            action=decision.action,
            target=decision.target,
            status=ResponseStatus.FAILED,
            command=command,
            armed=True,
            detail=detail,
            retryable=not hard,
            at=now,
        )
