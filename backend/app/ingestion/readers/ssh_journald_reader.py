#Reads the systemd journal of a REMOTE machine over SSH.
#
#This is how ACT running on Windows watches the Kali virtual machine live.
#It runs:
#
#    ssh kali@192.168.x.x journalctl -o short-iso --no-pager -t sshd -f
#
#and streams the output exactly like the local reader does.
#
#Note how small this file is. It reuses JournaldReader's command builder and
#only wraps it in an ssh call. That is the whole point of the reader layer:
#a new log source is one new file, and nothing downstream changes. The parser,
#the normalizer, the correlator and the graph never learn that the logs came
#from another machine.

import shlex
import shutil
from typing import List, Optional

from app.ingestion.readers.journald_reader import JournaldReader

SSH_OPTIONS = [
    "-o", "BatchMode=yes",            # never sit waiting for a password prompt
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "ServerAliveInterval=15",   # notice a dead VM instead of hanging
    "-o", "ServerAliveCountMax=3",
    "-o", "ConnectTimeout=10",
]


class SSHJournalReader(JournaldReader):

    name = "ssh-journald"

    def __init__(
        self,
        host: str,
        user: Optional[str] = None,
        port: int = 22,
        key_file: Optional[str] = None,
        ssh_path: str = "ssh",
        use_sudo: bool = False,
        **journal_options,
    ):
        super().__init__(**journal_options)

        self.host = host
        self.user = user
        self.port = port
        self.key_file = key_file
        self.ssh_path = ssh_path

        #only needed if the login user is not in the systemd-journal group.
        #Adding the user to that group is the better answer, see docs/KALI_SETUP.md
        self.use_sudo = use_sudo

    @property
    def target(self) -> str:
        return f"{self.user}@{self.host}" if self.user else self.host

    def check_available(self) -> None:
        #we need ssh HERE, journalctl lives on the far side

        if shutil.which(self.ssh_path) is None:
            raise RuntimeError(
                "The 'ssh' command was not found on this machine. "
                "On Windows install the OpenSSH Client from "
                "Settings, Apps, Optional features."
            )

    def describe(self) -> str:
        return f"systemd journal on {self.target}"

    def build_command(self) -> List[str]:

        #the journalctl command that will run on the remote machine
        remote_parts = super().build_command()

        if self.use_sudo:
            remote_parts = ["sudo", "-n"] + remote_parts

        remote = " ".join(shlex.quote(part) for part in remote_parts)

        command = [self.ssh_path, *SSH_OPTIONS]

        if self.port and self.port != 22:
            command += ["-p", str(self.port)]

        if self.key_file:
            command += ["-i", self.key_file]

        if self.follow:
            #keep the pipe alive and forward Ctrl-C style termination cleanly
            command += ["-T"]

        command += [self.target, remote]

        return command

    def explain_failure(self, return_code: int, error: str) -> str:
        """Turn ssh's exit codes into something a human can act on."""

        error = (error or "").strip()

        if return_code == 255:
            return (
                f"Could not connect to {self.target}. Check that the virtual "
                f"machine is running, that its address is correct, that SSH is "
                f"started (sudo systemctl start ssh), and that key based login "
                f"works: ssh {self.target}\n{error}"
            )

        if "Permission denied" in error:
            return (
                f"SSH refused the login for {self.target}. Set up a key with "
                f"ssh-copy-id, or check the username.\n{error}"
            )

        if "No journal files were opened" in error or "insufficient permissions" in error:
            return (
                f"Connected to {self.target}, but that user cannot read the "
                f"journal. On the Kali machine run:\n"
                f"    sudo usermod -aG systemd-journal {self.user or '$USER'}\n"
                f"then log out and back in.\n{error}"
            )

        return f"journalctl on {self.target} exited with code {return_code}: {error}"
