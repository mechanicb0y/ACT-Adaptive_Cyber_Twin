#This reader gets real-time logs from systemd using journalctl. It uses ISO timestamps for accurate dates. 
#It is the main log source on modern Linux systems, while file reading is used for replaying saved logs.

import shutil
import subprocess
from typing import Iterator, List, Optional, Sequence

from app.ingestion.readers.base_reader import BaseLogReader


class JournaldReader(BaseLogReader):

    name = "journald"

    def __init__(
        self,
        units: Optional[Sequence[str]] = None,
        since: Optional[str] = None,
        follow: bool = False,
        identifiers: Optional[Sequence[str]] = None,
        extra_args: Optional[Sequence[str]] = None,
        journalctl_path: str = "journalctl",
    ):
        # e.g. ["ssh"] or ["ssh", "sshd"]
        self.units = list(units or [])

        # e.g. ["sshd", "sudo", "useradd"] -> journalctl -t sshd -t sudo
        self.identifiers = list(identifiers or [])

        # e.g. "-1h", "today", "2026-08-06 09:00:00"
        self.since = since

        self.follow = follow
        self.extra_args = list(extra_args or [])
        self.journalctl_path = journalctl_path

        self._process: Optional[subprocess.Popen] = None

        #True when we shut the reader down ourselves, so the non zero exit
        #code that follows is expected and must not be reported as a failure
        self._stopped = False

    def stop(self) -> None:
        self._stopped = True
        self.close()

    @staticmethod
    def is_available(journalctl_path: str = "journalctl") -> bool:
        """True when journalctl exists on this machine (Linux with systemd)."""

        return shutil.which(journalctl_path) is not None

    def check_available(self) -> None:
        #overridden by SSHJournalReader, which needs ssh locally, not journalctl

        if not self.is_available(self.journalctl_path):
            raise RuntimeError(
                "journalctl was not found on this system. "
                "Run ACT on a Linux host with systemd, use SSHJournalReader to "
                "read a remote machine, or use FileLogReader to replay a log file."
            )

    def describe(self) -> str:
        return "systemd journal on this machine"

    def explain_failure(self, return_code: int, error: str) -> str:
        #SSHJournalReader replaces this with advice about connections and keys
        return f"journalctl exited with code {return_code}: {(error or '').strip()}"

    def build_command(self) -> List[str]:

        command = [self.journalctl_path, "-o", "short-iso", "--no-pager"]

        for unit in self.units:
            command += ["-u", unit]

        for identifier in self.identifiers:
            command += ["-t", identifier]

        if self.since:
            command += ["--since", self.since]

        if self.follow:
            command.append("-f")

        command += self.extra_args

        return command

    def close(self) -> None:

        if self._process is None:
            return

        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()

        self._process = None

    def read(self) -> Iterator[str]:

        self.check_available()

        self._process = subprocess.Popen(
            self.build_command(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # line buffered, so -f streams in real time
        )

        try:
            for line in self._process.stdout:

                stripped = line.rstrip("\n")

                if not stripped.strip():
                    continue

                # journalctl banner lines, not real events
                if stripped.startswith("-- "):
                    continue

                yield stripped

            return_code = self._process.wait()

            #a non zero exit matters in follow mode too: it usually means the
            #connection died or the user cannot read the journal at all
            if return_code not in (0, None) and not self._stopped:
                error = self._process.stderr.read() if self._process.stderr else ""
                raise RuntimeError(self.explain_failure(return_code, error))

        finally:
            self.close()
