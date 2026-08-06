#Read log lines from a file.


import os
import time
from pathlib import Path
from typing import Iterator, Optional

from app.ingestion.readers.base_reader import BaseLogReader


class FileLogReader(BaseLogReader):

    name = "file"

    def __init__(
        self,
        path: str | Path,
        follow: bool = False,
        from_start: bool = True,
        poll_interval: float = 0.5,
        encoding: str = "utf-8",
    ):
        self.path = Path(path)
        self.follow = follow
        self.from_start = from_start
        self.poll_interval = poll_interval
        self.encoding = encoding

        self._handle = None
        self._stopped = False

    def stop(self) -> None:
        """Ask a follow-mode reader to finish after the current line."""

        self._stopped = True

    def close(self) -> None:

        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def _open(self):

        return self.path.open("r", encoding=self.encoding, errors="replace")

    def _inode(self) -> Optional[int]:

        try:
            return os.stat(self.path).st_ino
        except OSError:
            return None

    def read(self) -> Iterator[str]:

        if not self.path.exists():
            raise FileNotFoundError(f"Log file not found: {self.path}")

        self._handle = self._open()
        current_inode = self._inode()

        try:
            if self.follow and not self.from_start:
                self._handle.seek(0, os.SEEK_END)

            while not self._stopped:

                line = self._handle.readline()

                if line:
                    stripped = line.rstrip("\n")
                    if stripped.strip():
                        yield stripped
                    continue

                # End of file reached.
                if not self.follow:
                    return

                # Detect rotation: file replaced or truncated.
                new_inode = self._inode()
                position = self._handle.tell()

                rotated = (
                    new_inode != current_inode
                    or (
                        self.path.exists()
                        and self.path.stat().st_size < position
                    )
                )

                if rotated:
                    self.close()
                    self._handle = self._open()
                    current_inode = self._inode()
                    continue

                time.sleep(self.poll_interval)

        finally:
            self.close()
