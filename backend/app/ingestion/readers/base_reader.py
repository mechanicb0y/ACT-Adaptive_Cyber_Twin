#A reader only provides raw log lines. It does not parse, process, or store them. 
#Using generators lets ACT handle both log files and live log streams the same way.

from abc import ABC, abstractmethod
from typing import Iterator


class BaseLogReader(ABC):

    # Used in logs and stats output.
    name: str = "unnamed-reader"

    @abstractmethod
    def read(self) -> Iterator[str]:
        """Yield raw log lines, one at a time."""

    def close(self) -> None:
        """Release any resource. Safe to call more than once."""

    def __enter__(self) -> "BaseLogReader":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
