#A parser converts one raw log line into a dictionary or returns None if the log is not security-related.
#Ignoring unknown logs is normal and prevents unnecessary errors or stopping the ingestion process.

from abc import ABC, abstractmethod
from typing import Optional


class BaseParser(ABC):

    @abstractmethod
    def parse(self, log_line: str) -> Optional[dict]:
        """Parse one log line. Return None if no rule matched."""
