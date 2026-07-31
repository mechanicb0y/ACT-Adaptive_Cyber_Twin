from abc import ABC, abstractmethod


class BaseParser(ABC):

    @abstractmethod
    def parse(self, log_line: str) -> dict:

        pass