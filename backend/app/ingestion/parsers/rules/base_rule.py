from abc import ABC, abstractmethod


class BaseRule(ABC):

    #Base class for every Linux parsing rule.

    @abstractmethod
    def matches(self, log_line: str) -> bool:

        #Returns True if this rule can parse the log.
  
        pass

    @abstractmethod
    def parse(self, log_line: str) -> dict:

        #Parse the log and return a normalized dictionary.

        pass