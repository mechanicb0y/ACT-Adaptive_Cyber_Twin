#The result of ACT actually carrying out (or simulating) a decision.
#
#Every response records exactly what command it would run and whether it really
#ran, so nothing the system does to a machine is ever invisible.

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


class ResponseStatus:

    DRY_RUN = "dry_run"            #not armed, command was only logged
    PENDING = "pending"           #accepted, running in the background right now
    EXECUTED = "executed"          #command ran successfully
    FAILED = "failed"             #command ran but returned an error
    SKIPPED = "skipped"           #nothing to do (e.g. monitor/alert)
    BLOCKED = "blocked"           #refused, for example a prohibited action


@dataclass(slots=True)
class ResponseResult:

    action: str

    target: Optional[str]

    status: str                   #one of ResponseStatus.*

    #the exact command ACT ran or would run
    command: Optional[str] = None

    #whether the machine was actually touched
    armed: bool = False

    #output or error text from the command
    detail: str = ""

    at: Optional[datetime] = None

    #a FAILED result that is worth retrying (timeout, connection dropped, VM
    #briefly unreachable) rather than a hard stop (auth denied, sudo, refused)
    retryable: bool = False

    @property
    def took_effect(self) -> bool:
        return self.status == ResponseStatus.EXECUTED
