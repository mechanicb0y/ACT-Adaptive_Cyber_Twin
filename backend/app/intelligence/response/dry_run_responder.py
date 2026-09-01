#The safe default responder. It never touches any machine.
#
#Even if something calls execute() directly, it only records what it WOULD have
#done. This is what ACT uses until the user explicitly arms a real responder.

from datetime import datetime

from app.intelligence.response.base_responder import BaseResponder
from app.models.decision import Decision
from app.models.response import ResponseResult, ResponseStatus


class DryRunResponder(BaseResponder):

    name = "dry-run"

    def execute(self, decision: Decision, command: str) -> ResponseResult:
        #reachable only if armed=True was passed, but this responder still
        #refuses to run anything. Safety is the default, not an option.
        return ResponseResult(
            action=decision.action,
            target=decision.target,
            status=ResponseStatus.DRY_RUN,
            command=command,
            armed=False,
            detail="Dry-run responder: command logged, never executed.",
            at=datetime.now(),
        )
