#Contract for anything that carries out a Decision.
#
#The same shape whether ACT only logs the action (dry run) or really executes
#it on the Kali VM (SSH). Swapping one for the other changes nothing else.

from abc import ABC, abstractmethod
from datetime import datetime

from app.intelligence.response.commands import build_command
from app.models.decision import Action, Decision
from app.models.response import ResponseResult, ResponseStatus


class BaseResponder(ABC):

    #actions this responder is allowed to actually run. Anything else is
    #refused even when armed, a hard safety floor.
    allowed_actions = set(Action.SIDE_EFFECTING)

    def plan(self, decision: Decision) -> str | None:
        #the command that WOULD run for this decision
        return build_command(decision.action, decision.target)

    def respond(self, decision: Decision, armed: bool = False) -> ResponseResult:

        now = datetime.now()

        #non side-effecting decisions never touch the machine
        if not decision.changes_the_machine:
            return ResponseResult(
                action=decision.action,
                target=decision.target,
                status=ResponseStatus.SKIPPED,
                armed=armed,
                detail="No machine action needed for this decision.",
                at=now,
            )

        command = self.plan(decision)

        if command is None:
            return ResponseResult(
                action=decision.action,
                target=decision.target,
                status=ResponseStatus.SKIPPED,
                armed=armed,
                detail="No command available for this action/target.",
                at=now,
            )

        if decision.action not in self.allowed_actions:
            return ResponseResult(
                action=decision.action,
                target=decision.target,
                status=ResponseStatus.BLOCKED,
                command=command,
                armed=armed,
                detail=f"Action '{decision.action}' is not permitted to execute.",
                at=now,
            )

        #not armed -> log only, never run
        if not armed:
            return ResponseResult(
                action=decision.action,
                target=decision.target,
                status=ResponseStatus.DRY_RUN,
                command=command,
                armed=False,
                detail="Dry run: ACT is not armed, the command was not executed.",
                at=now,
            )

        return self.execute(decision, command)

    @abstractmethod
    def execute(self, decision: Decision, command: str) -> ResponseResult:
        """Actually carry out the command. Only reached when armed."""
