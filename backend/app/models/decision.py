#What ACT decides to DO about an attacker.
#
#The decision engine turns understanding into a recommended action. A Decision
#is never executed by itself: the response engine executes it, and only when
#armed. This separation keeps "what to do" and "actually doing it" apart.

from dataclasses import dataclass, field
from typing import List, Optional


class Action:
    #the defensive actions ACT can recommend

    MONITOR = "monitor"                 #do nothing yet, keep watching
    ALERT = "alert"                     #raise an alert for a human
    BLOCK_IP = "block_ip"               #firewall-drop the source address
    LOCK_ACCOUNT = "lock_account"       #disable the targeted user account
    ISOLATE_HOST = "isolate_host"       #cut the host off the network

    #actions that change the monitored machine, so they need arming
    SIDE_EFFECTING = {BLOCK_IP, LOCK_ACCOUNT, ISOLATE_HOST}


@dataclass(slots=True)
class Decision:

    action: str                          #one of Action.*

    target: Optional[str] = None         #ip or username the action applies to

    #how urgent, mirrors behaviour severity (Low/Medium/High/Critical)
    urgency: str = "Low"

    #0..1, how sure the engine is that this action is right
    confidence: float = 0.0

    #why this action was chosen, in plain language
    rationale: str = ""

    #the risk score that drove the decision
    risk_score: int = 0

    #the reasons/evidence that led here
    factors: List[str] = field(default_factory=list)

    #other responses worth a human's attention, in plain language, e.g.
    #["lock account 'kali'", "isolate the host"]. Advisory only: ACT never
    #executes these, it only carries out `action`.
    also_consider: List[str] = field(default_factory=list)

    @property
    def changes_the_machine(self) -> bool:
        return self.action in Action.SIDE_EFFECTING

    @property
    def needs_arming(self) -> bool:
        #a side-effecting action will only run if ACT is armed
        return self.changes_the_machine
