#What ACT thinks the attacker will do NEXT.
#
#This is the first piece of real foresight in the project. Everything before
#answered "what happened". A Prediction answers "what happens next" and "how
#unusual is this", so the decision engine can act before the attacker finishes.

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(slots=True)
class NextStep:
    #one possible next move by the attacker

    stage: int                 #kill chain stage number

    stage_name: str            #"Persistence", ...

    probability: float         #0..1, how likely this is the next move

    reason: str = ""           #why we think so


@dataclass(slots=True)
class Prediction:

    #the attacker being predicted (usually an ip address)
    actor: Optional[str] = None

    #the deepest stage reached so far
    current_stage: int = 0
    current_stage_name: Optional[str] = None

    #ranked guesses for the next move, most likely first
    next_steps: List[NextStep] = field(default_factory=list)

    #0..1 anomaly score from the ML model, how abnormal this activity is
    anomaly_score: float = 0.0

    #0..1 overall confidence in the prediction
    confidence: float = 0.0

    #plain sentence a human reads first
    summary: str = ""

    #which engine produced the anomaly score ("isolation-forest" or "statistical")
    model: str = "none"

    @property
    def most_likely(self) -> Optional[NextStep]:
        return self.next_steps[0] if self.next_steps else None
