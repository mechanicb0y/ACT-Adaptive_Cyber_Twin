#One attacker, fully understood: what they did, what they will do, what to do
#about it, and what ACT did in response. This is the output of the Cyber
#Cognitive Twin, the top of the whole pipeline.

from dataclasses import dataclass
from typing import Any, Dict, Optional

from app.models.decision import Decision
from app.models.prediction import Prediction
from app.models.response import ResponseResult


@dataclass(slots=True)
class TwinAssessment:

    actor: Optional[str]

    #how far the attacker got (0..1 of the kill chain)
    completeness: float

    succeeded: bool

    prediction: Prediction

    decision: Decision

    #the response ACT took or would take (may be a dry run)
    response: Optional[ResponseResult] = None

    #plain-language incident narrative (LLM or built-in)
    narrative: str = ""

    #where the narrative came from ("llm:model" or "built-in")
    narrator: str = "built-in"

    #the local model's independent risk judgment that fed the decision, if any:
    #{"recommendation", "confidence", "threat", "reasoning", "source"}
    llm_review: Optional[Dict[str, Any]] = None
