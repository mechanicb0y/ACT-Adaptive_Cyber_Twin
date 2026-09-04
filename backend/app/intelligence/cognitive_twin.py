#The Cyber Cognitive Twin: the top of the whole ACT pipeline.
#
#It takes the attack graph (what happened) and produces, for each attacker:
#   predict  -> what they will do next
#   decide   -> the best defensive action
#   respond  -> carry it out (dry run unless armed)
#   explain  -> a human incident narrative
#
#Everything below it stays deterministic and testable. Only the narrative may
#come from a language model, and even that has a built-in fallback. So the twin
#is ambitious on the outside and safe and explainable on the inside.

from typing import Dict, List, Optional

from app.intelligence.decision_engine import DecisionEngine
from app.intelligence.llm_analyst import LlmAnalyst
from app.intelligence.prediction_engine import PredictionEngine
from app.intelligence.response.base_responder import BaseResponder
from app.intelligence.response.dry_run_responder import DryRunResponder
from app.models.attack_graph import AttackGraph, AttackPath
from app.models.decision import Decision
from app.models.response import ResponseResult
from app.models.security_event import SecurityEvent
from app.models.twin import TwinAssessment


class CognitiveTwin:

    def __init__(
        self,
        prediction_engine: Optional[PredictionEngine] = None,
        decision_engine: Optional[DecisionEngine] = None,
        responder: Optional[BaseResponder] = None,
        analyst: Optional[LlmAnalyst] = None,
        armed: bool = False,
    ):
        self.prediction_engine = prediction_engine or PredictionEngine()
        self.decision_engine = decision_engine or DecisionEngine()

        #dry run responder by default: ACT never touches a machine until a real
        #responder is injected AND armed is turned on
        self.responder = responder or DryRunResponder()
        self.analyst = analyst or LlmAnalyst()

        self.armed = armed

    def assess_path(
        self,
        path: AttackPath,
        events: Optional[List[SecurityEvent]] = None,
        execute: bool = False,
        narrate: bool = True,
    ) -> TwinAssessment:
        """Full predict -> decide -> respond -> explain for one attacker.

        ``narrate=False`` skips the language-model narrative (and its retrieval)
        and uses the built-in template instead. The dashboard only shows the
        narrative for the worst attacker, so the others do not need to pay for
        a model round trip on every refresh.
        """

        actor_events = self._events_for(path.actor, events or [])

        prediction = self.prediction_engine.predict(path, actor_events)

        #ask the local model for an independent block/alert/monitor call and
        #feed it into the decision. Guarded: no model, or a bad reply, and the
        #decision engine simply runs on its deterministic logic alone.
        llm_review = None
        try:
            if path.highest_risk >= 35:            #don't bother the model with noise
                llm_review = self.analyst.assess_incident(path, prediction)
        except Exception:                          # noqa: BLE001
            llm_review = None

        decision = self.decision_engine.decide(path, prediction, llm=llm_review)

        #plan the response (dry run). Only execute when told to AND armed.
        response = self.responder.respond(
            decision, armed=self.armed and execute
        )

        narrative = self.analyst.explain(prediction, decision, allow_model=narrate)

        return TwinAssessment(
            actor=path.actor,
            completeness=path.completeness,
            succeeded=path.succeeded,
            prediction=prediction,
            decision=decision,
            response=response,
            narrative=narrative,
            narrator=self.analyst.narrator_name(),
            llm_review=llm_review,
        )

    def assess(
        self,
        graph: AttackGraph,
        events: Optional[List[SecurityEvent]] = None,
    ) -> List[TwinAssessment]:
        #one assessment per attacker, worst first (graph.paths is already
        #sorted). Only the worst gets a model-written narrative.
        return [
            self.assess_path(path, events, narrate=(index == 0))
            for index, path in enumerate(graph.paths)
        ]

    def respond_to(
        self,
        path: AttackPath,
        events: Optional[List[SecurityEvent]] = None,
    ) -> ResponseResult:
        """Actually carry out the decision for one attacker (executes if armed)."""

        return self.assess_path(path, events, execute=True).response

    @staticmethod
    def _events_for(actor: Optional[str], events: List[SecurityEvent]) -> List[SecurityEvent]:
        if not actor:
            return events
        matching = [e for e in events if e.ip_address == actor]
        return matching or events
