#Predicts the attacker's NEXT move.
#
#Two signals are combined:
#
#  1. A kill-chain transition model. Attacks move through stages in a fairly
#     predictable order (discovery -> guess passwords -> get in -> escalate ->
#     steal credentials -> persist). Given the deepest stage reached, the model
#     ranks what usually comes next.
#  2. The ML anomaly score. How far from normal this activity is. A very
#     abnormal, fast, successful attack raises confidence that it will continue.
#
#This is deterministic and explainable, which is exactly what a defence needs:
#every prediction can be justified out loud.

from typing import Dict, List, Optional

from app.intelligence.anomaly_model import AnomalyScorer, StatisticalScorer
from app.intelligence.feature_extractor import FeatureExtractor, FeatureVector
from app.models.attack_graph import AttackPath
from app.models.prediction import NextStep, Prediction

#stage number -> (name, what the attacker typically does at the NEXT stage)
STAGE_NAMES = {
    1: "Discovery",
    2: "Credential Access",
    3: "Initial Access",
    4: "Privilege Escalation",
    5: "Credential Theft",
    6: "Persistence",
    7: "Lateral Movement / Exfiltration",
}

#what reaching each NEXT stage would mean, in plain language
NEXT_ACTION = {
    2: "start guessing passwords for the accounts it found",
    3: "log in with a working password and gain access",
    4: "try to become root through sudo",
    5: "read the local password file to steal credentials",
    6: "create a hidden account so it can return later",
    7: "move to other machines or steal data",
}


class PredictionEngine:

    def __init__(
        self,
        scorer: Optional[AnomalyScorer] = None,
        extractor: Optional[FeatureExtractor] = None,
    ):
        self.scorer = scorer or StatisticalScorer()
        self.extractor = extractor or FeatureExtractor()

    def predict(
        self,
        path: AttackPath,
        events: Optional[list] = None,
    ) -> Prediction:

        actor = path.actor or "unknown"

        behaviors = [node.behavior for node in path.nodes]

        vector = self.extractor.extract(actor, events or [], behaviors)
        anomaly = self.scorer.score(vector)

        current = path.deepest_stage
        current_name = STAGE_NAMES.get(current)

        next_steps = self._rank_next_steps(path, anomaly)

        confidence = self._confidence(path, anomaly, next_steps)

        summary = self._summary(actor, current_name, next_steps, path)

        return Prediction(
            actor=actor,
            current_stage=current,
            current_stage_name=current_name,
            next_steps=next_steps,
            anomaly_score=anomaly,
            confidence=confidence,
            summary=summary,
            model=self.scorer.name,
        )

    def _rank_next_steps(self, path: AttackPath, anomaly: float) -> List[NextStep]:

        current = path.deepest_stage
        reached = set(path.stages_reached)

        steps: List[NextStep] = []

        #the natural next stage is the strongest candidate
        nxt = current + 1
        if nxt in NEXT_ACTION:
            #more likely when the attack is abnormal and already succeeded
            base = 0.6 + 0.2 * anomaly + (0.1 if path.succeeded else 0.0)
            steps.append(NextStep(
                stage=nxt,
                stage_name=STAGE_NAMES.get(nxt, "Beyond kill chain"),
                probability=round(min(0.95, base), 3),
                reason=f"attacker will likely {NEXT_ACTION[nxt]}",
            ))

        #a stage that was skipped is the next most likely fill-in
        for stage in range(1, current):
            if stage not in reached and (stage + 1) in NEXT_ACTION:
                steps.append(NextStep(
                    stage=stage,
                    stage_name=STAGE_NAMES.get(stage, "?"),
                    probability=round(0.25 + 0.1 * anomaly, 3),
                    reason=f"stage {stage} was skipped and may still happen",
                ))
                break

        if not steps:
            steps.append(NextStep(
                stage=1,
                stage_name="Discovery",
                probability=0.3,
                reason="early activity, the attacker is still probing",
            ))

        steps.sort(key=lambda s: s.probability, reverse=True)
        return steps

    def _confidence(self, path, anomaly, next_steps) -> float:

        #more evidence and a clearer top candidate mean more confidence
        top = next_steps[0].probability if next_steps else 0.0
        evidence = min(1.0, len(path.nodes) / 5.0)

        return round(0.4 * top + 0.3 * anomaly + 0.3 * evidence, 3)

    def _summary(self, actor, current_name, next_steps, path) -> str:

        where = f"reached {current_name}" if current_name else "is early in the attack"

        if not next_steps:
            return f"{actor} {where}."

        top = next_steps[0]

        return (
            f"{actor} {where} and will most likely {top.stage_name} next "
            f"({int(top.probability * 100)}% likely)."
        )
