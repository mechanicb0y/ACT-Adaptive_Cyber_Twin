#Decides the best defensive action for one attacker.
#
#It reads the attack path (how bad, did it succeed, how far did it get) and the
#prediction (what is coming) and chooses one action from a clear policy. The
#thresholds live in the config file, so the aggressiveness of the response is
#tunable without code.
#
#The engine only DECIDES. It never runs anything. That is the response engine's
#job, and only when armed. Keeping the two apart is what makes an autonomous
#system safe to reason about.
#
#Policy in one paragraph: a source is only blocked when the activity is an
#actual attack pattern (a correlation rule fired: brute force, user
#enumeration, credential access, persistence, ...) AND it is serious (the
#attacker got in, or the risk score is at the block threshold) AND the engine
#is confident (>= block_confidence). Anything short of that is an ALERT for a
#human, or just MONITOR. Locking the compromised account and isolating a
#persisted host are surfaced as advice, never executed automatically.

from typing import List, Optional

from app.models.attack_graph import AttackPath
from app.models.decision import Action, Decision
from app.models.prediction import Prediction
from app.models.severity import Severity

#a behavior produced by any of these rules is a real attack pattern, not noise
DANGEROUS_RULES = {
    "brute-force",
    "distributed-brute-force",
    "successful-brute-force",
    "user-enumeration",
    "privilege-escalation",
    "sensitive-file-access",
    "persistence",
}

#kill-chain stage at which the attacker has a foothold that outlives a reboot
PERSISTENCE_STAGE = 6


class DecisionPolicy:

    def __init__(
        self,
        block_threshold: int = 70,
        alert_threshold: int = 40,
        block_confidence: float = 0.9,
    ):
        #risk at or above this -> eligible to block the source
        self.block_threshold = block_threshold
        #risk at or above this -> raise an alert
        self.alert_threshold = alert_threshold
        #confidence at or above this -> ACT is willing to block; below it the
        #recommendation is downgraded to an alert for a human to confirm
        self.block_confidence = block_confidence


class DecisionEngine:

    def __init__(self, policy: Optional[DecisionPolicy] = None):
        self.policy = policy or DecisionPolicy()

    def decide(
        self,
        path: AttackPath,
        prediction: Optional[Prediction] = None,
        llm: Optional[dict] = None,
    ) -> Decision:

        risk = path.highest_risk
        actor = path.actor
        severity = Severity.from_score(risk)
        confidence = self._confidence(risk, prediction)

        rules = {n.behavior.rule for n in path.nodes if n.behavior.rule}
        dangerous = bool(rules & DANGEROUS_RULES)

        #the local model's independent opinion, blended in. It is given weight
        #but never full control: a wrong model cannot invent a block on its own
        #(the pattern + seriousness checks still gate), and it cannot talk ACT
        #out of blocking a confirmed compromise.
        llm_rec = None
        if isinstance(llm, dict) and llm.get("recommendation") in ("block", "alert", "monitor"):
            llm_rec = llm["recommendation"]
            try:
                llm_conf = max(0.0, min(1.0, float(llm.get("confidence"))))
            except (TypeError, ValueError):
                llm_conf = 0.5
            confidence = round(0.6 * confidence + 0.4 * llm_conf, 3)
            if path.succeeded:
                #a confirmed break-in stays firmly blockable no matter what
                confidence = max(confidence, self.policy.block_confidence)

        #the compromised account, if the attacker got in
        target_user = None
        for node in path.nodes:
            if node.behavior.attributes.get("compromised"):
                target_user = node.behavior.attributes.get("target_user") or target_user

        persisted = path.succeeded and (
            "persistence" in rules or path.deepest_stage >= PERSISTENCE_STAGE
        )

        #advice that rides alongside the chosen action but is never executed
        also_consider: List[str] = []
        if target_user:
            also_consider.append(f"lock the compromised account '{target_user}'")
        if persisted:
            also_consider.append("isolate the host and rebuild it (an attacker has persisted)")

        factors: List[str] = []
        if path.succeeded:
            factors.append("the attacker successfully logged in")
        if dangerous:
            factors.append("activity matches a known attack pattern: " + ", ".join(sorted(rules)))
        if risk >= self.policy.block_threshold:
            factors.append(f"risk {risk} is at or above the block threshold")
        if prediction and prediction.most_likely:
            factors.append(f"predicted next move: {prediction.most_likely.stage_name}")
        if llm_rec:
            factors.append(
                f"local AI ({llm.get('source', 'llm')}) called it "
                f"{llm.get('threat') or 'unknown'} threat, recommended '{llm_rec}' "
                f"at {round(float(llm.get('confidence', 0)) * 100)}% "
                f"-> blended confidence {round(confidence * 100)}%"
            )

        serious = path.succeeded or risk >= self.policy.block_threshold

        #the confidence bar, with a small grace when the local model also says
        #"block" (it can tip a borderline case, not create one)
        confident = confidence >= self.policy.block_confidence or (
            llm_rec == "block" and confidence >= self.policy.block_confidence - 0.05
        )

        # ---- block the source: only for a serious, confident, real attack ----
        if dangerous and serious and confident:

            urgency = Severity.CRITICAL if (path.succeeded or severity == Severity.CRITICAL) else Severity.HIGH

            rationale = (
                f"Block {actor}: "
                + ("the host is compromised" if path.succeeded
                   else f"risk score {risk} is {severity.lower()} and confidence is {round(confidence * 100)}%")
                + (f". Also lock account '{target_user}'" if target_user else "")
                + (". Treat the host as untrusted until rebuilt" if persisted else "")
                + "."
            )

            return Decision(
                action=Action.BLOCK_IP,
                target=actor,
                urgency=urgency,
                confidence=confidence,
                rationale=rationale,
                risk_score=risk,
                factors=factors,
                also_consider=also_consider,
            )

        # ---- a real attack, but not confident/serious enough to act on ----
        if dangerous and (risk >= self.policy.alert_threshold or path.succeeded):

            reason = (
                f"risk {risk} is below the block threshold"
                if risk < self.policy.block_threshold
                else f"confidence {round(confidence * 100)}% is below the block threshold "
                     f"({round(self.policy.block_confidence * 100)}%)"
            )

            return Decision(
                action=Action.ALERT,
                target=actor,
                urgency=Severity.MEDIUM if severity in (Severity.LOW, Severity.MEDIUM) else Severity.HIGH,
                confidence=confidence,
                rationale=f"Alert a human about {actor}: this looks like an attack but {reason}, so a person should confirm before blocking.",
                risk_score=risk,
                factors=factors or [f"risk {risk}"],
                also_consider=also_consider,
            )

        # ---- not a recognised attack pattern: alert only if the score is high ----
        if not dangerous and risk >= self.policy.alert_threshold:
            return Decision(
                action=Action.ALERT,
                target=actor,
                urgency=Severity.MEDIUM,
                confidence=confidence,
                rationale=(
                    f"Alert a human about {actor}: risk {risk} is elevated, but the "
                    f"activity does not match a known attack pattern."
                ),
                risk_score=risk,
                factors=factors or [f"risk {risk}"],
            )

        # ---- nothing worth acting on ----
        return Decision(
            action=Action.MONITOR,
            target=actor,
            urgency=Severity.LOW,
            confidence=confidence,
            rationale=f"Keep watching {actor}: activity is low risk for now.",
            risk_score=risk,
            factors=factors or ["low risk"],
        )

    def _confidence(self, risk: int, prediction: Optional[Prediction]) -> float:

        base = min(1.0, risk / 100.0)

        if prediction:
            return round(0.7 * base + 0.3 * prediction.confidence, 3)

        return round(base, 3)
