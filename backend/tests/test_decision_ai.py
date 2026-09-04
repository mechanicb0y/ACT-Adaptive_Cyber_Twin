"""The local AI model is a real participant in the decision, not just a narrator.

It blends into the confidence, contributes its own risk estimate, can tip a
borderline block, and can pull ACT's attention onto something the statistical
score under-weighted (monitor -> alert). It can never invent a block on its own.
"""

from datetime import datetime, timedelta
from uuid import uuid4

from app.intelligence.decision_engine import DecisionEngine, DecisionPolicy
from app.models.attack_graph import AttackNode, AttackPath
from app.models.behavior import Behavior
from app.models.decision import Action
from app.models.severity import Severity

START = datetime(2026, 9, 3, 2, 0, 0)


def _behaviour(risk, rule="brute-force", attrs=None, stage=2):
    return Behavior(
        id=str(uuid4()), name="x", description="x", severity=Severity.HIGH,
        confidence=0.8, rule=rule, risk_score=risk, stage=stage,
        stage_name="Credential Access",
        first_seen=START, last_seen=START + timedelta(seconds=5),
        attributes=attrs or {"ip_address": "198.51.100.7"},
    )


def _path(*behaviours):
    return AttackPath(
        nodes=[AttackNode(id=b.id, behavior=b) for b in behaviours],
        edges=[], total_stages=6,
    )


def test_ai_vote_is_recorded_on_the_decision():

    llm = {"recommendation": "block", "confidence": 0.9, "threat": "high",
           "risk": 88, "reasoning": "clear brute force", "source": "ollama:llama3.2"}

    decision = DecisionEngine().decide(_path(_behaviour(95)), llm=llm)

    ai = decision.ai_assessment
    assert ai is not None
    assert ai["recommendation"] == "block"
    assert ai["source"] == "ollama:llama3.2"
    #the model's risk estimate is blended with the statistical one
    assert ai["statistical_risk"] == 95
    assert 88 <= ai["ai_adjusted_risk"] <= 95
    #and its confidence is blended in
    assert ai["statistical_confidence"] != ai["blended_confidence"]


def test_ai_can_tip_a_borderline_case_over_the_block_line():

    #risk 80, no compromise: statistically an ALERT (confidence 0.80, below the
    #0.90 bar, and no "block" vote to grant the grace margin)
    borderline = _path(_behaviour(80))
    assert DecisionEngine().decide(borderline).action == Action.ALERT

    #the local model independently says "block" with conviction -> the blended
    #confidence clears the grace margin and ACT blocks, recording that the
    #model is what carried it over the line
    llm = {"recommendation": "block", "confidence": 0.95, "threat": "high", "risk": 82}
    decision = DecisionEngine().decide(borderline, llm=llm)

    assert decision.action == Action.BLOCK_IP
    assert "threshold" in decision.ai_assessment["influence"]


def test_ai_escalates_a_monitor_to_an_alert():

    #low statistical risk on a real attack pattern -> normally MONITOR
    quiet = _path(_behaviour(22))
    assert DecisionEngine().decide(quiet).action == Action.MONITOR

    #the model saw something the score under-weighted
    llm = {"recommendation": "alert", "confidence": 0.8, "threat": "medium", "risk": 55}
    decision = DecisionEngine().decide(quiet, llm=llm)

    assert decision.action == Action.ALERT
    assert decision.ai_assessment["influence"] == "escalated monitor -> alert"
    assert "local AI" in " ".join(decision.factors)


def test_ai_cannot_invent_a_block_without_a_real_attack_pattern():

    #high score, but no correlation rule fired, and the model screams "block"
    no_pattern = _path(_behaviour(95, rule="session-activity"))
    llm = {"recommendation": "block", "confidence": 0.99, "threat": "critical", "risk": 99}

    decision = DecisionEngine().decide(no_pattern, llm=llm)

    #still only an alert: the pattern gate is not something the model can bypass
    assert decision.action == Action.ALERT


def test_a_weak_ai_opinion_does_not_escalate():

    quiet = _path(_behaviour(20))
    llm = {"recommendation": "monitor", "confidence": 0.4, "threat": "low", "risk": 15}

    assert DecisionEngine().decide(quiet, llm=llm).action == Action.MONITOR


def test_ai_cannot_talk_act_out_of_blocking_a_confirmed_compromise():

    compromised = _path(_behaviour(
        100, rule="successful-brute-force",
        attrs={"ip_address": "198.51.100.7", "compromised": True, "target_user": "kali"},
    ))
    llm = {"recommendation": "monitor", "confidence": 0.9, "threat": "low", "risk": 10}

    decision = DecisionEngine().decide(compromised, llm=llm)

    assert decision.action == Action.BLOCK_IP
