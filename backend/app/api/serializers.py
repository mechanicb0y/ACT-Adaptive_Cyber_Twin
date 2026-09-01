#Turns ACT objects into plain JSON friendly dictionaries for the API.
#
#Kept separate from the FastAPI routers on purpose. The API shape is a contract
#with the dashboard, so it is written by hand and tested, instead of dumping
#whatever the dataclasses happen to contain today.

from datetime import datetime
from typing import Any, Dict, List, Optional

from app.models.behavior import Behavior
from app.models.decision import Decision
from app.models.mitre import MitreTechnique
from app.models.prediction import Prediction
from app.models.response import ResponseResult
from app.models.security_event import SecurityEvent
from app.models.twin import TwinAssessment


def isoformat(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat(sep=" ", timespec="seconds") if value else None


def event_to_dict(event: SecurityEvent) -> Dict[str, Any]:

    return {
        "id": event.id,
        "timestamp": isoformat(event.timestamp),
        "ingested_at": isoformat(event.ingested_at),
        "source": event.source,
        "host": event.host,
        "event_type": event.event_type,
        "description": event.description,
        "user": event.user,
        "process": event.process,
        "ip_address": event.ip_address,
        "metadata": event.metadata,
        "raw_log": event.raw_log,
    }


def technique_to_dict(technique: MitreTechnique) -> Dict[str, Any]:

    return {
        "id": technique.id,
        "name": technique.name,
        "tactic": technique.tactic,
        "tactic_id": technique.tactic_id,
        "description": technique.description,
        "url": technique.url,
    }


def behavior_to_dict(
    behavior: Behavior,
    evidence_limit: int = 20,
) -> Dict[str, Any]:

    evidence = behavior.evidence

    if evidence_limit > 0:
        evidence = evidence[:evidence_limit]

    return {
        "id": behavior.id,
        "name": behavior.name,
        "description": behavior.description,
        "rule": behavior.rule,
        "severity": behavior.severity,
        "risk_score": behavior.risk_score,
        "confidence": behavior.confidence,
        "stage": behavior.stage,
        "stage_name": behavior.stage_name,
        "techniques": [technique_to_dict(t) for t in behavior.techniques],
        "risk_factors": [
            {"name": f.name, "points": f.points, "detail": f.detail}
            for f in behavior.risk_factors
        ],
        "attributes": behavior.attributes,
        "first_seen": isoformat(behavior.first_seen),
        "last_seen": isoformat(behavior.last_seen),
        "duration_seconds": behavior.duration_seconds,
        "evidence_count": len(behavior.evidence),
        "evidence": [event_to_dict(event) for event in evidence],
    }


def behaviors_to_list(
    behaviors: List[Behavior],
    evidence_limit: int = 20,
) -> List[Dict[str, Any]]:

    return [behavior_to_dict(b, evidence_limit) for b in behaviors]


def events_to_list(events: List[SecurityEvent]) -> List[Dict[str, Any]]:
    return [event_to_dict(event) for event in events]


# ----------------------------------------------------- intelligence layer #


def prediction_to_dict(prediction: Prediction) -> Dict[str, Any]:
    return {
        "actor": prediction.actor,
        "current_stage": prediction.current_stage,
        "current_stage_name": prediction.current_stage_name,
        "anomaly_score": prediction.anomaly_score,
        "confidence": prediction.confidence,
        "model": prediction.model,
        "summary": prediction.summary,
        "next_steps": [
            {
                "stage": s.stage,
                "stage_name": s.stage_name,
                "probability": s.probability,
                "reason": s.reason,
            }
            for s in prediction.next_steps
        ],
    }


def decision_to_dict(decision: Decision) -> Dict[str, Any]:
    return {
        "action": decision.action,
        "target": decision.target,
        "urgency": decision.urgency,
        "confidence": decision.confidence,
        "rationale": decision.rationale,
        "risk_score": decision.risk_score,
        "factors": decision.factors,
        "also_consider": decision.also_consider,
        "changes_the_machine": decision.changes_the_machine,
        "needs_arming": decision.needs_arming,
    }


def response_to_dict(response: Optional[ResponseResult]) -> Optional[Dict[str, Any]]:
    if response is None:
        return None
    return {
        "action": response.action,
        "target": response.target,
        "status": response.status,
        "command": response.command,
        "armed": response.armed,
        "detail": response.detail,
        "at": isoformat(response.at),
        "took_effect": response.took_effect,
    }


def assessment_to_dict(assessment: TwinAssessment) -> Dict[str, Any]:
    return {
        "actor": assessment.actor,
        "completeness": assessment.completeness,
        "succeeded": assessment.succeeded,
        "prediction": prediction_to_dict(assessment.prediction),
        "decision": decision_to_dict(assessment.decision),
        "response": response_to_dict(assessment.response),
        "narrative": assessment.narrative,
        "narrator": assessment.narrator,
        "llm_review": assessment.llm_review,
    }


def assessments_to_list(assessments: List[TwinAssessment]) -> List[Dict[str, Any]]:
    return [assessment_to_dict(a) for a in assessments]
