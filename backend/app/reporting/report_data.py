#Builds the report payload for one attacker from the objects ACT already has.
#
#Nothing in here is rendering: it only collects and orders facts. The HTML and
#PDF renderers both read this same dict, so the two formats can never drift.

from datetime import datetime
from typing import Any, Dict, List, Optional

from app.models.attack_graph import AttackPath
from app.models.severity import Severity
from app.models.twin import TwinAssessment

REPORT_TITLE = "ACT Incident Report"
TOOL_VERSION = "1.0.0"


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat(sep=" ", timespec="seconds") if value else None


def _techniques(path: AttackPath) -> List[Dict[str, str]]:
    seen: Dict[str, Dict[str, str]] = {}
    for node in path.nodes:
        for technique in node.behavior.techniques:
            seen.setdefault(technique.id, {
                "id": technique.id,
                "name": technique.name,
                "tactic": technique.tactic,
                "tactic_id": technique.tactic_id,
                "url": technique.url,
            })
    return list(seen.values())


def _kill_chain(
    path: AttackPath, all_stages: Optional[Dict[int, str]] = None
) -> List[Dict[str, Any]]:
    """One row per kill-chain stage, in order.

    When ``all_stages`` (the full stage-number -> name map from the MITRE
    knowledge base) is supplied, every stage is included - not just the ones
    this attacker reached - each flagged ``observed``, so the report and its
    attack-flow diagram can show the whole kill chain with the attacker's
    actual path highlighted against it. Falls back to reached-only stages
    (the old behaviour) when the map isn't available.
    """
    by_stage: Dict[int, Dict[str, Any]] = {}
    for node in path.nodes:
        stage = node.stage
        if stage <= 0:
            continue
        row = by_stage.setdefault(stage, {
            "stage": stage,
            "name": node.stage_name,
            "behaviors": [],
            "techniques": [],
            "risk_score": 0,
            "severity": "Low",
            "observed": True,
        })
        row["behaviors"].append(node.behavior.name)
        row["risk_score"] = max(row["risk_score"], node.behavior.risk_score)
        if Severity.rank(node.behavior.severity) > Severity.rank(row["severity"]):
            row["severity"] = node.behavior.severity
        for technique in node.behavior.techniques:
            if technique.id not in row["techniques"]:
                row["techniques"].append(technique.id)

    if all_stages:
        for stage, name in all_stages.items():
            by_stage.setdefault(stage, {
                "stage": stage,
                "name": name,
                "behaviors": [],
                "techniques": [],
                "risk_score": 0,
                "severity": "Low",
                "observed": False,
            })

    return [by_stage[k] for k in sorted(by_stage)]


def _timeline(path: AttackPath) -> List[Dict[str, Any]]:
    #every distinct evidence event across the path, oldest first
    events: Dict[str, Dict[str, Any]] = {}
    for node in path.nodes:
        for event in node.behavior.evidence:
            events.setdefault(event.id, {
                "time": _iso(event.timestamp),
                "type": event.event_type,
                "user": event.user,
                "ip_address": event.ip_address,
                "host": event.host,
                "description": event.description,
            })
    return sorted(events.values(), key=lambda row: row["time"] or "")


def _behaviours(path: AttackPath) -> List[Dict[str, Any]]:
    rows = []
    for node in path.nodes:
        behavior = node.behavior
        rows.append({
            "name": behavior.name,
            "rule": behavior.rule,
            "severity": behavior.severity,
            "risk_score": behavior.risk_score,
            "stage": behavior.stage,
            "stage_name": behavior.stage_name,
            "description": behavior.description,
            "first_seen": _iso(behavior.first_seen),
            "last_seen": _iso(behavior.last_seen),
            "techniques": [t.id for t in behavior.techniques],
            "risk_factors": [
                {"name": f.name, "points": f.points, "detail": f.detail}
                for f in behavior.risk_factors
            ],
        })
    return rows


def _actions(assessment: TwinAssessment) -> Dict[str, Any]:
    decision = assessment.decision
    response = assessment.response
    return {
        "decision": decision.action,
        "target": decision.target,
        "urgency": decision.urgency,
        "confidence": decision.confidence,
        "rationale": decision.rationale,
        "factors": list(decision.factors or []),
        "also_consider": list(decision.also_consider or []),
        "response_status": response.status if response else None,
        "response_command": response.command if response else None,
        "response_detail": response.detail if response else None,
        "response_armed": bool(response.armed) if response else False,
        "response_at": _iso(response.at) if response and response.at else None,
    }


def build_report(
    assessment: TwinAssessment,
    path: AttackPath,
    generated_at: Optional[datetime] = None,
    monitored_host: Optional[str] = None,
    armed: bool = False,
    all_stages: Optional[Dict[int, str]] = None,
) -> Dict[str, Any]:
    """Collect every fact the report shows into one JSON-friendly dict."""

    generated_at = generated_at or datetime.now()
    decision = assessment.decision
    prediction = assessment.prediction

    ai = decision.ai_assessment or assessment.llm_review

    return {
        "meta": {
            "title": REPORT_TITLE,
            "tool": "ACT - Adaptive Cyber Twin",
            "version": TOOL_VERSION,
            "generated_at": _iso(generated_at),
            "monitored_host": monitored_host,
            "auto_response_armed": bool(armed),
            "narrator": assessment.narrator,
        },
        "attacker": {
            "actor": assessment.actor,
            "first_activity": _iso(path.started_at),
            "last_activity": _iso(path.ended_at),
            "succeeded": bool(path.succeeded),
            "completeness": path.completeness,
            "deepest_stage": path.deepest_stage,
            "total_stages": path.total_stages,
            "current_stage_name": prediction.current_stage_name,
        },
        "risk": {
            "score": path.highest_risk,
            "severity": _severity_for(path.highest_risk),
            "decision_confidence": decision.confidence,
            "anomaly_score": round(prediction.anomaly_score, 3),
            "prediction_confidence": prediction.confidence,
        },
        "ai": ai,
        "summary": assessment.narrative,
        "mitre_techniques": _techniques(path),
        "kill_chain": _kill_chain(path, all_stages),
        "prediction": {
            "summary": prediction.summary,
            "model": prediction.model,
            "next_steps": [
                {
                    "stage": s.stage,
                    "stage_name": s.stage_name,
                    "probability": s.probability,
                    "reason": s.reason,
                }
                for s in prediction.next_steps
            ],
        },
        "behaviours": _behaviours(path),
        "timeline": _timeline(path),
        "actions_taken": _actions(assessment),
    }


def _severity_for(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"
