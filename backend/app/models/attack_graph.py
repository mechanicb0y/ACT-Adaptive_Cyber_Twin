#The attack graph turns a LIST of behaviors into a PATH.
#
#A list says "these seven things happened".
#A graph says "this is one attacker, and this is how far he got".
#
#Nodes are behaviors. Edges mean "these two share an actor and one came after
#the other". A connected group of nodes is one attack path, so two unrelated
#attackers produce two separate paths instead of one confused blob.

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.models.behavior import Behavior


@dataclass(slots=True)
class AttackNode:

    id: str

    behavior: Behavior

    @property
    def label(self) -> str:
        return self.behavior.name

    @property
    def stage(self) -> int:
        return self.behavior.stage

    @property
    def stage_name(self) -> str:
        return self.behavior.stage_name or "Unmapped"

    @property
    def risk_score(self) -> int:
        return self.behavior.risk_score

    @property
    def technique_ids(self) -> List[str]:
        return self.behavior.technique_ids

    def to_dict(self) -> Dict[str, Any]:
        #shape the future dashboard will draw
        return {
            "id": self.id,
            "label": self.label,
            "rule": self.behavior.rule,
            "stage": self.stage,
            "stage_name": self.stage_name,
            "severity": self.behavior.severity,
            "risk_score": self.risk_score,
            "techniques": [
                {"id": t.id, "name": t.name, "tactic": t.tactic, "url": t.url}
                for t in self.behavior.techniques
            ],
            "description": self.behavior.description,
            "first_seen": str(self.behavior.first_seen) if self.behavior.first_seen else None,
            "last_seen": str(self.behavior.last_seen) if self.behavior.last_seen else None,
            "evidence_count": len(self.behavior.evidence),
        }


@dataclass(slots=True)
class AttackEdge:

    source: str

    target: str

    #why the two are linked, e.g. ["same source address 192.168.1.50"]
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "reasons": self.reasons,
        }


@dataclass(slots=True)
class AttackPath:
    """One attacker: a connected group of behaviors, ordered by kill chain stage."""

    nodes: List[AttackNode] = field(default_factory=list)

    edges: List[AttackEdge] = field(default_factory=list)

    #how many stages exist in total, used for the completeness percentage
    total_stages: int = 6

    @property
    def actor(self) -> Optional[str]:
        #the address responsible for most of the behaviors
        counts: Dict[str, int] = {}

        for node in self.nodes:
            ip_address = node.behavior.attributes.get("ip_address")
            if ip_address:
                counts[ip_address] = counts.get(ip_address, 0) + 1

        if not counts:
            return None

        return max(counts, key=counts.get)

    @property
    def stages_reached(self) -> List[int]:
        return sorted({node.stage for node in self.nodes if node.stage > 0})

    @property
    def deepest_stage(self) -> int:
        stages = self.stages_reached
        return stages[-1] if stages else 0

    @property
    def completeness(self) -> float:
        #how far along the kill chain the attacker got, 0.0 to 1.0
        if self.total_stages <= 0:
            return 0.0
        return round(self.deepest_stage / self.total_stages, 4)

    @property
    def highest_risk(self) -> int:
        return max((node.risk_score for node in self.nodes), default=0)

    @property
    def technique_ids(self) -> List[str]:
        found: List[str] = []
        for node in self.nodes:
            for technique_id in node.technique_ids:
                if technique_id not in found:
                    found.append(technique_id)
        return found

    @property
    def started_at(self) -> Optional[datetime]:
        times = [n.behavior.first_seen for n in self.nodes if n.behavior.first_seen]
        return min(times) if times else None

    @property
    def ended_at(self) -> Optional[datetime]:
        times = [n.behavior.last_seen for n in self.nodes if n.behavior.last_seen]
        return max(times) if times else None

    @property
    def succeeded(self) -> bool:
        #did the attacker actually get in
        return any(
            node.behavior.attributes.get("compromised") for node in self.nodes
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor": self.actor,
            "succeeded": self.succeeded,
            "deepest_stage": self.deepest_stage,
            "stages_reached": self.stages_reached,
            "total_stages": self.total_stages,
            "completeness": self.completeness,
            "highest_risk": self.highest_risk,
            "techniques": self.technique_ids,
            "started_at": str(self.started_at) if self.started_at else None,
            "ended_at": str(self.ended_at) if self.ended_at else None,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
        }


@dataclass(slots=True)
class AttackGraph:
    """Every attack path found in the current event store."""

    paths: List[AttackPath] = field(default_factory=list)

    @property
    def worst_path(self) -> Optional[AttackPath]:
        if not self.paths:
            return None
        return max(self.paths, key=lambda path: (path.completeness, path.highest_risk))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_count": len(self.paths),
            "paths": [path.to_dict() for path in self.paths],
        }
