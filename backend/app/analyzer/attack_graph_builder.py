#Builds the attack graph from a list of scored, MITRE mapped behaviors.
#
#How the edges are decided:
#
#  1. every behavior gets a set of ACTOR KEYS taken from its attributes,
#     for example ("ip", "192.168.1.50") and ("user", "kali")
#  2. behaviors sharing an actor key are put in order (kill chain stage first,
#     then time) and each one is linked to the one immediately before it
#  3. a link is dropped if the two are too far apart in time
#  4. edges with the same two ends are merged, keeping all the reasons
#
#Linking only to the IMMEDIATE predecessor is what keeps the graph readable.
#Linking every pair would produce a mesh that nobody can look at.
#
#Step 3 matters more than it looks. Without it, two unrelated attackers who both
#happen to attack "root", five hours apart, are joined into one fake attack.

from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from app.analyzer.mitre_mapper import MitreMapper
from app.models.attack_graph import AttackEdge, AttackGraph, AttackNode, AttackPath
from app.models.behavior import Behavior

ActorKey = Tuple[str, str]

DEFAULT_MAX_GAP_SECONDS = 3600


class AttackGraphBuilder:

    def __init__(
        self,
        mapper: Optional[MitreMapper] = None,
        total_stages: int = 0,
        max_gap_seconds: int = DEFAULT_MAX_GAP_SECONDS,
    ):
        self.mapper = mapper

        #fall back to the mapper's stage count so the two never disagree
        self.total_stages = total_stages or (mapper.total_stages if mapper else 6)

        self.max_gap_seconds = max_gap_seconds

    @staticmethod
    def actor_keys(behavior: Behavior) -> Set[ActorKey]:
        #who this behavior is about, used to decide what connects to what

        keys: Set[ActorKey] = set()

        attributes = behavior.attributes

        if attributes.get("ip_address"):
            keys.add(("ip", str(attributes["ip_address"])))

        if attributes.get("target_user"):
            keys.add(("user", str(attributes["target_user"])))

        if attributes.get("host"):
            keys.add(("host", str(attributes["host"])))

        return keys

    @staticmethod
    def gap_seconds(earlier: Behavior, later: Behavior) -> float:
        """Distance between two time spans. Zero when they overlap."""

        def span(behavior: Behavior) -> Tuple[datetime, datetime]:
            start = behavior.first_seen or behavior.last_seen
            end = behavior.last_seen or behavior.first_seen
            return start, end

        first_start, first_end = span(earlier)
        second_start, second_end = span(later)

        if first_start is None or second_start is None:
            return 0.0

        if first_end >= second_start and second_end >= first_start:
            return 0.0

        if first_end < second_start:
            return (second_start - first_end).total_seconds()

        return (first_start - second_end).total_seconds()

    def close_enough(self, earlier: Behavior, later: Behavior) -> bool:

        if self.max_gap_seconds <= 0:
            return True

        return self.gap_seconds(earlier, later) <= self.max_gap_seconds

    @staticmethod
    def describe_key(key: ActorKey) -> str:

        kind, value = key

        if kind == "ip":
            return f"same source address {value}"
        if kind == "user":
            return f"same user account {value}"

        return f"same host {value}"

    @staticmethod
    def order(behaviors: List[Behavior]) -> List[Behavior]:
        """Kill chain stage first, time second.

        Sorting by time alone gives the wrong story: the compromise behavior
        starts at the timestamp of the FIRST failed login it used as evidence,
        so it would appear before the brute force that produced it. The stage
        number carries the logical order, and time only breaks ties.
        """

        return sorted(
            behaviors,
            key=lambda behavior: (
                behavior.stage if behavior.stage > 0 else 99,
                behavior.first_seen or behavior.last_seen,
            ),
        )

    def build(self, behaviors: List[Behavior]) -> AttackGraph:

        if not behaviors:
            return AttackGraph()

        if self.mapper is not None:
            behaviors = self.mapper.map_all(behaviors)

        ordered = self.order(behaviors)

        nodes = {behavior.id: AttackNode(id=behavior.id, behavior=behavior) for behavior in ordered}

        edges = self._build_edges(ordered)

        return AttackGraph(paths=self._split_into_paths(ordered, nodes, edges))

    def _build_edges(self, ordered: List[Behavior]) -> List[AttackEdge]:

        #actor key -> behaviors that mention it, already in order
        by_key: Dict[ActorKey, List[Behavior]] = {}

        for behavior in ordered:
            for key in self.actor_keys(behavior):
                by_key.setdefault(key, []).append(behavior)

        merged: Dict[Tuple[str, str], AttackEdge] = {}

        for key, chain in by_key.items():

            reason = self.describe_key(key)

            for previous, following in zip(chain, chain[1:]):

                if previous.id == following.id:
                    continue

                #too far apart in time to be the same session
                if not self.close_enough(previous, following):
                    continue

                pair = (previous.id, following.id)

                edge = merged.get(pair)

                if edge is None:
                    merged[pair] = AttackEdge(
                        source=previous.id,
                        target=following.id,
                        reasons=[reason],
                    )
                elif reason not in edge.reasons:
                    edge.reasons.append(reason)

        return list(merged.values())

    def _split_into_paths(
        self,
        ordered: List[Behavior],
        nodes: Dict[str, AttackNode],
        edges: List[AttackEdge],
    ) -> List[AttackPath]:
        """Separate attackers must not be drawn as one attack.

        Two behaviors belong to the same path when an edge connects them,
        ignoring direction. This is a plain connected components search.
        """

        neighbours: Dict[str, Set[str]] = {behavior.id: set() for behavior in ordered}

        for edge in edges:
            neighbours[edge.source].add(edge.target)
            neighbours[edge.target].add(edge.source)

        seen: Set[str] = set()
        paths: List[AttackPath] = []

        for behavior in ordered:

            if behavior.id in seen:
                continue

            #walk everything reachable from this behavior
            group: Set[str] = set()
            stack = [behavior.id]

            while stack:
                current = stack.pop()

                if current in group:
                    continue

                group.add(current)
                stack.extend(neighbours[current] - group)

            seen |= group

            path_nodes = [nodes[item.id] for item in ordered if item.id in group]

            path_edges = [
                edge
                for edge in edges
                if edge.source in group and edge.target in group
            ]

            paths.append(
                AttackPath(
                    nodes=path_nodes,
                    edges=path_edges,
                    total_stages=self.total_stages,
                )
            )

        #the attacker who got furthest is listed first
        paths.sort(
            key=lambda path: (path.completeness, path.highest_risk),
            reverse=True,
        )

        return paths
