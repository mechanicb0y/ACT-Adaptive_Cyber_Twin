#Turns ACT behaviors into MITRE ATT&CK techniques and kill chain stages.
#
#The mapping lives in data/mitre_attack.json, not in the code, for two reasons:
#ATT&CK is updated a few times a year, and a new correlation rule should be
#mappable by editing a file instead of editing Python.
#
#The knowledge base is kept offline on purpose. A live demo must never depend
#on the internet being available in the exam room.

import json
from pathlib import Path
from typing import Dict, List, Optional

from app.models.behavior import Behavior
from app.models.mitre import MitreTechnique

DEFAULT_KNOWLEDGE_BASE = (
    Path(__file__).resolve().parents[2] / "data" / "mitre_attack.json"
)

UNKNOWN_STAGE = 0
UNKNOWN_STAGE_NAME = "Unmapped"


class MitreMapper:

    def __init__(self, knowledge_base: Optional[dict] = None, path=None):

        data = knowledge_base if knowledge_base is not None else self._load(path)

        self.raw = data

        #stage number -> stage name
        self.stages: Dict[int, str] = {
            int(item["stage"]): item["name"] for item in data.get("stages", [])
        }

        self.rules: Dict[str, dict] = data.get("rules", {})

    @staticmethod
    def _load(path=None) -> dict:

        target = Path(path) if path else DEFAULT_KNOWLEDGE_BASE

        if not target.exists():
            return {}

        try:
            return json.loads(target.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            #a missing or broken knowledge base must not stop detection
            return {}

    def techniques_for(self, rule_name: Optional[str]) -> List[MitreTechnique]:

        entry = self.rules.get(rule_name or "", {})

        return [
            MitreTechnique(
                id=item["id"],
                name=item["name"],
                tactic=item["tactic"],
                tactic_id=item.get("tactic_id", ""),
                description=item.get("description", ""),
            )
            for item in entry.get("techniques", [])
        ]

    def stage_for(self, rule_name: Optional[str]) -> int:
        return int(self.rules.get(rule_name or "", {}).get("stage", UNKNOWN_STAGE))

    def stage_name(self, stage: int) -> str:
        return self.stages.get(stage, UNKNOWN_STAGE_NAME)

    def map(self, behavior: Behavior) -> Behavior:
        #fills the technique list and the kill chain stage on one behavior

        behavior.techniques = self.techniques_for(behavior.rule)
        behavior.stage = self.stage_for(behavior.rule)
        behavior.stage_name = self.stage_name(behavior.stage)

        return behavior

    def map_all(self, behaviors: List[Behavior]) -> List[Behavior]:
        return [self.map(behavior) for behavior in behaviors]

    @property
    def total_stages(self) -> int:
        return len(self.stages)
