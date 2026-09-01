#Detection settings live here instead of inside the code.
#Tuning a threshold or a time window should never mean editing Python.
#JSON is used on purpose so there is no extra dependency to install.

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "detection.json"


@dataclass(slots=True)
class RuleSettings:

    enabled: bool = True

    #how many events are needed
    threshold: int = 5

    #how close together they must be, in seconds
    window_seconds: int = 300

    #rule specific extras
    options: Dict[str, Any] = field(default_factory=dict)

    def option(self, key: str, fallback=None):
        return self.options.get(key, fallback)


class DetectionConfig:

    def __init__(
        self,
        rules: Optional[Dict[str, RuleSettings]] = None,
        sections: Optional[Dict[str, Any]] = None,
    ):
        self.rules: Dict[str, RuleSettings] = rules or {}

        #non rule settings, for example the "graph" block
        self.sections: Dict[str, Any] = sections or {}

    def section(self, name: str) -> Dict[str, Any]:
        return self.sections.get(name) or {}

    def option(self, section: str, key: str, fallback=None):
        return self.section(section).get(key, fallback)

    def for_rule(self, rule_name: str, defaults: Optional[RuleSettings] = None) -> RuleSettings:
        #a rule that is not in the config falls back to its own defaults
        return self.rules.get(rule_name) or defaults or RuleSettings()

    def is_enabled(self, rule_name: str, defaults: Optional[RuleSettings] = None) -> bool:
        return self.for_rule(rule_name, defaults).enabled

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DetectionConfig":

        rules = {}

        for name, values in (data.get("rules") or {}).items():

            values = values or {}

            known = {"enabled", "threshold", "window_seconds"}

            rules[name] = RuleSettings(
                enabled=values.get("enabled", True),
                threshold=values.get("threshold", 5),
                window_seconds=values.get("window_seconds", 300),
                options={k: v for k, v in values.items() if k not in known},
            )

        sections = {
            key: value
            for key, value in data.items()
            if key != "rules" and not key.startswith("_") and isinstance(value, dict)
        }

        return cls(rules, sections)

    @classmethod
    def load(cls, path: Optional[str | Path] = None) -> "DetectionConfig":
        #missing or broken config must not stop ACT, the rules have their own defaults

        target = Path(path) if path else DEFAULT_CONFIG_PATH

        if not target.exists():
            return cls()

        try:
            data = json.loads(target.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return cls()

        return cls.from_dict(data)
