#Someone used sudo to touch a file that holds credentials.
#`sudo apt update` is administration. `sudo cat /etc/shadow` is credential theft.
#The difference is the command, which Week 1 stored in the event metadata.
#The watched paths come from the config file, not from the code.

from typing import List

from app.analyzer.correlation.base_correlation_rule import BaseCorrelationRule
from app.analyzer.correlation.time_window import group_by
from app.config.detection_config import RuleSettings
from app.models.behavior import Behavior
from app.models.event_types import EventType
from app.storage.event_store import EventStore

DEFAULT_SENSITIVE_PATHS = [
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/root/.ssh",
    "id_rsa",
    "authorized_keys",
]


class SensitiveFileAccessRule(BaseCorrelationRule):

    name = "sensitive-file-access"
    behavior_name = "Sensitive File Access"
    base_score = 70
    base_confidence = 0.9

    default_settings = RuleSettings(threshold=1, window_seconds=300)

    def detect(self, store: EventStore, settings: RuleSettings) -> List[Behavior]:

        commands = store.get_by_type(EventType.SUDO_COMMAND)

        watched = settings.option("sensitive_paths", DEFAULT_SENSITIVE_PATHS)

        behaviors: List[Behavior] = []

        def touches_sensitive_file(event) -> bool:
            command = str(event.metadata.get("command", ""))
            return any(path in command for path in watched)

        suspicious = [event for event in commands if touches_sensitive_file(event)]

        for user, events in group_by(suspicious, lambda e: e.user).items():

            if len(events) < settings.threshold:
                continue

            used = [str(event.metadata.get("command", "")) for event in events]

            behaviors.append(
                self.build_behavior(
                    description=(
                        f"User '{user}' accessed sensitive files with sudo: "
                        + "; ".join(used)
                    ),
                    evidence=events,
                    attributes={
                        "target_user": user,
                        "commands": used,
                        "credential_access": True,
                    },
                )
            )

        return behaviors
