#One MITRE ATT&CK technique.
#ATT&CK is the industry standard vocabulary for attacker behaviour. Saying
#"T1110.001" instead of "5 failed logins" is what makes ACT's output readable
#by any security team, and it is what the attack graph orders itself by.

from dataclasses import dataclass
from typing import Optional

ATTACK_URL = "https://attack.mitre.org/techniques"


@dataclass(slots=True)
class MitreTechnique:

    id: str          #T1110.001

    name: str        #Brute Force: Password Guessing

    tactic: str      #Credential Access

    tactic_id: str   #TA0006

    description: str = ""

    @property
    def url(self) -> str:
        #T1110.001 -> https://attack.mitre.org/techniques/T1110/001/
        return f"{ATTACK_URL}/{self.id.replace('.', '/')}/"

    @property
    def parent_id(self) -> Optional[str]:
        #the technique a sub technique belongs to, T1110.001 -> T1110
        if "." not in self.id:
            return None
        return self.id.split(".")[0]

    def __str__(self) -> str:
        return f"{self.id} {self.name} ({self.tactic})"
