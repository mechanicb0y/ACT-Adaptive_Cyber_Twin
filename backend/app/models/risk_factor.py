#One reason a behavior got its score.
#Keeping the reasons instead of only the number is what makes the score explainable:
#the dashboard can answer "why is this 87?" without guessing.

from dataclasses import dataclass


@dataclass(slots=True)
class RiskFactor:

    name: str       #short id, e.g. "external_ip"

    points: int     #how much it added to the score

    detail: str     #human readable reason

    def __str__(self) -> str:
        sign = "+" if self.points >= 0 else ""
        return f"{sign}{self.points} {self.detail}"
