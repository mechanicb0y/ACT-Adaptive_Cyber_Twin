#Severity levels used by every behavior.
#The risk engine decides the level from the score, so severity is never typed by hand.


class Severity:

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    #score thresholds, lowest first
    LEVELS = [
        (80, CRITICAL),
        (60, HIGH),
        (35, MEDIUM),
        (0, LOW),
    ]

    ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3}

    @classmethod
    def from_score(cls, score: int) -> str:

        for minimum, level in cls.LEVELS:
            if score >= minimum:
                return level

        return cls.LOW

    @classmethod
    def rank(cls, severity: str) -> int:
        #used for sorting, highest severity first
        return cls.ORDER.get(severity, 0)
