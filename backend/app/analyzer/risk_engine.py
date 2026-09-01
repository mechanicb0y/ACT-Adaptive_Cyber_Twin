#The risk engine replaces the hard coded "confidence = 0.9" from Week 1.
#It gives every behavior a score from 0 to 100 built from real indicators, and it
#keeps the list of reasons, so the score can always be explained instead of trusted.
#The rules decide WHAT happened. This decides HOW DANGEROUS it is.

from typing import List, Tuple

from app.analyzer.correlation.time_window import events_per_minute, is_external_ip
from app.models.behavior import Behavior
from app.models.risk_factor import RiskFactor
from app.models.severity import Severity

#accounts worth more to an attacker than a normal user
PRIVILEGED_USERS = {"root", "admin", "administrator", "ubuntu", "ec2-user"}

#hours when almost nobody should be working
NIGHT_HOURS = range(0, 6)

MAX_SCORE = 100


class RiskEngine:

    def __init__(self, night_hours=NIGHT_HOURS, privileged_users=PRIVILEGED_USERS):
        self.night_hours = night_hours
        self.privileged_users = privileged_users

    def score(self, behavior: Behavior) -> Tuple[int, List[RiskFactor]]:

        factors: List[RiskFactor] = []
        attributes = behavior.attributes

        #1. what kind of attack it is
        base = int(attributes.get("base_score", 30))
        factors.append(RiskFactor("base", base, f"{behavior.name} base risk"))

        #2. how many events, more attempts means more determination
        volume = len(behavior.evidence)
        if volume >= 20:
            factors.append(RiskFactor("volume", 15, f"{volume} events"))
        elif volume >= 10:
            factors.append(RiskFactor("volume", 10, f"{volume} events"))
        elif volume >= 5:
            factors.append(RiskFactor("volume", 5, f"{volume} events"))

        #3. how fast, a human types slowly and a script does not
        rate = events_per_minute(behavior.evidence)
        if rate >= 30:
            factors.append(RiskFactor("rate", 15, f"very fast, {rate:.0f} events per minute"))
        elif rate >= 10:
            factors.append(RiskFactor("rate", 8, f"automated speed, {rate:.0f} events per minute"))

        #4. who was targeted
        target = (attributes.get("target_user") or "").lower()
        if target in self.privileged_users:
            factors.append(RiskFactor("privileged_target", 15, f"target is a privileged account '{target}'"))

        #5. where it came from
        ip_address = attributes.get("ip_address")
        if is_external_ip(ip_address):
            factors.append(RiskFactor("external_ip", 10, f"source {ip_address} is outside the network"))

        #6. how wide it was
        distinct_users = int(attributes.get("distinct_users", 0))
        if distinct_users >= 5:
            factors.append(RiskFactor("many_users", 10, f"{distinct_users} usernames tried"))
        elif distinct_users >= 3:
            factors.append(RiskFactor("many_users", 5, f"{distinct_users} usernames tried"))

        distinct_ips = int(attributes.get("distinct_ips", 0))
        if distinct_ips >= 3:
            factors.append(RiskFactor("many_ips", 10, f"attack spread over {distinct_ips} addresses"))

        #7. did it actually work
        if attributes.get("compromised"):
            factors.append(RiskFactor("compromised", 20, "the attacker successfully logged in"))

        if attributes.get("credential_access"):
            factors.append(RiskFactor("credential_access", 10, "credential files were read"))

        if attributes.get("persistence"):
            factors.append(RiskFactor("persistence", 10, "a new account was created"))

        if attributes.get("after_remote_login"):
            factors.append(RiskFactor("after_remote_login", 15, "happened right after a remote login"))

        #8. when it happened
        if behavior.first_seen and behavior.first_seen.hour in self.night_hours:
            factors.append(RiskFactor("night", 5, f"started at {behavior.first_seen:%H:%M}, outside working hours"))

        total = sum(factor.points for factor in factors)

        return max(0, min(MAX_SCORE, total)), factors

    def apply(self, behavior: Behavior) -> Behavior:
        #fill in the score, the reasons and the severity

        score, factors = self.score(behavior)

        behavior.risk_score = score
        behavior.risk_factors = factors
        behavior.severity = Severity.from_score(score)

        return behavior
