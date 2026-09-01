"""End to end on the real attack log: every stage of the attack must be seen.

This is the test to show in the defense. The log contains one full attack and
ACT has to name each stage of it, not only the brute force.
"""

from app.analyzer.behavior_correlator import BehaviorCorrelator
from app.analyzer.normalizer import EventNormalizer
from app.ingestion.parsers.linux_parser import LinuxParser
from app.ingestion.pipeline import IngestionPipeline
from app.ingestion.readers.file_log_reader import FileLogReader
from app.models.severity import Severity
from app.storage.event_store import EventStore

ATTACKER_IP = "192.168.1.50"


def analyse(log_path):

    store = EventStore()

    IngestionPipeline(
        reader=FileLogReader(log_path),
        parser=LinuxParser(),
        event_store=store,
        normalizer=EventNormalizer(),
    ).run()

    return BehaviorCorrelator(store).detect()


def by_rule(behaviors):
    return {behavior.rule: behavior for behavior in behaviors}


def test_every_stage_of_the_attack_is_detected(bruteforce_log):

    found = by_rule(analyse(bruteforce_log))

    assert "user-enumeration" in found         # looking for accounts
    assert "brute-force" in found              # guessing passwords
    assert "successful-brute-force" in found   # got in
    assert "privilege-escalation" in found     # trying to become root
    assert "sensitive-file-access" in found    # reading /etc/shadow
    assert "persistence" in found              # creating a backdoor account


def test_the_compromise_is_the_most_dangerous_finding(bruteforce_log):

    behaviors = analyse(bruteforce_log)

    top = behaviors[0]

    assert top.rule == "successful-brute-force"
    assert top.severity == Severity.CRITICAL
    assert top.attributes["compromised"] is True
    assert top.attributes["ip_address"] == ATTACKER_IP


def test_week_1_found_two_behaviors_week_2_finds_more(bruteforce_log):

    behaviors = analyse(bruteforce_log)

    assert len(behaviors) >= 7


def test_the_enumeration_lists_the_usernames_the_attacker_tried(bruteforce_log):

    enumeration = by_rule(analyse(bruteforce_log))["user-enumeration"]

    assert enumeration.attributes["distinct_users"] >= 3
    assert "admin" in enumeration.attributes["users"]
    assert "admin" in enumeration.attributes["invalid_users"]


def test_attacking_root_is_scored_higher_than_attacking_a_normal_user(bruteforce_log):

    brute = [b for b in analyse(bruteforce_log) if b.rule == "brute-force"]

    scores = {behavior.attributes["target_user"]: behavior.risk_score for behavior in brute}

    assert scores["root"] > scores["kali"]


def test_the_backdoor_account_is_named(bruteforce_log):

    persistence = by_rule(analyse(bruteforce_log))["persistence"]

    assert persistence.attributes["accounts"] == ["backdoor"]
    assert persistence.attributes["after_remote_login"] is True


def test_the_stolen_file_is_named(bruteforce_log):

    access = by_rule(analyse(bruteforce_log))["sensitive-file-access"]

    assert any("/etc/shadow" in command for command in access.attributes["commands"])


def test_every_behavior_can_explain_its_own_score(bruteforce_log):

    for behavior in analyse(bruteforce_log):

        assert behavior.risk_score == min(
            100, max(0, sum(factor.points for factor in behavior.risk_factors))
        )
        assert behavior.severity == Severity.from_score(behavior.risk_score)
