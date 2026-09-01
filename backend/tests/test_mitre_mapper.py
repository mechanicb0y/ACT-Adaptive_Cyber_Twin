from uuid import uuid4

from app.analyzer.correlation import default_correlation_rules
from app.analyzer.mitre_mapper import DEFAULT_KNOWLEDGE_BASE, MitreMapper
from app.models.behavior import Behavior
from app.models.mitre import MitreTechnique
from app.models.severity import Severity


def behavior(rule):
    return Behavior(
        id=str(uuid4()),
        name="test",
        description="test",
        severity=Severity.LOW,
        confidence=0.8,
        rule=rule,
    )


def test_knowledge_base_file_exists_and_loads():

    mapper = MitreMapper()

    assert DEFAULT_KNOWLEDGE_BASE.exists()
    assert mapper.total_stages == 6
    assert mapper.rules


def test_brute_force_maps_to_password_guessing():

    mapped = MitreMapper().map(behavior("brute-force"))

    assert mapped.technique_ids == ["T1110.001"]
    assert mapped.tactics == ["Credential Access"]
    assert mapped.stage == 2
    assert mapped.stage_name == "Credential Access"


def test_a_behavior_can_map_to_more_than_one_technique():

    mapped = MitreMapper().map(behavior("successful-brute-force"))

    assert mapped.technique_ids == ["T1110.001", "T1078.003"]
    assert "Initial Access" in mapped.tactics
    assert mapped.stage == 3


def test_every_correlation_rule_is_mapped():

    mapper = MitreMapper()

    for rule in default_correlation_rules():

        mapped = mapper.map(behavior(rule.name))

        assert mapped.techniques, f"rule '{rule.name}' has no ATT&CK technique"
        assert mapped.stage > 0, f"rule '{rule.name}' has no kill chain stage"


def test_stages_run_from_discovery_to_persistence():

    mapper = MitreMapper()

    stages = {
        rule.name: mapper.stage_for(rule.name) for rule in default_correlation_rules()
    }

    assert stages["user-enumeration"] < stages["brute-force"]
    assert stages["brute-force"] < stages["successful-brute-force"]
    assert stages["successful-brute-force"] < stages["privilege-escalation"]
    assert stages["privilege-escalation"] < stages["sensitive-file-access"]
    assert stages["sensitive-file-access"] < stages["persistence"]


def test_an_unknown_rule_is_left_unmapped_instead_of_crashing():

    mapped = MitreMapper().map(behavior("rule-that-does-not-exist"))

    assert mapped.techniques == []
    assert mapped.stage == 0
    assert mapped.stage_name == "Unmapped"


def test_a_missing_knowledge_base_does_not_stop_act(tmp_path):

    mapper = MitreMapper(path=tmp_path / "nothing.json")

    assert mapper.rules == {}
    assert mapper.map(behavior("brute-force")).techniques == []


def test_a_broken_knowledge_base_does_not_stop_act(tmp_path):

    path = tmp_path / "broken.json"
    path.write_text("{ not json at all", encoding="utf-8")

    assert MitreMapper(path=path).rules == {}


def test_technique_builds_its_own_attack_url():

    technique = MitreTechnique(
        id="T1110.001",
        name="Brute Force: Password Guessing",
        tactic="Credential Access",
        tactic_id="TA0006",
    )

    assert technique.url == "https://attack.mitre.org/techniques/T1110/001/"
    assert technique.parent_id == "T1110"

    parent = MitreTechnique(id="T1110", name="Brute Force", tactic="x", tactic_id="y")

    assert parent.url == "https://attack.mitre.org/techniques/T1110/"
    assert parent.parent_id is None
