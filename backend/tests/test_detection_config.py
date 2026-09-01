import json

from app.config.detection_config import DEFAULT_CONFIG_PATH, DetectionConfig, RuleSettings


def test_real_config_file_exists_and_loads():

    config = DetectionConfig.load()

    assert DEFAULT_CONFIG_PATH.exists()
    assert config.for_rule("brute-force").threshold == 5
    assert config.for_rule("brute-force").window_seconds == 120


def test_unknown_rule_falls_back_to_its_own_defaults():

    config = DetectionConfig()

    defaults = RuleSettings(threshold=9, window_seconds=99)

    assert config.for_rule("does-not-exist", defaults).threshold == 9


def test_extra_keys_become_options():

    config = DetectionConfig.from_dict(
        {"rules": {"sensitive-file-access": {"sensitive_paths": ["/etc/shadow"]}}}
    )

    settings = config.for_rule("sensitive-file-access")

    assert settings.option("sensitive_paths") == ["/etc/shadow"]


def test_a_rule_can_be_switched_off():

    config = DetectionConfig.from_dict({"rules": {"brute-force": {"enabled": False}}})

    assert config.is_enabled("brute-force") is False


def test_thresholds_can_be_changed_without_touching_code(tmp_path):

    path = tmp_path / "detection.json"
    path.write_text(
        json.dumps({"rules": {"brute-force": {"threshold": 50, "window_seconds": 5}}}),
        encoding="utf-8",
    )

    settings = DetectionConfig.load(path).for_rule("brute-force")

    assert settings.threshold == 50
    assert settings.window_seconds == 5


def test_a_broken_config_does_not_crash_act(tmp_path):

    path = tmp_path / "broken.json"
    path.write_text("{ this is not json", encoding="utf-8")

    assert DetectionConfig.load(path).rules == {}
    assert DetectionConfig.load(tmp_path / "missing.json").rules == {}
