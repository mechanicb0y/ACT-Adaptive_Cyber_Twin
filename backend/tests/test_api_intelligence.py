"""The AI layer as the API exposes it, tested without a web server."""

import pytest

from app.api.engine import AnalysisEngine
from app.api.serializers import assessment_to_dict
from app.models.decision import Action
from app.models.response import ResponseStatus


@pytest.fixture
def engine(bruteforce_log):
    e = AnalysisEngine()
    e.ingest_file(str(bruteforce_log))
    return e


def test_engine_exposes_assessments(engine):

    assessments = engine.assessments()

    assert len(assessments) == 1
    assert assessments[0].decision.action == Action.BLOCK_IP


def test_engine_starts_disarmed(engine):

    assert engine.armed is False

    #stats advertise the AI layer state
    intel = engine.stats()["intelligence"]
    assert intel["armed"] is False
    assert intel["assessments"] == 1
    assert intel["top"]["action"] == Action.BLOCK_IP
    assert intel["anomaly_model"] in ("statistical", "isolation-forest")


def test_arming_without_an_ssh_target_is_refused(engine):

    #the sample log was read from a file, so ACT has no machine to act on
    result = engine.arm()

    assert result["armed"] is False
    assert "SSH" in result["error"]
    assert engine.armed is False


def test_arming_after_an_ssh_source_is_known(engine):

    #pretend an SSH source was configured (as ingest_ssh would record)
    engine._ssh_identity = {"host": "192.168.10.139", "user": "kali", "port": 22, "key_file": None}

    result = engine.arm()

    assert result["armed"] is True
    assert result["target_host"] == "kali@192.168.10.139"
    assert engine.armed is True

    engine.disarm()
    assert engine.armed is False


def test_respond_is_a_dry_run_until_armed(engine):

    result = engine.respond("192.168.1.50")

    assert result is not None
    assert result.status == ResponseStatus.DRY_RUN
    assert "DROP" in result.command


def test_respond_to_an_unknown_actor_returns_none(engine):

    assert engine.respond("10.0.0.99") is None


def test_assessment_serializes_for_the_dashboard(engine):

    data = assessment_to_dict(engine.assessments()[0])

    assert data["actor"] == "192.168.1.50"
    assert data["prediction"]["next_steps"]
    assert data["decision"]["action"] == Action.BLOCK_IP
    assert data["decision"]["needs_arming"] is True
    assert data["response"]["status"] == ResponseStatus.DRY_RUN
    assert data["narrative"]
    assert data["narrator"] == "built-in"


def test_reset_clears_the_ai_layer(engine):

    engine.reset()

    assert engine.assessments() == []
    assert engine.stats()["intelligence"]["assessments"] == 0
