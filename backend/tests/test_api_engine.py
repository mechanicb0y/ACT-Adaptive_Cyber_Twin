"""The API's whole brain lives in AnalysisEngine, so it is tested here with no
web server involved. The FastAPI routers on top are thin enough to read."""

import pytest

from app.api.engine import AnalysisEngine
from app.api.serializers import behavior_to_dict, event_to_dict
from app.models.event_types import EventType

ATTACKER_IP = "192.168.1.50"


@pytest.fixture
def engine(bruteforce_log):
    item = AnalysisEngine()
    item.ingest_file(str(bruteforce_log))
    return item


def test_ingesting_a_file_fills_the_store(engine):

    assert len(engine.store.all()) == 28
    assert engine.last_stats.lines_read == 35
    assert engine.last_stats.parse_errors == 0


def test_a_sample_log_can_be_loaded_by_name_alone():

    engine = AnalysisEngine()
    engine.ingest_file("auth_bruteforce.log")

    assert len(engine.store.all()) == 28


def test_behaviors_are_detected_scored_and_mapped(engine):

    behaviors = engine.behaviors()

    assert len(behaviors) == 7
    assert all(b.risk_score > 0 for b in behaviors)
    assert all(b.techniques for b in behaviors)


def test_behaviors_can_be_filtered(engine):

    assert len(engine.behaviors(min_risk=80)) == 3
    assert len(engine.behaviors(rule="brute-force")) == 2
    assert len(engine.behaviors(severity="critical")) == 3
    assert engine.behaviors(rule="does-not-exist") == []


def test_the_attack_graph_is_built(engine):

    graph = engine.attack_graph()

    assert len(graph.paths) == 1
    assert graph.paths[0].completeness == 1.0


def test_results_are_cached_until_new_events_arrive(engine):

    first = engine.behaviors()
    second = engine.behaviors()

    #same objects back, detection did not run twice
    assert first[0] is second[0]


def test_the_cache_is_rebuilt_after_more_ingestion(engine, logs_dir):

    before = len(engine.behaviors())

    engine.ingest_file(str(logs_dir / "two_attackers.log"))

    after = engine.behaviors()

    assert len(after) > before
    assert len(engine.attack_graph().paths) == 3


def test_events_can_be_filtered_and_paged(engine):

    failures, total = engine.events(event_type=EventType.FAILED_LOGIN, limit=5)

    assert total == 20
    assert len(failures) == 5

    from_attacker, total = engine.events(ip_address=ATTACKER_IP, limit=0)

    assert total == len(from_attacker) == 21

    by_user, _ = engine.events(user="root", limit=0)

    assert len(by_user) == 7

    found, _ = engine.events(search="shadow", limit=0)

    assert len(found) == 1


def test_events_come_back_newest_first_by_default(engine):

    newest, _ = engine.events(limit=3)

    assert newest[0].timestamp >= newest[1].timestamp >= newest[2].timestamp

    oldest, _ = engine.events(limit=3, newest_first=False)

    assert oldest[0].timestamp <= oldest[1].timestamp


def test_events_since_feeds_the_live_stream(engine):

    index, new = engine.events_since(0)

    assert index == 28
    assert len(new) == 28

    index, new = engine.events_since(index)

    assert new == []

    #a reset must not leave the client stuck on an old index
    engine.reset()

    index, new = engine.events_since(999)

    assert index == 0
    assert new == []


def test_stats_describe_the_whole_picture(engine):

    stats = engine.stats()

    assert stats["events"]["total"] == 28
    assert stats["events"]["by_type"][EventType.FAILED_LOGIN] == 20
    assert stats["ingestion"]["coverage"] > 0.7
    assert stats["behaviors"]["total"] == 7
    assert stats["behaviors"]["highest_risk"] == 100
    assert stats["attack"]["paths"] == 1
    assert stats["attack"]["compromised"] is True
    assert stats["attack"]["actor"] == ATTACKER_IP
    assert stats["live"]["running"] is False


def test_stats_rank_the_attackers_and_the_targets(engine):

    stats = engine.stats()

    assert stats["top_attackers"][0]["ip_address"] == ATTACKER_IP
    assert stats["top_attackers"][0]["highest_risk"] == 100

    users = [item["user"] for item in stats["top_targets"]]

    assert "kali" in users


def test_stats_count_the_attack_techniques(engine):

    ids = {item["id"] for item in engine.stats()["techniques"]}

    assert "T1110.001" in ids
    assert "T1136.001" in ids


def test_empty_engine_does_not_crash():

    stats = AnalysisEngine().stats()

    assert stats["events"]["total"] == 0
    assert stats["behaviors"]["total"] == 0
    assert stats["attack"]["paths"] == 0
    assert stats["attack"]["worst_completeness"] == 0.0
    assert stats["events"]["first"] is None


def test_reset_clears_everything(engine):

    engine.reset()

    assert engine.store.all() == []
    assert engine.behaviors() == []
    assert engine.attack_graph().paths == []
    assert engine.last_stats.lines_read == 0


def test_sample_logs_are_listed_for_the_dashboard(engine):

    names = {item["name"] for item in engine.available_logs()}

    assert "auth_bruteforce.log" in names
    assert "two_attackers.log" in names


def test_ingesting_a_missing_file_raises_clearly():

    with pytest.raises(FileNotFoundError):
        AnalysisEngine().ingest_file("nope_does_not_exist.log")


def test_event_serializer_shape(engine):

    data = event_to_dict(engine.store.all()[0])

    assert set(data) == {
        "id", "timestamp", "ingested_at", "source", "host", "event_type",
        "description", "user", "process", "ip_address", "metadata", "raw_log",
    }
    assert isinstance(data["timestamp"], str)


def test_behavior_serializer_shape(engine):

    top = engine.behaviors()[0]

    data = behavior_to_dict(top, evidence_limit=3)

    assert data["risk_score"] == 100
    assert data["severity"] == "Critical"
    assert data["stage_name"] == "Initial Access"
    assert len(data["techniques"]) == 2
    assert data["techniques"][0]["url"].startswith("https://attack.mitre.org")
    assert data["risk_factors"]
    assert data["evidence_count"] == 21
    assert len(data["evidence"]) == 3      # limited, but the real count is kept
