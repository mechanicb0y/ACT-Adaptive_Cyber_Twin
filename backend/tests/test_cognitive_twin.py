"""End to end: real attack log -> the full AI layer."""

from app.analyzer.behavior_correlator import BehaviorCorrelator
from app.analyzer.normalizer import EventNormalizer
from app.ingestion.parsers.linux_parser import LinuxParser
from app.ingestion.pipeline import IngestionPipeline
from app.ingestion.readers.file_log_reader import FileLogReader
from app.intelligence.cognitive_twin import CognitiveTwin
from app.intelligence.llm_analyst import LlmAnalyst
from app.intelligence.response.dry_run_responder import DryRunResponder
from app.intelligence.response.ssh_responder import SSHResponder
from app.models.decision import Action
from app.models.response import ResponseStatus
from app.storage.event_store import EventStore


def analyse(log_path):
    store = EventStore()
    IngestionPipeline(
        reader=FileLogReader(log_path),
        parser=LinuxParser(),
        event_store=store,
        normalizer=EventNormalizer(),
    ).run()
    graph = BehaviorCorrelator(store).build_attack_graph()
    return graph, store


def test_twin_produces_a_full_assessment(bruteforce_log):

    graph, store = analyse(bruteforce_log)

    assessments = CognitiveTwin().assess(graph, store.all())

    assert len(assessments) == 1

    a = assessments[0]

    assert a.actor == "192.168.1.50"
    assert a.succeeded is True
    assert a.prediction.next_steps                 # it predicted something
    assert a.decision.action == Action.BLOCK_IP    # and decided to block
    assert a.response.status == ResponseStatus.DRY_RUN   # but did NOT execute
    assert a.narrative                              # and explained it
    assert a.narrator == "built-in"                # no LLM key in tests


def test_the_twin_is_safe_by_default(bruteforce_log):

    graph, store = analyse(bruteforce_log)

    #a plain twin is never armed, so responding is still only a dry run
    twin = CognitiveTwin()
    result = twin.respond_to(graph.paths[0], store.all())

    assert result.status == ResponseStatus.DRY_RUN
    assert result.armed is False


def test_two_attackers_get_two_assessments(logs_dir):

    graph, store = analyse(logs_dir / "two_attackers.log")

    assessments = CognitiveTwin().assess(graph, store.all())

    assert len(assessments) == 2
    assert {a.actor for a in assessments} == {"10.10.10.22", "185.220.101.34"}


def test_arming_lets_a_real_responder_be_used(bruteforce_log):

    graph, store = analyse(bruteforce_log)

    #an armed twin with an SSH responder aimed at an unreachable host: the
    #decision is still made, the command still built, execution just fails
    twin = CognitiveTwin(
        responder=SSHResponder(host="203.0.113.5", user="kali", ssh_path="not-a-real-ssh"),
        armed=True,
    )

    result = twin.respond_to(graph.paths[0], store.all())

    assert result.status == ResponseStatus.FAILED     # tried to run, host is fake
    assert result.command and "DROP" in result.command


def test_llm_analyst_falls_back_without_a_key(bruteforce_log):

    graph, store = analyse(bruteforce_log)

    analyst = LlmAnalyst(api_key=None)

    assert analyst.available is False
    assert analyst.narrator_name() == "built-in"

    twin = CognitiveTwin(analyst=analyst)
    a = twin.assess(graph, store.all())[0]

    #the built-in narrative mentions the attacker and the action
    assert "192.168.1.50" in a.narrative
    assert a.narrative


def test_analyst_picks_the_provider_from_the_key():

    #an explicit key is treated as Gemini by default, and names itself
    gemini = LlmAnalyst(api_key="fake-gemini-key")
    assert gemini.available is True
    assert gemini.provider == "gemini"
    assert gemini.model.startswith("gemini")
    assert gemini.narrator_name().startswith("llm:gemini")

    anthropic = LlmAnalyst(api_key="sk-ant-fake", provider="anthropic")
    assert anthropic.provider == "anthropic"
    assert anthropic.narrator_name().startswith("llm:claude")


def test_analyst_detects_gemini_from_the_environment():

    import os
    #force the cloud path by disabling local ollama detection for this test
    os.environ["ACT_LLM_PROVIDER"] = "gemini"
    os.environ["GEMINI_API_KEY"] = "env-gemini-key"
    try:
        analyst = LlmAnalyst()
        assert analyst.provider == "gemini"
        assert analyst.available is True
    finally:
        del os.environ["GEMINI_API_KEY"]
        del os.environ["ACT_LLM_PROVIDER"]


def test_ollama_provider_is_selected_by_override():

    import os
    os.environ["ACT_LLM_PROVIDER"] = "ollama"
    try:
        analyst = LlmAnalyst()
        assert analyst.provider == "ollama"
        assert analyst.available is True                  # ollama needs no key
        assert analyst.model                              # a model name is chosen
    finally:
        del os.environ["ACT_LLM_PROVIDER"]


def test_rag_grounds_the_analyst_and_shows_in_the_name(bruteforce_log):

    from app.intelligence.rag.embedder import HashingEmbedder
    from app.intelligence.rag.knowledge_base import build_documents
    from app.intelligence.rag.retriever import Retriever

    retriever = Retriever(embedder=HashingEmbedder())
    retriever.index(build_documents())

    #a Gemini analyst (fake key) with RAG advertises "+rag"
    analyst = LlmAnalyst(api_key="fake", retriever=retriever)
    assert analyst.narrator_name().endswith("+rag")

    graph, store = analyse(bruteforce_log)
    a_pred = CognitiveTwin().assess(graph, store.all())[0].prediction
    a_dec = CognitiveTwin().assess(graph, store.all())[0].decision

    #retrieval returns relevant context for a real incident
    context = analyst._retrieve(analyst.facts(a_pred, a_dec))
    assert context
    assert any("block" in c.lower() or "brute" in c.lower() or "mitre" in c.lower() for c in context)


def test_llm_prompt_is_built_from_real_facts(bruteforce_log):

    graph, store = analyse(bruteforce_log)
    twin = CognitiveTwin()
    a = twin.assess(graph, store.all())[0]

    facts = LlmAnalyst().facts(a.prediction, a.decision)

    assert facts["attacker"] == "192.168.1.50"
    assert facts["recommended_action"] == Action.BLOCK_IP
    assert facts["risk_score"] == 100
