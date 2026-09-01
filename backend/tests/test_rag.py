import math

from app.intelligence.rag.embedder import HashingEmbedder, l2_normalize, tokenize
from app.intelligence.rag.knowledge_base import build_documents
from app.intelligence.rag.retriever import Retriever
from app.intelligence.rag.vector_store import VectorStore, cosine


# ------------------------------------------------------------ embedder #


def test_hashing_embedder_is_deterministic_and_normalized():

    e = HashingEmbedder(dim=128)

    v1 = e.embed("failed password brute force")
    v2 = e.embed("failed password brute force")

    assert v1 == v2                          # deterministic
    assert len(v1) == 128
    assert abs(math.sqrt(sum(x * x for x in v1)) - 1.0) < 1e-6   # unit length


def test_similar_text_scores_higher_than_unrelated():

    e = HashingEmbedder()

    brute = e.embed("brute force many failed login attempts")
    similar = e.embed("repeated failed logins, a brute force attack")
    unrelated = e.embed("the weather today is sunny and warm")

    assert cosine(brute, similar) > cosine(brute, unrelated)


def test_tokenize_and_normalize_helpers():

    assert tokenize("Failed-password, for ROOT!") == ["failed", "password", "for", "root"]
    assert l2_normalize([0.0, 0.0]) == [0.0, 0.0]


# ------------------------------------------------------------ vector store #


def test_store_search_returns_nearest_first():

    e = HashingEmbedder()
    store = VectorStore(embedder_name=e.name)

    store.add("a", "brute force password guessing", e.embed("brute force password guessing"))
    store.add("b", "creating a backdoor account for persistence", e.embed("creating a backdoor account for persistence"))

    hits = store.search(e.embed("guessing the password by force"), k=2)

    assert hits[0].id == "a"
    assert hits[0].score >= hits[1].score


def test_store_saves_and_loads(tmp_path):

    e = HashingEmbedder()
    store = VectorStore(embedder_name=e.name)
    store.add("x", "hello world", e.embed("hello world"), {"type": "test"})

    path = tmp_path / "index.json"
    store.save(path)

    loaded = VectorStore.load(path)

    assert loaded is not None
    assert len(loaded) == 1
    assert loaded.embedder_name == e.name
    assert loaded.records[0].metadata == {"type": "test"}


def test_loading_a_missing_index_returns_none(tmp_path):
    assert VectorStore.load(tmp_path / "nope.json") is None


# ------------------------------------------------------------ knowledge base #


def test_knowledge_base_has_techniques_and_playbook():

    docs = build_documents()

    ids = {d["id"] for d in docs}
    types = {d["metadata"]["type"] for d in docs}

    assert any(i.startswith("mitre-T") for i in ids)     # MITRE techniques
    assert "play-compromise" in ids                       # playbook entries
    assert types == {"technique", "playbook"}


# ------------------------------------------------------------ retriever #


def test_retriever_indexes_and_retrieves_relevant_knowledge():

    retriever = Retriever(embedder=HashingEmbedder())
    retriever.index(build_documents())

    assert retriever.size > 5

    hits = retriever.retrieve("brute force password guessing attack", k=3)

    assert hits
    joined = " ".join(h.text.lower() for h in hits)
    assert "brute" in joined or "password" in joined


def test_retriever_build_caches_the_index(tmp_path):

    path = tmp_path / "rag.json"

    #first build creates and saves
    first = Retriever.build(path=path, prefer_ollama=False)
    assert first.size > 0
    assert path.exists()

    #second build loads the saved index (same embedder), same size
    second = Retriever.build(path=path, prefer_ollama=False)
    assert second.size == first.size


def test_retriever_is_empty_safe():

    retriever = Retriever(embedder=HashingEmbedder())

    assert retriever.retrieve("anything") == []
    assert retriever.retrieve_texts("anything") == []
