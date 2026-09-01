#Ties the embedder and the vector store together into one simple thing:
#"given this incident, hand me the few most relevant pieces of knowledge."
#
#It indexes the knowledge base once and saves the vectors to disk, so every run
#after the first loads instantly instead of re-embedding. That persistence is
#what keeps RAG fast.

from pathlib import Path
from typing import List, Optional

from app.intelligence.rag.embedder import Embedder, HashingEmbedder, build_embedder
from app.intelligence.rag.knowledge_base import build_documents
from app.intelligence.rag.vector_store import SearchHit, VectorStore

BACKEND_DIR = Path(__file__).resolve().parents[3]
DEFAULT_INDEX_PATH = BACKEND_DIR / "data" / "rag_index.json"


class Retriever:

    def __init__(self, embedder: Optional[Embedder] = None, store: Optional[VectorStore] = None):
        self.embedder = embedder or HashingEmbedder()
        self.store = store or VectorStore(embedder_name=self.embedder.name)

    @property
    def size(self) -> int:
        return len(self.store)

    def index(self, documents) -> None:
        #embed every document and put it in the store
        for doc in documents:
            vector = self.embedder.embed(doc["text"])
            self.store.add(doc["id"], doc["text"], vector, doc.get("metadata"))

    def retrieve(self, query: str, k: int = 4) -> List[SearchHit]:
        if not self.store.records:
            return []
        return self.store.search(self.embedder.embed(query), k=k)

    def retrieve_texts(self, query: str, k: int = 4) -> List[str]:
        return [hit.text for hit in self.retrieve(query, k)]

    @classmethod
    def build(
        cls,
        path: Optional[str | Path] = None,
        prefer_ollama: bool = True,
        documents=None,
    ) -> "Retriever":
        """Load the saved index if it matches the embedder, else build and save it."""

        path = Path(path or DEFAULT_INDEX_PATH)
        embedder = build_embedder(prefer_ollama=prefer_ollama)

        cached = VectorStore.load(path)
        if cached is not None and cached.embedder_name == embedder.name and len(cached):
            return cls(embedder=embedder, store=cached)

        #build fresh
        retriever = cls(embedder=embedder, store=VectorStore(embedder_name=embedder.name))
        retriever.index(documents if documents is not None else build_documents())

        try:
            retriever.store.save(path)
        except OSError:
            pass   #a read-only disk must not stop ACT

        return retriever
