#A small vector database: stores text + its vector, and finds the nearest ones.
#
#This is the "store the data in vectors" part. Every knowledge chunk is kept as
#a vector, and a search is just cosine similarity against the query vector,
#returning the closest matches. Over a few dozen chunks this is effectively
#instant, which is what makes RAG fast.
#
#It is pure Python with an optional numpy fast path, and it persists to a JSON
#file so the index is built once and loaded instantly afterwards. No external
#database, no server.

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import numpy as _np          #optional, only for speed
except Exception:                # noqa: BLE001
    _np = None


@dataclass(slots=True)
class VectorRecord:
    id: str
    text: str
    vector: List[float]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SearchHit:
    id: str
    text: str
    score: float
    metadata: Dict[str, Any]


def cosine(a: List[float], b: List[float]) -> float:
    #vectors are stored L2-normalized, so cosine is just the dot product
    if _np is not None:
        return float(_np.dot(a, b))
    return sum(x * y for x, y in zip(a, b))


class VectorStore:

    def __init__(self, embedder_name: str = "", dim: int = 0):
        self.records: List[VectorRecord] = []
        #remember which embedder built this index; mixing embedders is invalid
        self.embedder_name = embedder_name
        self.dim = dim
        self._matrix = None       #cached numpy matrix for fast search

    def add(self, id: str, text: str, vector: List[float], metadata: Optional[Dict] = None) -> None:
        self.records.append(VectorRecord(id, text, vector, metadata or {}))
        self._matrix = None
        if not self.dim:
            self.dim = len(vector)

    def __len__(self) -> int:
        return len(self.records)

    def search(self, query_vector: List[float], k: int = 4) -> List[SearchHit]:

        if not self.records:
            return []

        if _np is not None:
            if self._matrix is None:
                self._matrix = _np.array([r.vector for r in self.records], dtype=float)
            scores = self._matrix.dot(_np.array(query_vector, dtype=float))
            order = scores.argsort()[::-1][:k]
            return [
                SearchHit(self.records[i].id, self.records[i].text, float(scores[i]), self.records[i].metadata)
                for i in order
            ]

        scored = [
            (cosine(query_vector, r.vector), r)
            for r in self.records
        ]
        scored.sort(key=lambda pair: pair[0], reverse=True)

        return [
            SearchHit(r.id, r.text, float(score), r.metadata)
            for score, r in scored[:k]
        ]

    # ------------------------------------------------------------ persistence #

    def to_dict(self) -> Dict[str, Any]:
        return {
            "embedder": self.embedder_name,
            "dim": self.dim,
            "records": [
                {"id": r.id, "text": r.text, "vector": r.vector, "metadata": r.metadata}
                for r in self.records
            ],
        }

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict()), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> Optional["VectorStore"]:
        path = Path(path)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

        store = cls(embedder_name=data.get("embedder", ""), dim=data.get("dim", 0))
        for row in data.get("records", []):
            store.records.append(
                VectorRecord(row["id"], row["text"], row["vector"], row.get("metadata", {}))
            )
        return store
