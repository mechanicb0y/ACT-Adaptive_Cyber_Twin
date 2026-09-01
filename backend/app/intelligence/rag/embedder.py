#Turns text into a vector (a list of numbers) so similar text sits close together.
#
#Two implementations behind one interface:
#
#  * OllamaEmbedder  asks a local Ollama model (nomic-embed-text) for a real
#    semantic embedding. Runs on the user's machine, nothing leaves it.
#  * HashingEmbedder pure Python, no server, no dependency. It hashes words into
#    a fixed-length vector (the "hashing trick"). Deterministic and instant,
#    which makes it perfect for tests and for a machine without Ollama.
#
#`build_embedder()` uses Ollama when it is reachable, otherwise the hashing one,
#so RAG works everywhere and gets smarter when a local model is available.

import hashlib
import json
import math
import os
import re
import urllib.request
from typing import List, Protocol

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_EMBED_MODEL = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text")

_WORD = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> List[str]:
    return _WORD.findall((text or "").lower())


def l2_normalize(vector: List[float]) -> List[float]:
    length = math.sqrt(sum(x * x for x in vector))
    if length == 0:
        return vector
    return [x / length for x in vector]


class Embedder(Protocol):
    name: str
    dim: int
    def embed(self, text: str) -> List[float]: ...


class HashingEmbedder:
    """Bag-of-words hashed into a fixed vector. Offline, deterministic, fast."""

    name = "hashing"

    def __init__(self, dim: int = 384):
        self.dim = dim

    def embed(self, text: str) -> List[float]:

        vector = [0.0] * self.dim

        for token in tokenize(text):
            #two independent hashes: one picks the slot, one picks the sign.
            #signed hashing reduces collisions cancelling meaning.
            digest = hashlib.md5(token.encode("utf-8")).digest()
            slot = int.from_bytes(digest[:4], "big") % self.dim
            sign = 1.0 if digest[4] & 1 else -1.0
            vector[slot] += sign

        return l2_normalize(vector)

    def embed_many(self, texts: List[str]) -> List[List[float]]:
        return [self.embed(t) for t in texts]


class OllamaEmbedder:
    """Real embeddings from a local Ollama model."""

    name = "ollama"

    def __init__(self, model: str = DEFAULT_EMBED_MODEL, host: str = OLLAMA_HOST, timeout: int = 30):
        self.model = model
        self.host = host.rstrip("/")
        self.timeout = timeout
        self.dim = 0   #learned from the first response

    def embed(self, text: str) -> List[float]:

        payload = json.dumps({"model": self.model, "prompt": text}).encode("utf-8")

        request = urllib.request.Request(
            f"{self.host}/api/embeddings",
            data=payload,
            headers={"content-type": "application/json"},
        )

        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            body = json.loads(response.read().decode("utf-8"))

        vector = body.get("embedding") or []
        self.dim = len(vector)

        return l2_normalize([float(x) for x in vector])

    def embed_many(self, texts: List[str]) -> List[List[float]]:
        return [self.embed(t) for t in texts]


def ollama_reachable(host: str = OLLAMA_HOST, timeout: float = 0.4) -> bool:
    #a quick, non-blocking check so we never hang if Ollama is not running
    try:
        with urllib.request.urlopen(f"{host.rstrip('/')}/api/tags", timeout=timeout):
            return True
    except Exception:                                       # noqa: BLE001
        return False


def build_embedder(prefer_ollama: bool = True) -> Embedder:
    if prefer_ollama and ollama_reachable():
        try:
            embedder = OllamaEmbedder()
            embedder.embed("warmup")   #confirm the embed model is actually pulled
            return embedder
        except Exception:                                   # noqa: BLE001
            pass
    return HashingEmbedder()
