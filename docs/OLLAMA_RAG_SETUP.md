# Local AI: Ollama + RAG

ACT's incident narrator can run **entirely on your machine** with Ollama — fast,
private, no API key, no cost — and it grounds every explanation in a **local
vector store** of security knowledge (RAG). Nothing leaves your computer.

If you skip this, ACT still works: it falls back to the built-in explanation.
This upgrades the wording and makes it context-aware.

---

## 1. How it fits together

```
incident facts ─┐
                ├─►  RAG retriever  ──►  top-k knowledge chunks ─┐
knowledge base ─┘   (local vectors)                             ├─►  Ollama model ─►  narrative
                                                                │     (local)
                        the deterministic engines still decide ─┘     ACT still acts
```

- **Ollama** runs a small language model locally and writes the narrative.
- **RAG** retrieves the few most relevant facts (MITRE techniques, response
  playbook) from a local vector store and feeds them to the model, so the
  wording is precise and grounded, not guessed.
- The model **only explains.** Prediction, decision, and response stay in ACT's
  own deterministic engines — the AI never decides what to do.

---

## 2. Install Ollama

1. Download from **https://ollama.com/download** (Windows installer) and run it.
   Ollama then runs in the background at `http://localhost:11434`.
2. Pull a small, fast model and the embedding model:

```powershell
ollama pull llama3.2          # the narrator model (small + fast; or llama3.2:1b for speed)
ollama pull nomic-embed-text  # the embedding model for RAG
```

3. Confirm it's up:

```powershell
ollama list
curl http://localhost:11434/api/tags
```

That's it. ACT **auto-detects** Ollama — if it's running, ACT uses it.

---

## 3. Run ACT

```powershell
cd C:\Users\awabn\ACT\backend

# CLI: the EXPLAIN line now reads (llm:llama3.2+rag)
python -m app.main --file tests/logs/auth_bruteforce.log --twin

# on the live VM
python -m app.main --ssh kali@192.168.10.139 --since=-1h --twin

# dashboard: the Cognitive Twin panel shows the provider and RAG badge
python -m uvicorn app.api.main:app --reload
```

The first run builds the RAG vector index and saves it to
`backend/data/rag_index.json`. Every run after that loads it instantly.

---

## 4. Choosing the model (speed vs quality)

| Model | Speed | Notes |
|---|---|---|
| `llama3.2:1b` | fastest | great for a snappy live demo |
| `llama3.2` (3b) | fast | good balance (default) |
| `phi3` / `qwen2.5` | fast | solid alternatives |

Set the model with an environment variable (then reopen the terminal):

```powershell
setx OLLAMA_MODEL "llama3.2:1b"
```

---

## 5. Forcing a provider

ACT picks in this order: **Ollama if running → Gemini key → Anthropic key →
built-in**. Override it explicitly:

```powershell
setx ACT_LLM_PROVIDER "ollama"     # or gemini, anthropic, none
```

- `GEMINI_API_KEY` — use Google Gemini instead.
- `ANTHROPIC_API_KEY` — use Claude instead.
- `OLLAMA_MODEL`, `OLLAMA_EMBED_MODEL`, `OLLAMA_HOST` — tune the local setup.

---

## 6. Why this is fast

- **Local model** — no round-trip to a cloud API.
- **Vector retrieval** — a cosine search over ~15 small vectors is effectively
  instant, and the index is built once and cached to disk.
- **Narrative cache** — ACT remembers the narrative for an unchanged incident,
  so repeated dashboard refreshes don't re-run the model.

---

## 7. Why RAG matters for the defense

Without RAG, a language model answers from its own memory, which can drift or
invent. With RAG, ACT hands the model its **own** knowledge base — the same
MITRE techniques and response playbook the rest of the system uses — and asks it
to explain *using those facts*. So the narrative stays consistent with what ACT
detected, and you can point to exactly which knowledge grounded each explanation.

It also keeps the whole AI layer **local and private**: logs, incidents, and the
knowledge base never leave the machine.
