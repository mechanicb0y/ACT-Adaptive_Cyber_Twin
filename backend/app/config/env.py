"""Load the local ``.env`` file into the process environment.

Import this as early as possible, before anything reads ``os.environ``. It is
safe to import more than once - python-dotenv will not clobber a value that is
already set in the real environment.

The file lives at ``backend/.env`` and is git-ignored. See
``docs/OLLAMA_RAG_SETUP.md``.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

#this file is app/config/env.py, so parents[2] is the backend/ directory
ENV_PATH = Path(__file__).resolve().parents[2] / ".env"

load_dotenv(ENV_PATH)

#OLLAMA_PATH is the Ollama install directory. Put it on PATH so the `ollama`
#command resolves even when the shell that started us was opened before Ollama
#was installed (a fresh terminal picks it up on its own; this covers the rest).
_ollama_dir = os.environ.get("OLLAMA_PATH", "").strip()
if _ollama_dir and Path(_ollama_dir).is_dir():
    _parts = os.environ.get("PATH", "").split(os.pathsep)
    if _ollama_dir not in _parts:
        os.environ["PATH"] = _ollama_dir + os.pathsep + os.environ.get("PATH", "")
