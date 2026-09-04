#The knowledge ACT retrieves from when explaining an incident.
#
#This is the corpus behind RAG. Each entry is a short, self-contained fact about
#an attack technique or a defensive response. When the analyst writes a
#narrative, it first retrieves the few entries most relevant to the current
#incident and grounds the explanation in them, instead of relying on the model's
#memory alone.
#
#The corpus is built from ACT's own MITRE knowledge base plus a small defensive
#playbook, so it stays consistent with what the rest of the system detects.

import json
from pathlib import Path
from typing import Any, Dict, List

BACKEND_DIR = Path(__file__).resolve().parents[3]
MITRE_PATH = BACKEND_DIR / "data" / "mitre_attack.json"

#a compact SOC playbook: what each response means and when it is appropriate
RESPONSE_PLAYBOOK = [
    ("play-block-ip",
     "Blocking an IP address with a firewall DROP rule stops all further traffic "
     "from that source immediately. It is the right first response to an active "
     "brute-force or a confirmed compromise coming from a single address. It is "
     "reversible by deleting the rule."),
    ("play-lock-account",
     "Locking a user account prevents anyone from logging in as that user, even "
     "with the correct password. Use it when an account has been compromised or "
     "targeted heavily. It is reversible by unlocking the account."),
    ("play-isolate-host",
     "Isolating a host cuts it off from the network. It is the strongest response, "
     "reserved for a fully compromised machine where the attacker may spread. It "
     "is disruptive, so it is used carefully."),
    ("play-brute-force",
     "A brute-force attack is many failed logins for one account in a short time. "
     "The standard response is to block the source address before the attacker "
     "guesses the password."),
    ("play-compromise",
     "An account compromise is a successful login that follows many failures from "
     "the same source. This is an emergency: block the source and lock the "
     "affected account, then investigate what the attacker did while inside."),
    ("play-persistence",
     "Persistence is when an attacker creates a new account or backdoor so they "
     "can return later. After removing it, assume the machine is untrusted until "
     "reviewed, because other backdoors may exist."),
    ("play-enumeration",
     "User enumeration is one source trying many different usernames to learn "
     "which accounts exist. It usually precedes a targeted brute force, so it is "
     "an early warning worth blocking."),
    ("play-privesc",
     "Privilege escalation is an attempt to gain root, usually through sudo. After "
     "a remote login, repeated failed sudo attempts are a strong signal the "
     "attacker is trying to take full control."),
]

#kill-chain stage notes, so the model can ground "what comes next"
KILL_CHAIN = [
    ("chain-order",
     "Attacks usually progress through stages in order: discovery of accounts, "
     "credential access by guessing passwords, initial access by logging in, "
     "privilege escalation to root, credential theft from the password file, then "
     "persistence by creating a backdoor, and finally spreading to other hosts."),
]


def _technique_documents() -> List[Dict[str, Any]]:

    if not MITRE_PATH.exists():
        return []

    try:
        data = json.loads(MITRE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    docs: List[Dict[str, Any]] = []
    seen = set()

    for rule, mapping in (data.get("rules") or {}).items():
        for tech in mapping.get("techniques", []):
            tid = tech.get("id")
            if not tid or tid in seen:
                continue
            seen.add(tid)
            docs.append({
                "id": f"mitre-{tid}",
                "text": (
                    f"MITRE ATT&CK {tid} {tech.get('name','')} "
                    f"(tactic: {tech.get('tactic','')}). {tech.get('description','')}"
                ),
                "metadata": {"type": "technique", "technique": tid, "rule": rule},
            })

    return docs


def build_documents() -> List[Dict[str, Any]]:
    """The full RAG corpus: techniques + playbook + kill-chain notes."""

    docs = _technique_documents()

    for doc_id, text in RESPONSE_PLAYBOOK + KILL_CHAIN:
        docs.append({"id": doc_id, "text": text, "metadata": {"type": "playbook"}})

    return docs
