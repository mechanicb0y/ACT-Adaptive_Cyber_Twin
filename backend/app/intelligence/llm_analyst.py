#Turns ACT's structured findings into a human incident report, in plain English,
#grounded in a retrieved security knowledge base (RAG).
#
#Providers, in order of preference:
#   * Ollama    a local model on this machine (fast, private, no key, no cost)
#   * Gemini    Google, GEMINI_API_KEY / GOOGLE_API_KEY
#   * Anthropic Claude, ANTHROPIC_API_KEY
#   * built-in  a deterministic template, when nothing else is available
#
#RAG: before writing, the analyst retrieves the few knowledge chunks most
#relevant to this incident (MITRE technique notes, response playbook) from a
#local vector store and puts them in the prompt. This grounds the narrative in
#ACT's own knowledge instead of the model's memory. The retrieval is a cosine
#search over a few dozen vectors, so it is effectively instant.
#
#Design rules that never change with the provider:
#  * The LLM only EXPLAINS. It never decides the action and never runs anything.
#  * Everything is optional and degrades gracefully. No Ollama, no key, no
#    retriever -> a built-in template. The pipeline never breaks.
#  * A narrative cache means repeated identical requests return instantly.

import hashlib
import json
import os
import urllib.request
from typing import Optional

from app.intelligence.rag.embedder import OLLAMA_HOST, ollama_reachable

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"

DEFAULT_OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-5"

SYSTEM_PROMPT = (
    "You are a senior SOC analyst. You are given structured facts about one "
    "attacker (already detected and scored by a tool called ACT) and some "
    "relevant reference knowledge. Write a short, calm incident summary (4-6 "
    "sentences) for a security team: what the attacker did, how far they got, "
    "what they will likely do next, and whether the recommended action is "
    "appropriate. Use the reference knowledge to be precise. Do not invent facts "
    "beyond those given. Do not use markdown."
)

#a second, separate job for the local model: an actual risk judgment that
#feeds into the decision engine, not just prose. Strict JSON, no prose.
RISK_SYSTEM_PROMPT = (
    "You are a senior SOC analyst assisting an automated defence system. You are "
    "given structured facts about ONE attacker and some reference knowledge. "
    "Judge how dangerous this is and whether the source IP should be blocked "
    "now. Reply with ONE line of strict JSON and nothing else:\n"
    '{"recommendation": "block" | "alert" | "monitor", "confidence": <number 0.0-1.0>, '
    '"threat": "critical" | "high" | "medium" | "low", '
    '"risk": <integer 0-100>, "reasoning": "<one short sentence>"}\n'
    'Recommend "block" only for a clear, active attack: a brute-force or user '
    'enumeration pattern, credential access, a successful compromise, or '
    'persistence. Use "monitor" for weak or ambiguous signals. "risk" is your '
    "own 0-100 severity estimate for this incident. Base confidence on how "
    "certain you are. Do not invent facts beyond those given."
)


class LlmAnalyst:

    def __init__(
        self,
        api_key: Optional[str] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        retriever=None,
        timeout: int = 30,
    ):
        #kept modest on purpose: the dashboard polls, and a slow model must not
        #stall a request. The risk judgment is a tiny JSON reply, so it gets a
        #tighter budget still.
        self.timeout = int(os.environ.get("ACT_LLM_TIMEOUT", timeout))
        self.review_timeout = min(self.timeout, 15)
        self.retriever = retriever
        self._cache: dict = {}

        if provider:
            self.provider = provider
            self.api_key = api_key
        elif api_key:
            self.provider, self.api_key = "gemini", api_key
        else:
            self.provider, self.api_key = self._detect()

        self.model = model or self._default_model()

    @staticmethod
    def _detect():
        #explicit override first
        forced = os.environ.get("ACT_LLM_PROVIDER")
        if forced:
            if forced == "gemini":
                return "gemini", os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
            if forced == "anthropic":
                return "anthropic", os.environ.get("ANTHROPIC_API_KEY")
            if forced == "ollama":
                return "ollama", None
            if forced in ("none", "off"):
                return None, None

        #local model preferred: fast, private, free
        if ollama_reachable():
            return "ollama", None

        gemini = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if gemini:
            return "gemini", gemini

        anthropic = os.environ.get("ANTHROPIC_API_KEY")
        if anthropic:
            return "anthropic", anthropic

        return None, None

    def _default_model(self) -> str:
        if self.provider == "ollama":
            return DEFAULT_OLLAMA_MODEL
        if self.provider == "gemini":
            return os.environ.get("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
        if self.provider == "anthropic":
            return os.environ.get("ANTHROPIC_MODEL", DEFAULT_ANTHROPIC_MODEL)
        return "none"

    @property
    def available(self) -> bool:
        #ollama needs no key; the cloud providers do
        if self.provider == "ollama":
            return True
        return bool(self.api_key and self.provider)

    def narrator_name(self) -> str:
        if not self.available:
            return "built-in"
        tag = f"llm:{self.model}"
        if self.retriever and self.retriever.size:
            tag += "+rag"
        return tag

    # ------------------------------------------------------------ facts + RAG #

    def facts(self, prediction, decision) -> dict:
        nxt = prediction.most_likely
        return {
            "attacker": prediction.actor,
            "current_stage": prediction.current_stage_name,
            "anomaly_score": prediction.anomaly_score,
            "predicted_next": nxt.stage_name if nxt else None,
            "predicted_next_reason": nxt.reason if nxt else None,
            "recommended_action": decision.action,
            "action_target": decision.target,
            "urgency": decision.urgency,
            "rationale": decision.rationale,
            "risk_score": decision.risk_score,
            "also_consider": list(getattr(decision, "also_consider", []) or []),
        }

    def incident_facts(self, path, prediction) -> dict:
        """Facts for the risk judgment: taken from the attack path, before any
        decision has been made, so the model's opinion is independent."""

        nxt = prediction.most_likely
        rules = sorted({n.behavior.rule for n in path.nodes if n.behavior.rule})
        return {
            "attacker": path.actor,
            "matched_attack_rules": rules,
            "risk_score": path.highest_risk,
            "got_in": bool(path.succeeded),
            "deepest_stage_reached": path.deepest_stage,
            "stages": [n.stage_name for n in path.nodes],
            "techniques": path.technique_ids,
            "anomaly_score": round(prediction.anomaly_score, 3),
            "predicted_next_move": nxt.stage_name if nxt else None,
        }

    def assess_incident(self, path, prediction) -> Optional[dict]:
        """Ask the local model for an independent block / alert / monitor call.

        Returns ``{"recommendation", "confidence", "threat", "reasoning",
        "source"}`` or ``None`` when no model is available or the reply cannot
        be parsed. The decision engine blends this with its own confidence.
        """

        if not self.available:
            return None

        facts = self.incident_facts(path, prediction)
        key = "risk:" + hashlib.md5(json.dumps(facts, sort_keys=True).encode()).hexdigest()
        if key in self._cache:
            return self._cache[key]

        context = self._retrieve({
            "current_stage": facts.get("deepest_stage_reached"),
            "predicted_next": facts.get("predicted_next_move"),
            "recommended_action": "block",
        })
        prompt = self._prompt(facts, context)

        try:
            if self.provider == "ollama":
                raw = self._call_ollama(
                    prompt, system=RISK_SYSTEM_PROMPT,
                    timeout=self.review_timeout, num_predict=160,
                )
            elif self.provider == "gemini":
                raw = self._call_gemini(prompt, system=RISK_SYSTEM_PROMPT)
            else:
                raw = self._call_anthropic(prompt, system=RISK_SYSTEM_PROMPT)
            judgment = self._parse_judgment(raw)
        except Exception:                                   # noqa: BLE001
            judgment = None

        if judgment is not None:
            judgment["source"] = f"{self.provider}:{self.model}"

        self._cache[key] = judgment
        return judgment

    @staticmethod
    def _parse_judgment(raw: str) -> Optional[dict]:

        if not raw:
            return None

        text = raw.strip()
        if "```" in text:
            segments = text.split("```")
            text = segments[1] if len(segments) >= 2 else text
            if text.lstrip().lower().startswith("json"):
                text = text.lstrip()[4:]

        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end == -1 or end < start:
            return None

        try:
            data = json.loads(text[start:end + 1])
        except Exception:                                   # noqa: BLE001
            return None

        rec = str(data.get("recommendation", "")).lower().strip()
        if rec not in ("block", "alert", "monitor"):
            return None

        try:
            conf = float(data.get("confidence"))
        except (TypeError, ValueError):
            conf = 0.5
        conf = max(0.0, min(1.0, conf))

        threat = str(data.get("threat", "")).lower().strip()
        if threat not in ("critical", "high", "medium", "low"):
            threat = None

        risk = None
        try:
            risk = int(round(float(data.get("risk"))))
            risk = max(0, min(100, risk))
        except (TypeError, ValueError):
            risk = None

        return {
            "recommendation": rec,
            "confidence": round(conf, 3),
            "threat": threat,
            "risk": risk,
            "reasoning": str(data.get("reasoning", ""))[:300],
        }

    def _retrieve(self, facts: dict) -> list:
        if not self.retriever:
            return []
        #a query that captures the incident: stage, next move, action
        query = " ".join(str(x) for x in [
            facts.get("current_stage"), facts.get("predicted_next"),
            facts.get("recommended_action"), "brute force compromise response",
        ] if x)
        try:
            return self.retriever.retrieve_texts(query, k=4)
        except Exception:                                   # noqa: BLE001
            return []

    def _prompt(self, facts: dict, context: list) -> str:
        parts = []
        if context:
            parts.append("Reference knowledge:\n" + "\n".join(f"- {c}" for c in context))
        parts.append("Incident facts:\n" + json.dumps(facts, indent=2))
        return "\n\n".join(parts)

    # ------------------------------------------------------------ explain #

    def explain(self, prediction, decision, allow_model: bool = True) -> str:

        facts = self.facts(prediction, decision)

        #caller asked for the cheap path (used for every attacker except the
        #worst): a deterministic template, no model call, no retrieval
        if not allow_model:
            return self._template(facts, None)

        if not self.available:
            return self._template(facts, self._retrieve(facts))

        key = hashlib.md5(json.dumps(facts, sort_keys=True).encode()).hexdigest()
        if key in self._cache:
            return self._cache[key]

        context = self._retrieve(facts)
        prompt = self._prompt(facts, context)

        try:
            if self.provider == "ollama":
                text = self._call_ollama(prompt)
            elif self.provider == "gemini":
                text = self._call_gemini(prompt)
            else:
                text = self._call_anthropic(prompt)
        except Exception:                                   # noqa: BLE001
            text = self._template(facts, context)

        self._cache[key] = text
        return text

    # ------------------------------------------------------------ providers #

    def _call_ollama(
        self,
        prompt: str,
        system: str = SYSTEM_PROMPT,
        timeout: Optional[int] = None,
        num_predict: int = 320,
    ) -> str:

        payload = json.dumps({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {"temperature": 0.3, "num_predict": num_predict},
        }).encode("utf-8")

        request = urllib.request.Request(
            f"{OLLAMA_HOST.rstrip('/')}/api/chat",
            data=payload,
            headers={"content-type": "application/json"},
        )

        with urllib.request.urlopen(request, timeout=timeout or self.timeout) as response:
            body = json.loads(response.read().decode("utf-8"))

        return (body.get("message", {}).get("content", "") or "").strip()

    def _call_gemini(self, prompt: str, system: str = SYSTEM_PROMPT) -> str:

        payload = json.dumps({
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": 400, "temperature": 0.3},
        }).encode("utf-8")

        request = urllib.request.Request(
            GEMINI_URL.format(model=self.model),
            data=payload,
            headers={"content-type": "application/json", "x-goog-api-key": self.api_key},
        )

        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            body = json.loads(response.read().decode("utf-8"))

        candidates = body.get("candidates", [])
        if not candidates:
            return ""
        parts = candidates[0].get("content", {}).get("parts", [])
        return "".join(p.get("text", "") for p in parts).strip()

    def _call_anthropic(self, prompt: str, system: str = SYSTEM_PROMPT) -> str:

        payload = json.dumps({
            "model": self.model,
            "max_tokens": 400,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }).encode("utf-8")

        request = urllib.request.Request(
            ANTHROPIC_URL,
            data=payload,
            headers={
                "content-type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
        )

        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            body = json.loads(response.read().decode("utf-8"))

        parts = body.get("content", [])
        return "".join(p.get("text", "") for p in parts if p.get("type") == "text").strip()

    # ------------------------------------------------------------ fallback #

    def _template(self, facts: dict, context: Optional[list] = None) -> str:

        attacker = facts["attacker"] or "An unknown source"
        stage = facts["current_stage"] or "an early stage"
        nxt = facts["predicted_next"]
        action = facts["recommended_action"]
        target = facts["action_target"]

        lines = [
            f"{attacker} has been detected reaching {stage}, with a risk score "
            f"of {facts['risk_score']} out of 100 and an anomaly level of "
            f"{facts['anomaly_score']:.0%}."
        ]

        if nxt:
            lines.append(
                f"Based on the attack pattern, the most likely next move is "
                f"{nxt}: {facts['predicted_next_reason']}."
            )

        if action == "monitor":
            lines.append("The activity is low risk, so ACT recommends continued monitoring.")
        elif action == "alert":
            lines.append(f"ACT recommends alerting a human analyst about {target}.")
        else:
            lines.append(
                f"ACT recommends action '{action}' on {target}. {facts['rationale']}"
            )

        extra = facts.get("also_consider") or []
        if extra:
            lines.append("A responder should also consider: " + "; ".join(extra) + ".")

        return " ".join(lines)
