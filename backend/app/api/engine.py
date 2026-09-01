#The AnalysisEngine is everything the API does, with no web framework in it.
#
#It owns the event store, the ingestion pipeline, the correlator and the graph
#builder, and it caches results so a dashboard polling every second does not
#re-run detection on thousands of events each time.
#
#Keeping it framework independent means the whole API can be tested without
#starting a server, and swapping FastAPI for something else later would not
#touch a single line of logic.

import queue
import threading
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from app.analyzer.behavior_correlator import BehaviorCorrelator
from app.analyzer.normalizer import EventNormalizer
from app.config.detection_config import DetectionConfig
from app.ingestion.parsers.linux_parser import LinuxParser
from app.ingestion.pipeline import IngestionPipeline, IngestionStats
from app.ingestion.readers.base_reader import BaseLogReader
from app.ingestion.readers.file_log_reader import FileLogReader
from app.ingestion.readers.journald_reader import JournaldReader
from app.ingestion.readers.ssh_journald_reader import SSHJournalReader
from app.intelligence.cognitive_twin import CognitiveTwin
from app.intelligence.decision_engine import DecisionEngine, DecisionPolicy
from app.intelligence.llm_analyst import LlmAnalyst
from app.intelligence.rag.retriever import Retriever
from app.intelligence.response.commands import build_command
from app.intelligence.response.ssh_responder import SSHResponder
from app.models.attack_graph import AttackGraph
from app.models.decision import Action, Decision
from app.models.response import ResponseResult, ResponseStatus
from app.models.twin import TwinAssessment
from app.models.behavior import Behavior
from app.models.security_event import SecurityEvent
from app.storage.event_store import EventStore

BACKEND_DIR = Path(__file__).resolve().parents[2]
SAMPLE_LOGS_DIR = BACKEND_DIR / "tests" / "logs"

DEFAULT_JOURNAL_IDENTIFIERS = ["sshd", "sshd-session", "sudo", "useradd", "su"]


class AnalysisEngine:

    def __init__(self, config_path: Optional[str] = None):

        self.store = EventStore()
        self.parser = LinuxParser()
        self.normalizer = EventNormalizer()

        self.config = DetectionConfig.load(config_path)

        self.correlator = BehaviorCorrelator(self.store, config=self.config)

        #RAG: a local vector store of security knowledge, built/loaded once.
        #Failure here must not stop ACT, so it is guarded.
        try:
            self.retriever = Retriever.build()
        except Exception:                                   # noqa: BLE001
            self.retriever = None

        #the AI layer. Dry run by default: it never touches a machine until
        #the user arms it with a real SSH responder. Decision thresholds come
        #from the config file so the response aggressiveness is tunable. The
        #analyst prefers a local Ollama model and grounds itself in the RAG store.
        self.twin = CognitiveTwin(
            decision_engine=DecisionEngine(DecisionPolicy(
                block_threshold=int(self.config.option("response", "block_threshold", 70)),
                alert_threshold=int(self.config.option("response", "alert_threshold", 40)),
                block_confidence=float(self.config.option("response", "auto_execute_confidence", 0.9)),
            )),
            analyst=LlmAnalyst(retriever=self.retriever),
        )
        self._armed = False
        self._ssh_identity: Dict[str, Any] = {}   #host/user/etc of the last SSH source
        self._allow_account_lock = False

        #ACT is always autonomous: the moment a VM is connected over SSH it
        #carries out any blocking decision itself, with no prompt and no preview.
        #The only bar is the decision engine's own confidence gate.
        self._auto_threshold = float(
            self.config.option("response", "auto_execute_confidence", 0.9)
        )

        #the most recent response per attacker (for the dashboard to display)
        #and the set of attackers a real block has already been executed for
        #(so it is not re-run on every poll)
        self._last_responses: Dict[str, ResponseResult] = {}
        self._executed: set = set()

        #Blocks run on a background worker, never on the request thread. A slow
        #or hanging SSH call must not freeze the dashboard (that was the cause of
        #"everything takes minutes" and "the buttons do nothing").
        self._block_jobs: "queue.Queue" = queue.Queue()
        self._block_inflight: set = set()
        self._block_last_try: Dict[str, float] = {}
        self._block_attempts: Dict[str, int] = {}
        self._block_backoff = 15.0      #seconds between retries
        self._block_max_attempts = 6    #give up (show FAILED) only after this many
        self._block_worker = threading.Thread(
            target=self._block_loop, name="act-block-worker", daemon=True
        )
        self._block_worker.start()

        self.last_stats = IngestionStats()
        self.sources: List[str] = []

        #cache, rebuilt only when the number of stored events changes
        self._cached_at = -1
        self._behaviors: List[Behavior] = []
        self._graph: Optional[AttackGraph] = None
        self._assessments: List[TwinAssessment] = []
        self._lock = threading.Lock()

        #behaviors/graph are cheap and rebuild on every change; the AI layer
        #(prediction + local model + narrative) is throttled so a fast burst of
        #events cannot pin the model and stall every request behind it
        self._assessed_at = 0.0
        self._assessed_count = -1
        self._assess_interval = 5.0

        #live monitoring
        self._live_thread: Optional[threading.Thread] = None
        self._live_reader: Optional[BaseLogReader] = None
        self._live_source: Optional[str] = None
        self._live_error: Optional[str] = None

    # ------------------------------------------------------------------ #
    # ingestion
    # ------------------------------------------------------------------ #

    def _run(self, reader: BaseLogReader, label: str) -> IngestionStats:

        pipeline = IngestionPipeline(
            reader=reader,
            parser=self.parser,
            event_store=self.store,
            normalizer=self.normalizer,
        )

        stats = pipeline.run()

        self._merge_stats(stats, label)

        return stats

    def _merge_stats(self, stats: IngestionStats, label: str) -> None:

        self.last_stats.lines_read += stats.lines_read
        self.last_stats.events_created += stats.events_created
        self.last_stats.lines_unmatched += stats.lines_unmatched
        self.last_stats.parse_errors += stats.parse_errors
        self.last_stats.errors.extend(stats.errors[:20])

        if label not in self.sources:
            self.sources.append(label)

    def ingest_file(self, path: str) -> IngestionStats:
        """Replay a saved log.

        This is reachable over HTTP, so it is confined to the bundled sample
        log directory: the caller may pass a bare name or an absolute path, but
        the resolved file must sit inside ``SAMPLE_LOGS_DIR``. Arbitrary paths
        and ``..`` traversal are refused. (The CLI reads other files by building
        its own FileLogReader; it does not come through here.)
        """

        safe_dir = SAMPLE_LOGS_DIR.resolve()
        target = (safe_dir / Path(path).name).resolve()

        try:
            inside = target.is_relative_to(safe_dir)
        except AttributeError:                               # Python < 3.9
            inside = str(target).startswith(str(safe_dir))

        if not inside or not target.is_file():
            raise FileNotFoundError(
                f"Unknown sample log '{Path(path).name}'. "
                f"Choose one of: {', '.join(p.name for p in sorted(safe_dir.glob('*.log')))}"
            )

        return self._run(FileLogReader(target), f"file {target.name}")

    def ingest_journal(
        self,
        since: str = "-24h",
        units: Optional[Sequence[str]] = None,
    ) -> IngestionStats:

        reader = JournaldReader(
            units=list(units) if units else None,
            identifiers=None if units else DEFAULT_JOURNAL_IDENTIFIERS,
            since=since,
        )

        return self._run(reader, "systemd journal")

    def build_ssh_reader(
        self,
        host: str,
        user: Optional[str] = None,
        port: int = 22,
        key_file: Optional[str] = None,
        since: str = "-24h",
        units: Optional[Sequence[str]] = None,
        follow: bool = False,
        use_sudo: bool = False,
    ) -> SSHJournalReader:
        #one place that knows how to point ACT at a remote machine

        #remember how to reach this machine, so the response engine can act on
        #the same host ACT is watching
        self._ssh_identity = {
            "host": host, "user": user, "port": port, "key_file": key_file,
        }

        #in autonomous mode, knowing the machine is enough to go live: point the
        #responder at it now so the next analysis can act without a button press
        self._sync_responder()

        return SSHJournalReader(
            host=host,
            user=user,
            port=port,
            key_file=key_file,
            use_sudo=use_sudo,
            units=list(units) if units else None,
            identifiers=None if units else DEFAULT_JOURNAL_IDENTIFIERS,
            since=since,
            follow=follow,
        )

    def ingest_ssh(
        self,
        host: str,
        user: Optional[str] = None,
        port: int = 22,
        key_file: Optional[str] = None,
        since: str = "-24h",
        units: Optional[Sequence[str]] = None,
        use_sudo: bool = False,
    ) -> IngestionStats:
        """Read the journal of another machine, for example the Kali VM."""

        reader = self.build_ssh_reader(
            host=host, user=user, port=port, key_file=key_file,
            since=since, units=units, use_sudo=use_sudo,
        )

        return self._run(reader, reader.describe())

    # ------------------------------------------------------------------ #
    # live monitoring
    # ------------------------------------------------------------------ #

    @property
    def live_running(self) -> bool:
        return self._live_thread is not None and self._live_thread.is_alive()

    @property
    def live_source(self) -> Optional[str]:
        return self._live_source if self.live_running else None

    @property
    def live_error(self) -> Optional[str]:
        return self._live_error

    def start_live(
        self,
        file: Optional[str] = None,
        since: str = "-5m",
        units: Optional[Sequence[str]] = None,
        host: Optional[str] = None,
        user: Optional[str] = None,
        port: int = 22,
        key_file: Optional[str] = None,
        use_sudo: bool = False,
    ) -> bool:
        """Follow a file, this machine, or a remote machine over SSH.

        Returns False if a live monitor is already running.
        """

        if self.live_running:
            return False

        if host:
            #watching the Kali virtual machine
            reader = self.build_ssh_reader(
                host=host, user=user, port=port, key_file=key_file,
                since=since, units=units, follow=True, use_sudo=use_sudo,
            )
        elif file:
            target = Path(file)
            if not target.is_absolute():
                candidate = SAMPLE_LOGS_DIR / target.name
                target = candidate if candidate.exists() else BACKEND_DIR / target

            reader = FileLogReader(target, follow=True, from_start=False)
        else:
            reader = JournaldReader(
                units=list(units) if units else None,
                identifiers=None if units else DEFAULT_JOURNAL_IDENTIFIERS,
                since=since,
                follow=True,
            )

        label = f"live {reader.describe()}" if hasattr(reader, "describe") else "live"

        if file and not host:
            label = f"live file {Path(file).name}"

        self._live_reader = reader
        self._live_source = label
        self._live_error = None

        def worker():
            try:
                self._run(reader, label)
            except Exception as error:                      # noqa: BLE001
                #the dashboard shows this, so a bad SSH setup is visible
                #instead of just producing a silent empty page
                self._live_error = str(error)
                self.last_stats.errors.append(f"live: {error}")

        self._live_thread = threading.Thread(target=worker, daemon=True)
        self._live_thread.start()

        return True

    def stop_live(self) -> bool:

        if not self.live_running:
            return False

        reader = self._live_reader

        #FileLogReader can be asked to finish, journalctl is terminated
        if hasattr(reader, "stop"):
            reader.stop()

        if hasattr(reader, "close"):
            reader.close()

        self._live_thread.join(timeout=5)
        self._live_thread = None
        self._live_reader = None

        return True

    def check_ssh(
        self,
        host: str,
        user: Optional[str] = None,
        port: int = 22,
        key_file: Optional[str] = None,
        use_sudo: bool = False,
    ) -> Dict[str, Any]:
        """Try to read one line from the remote journal, and report what happened.

        Used by the dashboard's Test connection button so a broken setup shows
        a real reason instead of an empty page.
        """

        reader = self.build_ssh_reader(
            host=host, user=user, port=port, key_file=key_file,
            since="-10m", use_sudo=use_sudo,
        )

        try:
            lines = list(reader.read())
        except RuntimeError as error:
            return {"ok": False, "target": reader.target, "error": str(error)}
        except Exception as error:                          # noqa: BLE001
            return {"ok": False, "target": reader.target, "error": str(error)}
        finally:
            reader.close()

        return {
            "ok": True,
            "target": reader.target,
            "lines_seen": len(lines),
            "sample": lines[-1] if lines else None,
            "command": " ".join(reader.build_command()),
        }

    # ------------------------------------------------------------------ #
    # analysis, cached
    # ------------------------------------------------------------------ #

    def _refresh(self) -> None:

        count = len(self.store.events)
        now = time.monotonic()

        if count != self._cached_at:
            with self._lock:
                self._behaviors = self.correlator.detect()
                self._graph = self.correlator.build_attack_graph(self._behaviors)
                self._cached_at = count

        graph = self._graph or AttackGraph()

        #rebuild the AI assessments on a change, but no more than once every few
        #seconds, and always if we have attack paths but no assessment yet
        due = (count != self._assessed_count) and (now - self._assessed_at) >= self._assess_interval
        missing = bool(graph.paths) and not self._assessments

        if due or missing:
            with self._lock:
                self._assessments = self.twin.assess(graph, self.store.all())
            self._assessed_at = now
            self._assessed_count = count
        elif not graph.paths:
            self._assessments = []

        #autonomous: queue a block for every attacker the engine decided on.
        #The actual SSH call happens on the background worker, so this returns
        #straight away and the request that triggered _refresh never blocks.
        self._auto_execute()

    def _pending_response(self, decision: Decision, detail: str) -> ResponseResult:
        return ResponseResult(
            action=decision.action,
            target=decision.target,
            status=ResponseStatus.PENDING,
            command=build_command(decision.action, decision.target),
            armed=self.twin.armed,
            detail=detail,
            at=datetime.now(),
        )

    def _auto_execute(self) -> None:
        """Queue the response for every attacker the engine decided to block.

        The decision engine has already applied the confidence gate, so any
        machine-changing decision here is one ACT means to run. Work is handed
        to the background worker; this method never makes a network call.
        """

        now = time.monotonic()

        for assessment in self._assessments:

            decision = assessment.decision
            actor = assessment.actor

            #only machine-changing actions (block_ip / lock_account / isolate)
            if not decision.needs_arming or not actor:
                continue

            prior = self._last_responses.get(actor)

            #no VM connected: a dry run is instant and needs no network, so do
            #it inline and show the exact command that would run
            if not self.twin.armed:
                result = self.twin.responder.respond(decision, armed=False)
                self._last_responses[actor] = result
                assessment.response = result
                continue

            #already blocked for real, or a block is running right now
            if actor in self._executed or actor in self._block_inflight:
                if prior is not None:
                    assessment.response = prior
                continue

            #a hard failure (bad sudo, refused, ...) stays failed - retrying
            #would not help
            if prior is not None and prior.status == ResponseStatus.FAILED:
                assessment.response = prior
                continue

            #a retry is still in flight conceptually: wait out the backoff, keep
            #showing "retrying…" rather than a scary failure
            if (prior is not None and prior.status == ResponseStatus.PENDING
                    and now - self._block_last_try.get(actor, 0.0) < self._block_backoff):
                assessment.response = prior
                continue

            attempt = self._block_attempts.get(actor, 0) + 1
            detail = ("carrying out the block on the VM…" if attempt == 1
                      else f"still working on the block — retry {attempt}/{self._block_max_attempts}…")
            pending = self._pending_response(decision, detail)
            self._last_responses[actor] = pending
            assessment.response = pending
            self._block_inflight.add(actor)
            self._block_jobs.put((actor, decision))

    def _block_loop(self) -> None:
        """Drains block jobs one at a time, off the request path."""

        while True:
            actor, decision = self._block_jobs.get()

            attempts = self._block_attempts.get(actor, 0) + 1
            self._block_attempts[actor] = attempts

            try:
                result = self.twin.responder.respond(decision, armed=self.twin.armed)
            except Exception as error:                       # noqa: BLE001
                result = ResponseResult(
                    action=decision.action,
                    target=decision.target,
                    status=ResponseStatus.FAILED,
                    command=build_command(decision.action, decision.target),
                    armed=self.twin.armed,
                    detail=f"responder error: {error}",
                    retryable=True,
                    at=datetime.now(),
                )

            self._block_last_try[actor] = time.monotonic()

            if result.status == ResponseStatus.EXECUTED:
                self._executed.add(actor)
                self._last_responses[actor] = result

            elif (result.status == ResponseStatus.FAILED
                  and getattr(result, "retryable", False)
                  and attempts < self._block_max_attempts):
                #transient: don't show a failure, keep it pending and let
                #_auto_execute re-queue after the backoff
                self._last_responses[actor] = self._pending_response(
                    decision,
                    f"VM slow to respond — retry {attempts + 1}/{self._block_max_attempts} "
                    f"({result.detail})",
                )

            else:
                #success elsewhere, a hard failure, or retries exhausted
                self._last_responses[actor] = result

            self._block_inflight.discard(actor)
            self._block_jobs.task_done()

    def _sync_responder(self) -> None:
        """Point the twin's responder at the connected VM (or a dry run if none).

        A known SSH machine -> a live SSHResponder, armed and ready to execute.
        No machine to act on -> a dry-run responder that only records commands.
        """

        from app.intelligence.response.dry_run_responder import DryRunResponder

        host = self._ssh_identity.get("host")

        if not host:
            if not isinstance(self.twin.responder, DryRunResponder):
                self.twin.responder = DryRunResponder()
            self.twin.armed = False
            self._armed = False
            return

        #a VM just became reachable: drop any stale dry-run results so the next
        #analysis actually executes the block instead of showing the old preview
        was_armed = self._armed
        if not was_armed:
            self._last_responses = {}
            self._executed = set()
            self._block_attempts = {}
            self._block_last_try = {}
            self._cached_at = -1

        config_allows_lock = bool(
            self.config.option("response", "allow_account_lock", False)
        )

        allowed = {Action.BLOCK_IP}
        if self._allow_account_lock and config_allows_lock:
            allowed.add(Action.LOCK_ACCOUNT)

        self.twin.responder = SSHResponder(
            host=host,
            user=self._ssh_identity.get("user"),
            port=self._ssh_identity.get("port", 22),
            key_file=self._ssh_identity.get("key_file"),
            allowed_actions=allowed,
        )
        self.twin.armed = True
        self._armed = True

    def behaviors(
        self,
        min_risk: int = 0,
        rule: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Behavior]:

        self._refresh()

        found = [b for b in self._behaviors if b.risk_score >= min_risk]

        if rule:
            found = [b for b in found if b.rule == rule]

        if severity:
            found = [b for b in found if b.severity.lower() == severity.lower()]

        return found

    def attack_graph(self) -> AttackGraph:
        self._refresh()
        return self._graph or AttackGraph()

    # ------------------------------------------------------------------ #
    # the AI layer: predict, decide, respond, explain
    # ------------------------------------------------------------------ #

    def assessments(self) -> List[TwinAssessment]:
        self._refresh()

        #if a response was actually carried out for an attacker, show that
        #instead of the re-planned dry run
        for assessment in self._assessments:
            carried_out = self._last_responses.get(assessment.actor)
            if carried_out is not None:
                assessment.response = carried_out

        return self._assessments

    @property
    def armed(self) -> bool:
        return self._armed

    @property
    def llm_available(self) -> bool:
        return self.twin.analyst.available

    def response_mode(self) -> Dict[str, Any]:
        """Response state for the dashboard: is a VM connected and armed."""

        target = self._ssh_identity.get("host")

        return {
            "armed": self._armed,
            "auto_execute_confidence": self._auto_threshold,
            "ssh_target": (self.twin.responder.target_host
                           if self._armed and target else target),
        }

    def arm(self, allow_account_lock: bool = False) -> Dict[str, Any]:
        """Point ACT's responder at the known SSH machine so blocks execute.

        Normally automatic: connecting a VM (SSH ingest / Go live) arms ACT on
        its own. This is the explicit entry point, mostly for tests and the API.
        """

        if not self._ssh_identity.get("host"):
            return {
                "armed": False,
                "error": "No SSH target known. Read the VM over SSH first, then arm.",
            }

        self._allow_account_lock = bool(allow_account_lock)
        self._cached_at = -1
        self._sync_responder()

        return {
            "armed": self._armed,
            "target_host": self.twin.responder.target_host,
            "allowed_actions": sorted(self.twin.responder.allowed_actions),
        }

    def disarm(self) -> Dict[str, Any]:
        """Emergency stand-down: forget the SSH target so nothing executes."""

        from app.intelligence.response.dry_run_responder import DryRunResponder

        self._allow_account_lock = False
        self._ssh_identity = {}
        self.twin.responder = DryRunResponder()
        self.twin.armed = False
        self._armed = False
        self._last_responses = {}
        self._executed = set()
        self._block_attempts = {}
        self._block_last_try = {}
        self._cached_at = -1

        return {"armed": self._armed}

    def respond(self, actor: str) -> Optional[ResponseResult]:
        """Carry out the decision for one attacker (executes only if armed)."""

        graph = self.attack_graph()

        path = next((p for p in graph.paths if p.actor == actor), None)
        if path is None:
            return None

        result = self.twin.respond_to(path, self.store.all())
        self._last_responses[actor] = result
        return result

    # ------------------------------------------------------------------ #
    # events
    # ------------------------------------------------------------------ #

    def events(
        self,
        user: Optional[str] = None,
        ip_address: Optional[str] = None,
        event_type: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        newest_first: bool = True,
    ) -> Tuple[List[SecurityEvent], int]:
        """Filtered events plus the total count before paging."""

        found = list(self.store.all())

        if user:
            found = [e for e in found if e.user == user]

        if ip_address:
            found = [e for e in found if e.ip_address == ip_address]

        if event_type:
            found = [e for e in found if e.event_type == event_type]

        if search:
            needle = search.lower()
            found = [
                e
                for e in found
                if needle in (e.description or "").lower()
                or needle in (e.raw_log or "").lower()
            ]

        total = len(found)

        found.sort(key=lambda event: event.timestamp, reverse=newest_first)

        if offset:
            found = found[offset:]

        if limit > 0:
            found = found[:limit]

        return found, total

    def events_since(self, index: int) -> Tuple[int, List[SecurityEvent]]:
        """Used by the live stream. Returns the new index and whatever is new."""

        events = self.store.events

        if index > len(events):
            index = 0       #the store was reset under us

        return len(events), list(events[index:])

    # ------------------------------------------------------------------ #
    # dashboard summary
    # ------------------------------------------------------------------ #

    def top_attackers(self, limit: int = 5) -> List[Dict[str, Any]]:

        counts = Counter(
            event.ip_address for event in self.store.all() if event.ip_address
        )

        risk_by_ip: Dict[str, int] = {}

        for behavior in self.behaviors():
            ip_address = behavior.attributes.get("ip_address")
            if ip_address:
                risk_by_ip[ip_address] = max(
                    risk_by_ip.get(ip_address, 0), behavior.risk_score
                )

        return [
            {
                "ip_address": ip_address,
                "events": total,
                "highest_risk": risk_by_ip.get(ip_address, 0),
            }
            for ip_address, total in counts.most_common(limit)
        ]

    def top_targets(self, limit: int = 5) -> List[Dict[str, Any]]:

        counts = Counter(event.user for event in self.store.all() if event.user)

        return [
            {"user": user, "events": total}
            for user, total in counts.most_common(limit)
        ]

    def technique_counts(self) -> List[Dict[str, Any]]:

        found: Dict[str, Dict[str, Any]] = {}

        for behavior in self.behaviors():
            for technique in behavior.techniques:
                entry = found.setdefault(
                    technique.id,
                    {
                        "id": technique.id,
                        "name": technique.name,
                        "tactic": technique.tactic,
                        "url": technique.url,
                        "count": 0,
                    },
                )
                entry["count"] += 1

        return sorted(found.values(), key=lambda item: item["count"], reverse=True)

    def stats(self) -> Dict[str, Any]:

        events = self.store.all()
        behaviors = self.behaviors()
        graph = self.attack_graph()

        worst = graph.worst_path

        timestamps = [event.timestamp for event in events]

        return {
            "events": {
                "total": len(events),
                "by_type": dict(Counter(e.event_type for e in events)),
                "first": timestamps and min(timestamps).isoformat(sep=" ", timespec="seconds") or None,
                "last": timestamps and max(timestamps).isoformat(sep=" ", timespec="seconds") or None,
            },
            "ingestion": {
                "lines_read": self.last_stats.lines_read,
                "events_created": self.last_stats.events_created,
                "lines_unmatched": self.last_stats.lines_unmatched,
                "parse_errors": self.last_stats.parse_errors,
                "coverage": self.last_stats.coverage,
                "sources": self.sources,
            },
            "behaviors": {
                "total": len(behaviors),
                "by_severity": dict(Counter(b.severity for b in behaviors)),
                "by_rule": dict(Counter(b.rule for b in behaviors)),
                "highest_risk": max((b.risk_score for b in behaviors), default=0),
            },
            "attack": {
                "paths": len(graph.paths),
                "worst_completeness": worst.completeness if worst else 0.0,
                "deepest_stage": worst.deepest_stage if worst else 0,
                "total_stages": worst.total_stages if worst else 6,
                "compromised": any(path.succeeded for path in graph.paths),
                "actor": worst.actor if worst else None,
            },
            "techniques": self.technique_counts(),
            "top_attackers": self.top_attackers(),
            "top_targets": self.top_targets(),
            "intelligence": self._intelligence_summary(),
            "live": {
                "running": self.live_running,
                "source": self.live_source,
                "error": self.live_error,
            },
        }

    def _intelligence_summary(self) -> Dict[str, Any]:
        #a compact view of the AI layer for the dashboard header

        assessments = self.assessments()
        top = assessments[0] if assessments else None

        summary = {
            "armed": self._armed,
            "auto_execute_confidence": self._auto_threshold,
            "ssh_target": self._ssh_identity.get("host"),
            "llm": self.llm_available,
            "provider": self.twin.analyst.provider or "none",
            "narrator": self.twin.analyst.narrator_name(),
            "anomaly_model": self.twin.prediction_engine.scorer.name,
            "rag_documents": self.retriever.size if self.retriever else 0,
            "rag_embedder": self.retriever.embedder.name if self.retriever else "none",
            "assessments": len(assessments),
            "top": None,
        }

        if top:
            nxt = top.prediction.most_likely
            summary["top"] = {
                "actor": top.actor,
                "predicted_next": nxt.stage_name if nxt else None,
                "predicted_probability": nxt.probability if nxt else 0.0,
                "action": top.decision.action,
                "target": top.decision.target,
                "urgency": top.decision.urgency,
                "response_status": top.response.status if top.response else None,
            }

        return summary

    # ------------------------------------------------------------------ #

    def available_logs(self) -> List[Dict[str, Any]]:
        #sample logs the dashboard can offer to replay

        if not SAMPLE_LOGS_DIR.exists():
            return []

        return [
            {"name": path.name, "size": path.stat().st_size}
            for path in sorted(SAMPLE_LOGS_DIR.glob("*.log"))
        ]

    def reset(self) -> None:

        self.stop_live()

        self.store.events.clear()
        self.last_stats = IngestionStats()
        self.sources = []
        self._cached_at = -1
        self._assessed_at = 0.0
        self._assessed_count = -1
        self._behaviors = []
        self._graph = None
        self._assessments = []
        self._last_responses = {}
        self._executed = set()
        self._block_inflight = set()
        self._block_last_try = {}
        self._block_attempts = {}
        try:
            while True:
                self._block_jobs.get_nowait()
                self._block_jobs.task_done()
        except queue.Empty:
            pass
