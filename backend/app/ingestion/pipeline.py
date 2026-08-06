"""The ingestion pipeline.

The pipeline moves logs through these stages:

reader → parser → normalizer → event store → callback

It only controls the order of steps. Each part can be replaced without changing the pipeline, allowing support for 
new sources, systems, or storage. The callback allows real-time reactions without adding detection logic inside the pipeline.

"""

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from app.analyzer.normalizer import EventNormalizer
from app.ingestion.parsers.base_parser import BaseParser
from app.ingestion.readers.base_reader import BaseLogReader
from app.models.security_event import SecurityEvent
from app.storage.event_store import EventStore


@dataclass(slots=True)
class IngestionStats:
    """What happened during one ingestion run."""

    lines_read: int = 0
    events_created: int = 0
    lines_unmatched: int = 0
    parse_errors: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def coverage(self) -> float:
        """Share of lines ACT understood. A useful demo number."""

        if self.lines_read == 0:
            return 0.0

        return round(self.events_created / self.lines_read, 4)

    def summary(self) -> str:
        return (
            f"read={self.lines_read} "
            f"events={self.events_created} "
            f"unmatched={self.lines_unmatched} "
            f"errors={self.parse_errors} "
            f"coverage={self.coverage:.1%}"
        )


class IngestionPipeline:

    def __init__(
        self,
        reader: BaseLogReader,
        parser: BaseParser,
        event_store: EventStore,
        normalizer: Optional[EventNormalizer] = None,
        on_event: Optional[Callable[[SecurityEvent], None]] = None,
    ):
        self.reader = reader
        self.parser = parser
        self.event_store = event_store
        self.normalizer = normalizer or EventNormalizer()
        self.on_event = on_event

    def run(self) -> IngestionStats:
        """Consume the reader until it is exhausted (or forever, if following)."""

        stats = IngestionStats()

        for line in self.reader.read():

            stats.lines_read += 1

            try:
                raw_event = self.parser.parse(line)

            except Exception as error:
                # One bad line must never kill ingestion.
                stats.parse_errors += 1
                stats.errors.append(f"{type(error).__name__}: {error}")
                continue

            if raw_event is None:
                stats.lines_unmatched += 1
                continue

            event = self.normalizer.normalize(raw_event)

            self.event_store.add(event)
            stats.events_created += 1

            if self.on_event is not None:
                self.on_event(event)

        return stats
