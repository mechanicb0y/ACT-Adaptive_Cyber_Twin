import threading
import time

import pytest

from app.ingestion.readers.file_log_reader import FileLogReader
from app.ingestion.readers.journald_reader import JournaldReader


def test_file_reader_reads_every_non_empty_line(tmp_path):

    log = tmp_path / "auth.log"
    log.write_text("line one\n\nline two\n   \nline three\n", encoding="utf-8")

    lines = list(FileLogReader(log).read())

    assert lines == ["line one", "line two", "line three"]


def test_file_reader_raises_for_missing_file(tmp_path):

    reader = FileLogReader(tmp_path / "does_not_exist.log")

    with pytest.raises(FileNotFoundError):
        list(reader.read())


def test_file_reader_follow_picks_up_appended_lines(tmp_path):

    log = tmp_path / "live.log"
    log.write_text("first\n", encoding="utf-8")

    reader = FileLogReader(log, follow=True, poll_interval=0.05)

    collected = []

    def consume():
        for line in reader.read():
            collected.append(line)
            if len(collected) == 2:
                reader.stop()

    worker = threading.Thread(target=consume, daemon=True)
    worker.start()

    time.sleep(0.2)

    with log.open("a", encoding="utf-8") as handle:
        handle.write("second\n")

    worker.join(timeout=5)

    assert collected == ["first", "second"]


def test_journald_command_is_built_correctly():

    reader = JournaldReader(
        units=["ssh"],
        since="-1h",
        follow=True,
    )

    command = reader.build_command()

    assert command[0] == "journalctl"
    assert "-o" in command and "short-iso" in command
    assert "-u" in command and "ssh" in command
    assert "--since" in command and "-1h" in command
    assert "-f" in command


def test_journald_uses_identifiers_when_given():

    reader = JournaldReader(identifiers=["sshd", "sudo"])

    command = reader.build_command()

    assert command.count("-t") == 2
    assert "sshd" in command
    assert "sudo" in command
    assert "-f" not in command


def test_journald_reports_a_clear_error_when_unavailable():

    reader = JournaldReader(journalctl_path="definitely-not-a-real-binary")

    with pytest.raises(RuntimeError, match="journalctl"):
        list(reader.read())
