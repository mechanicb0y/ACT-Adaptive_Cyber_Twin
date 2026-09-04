import threading
import time

import pytest

from app.ingestion.readers.file_log_reader import FileLogReader
from app.ingestion.readers.journald_reader import JournaldReader
from app.ingestion.readers.ssh_journald_reader import SSHJournalReader


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


# ----------------------------------------------------- reading the Kali VM #


def test_ssh_reader_wraps_the_journalctl_command_in_ssh():

    reader = SSHJournalReader(
        host="192.168.86.130",
        user="kali",
        identifiers=["sshd", "sudo"],
        since="-1h",
        follow=True,
    )

    command = reader.build_command()

    assert command[0] == "ssh"
    assert "kali@192.168.86.130" in command
    assert "BatchMode=yes" in command          # never hang on a password prompt

    #the journalctl part is one argument, run by the remote shell
    remote = command[-1]

    assert remote.startswith("journalctl")
    assert "-t sshd" in remote
    assert "-t sudo" in remote
    assert "--since -1h" in remote
    assert remote.endswith("-f")


def test_ssh_reader_target_with_and_without_a_user():

    assert SSHJournalReader(host="10.0.0.5", user="kali").target == "kali@10.0.0.5"
    assert SSHJournalReader(host="10.0.0.5").target == "10.0.0.5"


def test_ssh_reader_supports_a_port_a_key_and_sudo():

    command = SSHJournalReader(
        host="10.0.0.5", user="kali", port=2222,
        key_file="/home/me/.ssh/act", use_sudo=True,
    ).build_command()

    assert "-p" in command and "2222" in command
    assert "-i" in command and "/home/me/.ssh/act" in command
    assert command[-1].startswith("sudo -n journalctl")


def test_ssh_reader_needs_ssh_locally_not_journalctl():

    #this is the whole point: ACT can run on Windows, which has no journalctl
    reader = SSHJournalReader(host="10.0.0.5", ssh_path="not-a-real-ssh-binary")

    with pytest.raises(RuntimeError, match="ssh"):
        list(reader.read())


@pytest.mark.parametrize(
    "code,stderr,expected",
    [
        (255, "connect to host port 22: Connection refused", "virtual machine is running"),
        (1, "Permission denied (publickey,password).", "ssh-copy-id"),
        (1, "No journal files were opened due to insufficient permissions.", "systemd-journal"),
    ],
)
def test_ssh_failures_explain_what_to_do(code, stderr, expected):

    reader = SSHJournalReader(host="192.168.86.130", user="kali")

    assert expected in reader.explain_failure(code, stderr)


def test_readers_describe_themselves_for_the_dashboard():

    assert "this machine" in JournaldReader().describe()
    assert "kali@10.0.0.5" in SSHJournalReader(host="10.0.0.5", user="kali").describe()
