from app.ingestion.parsers.linux_parser import LinuxParser
from app.ingestion.parsers.rules.ssh_failed_login_rule import SSHFailedLoginRule
from app.models.event_types import EventType


def test_parses_the_original_kali_sample_log(logs_dir, parser):

    log = (logs_dir / "ssh_failed_login.log").read_text(encoding="utf-8")

    line = next(
        candidate
        for candidate in log.splitlines()
        if candidate.strip() and not candidate.strip().startswith("#")
    )

    result = parser.parse(line)

    assert result["event_type"] == EventType.FAILED_LOGIN
    assert result["user"] == "kali"
    assert result["ip_address"] == "::1"
    assert result["host"] == "kali"  # read from the log, no longer hard-coded
    assert result["process"] == "sshd-session"


def test_rules_are_injectable():

    parser = LinuxParser(rules=[SSHFailedLoginRule()])

    assert len(parser.rules) == 1

    # sudo lines are now unknown to this stripped-down parser
    assert (
        parser.parse(
            "Aug  6 21:12:31 kali sudo[7692]:     kali : TTY=pts/1 ; "
            "PWD=/home/kali ; USER=root ; COMMAND=/usr/bin/id"
        )
        is None
    )


def test_default_parser_registers_all_rules(parser):

    assert len(parser.rules) == 6

    names = {rule.name for rule in parser.rules}

    assert names == {
        "ssh-failed-login",
        "ssh-invalid-user",
        "ssh-accepted-login",
        "sudo-auth-failure",
        "sudo-command",
        "user-added",
    }


def test_matched_rule_is_reported(parser):

    result = parser.parse(
        "Aug  6 21:11:51 kali sshd-session[7631]: "
        "Accepted password for kali from 192.168.1.50 port 51432 ssh2"
    )

    assert result["matched_rule"] == "ssh-accepted-login"
