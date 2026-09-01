"""One test per parsing rule, plus the cases where rules must NOT fire."""

import pytest

from app.ingestion.parsers.linux_parser import LinuxParser
from app.models.event_types import EventType, FailureReason


@pytest.fixture
def parse():
    parser = LinuxParser()
    return parser.parse


def test_ssh_failed_password(parse):

    result = parse(
        "Aug  6 21:11:09 kali sshd-session[7611]: "
        "Failed password for root from 192.168.1.50 port 51412 ssh2"
    )

    assert result["event_type"] == EventType.FAILED_LOGIN
    assert result["user"] == "root"
    assert result["ip_address"] == "192.168.1.50"
    assert result["metadata"]["port"] == 51412
    assert result["metadata"]["failure_reason"] == FailureReason.BAD_PASSWORD


def test_ssh_failed_password_for_invalid_user(parse):

    result = parse(
        "Aug  6 21:10:58 kali sshd-session[7601]: "
        "Failed password for invalid user admin from 192.168.1.50 port 51402 ssh2"
    )

    assert result["event_type"] == EventType.FAILED_LOGIN
    assert result["user"] == "admin"
    assert result["metadata"]["failure_reason"] == FailureReason.INVALID_USER


def test_ssh_invalid_user_notice(parse):

    result = parse(
        "Aug  6 21:10:58 kali sshd-session[7601]: "
        "Invalid user admin from 192.168.1.50 port 51402"
    )

    assert result["matched_rule"] == "ssh-invalid-user"
    assert result["event_type"] == EventType.FAILED_LOGIN
    assert result["user"] == "admin"


def test_ssh_accepted_password(parse):

    result = parse(
        "Aug  6 21:11:51 kali sshd-session[7631]: "
        "Accepted password for kali from 192.168.1.50 port 51432 ssh2"
    )

    assert result["event_type"] == EventType.SUCCESSFUL_LOGIN
    assert result["user"] == "kali"
    assert result["metadata"]["auth_method"] == "password"


def test_sudo_auth_failure(parse):

    result = parse(
        "Aug  6 21:12:14 kali sudo[7688]: pam_unix(sudo:auth): "
        "authentication failure; logname=kali uid=1000 euid=0 "
        "tty=/dev/pts/1 ruser=kali rhost=  user=kali"
    )

    assert result["event_type"] == EventType.SUDO_FAILURE
    assert result["user"] == "kali"


def test_sudo_command(parse):

    result = parse(
        "Aug  6 21:12:31 kali sudo[7692]:     kali : TTY=pts/1 ; "
        "PWD=/home/kali ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    )

    assert result["event_type"] == EventType.SUDO_COMMAND
    assert result["user"] == "kali"
    assert result["metadata"]["target_user"] == "root"
    assert result["metadata"]["command"] == "/usr/bin/cat /etc/shadow"


def test_user_added(parse):

    result = parse(
        "Aug  6 21:12:58 kali useradd[7703]: new user: name=backdoor, "
        "UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash, from=/dev/pts/1"
    )

    assert result["event_type"] == EventType.ACCOUNT_CREATED
    assert result["user"] == "backdoor"
    assert result["metadata"]["uid"] == 1001
    assert result["metadata"]["shell"] == "/bin/bash"


@pytest.mark.parametrize(
    "line",
    [
        "Aug  6 21:11:24 kali sshd-session[7614]: error: maximum authentication "
        "attempts exceeded for root from 192.168.1.50 port 51416 ssh2 [preauth]",
        "Aug  6 21:11:24 kali sshd-session[7614]: error: maximum authentication "
        "attempts exceeded for invalid user oracle from 10.0.0.9 port 4444 ssh2 [preauth]",
        "Aug  6 21:11:25 kali sshd-session[7615]: Connection closed by "
        "authenticating user root 192.168.1.50 port 51420 [preauth]",
        "Aug  6 21:11:26 kali sshd-session[7616]: Disconnected from "
        "authenticating user admin 192.168.1.50 port 51421 [preauth]",
        "Aug  6 21:11:27 kali sshd[7617]: Connection reset by "
        "authenticating user kali 192.168.1.50 port 51422 [preauth]",
    ],
)
def test_ssh_auth_abort_lines_count_as_failed_logins(parse, line):

    result = parse(line)

    assert result is not None
    assert result["matched_rule"] == "ssh-auth-abort"
    assert result["event_type"] == EventType.FAILED_LOGIN
    assert result["ip_address"] in ("192.168.1.50", "10.0.0.9")
    assert result["user"] in ("root", "oracle", "admin", "kali")


@pytest.mark.parametrize(
    "line",
    [
        "Aug  6 09:02:11 kali systemd[1]: Started ssh.service - OpenBSD Secure Shell server.",
        "Aug  6 09:14:03 kali CRON[1180]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)",
        "Aug  6 21:13:40 kali sshd-session[7631]: pam_unix(sshd:session): session closed for user kali",
        # a plain probe with no credentials tried must NOT look like a brute force
        "Aug  6 21:11:24 kali sshd-session[7000]: Connection closed by 192.168.1.50 port 51000 [preauth]",
        "",
        "   ",
    ],
)
def test_irrelevant_lines_return_none_instead_of_raising(parse, line):

    assert parse(line) is None


def test_parser_keeps_the_original_line_as_evidence(parse):

    line = (
        "Aug  6 21:11:09 kali sshd-session[7611]: "
        "Failed password for root from 192.168.1.50 port 51412 ssh2"
    )

    assert parse(line)["raw_log"] == line
