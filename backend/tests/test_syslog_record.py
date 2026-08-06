from app.ingestion.parsers.syslog_record import SyslogRecord

TRADITIONAL = (
    "Aug  6 21:11:09 kali sshd-session[7611]: "
    "Failed password for root from 192.168.1.50 port 51412 ssh2"
)

ISO = (
    "2026-08-06T21:11:09+0300 kali sudo[7692]: "
    "    kali : TTY=pts/1 ; PWD=/home/kali ; USER=root ; COMMAND=/usr/bin/id"
)


def test_splits_traditional_syslog_envelope():

    record = SyslogRecord.from_line(TRADITIONAL)

    assert record.envelope_parsed is True
    assert record.host == "kali"
    assert record.process == "sshd-session"
    assert record.pid == 7611
    assert record.timestamp.month == 8
    assert record.timestamp.day == 6
    assert record.timestamp.hour == 21
    assert record.message.startswith("Failed password for root")


def test_splits_iso_envelope():

    record = SyslogRecord.from_line(ISO)

    assert record.envelope_parsed is True
    assert record.process == "sudo"
    assert record.pid == 7692
    assert record.timestamp.year == 2026
    assert "COMMAND=/usr/bin/id" in record.message


def test_unframed_line_becomes_message_only():

    record = SyslogRecord.from_line("Failed password for root from 10.0.0.1 port 22 ssh2")

    assert record.envelope_parsed is False
    assert record.process == "unknown"
    assert record.message.startswith("Failed password")


def test_base_fields_carry_the_envelope_forward():

    record = SyslogRecord.from_line(TRADITIONAL)

    fields = record.base_fields()

    assert fields["source"] == "Linux"
    assert fields["host"] == "kali"
    assert fields["process"] == "sshd-session"
    assert fields["raw_log"] == TRADITIONAL
