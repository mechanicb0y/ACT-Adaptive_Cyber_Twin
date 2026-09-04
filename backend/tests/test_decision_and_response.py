from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from app.intelligence.decision_engine import DecisionEngine, DecisionPolicy
from app.intelligence.response.commands import build_command, build_undo_command
from app.intelligence.response.dry_run_responder import DryRunResponder
from app.intelligence.response.ssh_responder import SSHResponder
from app.models.attack_graph import AttackNode, AttackPath
from app.models.behavior import Behavior
from app.models.decision import Action, Decision
from app.models.response import ResponseStatus
from app.models.severity import Severity

START = datetime(2026, 8, 6, 21, 0, 0)


def behavior(risk, attrs=None, stage=2, rule="brute-force"):
    return Behavior(
        id=str(uuid4()), name="x", description="x", severity=Severity.HIGH,
        confidence=0.8, rule=rule, risk_score=risk, stage=stage,
        stage_name="Credential Access",
        first_seen=START, last_seen=START + timedelta(seconds=5),
        attributes=attrs or {"ip_address": "192.168.1.50"},
    )


def path(behaviors):
    return AttackPath(nodes=[AttackNode(id=b.id, behavior=b) for b in behaviors], edges=[], total_stages=6)


# ------------------------------------------------------------ decisions #


def test_a_compromise_is_blocked():

    p = path([behavior(100, {"ip_address": "192.168.1.50", "compromised": True, "target_user": "kali"})])

    decision = DecisionEngine().decide(p)

    assert decision.action == Action.BLOCK_IP
    assert decision.target == "192.168.1.50"
    assert decision.urgency == Severity.CRITICAL
    assert "kali" in decision.rationale        # mentions locking the account
    assert decision.changes_the_machine
    assert decision.needs_arming


def test_high_risk_without_confidence_only_alerts():

    #risk is above the block threshold, but with no compromise and no
    #prediction the confidence (0.75) is below block_confidence, so a human
    #is asked to confirm instead of an automatic block
    decision = DecisionEngine().decide(path([behavior(75)]))

    assert decision.action == Action.ALERT


def test_high_risk_with_high_confidence_blocks():

    decision = DecisionEngine().decide(path([behavior(95)]))

    assert decision.action == Action.BLOCK_IP
    assert decision.urgency == Severity.CRITICAL


def test_block_needs_a_real_attack_pattern_not_just_a_score():

    #a high score on activity that did not match any correlation rule is only
    #ever an alert, never an automatic block
    quiet = behavior(95, rule="session-activity")

    assert DecisionEngine().decide(path([quiet])).action == Action.ALERT


def test_medium_risk_only_alerts():

    decision = DecisionEngine().decide(path([behavior(50)]))

    assert decision.action == Action.ALERT
    assert not decision.changes_the_machine


def test_low_risk_only_monitors():

    decision = DecisionEngine().decide(path([behavior(20)]))

    assert decision.action == Action.MONITOR


def test_a_persisted_compromise_advises_isolating_the_host():

    p = path([behavior(
        100,
        {"ip_address": "192.168.1.50", "compromised": True, "target_user": "kali"},
        stage=6, rule="persistence",
    )])

    decision = DecisionEngine().decide(p)

    assert decision.action == Action.BLOCK_IP        # still blocks the source
    assert any("isolate" in tip for tip in decision.also_consider)
    assert any("kali" in tip for tip in decision.also_consider)


def test_block_confidence_is_configurable():

    #the same high-risk-no-compromise path: an alert by default, a block once
    #the confidence bar is lowered
    p = path([behavior(75)])

    assert DecisionEngine().decide(p).action == Action.ALERT

    lenient = DecisionEngine(DecisionPolicy(block_confidence=0.5))
    assert lenient.decide(p).action == Action.BLOCK_IP


# ------------------------------------------------------------ commands #


def test_every_action_command_is_reversible():

    assert "DROP" in build_command(Action.BLOCK_IP, "1.2.3.4")
    assert "-D INPUT -s 1.2.3.4" in build_undo_command(Action.BLOCK_IP, "1.2.3.4")

    #the forward command uses non-interactive sudo so a missing NOPASSWD rule
    #fails fast instead of hanging on a password prompt
    assert build_command(Action.LOCK_ACCOUNT, "eve") == "sudo -n passwd -l eve"
    assert build_undo_command(Action.LOCK_ACCOUNT, "eve") == "sudo passwd -u eve"


# ------------------------------------------------------------ responders #


def block_decision(target="192.168.1.50"):
    return Decision(action=Action.BLOCK_IP, target=target, urgency="Critical", risk_score=100)


def test_dry_run_never_executes_even_when_armed():

    result = DryRunResponder().respond(block_decision(), armed=True)

    assert result.status == ResponseStatus.DRY_RUN
    assert result.armed is False
    assert "DROP" in result.command


def test_a_monitor_decision_touches_nothing():

    monitor = Decision(action=Action.MONITOR, target="1.2.3.4")

    result = DryRunResponder().respond(monitor, armed=True)

    assert result.status == ResponseStatus.SKIPPED


def test_ssh_responder_dry_run_when_not_armed():

    responder = SSHResponder(host="192.168.10.139", user="kali")

    result = responder.respond(block_decision(), armed=False)

    assert result.status == ResponseStatus.DRY_RUN
    assert result.armed is False


def test_ssh_responder_refuses_actions_not_on_its_allow_list():

    #by default only BLOCK_IP is allowed; locking an account is refused
    responder = SSHResponder(host="192.168.10.139", user="kali")

    lock = Decision(action=Action.LOCK_ACCOUNT, target="eve", urgency="High")

    result = responder.respond(lock, armed=True)

    assert result.status == ResponseStatus.BLOCKED
    assert "not permitted" in result.detail


def test_ssh_responder_builds_the_right_remote_command():

    responder = SSHResponder(host="192.168.10.139", user="kali", port=2222, key_file="/k/id")

    command = responder.ssh_command("sudo iptables -A INPUT -s 1.2.3.4 -j DROP")

    assert command[0] == "ssh"
    assert "kali@192.168.10.139" in command
    assert "-p" in command and "2222" in command
    assert "-i" in command and "/k/id" in command
    assert command[-1].startswith("sudo iptables")


def test_ssh_responder_reports_failure_cleanly_when_host_unreachable():

    #points at a host that does not exist, execution must fail, not crash
    responder = SSHResponder(host="203.0.113.199", user="kali", timeout=3, ssh_path="not-a-real-ssh")

    result = responder.respond(block_decision(), armed=True)

    assert result.status == ResponseStatus.FAILED
    assert result.armed is True
