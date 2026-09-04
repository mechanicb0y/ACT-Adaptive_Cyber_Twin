#This module stores all Linux parsing rules in one place. To add a new rule, only update this list.
#The parser uses the first rule that matches, so more specific rules should come first.#

from app.ingestion.parsers.rules.base_rule import BaseRule
from app.ingestion.parsers.rules.ssh_accepted_login_rule import (
    SSHAcceptedLoginRule,
)
from app.ingestion.parsers.rules.ssh_auth_abort_rule import (
    SSHAuthAbortRule,
)
from app.ingestion.parsers.rules.ssh_failed_login_rule import (
    SSHFailedLoginRule,
)
from app.ingestion.parsers.rules.ssh_invalid_user_rule import (
    SSHInvalidUserRule,
)
from app.ingestion.parsers.rules.sudo_auth_failure_rule import (
    SudoAuthFailureRule,
)
from app.ingestion.parsers.rules.sudo_command_rule import SudoCommandRule
from app.ingestion.parsers.rules.user_added_rule import UserAddedRule


def default_linux_rules() -> list[BaseRule]:

    return [
        SSHFailedLoginRule(),
        SSHInvalidUserRule(),
        SSHAuthAbortRule(),
        SSHAcceptedLoginRule(),
        SudoAuthFailureRule(),
        SudoCommandRule(),
        UserAddedRule(),
    ]


__all__ = [
    "BaseRule",
    "SSHAcceptedLoginRule",
    "SSHAuthAbortRule",
    "SSHFailedLoginRule",
    "SSHInvalidUserRule",
    "SudoAuthFailureRule",
    "SudoCommandRule",
    "UserAddedRule",
    "default_linux_rules",
]
