#All correlation rules in one place. Adding a detection means adding one line here.
#Same registry pattern as the parsing rules in app/ingestion/parsers/rules.

from app.analyzer.correlation.base_correlation_rule import BaseCorrelationRule
from app.analyzer.correlation.brute_force_rule import BruteForceRule
from app.analyzer.correlation.distributed_brute_force_rule import (
    DistributedBruteForceRule,
)
from app.analyzer.correlation.persistence_rule import PersistenceRule
from app.analyzer.correlation.privilege_escalation_rule import (
    PrivilegeEscalationRule,
)
from app.analyzer.correlation.sensitive_file_access_rule import (
    SensitiveFileAccessRule,
)
from app.analyzer.correlation.successful_brute_force_rule import (
    SuccessfulBruteForceRule,
)
from app.analyzer.correlation.user_enumeration_rule import UserEnumerationRule


def default_correlation_rules() -> list[BaseCorrelationRule]:

    return [
        BruteForceRule(),
        UserEnumerationRule(),
        DistributedBruteForceRule(),
        SuccessfulBruteForceRule(),
        PrivilegeEscalationRule(),
        SensitiveFileAccessRule(),
        PersistenceRule(),
    ]


__all__ = [
    "BaseCorrelationRule",
    "BruteForceRule",
    "DistributedBruteForceRule",
    "PersistenceRule",
    "PrivilegeEscalationRule",
    "SensitiveFileAccessRule",
    "SuccessfulBruteForceRule",
    "UserEnumerationRule",
    "default_correlation_rules",
]
