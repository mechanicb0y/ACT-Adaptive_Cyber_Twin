
class EventType:

    FAILED_LOGIN = "FAILED_LOGIN"
    SUCCESSFUL_LOGIN = "SUCCESSFUL_LOGIN"
    SUDO_FAILURE = "SUDO_FAILURE"
    SUDO_COMMAND = "SUDO_COMMAND"
    ACCOUNT_CREATED = "ACCOUNT_CREATED"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def all(cls) -> list[str]:
        return [
            value
            for key, value in vars(cls).items()
            if not key.startswith("_") and isinstance(value, str)
        ]


class FailureReason:
    #Extra detail attached to FAILED_LOGIN events via ``metadata``.

    BAD_PASSWORD = "bad_password"
    INVALID_USER = "invalid_user"
