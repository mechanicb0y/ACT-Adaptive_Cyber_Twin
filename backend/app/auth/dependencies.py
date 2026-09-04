"""FastAPI dependencies for reading the caller and enforcing a role.

The heavy lifting (token parsing) happens once in :class:`AuthMiddleware`, which
stashes a :class:`CurrentUser` on ``request.state.act_user``. These dependencies
just read it, so they are cheap and never hit the database.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, HTTPException, Request, status

ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}


@dataclass(frozen=True, slots=True)
class CurrentUser:
    id: int
    username: str
    role: str
    auth_disabled: bool = False

    def can_act_as(self, minimum: str) -> bool:
        return ROLE_RANK.get(self.role, -1) >= ROLE_RANK[minimum]


#: Used when ``settings.auth_enabled`` is false - every request is this user.
PROTOTYPE_ADMIN = CurrentUser(id=0, username="prototype", role="admin",
                              auth_disabled=True)


def get_current_user(request: Request) -> CurrentUser:
    user = getattr(request.state, "act_user", None)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_role(minimum: str) -> Callable[..., CurrentUser]:
    """Dependency factory: 403 unless the caller's role is >= ``minimum``."""
    if minimum not in ROLE_RANK:
        raise ValueError(f"unknown role {minimum!r}")

    def _dep(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not user.can_act_as(minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"requires {minimum} role or higher",
            )
        return user

    return _dep


require_viewer = require_role("viewer")
require_analyst = require_role("analyst")
require_admin = require_role("admin")
