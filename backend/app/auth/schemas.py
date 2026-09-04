"""Request / response models for the auth endpoints."""

from __future__ import annotations

import datetime as _dt
from typing import Literal, Optional

from pydantic import BaseModel, Field

Role = Literal["admin", "analyst", "viewer"]


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)
    remember_me: bool = False


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # access-token lifetime, seconds
    role: Role
    username: str


class UserOut(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    role: Role
    is_active: bool
    oauth_provider: Optional[str] = None
    created_at: _dt.datetime
    last_login: Optional[_dt.datetime] = None

    model_config = {"from_attributes": True}


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=72)
    email: Optional[str] = Field(default=None, max_length=255)
    role: Role = "viewer"


class UserUpdate(BaseModel):
    password: Optional[str] = Field(default=None, min_length=8, max_length=72)
    email: Optional[str] = Field(default=None, max_length=255)
    role: Optional[Role] = None
    is_active: Optional[bool] = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=72)


class PasswordResetRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)


class PasswordResetConfirm(BaseModel):
    token: str = Field(min_length=8)
    new_password: str = Field(min_length=8, max_length=72)


class MessageResponse(BaseModel):
    detail: str
