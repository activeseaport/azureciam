"""Data structures returned by the native authentication client.

These are plain data objects so the UI layer never has to touch raw HTTP JSON.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ChallengeType(str, Enum):
    PASSWORD = "password"
    OOB = "oob"
    REDIRECT = "redirect"


@dataclass(frozen=True)
class ContinuationState:
    """Opaque handle to an in-progress flow, plus what the API asked for next."""

    continuation_token: str
    challenge_type: ChallengeType | None = None
    binding_method: str | None = None
    channel: str | None = None
    target: str | None = None
    code_length: int | None = None
    interval_seconds: int | None = None
    required_attributes: list[dict[str, Any]] = field(default_factory=list)

    @property
    def needs_redirect(self) -> bool:
        return self.challenge_type is ChallengeType.REDIRECT


@dataclass(frozen=True)
class AuthResult:
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str | None = None
    acquired_at: float = field(default_factory=time.time)

    @property
    def expires_at(self) -> float:
        return self.acquired_at + self.expires_in

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at - 60

    @property
    def claims(self) -> dict[str, Any]:
        """Decoded id_token claims. Not a signature validation."""
        if not self.id_token:
            return {}
        try:
            payload = self.id_token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            return json.loads(base64.urlsafe_b64decode(payload))
        except (IndexError, ValueError):
            return {}

    @property
    def display_name(self) -> str:
        claims = self.claims
        for key in ("name", "preferred_username", "email", "sub"):
            value = claims.get(key)
            if value:
                return str(value)
        return "(unknown user)"
