"""Errors raised by the native authentication client."""

from __future__ import annotations

from typing import Any


class NativeAuthError(Exception):
    """Raised when the native authentication API returns an error response."""

    def __init__(
        self,
        error: str,
        description: str = "",
        status_code: int | None = None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        self.error = error
        self.description = description
        self.status_code = status_code
        self.payload = payload or {}
        super().__init__(f"{error}: {description}" if description else error)

    @property
    def suberrors(self) -> list[str]:
        suberror = self.payload.get("suberror")
        return [suberror] if suberror else []

    @property
    def is_invalid_credentials(self) -> bool:
        return self.payload.get("suberror") in {
            "invalid_oob_value",
            "password_too_weak",
            "password_too_short",
            "password_too_long",
            "password_recently_used",
            "password_banned",
        } or self.error in {"invalid_grant", "unauthorized_client"}

    @property
    def user_message(self) -> str:
        for code, hint in _REMEDIATION.items():
            if code in self.description or code == self.error:
                return f"{hint}\n\nAzure said: {self.description or self.error}"
        return self.description or self.error


_PUBLIC_CLIENT_HINT = (
    "This app registration is treated as a confidential client, which the native "
    "authentication API does not support. In Entra, on the app registration:\n"
    "  1. Authentication > Advanced settings > Allow public client flows = Yes.\n"
    "  2. Remove every entry under Certificates & secrets.\n"
    "  3. Remove the 'Web' platform; native auth apps use no platform or "
    "'Mobile and desktop applications'.\n"
    "  4. Authentication > Native authentication = Enabled, and the app is "
    "linked to your sign-up/sign-in user flow."
)

_REMEDIATION = {
    "AADSTS550022": _PUBLIC_CLIENT_HINT,
    "unauthorized_client": _PUBLIC_CLIENT_HINT,
}
