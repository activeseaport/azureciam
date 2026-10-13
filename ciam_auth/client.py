"""HTTP client for the Microsoft Entra External ID (CIAM) native authentication API.

This module is the *only* place that talks to Azure. It has no printing, no
input() and no knowledge of how the app is presented to the user.

Every request is sent as a **public client**: `client_id` only, never a client
secret or assertion. The app registration must have "Allow public client flows"
and native authentication enabled, otherwise Azure replies `unauthorized_client`.

Flows implemented:
  * sign-in with password
  * sign-in with email one-time passcode (OOB)
  * sign-up (email + optional password + optional attributes)
  * self-service password reset
  * refresh token redemption
"""

from __future__ import annotations

import json
import time
from typing import Any

import requests

from .config import CiamConfig
from .errors import NativeAuthError
from .models import AuthResult, ChallengeType, ContinuationState

_FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}
_DEFAULT_CHALLENGE_TYPES = "password oob redirect"


class NativeAuthClient:
    def __init__(self, config: CiamConfig, session: requests.Session | None = None):
        self._config = config
        self._session = session or requests.Session()

    # ------------------------------------------------------------------ #
    # Sign in
    # ------------------------------------------------------------------ #
    def signin_start(
        self, username: str, challenge_type: str = _DEFAULT_CHALLENGE_TYPES
    ) -> ContinuationState:
        """Step 1: tell Azure who is signing in and get a challenge."""
        initiated = self._post(
            "/oauth2/v2.0/initiate",
            {"username": username, "challenge_type": challenge_type},
        )
        state = self._state(initiated)
        if state.needs_redirect:
            return state
        if not state.continuation_token:
            raise NativeAuthError(
                "invalid_response",
                "Missing continuation token in sign-in start response.",
            )
        return self.signin_challenge(state, challenge_type)

    def signin_challenge(
        self,
        state: ContinuationState,
        challenge_type: str = _DEFAULT_CHALLENGE_TYPES,
    ) -> ContinuationState:
        """Step 2: ask Azure which credential it wants (password or OOB code)."""
        if state.needs_redirect:
            return state
        if not state.continuation_token:
            raise NativeAuthError(
                "invalid_state",
                "Sign-in state is missing a continuation token.",
            )
        data = self._post(
            "/oauth2/v2.0/challenge",
            {
                "continuation_token": state.continuation_token,
                "challenge_type": challenge_type,
            },
        )
        return self._state(data)

    def signin_with_password(
        self, state: ContinuationState, password: str
    ) -> AuthResult:
        return self._token(
            {
                "continuation_token": state.continuation_token,
                "grant_type": "password",
                "password": password,
            }
        )

    def signin_with_code(self, state: ContinuationState, code: str) -> AuthResult:
        return self._token(
            {
                "continuation_token": state.continuation_token,
                "grant_type": "oob",
                "oob": code,
            }
        )

    def resend_code(self, state: ContinuationState) -> ContinuationState:
        return self.signin_challenge(state)

    def refresh(self, refresh_token: str) -> AuthResult:
        return self._token(
            {"grant_type": "refresh_token", "refresh_token": refresh_token}
        )

    # ------------------------------------------------------------------ #
    # Sign up
    # ------------------------------------------------------------------ #
    def signup_start(
        self,
        username: str,
        password: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> ContinuationState:
        body: dict[str, Any] = {
            "username": username,
            "challenge_type": _DEFAULT_CHALLENGE_TYPES,
        }
        if password:
            body["password"] = password
        if attributes:
            body["attributes"] = _json(attributes)

        started = self._post("/signup/v1.0/start", body)
        return self.signup_challenge(self._state(started))

    def signup_challenge(self, state: ContinuationState) -> ContinuationState:
        data = self._post(
            "/signup/v1.0/challenge",
            {
                "continuation_token": state.continuation_token,
                "challenge_type": _DEFAULT_CHALLENGE_TYPES,
            },
        )
        return self._state(data)

    def signup_submit_code(self, state: ContinuationState, code: str) -> ContinuationState:
        return self._signup_continue(state, {"grant_type": "oob", "oob": code})

    def signup_submit_password(
        self, state: ContinuationState, password: str
    ) -> ContinuationState:
        return self._signup_continue(
            state, {"grant_type": "password", "password": password}
        )

    def signup_submit_attributes(
        self, state: ContinuationState, attributes: dict[str, Any]
    ) -> ContinuationState:
        return self._signup_continue(
            state, {"grant_type": "attributes", "attributes": _json(attributes)}
        )

    def signin_after_signup(self, state: ContinuationState) -> AuthResult:
        return self._token(
            {
                "continuation_token": state.continuation_token,
                "grant_type": "continuation_token",
            }
        )

    def _signup_continue(
        self, state: ContinuationState, body: dict[str, Any]
    ) -> ContinuationState:
        payload = {"continuation_token": state.continuation_token, **body}
        data = self._post("/signup/v1.0/continue", payload)
        return self._state(data)

    # ------------------------------------------------------------------ #
    # Password reset
    # ------------------------------------------------------------------ #
    def reset_start(self, username: str) -> ContinuationState:
        started = self._post(
            "/resetpassword/v1.0/start",
            {"username": username, "challenge_type": _DEFAULT_CHALLENGE_TYPES},
        )
        return self.reset_challenge(self._state(started))

    def reset_challenge(self, state: ContinuationState) -> ContinuationState:
        data = self._post(
            "/resetpassword/v1.0/challenge",
            {
                "continuation_token": state.continuation_token,
                "challenge_type": _DEFAULT_CHALLENGE_TYPES,
            },
        )
        return self._state(data)

    def reset_submit_code(self, state: ContinuationState, code: str) -> ContinuationState:
        data = self._post(
            "/resetpassword/v1.0/continue",
            {
                "continuation_token": state.continuation_token,
                "grant_type": "oob",
                "oob": code,
            },
        )
        return self._state(data)

    def reset_submit_password(
        self, state: ContinuationState, new_password: str, poll_timeout: float = 60.0
    ) -> ContinuationState:
        submitted = self._post(
            "/resetpassword/v1.0/submit",
            {
                "continuation_token": state.continuation_token,
                "new_password": new_password,
            },
        )
        return self._poll_reset(self._state(submitted), poll_timeout)

    def signin_after_reset(self, state: ContinuationState) -> AuthResult:
        return self._token(
            {
                "continuation_token": state.continuation_token,
                "grant_type": "continuation_token",
            }
        )

    def _poll_reset(
        self, state: ContinuationState, timeout_seconds: float
    ) -> ContinuationState:
        deadline = time.time() + timeout_seconds
        interval = state.interval_seconds or 2
        current = state
        while True:
            data = self._post(
                "/resetpassword/v1.0/poll_completion",
                {"continuation_token": current.continuation_token},
            )
            current = self._state(data)
            status = data.get("status")
            if status == "succeeded":
                return current
            if status in {"failed", "password_reset_failed"}:
                raise NativeAuthError("password_reset_failed", "Password reset failed.")
            if time.time() >= deadline:
                raise NativeAuthError(
                    "timeout", "Timed out waiting for the password reset to complete."
                )
            time.sleep(interval)

    # ------------------------------------------------------------------ #
    # Transport
    # ------------------------------------------------------------------ #
    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self._config.authority}{path}"
        # Public client: client_id identifies the app, no secret is ever sent.
        payload = {"client_id": self._config.client_id, **body}
        try:
            response = self._session.post(
                url,
                data=payload,
                headers=_FORM_HEADERS,
                timeout=self._config.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise NativeAuthError("network_error", str(exc)) from exc

        try:
            data = response.json()
        except ValueError:
            raise NativeAuthError(
                "invalid_response",
                "The authentication service returned a non-JSON response.",
                status_code=response.status_code,
            ) from None

        if response.status_code >= 400 or "error" in data:
            raise NativeAuthError(
                error=str(data.get("error", "unknown_error")),
                description=str(data.get("error_description", "")),
                status_code=response.status_code,
                payload=data,
            )
        return data

    def _token(self, body: dict[str, Any]) -> AuthResult:
        data = self._post(
            "/oauth2/v2.0/token", {"scope": self._config.scope_string, **body}
        )
        return AuthResult(
            access_token=data["access_token"],
            token_type=data.get("token_type", "Bearer"),
            expires_in=int(data.get("expires_in", 3600)),
            refresh_token=data.get("refresh_token"),
            id_token=data.get("id_token"),
            scope=data.get("scope"),
        )

    @staticmethod
    def _state(data: dict[str, Any]) -> ContinuationState:
        challenge_type = data.get("challenge_type")
        return ContinuationState(
            continuation_token=data.get("continuation_token", ""),
            challenge_type=ChallengeType(challenge_type) if challenge_type else None,
            binding_method=data.get("binding_method"),
            channel=data.get("challenge_channel"),
            target=data.get("challenge_target_label"),
            code_length=data.get("code_length"),
            interval_seconds=data.get("interval"),
            required_attributes=data.get("required_attributes", []),
        )


def _json(value: Any) -> str:
    return json.dumps(value)
