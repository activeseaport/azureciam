"""Interactive console UI for the CIAM native authentication sample.

All Azure communication is delegated to ciam_auth.NativeAuthClient; this module
only prompts, prints and routes between flows.
"""

from __future__ import annotations

import getpass

from ciam_auth import AuthResult, ChallengeType, ContinuationState, NativeAuthClient
from ciam_auth.errors import NativeAuthError


class ConsoleApp:
    def __init__(self, client: NativeAuthClient) -> None:
        self._client = client
        self._session: AuthResult | None = None

    def run(self) -> None:
        print("Entra External ID (CIAM) — native authentication demo")
        while True:
            choice = self._menu()
            try:
                if choice == "1":
                    self._sign_in()
                elif choice == "2":
                    self._sign_up()
                elif choice == "3":
                    self._reset_password()
                elif choice == "4":
                    self._show_session()
                elif choice == "5":
                    self._refresh()
                elif choice == "6":
                    self._session = None
                    print("Signed out.")
                elif choice in {"q", "Q"}:
                    return
                else:
                    print("Unknown option.")
            except NativeAuthError as exc:
                print(f"\n  Error: {exc.user_message}")
                if exc.suberrors:
                    print(f"  Detail: {', '.join(exc.suberrors)}")
            except KeyboardInterrupt:
                print("\nCancelled.")

    # ------------------------------------------------------------------ #
    # Menu
    # ------------------------------------------------------------------ #
    def _menu(self) -> str:
        who = self._session.display_name if self._session else "not signed in"
        print(f"\n--- {who} ---")
        print(" 1. Sign in")
        print(" 2. Sign up")
        print(" 3. Reset password")
        print(" 4. Show tokens / claims")
        print(" 5. Refresh access token")
        print(" 6. Sign out")
        print(" q. Quit")
        return input("Choose: ").strip()

    # ------------------------------------------------------------------ #
    # Flows
    # ------------------------------------------------------------------ #
    def _sign_in(self) -> None:
        username = _ask("Email")
        state = self._client.signin_start(username)
        state = self._require_supported(state)

        if state.challenge_type is ChallengeType.PASSWORD:
            password = _ask_secret("Password")
            result = self._client.signin_with_password(state, password)
        else:
            code = self._ask_code(state)
            result = self._client.signin_with_code(state, code)

        self._store(result)

    def _sign_up(self) -> None:
        username = _ask("Email")
        password = _ask_secret("Choose a password (blank for email-code only)", allow_empty=True)

        state = self._client.signup_start(username, password or None)
        state = self._require_supported(state)

        code = self._ask_code(state)
        state = self._client.signup_submit_code(state, code)

        while state.challenge_type is not None or state.required_attributes:
            if state.challenge_type is ChallengeType.PASSWORD:
                new_password = _ask_secret("Set a password")
                state = self._client.signup_submit_password(state, new_password)
            elif state.required_attributes:
                state = self._client.signup_submit_attributes(
                    state, self._ask_attributes(state)
                )
            else:
                break

        self._store(self._client.signin_after_signup(state))

    def _reset_password(self) -> None:
        username = _ask("Email")
        state = self._require_supported(self._client.reset_start(username))

        code = self._ask_code(state)
        state = self._client.reset_submit_code(state, code)

        new_password = _ask_secret("New password")
        print("Applying the new password...")
        state = self._client.reset_submit_password(state, new_password)

        self._store(self._client.signin_after_reset(state))

    def _refresh(self) -> None:
        if not self._session or not self._session.refresh_token:
            print("No refresh token available. Sign in with the offline_access scope.")
            return
        self._store(self._client.refresh(self._session.refresh_token))

    # ------------------------------------------------------------------ #
    # Prompt helpers
    # ------------------------------------------------------------------ #
    def _ask_code(self, state: ContinuationState) -> str:
        target = state.target or "your email"
        length = state.code_length or 8
        print(f"A {length}-digit code was sent to {target}.")
        return _ask("Code")

    def _ask_attributes(self, state: ContinuationState) -> dict[str, str]:
        values: dict[str, str] = {}
        print("Additional information is required:")
        for attribute in state.required_attributes:
            name = attribute.get("name", "")
            if not name:
                continue
            values[name] = _ask(f"  {name}")
        return values

    def _require_supported(self, state: ContinuationState) -> ContinuationState:
        if state.needs_redirect:
            raise NativeAuthError(
                "redirect_required",
                "This account or tenant requires the browser-based flow; "
                "native authentication cannot complete it.",
            )
        return state

    # ------------------------------------------------------------------ #
    # Output
    # ------------------------------------------------------------------ #
    def _store(self, result: AuthResult) -> None:
        self._session = result
        print(f"\nSigned in as {result.display_name}.")

    def _show_session(self) -> None:
        if not self._session:
            print("Not signed in.")
            return
        result = self._session
        print(f"  access_token : {_mask(result.access_token)}")
        print(f"  refresh_token: {_mask(result.refresh_token)}")
        print(f"  expires_in   : {result.expires_in}s (expired: {result.is_expired})")
        print(f"  scope        : {result.scope or '-'}")
        claims = result.claims
        if claims:
            print("  id_token claims:")
            for key in sorted(claims):
                print(f"    {key}: {claims[key]}")


def _ask(label: str) -> str:
    while True:
        value = input(f"{label}: ").strip()
        if value:
            return value
        print("A value is required.")


def _ask_secret(label: str, allow_empty: bool = False) -> str:
    while True:
        value = getpass.getpass(f"{label}: ")
        if value or allow_empty:
            return value
        print("A value is required.")


def _mask(token: str | None) -> str:
    if not token:
        return "-"
    return f"{token[:8]}...{token[-6:]} ({len(token)} chars)"
