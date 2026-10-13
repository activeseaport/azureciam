"""Flask UI for the CIAM native authentication sample.

Like the console UI, this module never talks to Azure directly — every call goes
through ciam_auth.NativeAuthClient. Flow state lives in the signed Flask session.
"""

from __future__ import annotations

import os
import secrets
import string
from typing import Any

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    send_from_directory,
    url_for,
)

from ciam_auth import (
    AuthResult,
    ChallengeType,
    CiamConfig,
    ContinuationState,
    NativeAuthClient,
)
from ciam_auth.errors import NativeAuthError

_SID = "sid"


def create_app(config: CiamConfig | None = None) -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    @app.get("/images/<path:filename>")
    def images(filename: str):
        return send_from_directory(
            os.path.join(app.root_path, "images"), filename
        )

    client = NativeAuthClient(config or CiamConfig.from_env())
    # Flask's cookie is signed but not encrypted, so tokens stay in this
    # process and the cookie only carries an opaque key.
    store: dict[str, dict[str, Any]] = {}

    def bucket() -> dict[str, Any]:
        sid = session.get(_SID)
        if not sid or sid not in store:
            sid = secrets.token_urlsafe(32)
            session[_SID] = sid
            store[sid] = {}
        return store[sid]

    # -------------------------------------------------------------- #
    # Session helpers
    # -------------------------------------------------------------- #
    def start_flow(kind: str, state: ContinuationState, **extra: Any) -> None:
        bucket()["flow"] = {"kind": kind, "state": state, **extra}

    def current_flow(kind: str) -> dict[str, Any]:
        flow = bucket().get("flow")
        if not flow or flow.get("kind") != kind:
            raise _FlowExpired()
        return flow

    def advance(flow: dict[str, Any], state: ContinuationState) -> None:
        flow["state"] = state

    def finish(result: AuthResult) -> Any:
        data = bucket()
        data.pop("flow", None)
        data["tokens"] = result
        flash(f"Signed in as {result.display_name}.", "success")
        return redirect(url_for("home"))

    def signed_in() -> AuthResult | None:
        return bucket().get("tokens")

    def guard(state: ContinuationState) -> ContinuationState:
        if state.needs_redirect:
            raise NativeAuthError(
                "redirect_required",
                "This tenant requires the browser-based flow; native "
                "authentication cannot complete it.",
            )
        return state

    # -------------------------------------------------------------- #
    # Errors
    # -------------------------------------------------------------- #
    @app.errorhandler(NativeAuthError)
    def _on_auth_error(exc: NativeAuthError):
        flash(exc.user_message, "error")
        bucket().pop("flow", None)
        return redirect(url_for("signin"))

    @app.errorhandler(_FlowExpired)
    def _on_flow_expired(_: Exception):
        flash("That sign-in attempt expired. Please start again.", "error")
        bucket().pop("flow", None)
        return redirect(url_for("signin"))

    # -------------------------------------------------------------- #
    # Home / session
    # -------------------------------------------------------------- #
    @app.get("/")
    def home():
        result = signed_in()
        if not result:
            return redirect(url_for("signin_code"))
        return render_template("riskassessment.html", result=result, mask=_mask)

    @app.post("/refresh")
    def refresh():
        result = signed_in()
        if not result or not result.refresh_token:
            flash("No refresh token available.", "error")
            return redirect(url_for("home"))
        return finish(client.refresh(result.refresh_token))

    @app.post("/signout")
    def signout():
        store.pop(session.pop(_SID, ""), None)
        session.clear()
        flash("Signed out.", "success")
        return redirect(url_for("signin"))

    # -------------------------------------------------------------- #
    # Sign in
    # -------------------------------------------------------------- #
    @app.route("/signin", methods=["GET", "POST"])
    def signin():
        if signed_in():
            return redirect(url_for("home"))
        if request.method == "GET":
            return render_template(
                "signin.html",
                active_tab="password",
                submit_endpoint="signin",
            )

        username = request.form.get("username", "").strip()
        if not username:
            flash("Email is required.", "error")
            return redirect(url_for("signin"))

        state = guard(client.signin_start(username))
        start_flow("signin", state, username=username)
        return redirect(url_for("signin_credential"))

    @app.route("/signin/code", methods=["GET", "POST"])
    def signin_code():
        if signed_in():
            return redirect(url_for("home"))
        if request.method == "GET":
            return render_template(
                "signin.html",
                active_tab="code",
                submit_endpoint="signin_code",
            )

        username = request.form.get("username", "").strip()
        if not username:
            flash("Email is required.", "error")
            return redirect(url_for("signin_code"))

        state = guard(client.reset_start(username))
        start_flow("reset_code", state, username=username)
        return redirect(url_for("signin_code_verify"))

    @app.route("/sigin/code/verify", methods=["GET", "POST"])
    def signin_code_verify():
        flow = current_flow("reset_code")
        state = flow["state"]

        if request.method == "GET":
            return render_template("credential.html", state=state, action="signin_code")

        code = request.form.get("code", "").strip()
        verified = client.reset_submit_code(state, code)
        generated_password = _generate_password()
        completed = client.reset_submit_password(verified, generated_password)
        return finish(client.signin_after_reset(completed))


    @app.route("/signin/credential", methods=["GET", "POST"])
    def signin_credential():
        flow = current_flow("signin")
        state = flow["state"]

        if request.method == "GET":
            return render_template("credential.html", state=state, action="signin")

        if state.challenge_type is ChallengeType.PASSWORD:
            password = request.form.get("password", "")
            return finish(client.signin_with_password(state, password))

        code = request.form.get("code", "").strip()
        return finish(client.signin_with_code(state, code))

    @app.post("/signin/resend")
    def signin_resend():
        flow = current_flow("signin")
        advance(flow, guard(client.resend_code(flow["state"])))
        flash("A new code was sent.", "success")
        return redirect(url_for("signin_credential"))

    # -------------------------------------------------------------- #
    # Sign up
    # -------------------------------------------------------------- #
    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        if request.method == "GET":
            return render_template("signup.html")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        display_name = request.form.get("displayName", "").strip()
        if not username:
            flash("Email is required.", "error")
            return redirect(url_for("signup"))

        if not display_name:
            flash("Display Name is required.", "error")
            return redirect(url_for("signup"))

        if len(display_name) > 120:
            flash("Display Name must be 120 characters or fewer.", "error")
            return redirect(url_for("signup"))

        if (password or confirm_password) and password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("signup"))

        attributes = {"displayName": display_name} if display_name else None
        state = guard(
            client.signup_start(username, password or None, attributes=attributes)
        )
        start_flow("signup", state, username=username)
        return redirect(url_for("signup_verify"))

    @app.route("/signup/verify", methods=["GET", "POST"])
    def signup_verify():
        flow = current_flow("signup")
        state = flow["state"]

        if request.method == "GET":
            return render_template("credential.html", state=state, action="signup")

        code = request.form.get("code", "").strip()
        advance(flow, client.signup_submit_code(state, code))
        return redirect(url_for("signup_next"))

    @app.route("/signup/next", methods=["GET", "POST"])
    def signup_next():
        flow = current_flow("signup")
        state = flow["state"]

        if request.method == "POST":
            if state.challenge_type is ChallengeType.PASSWORD:
                advance(
                    flow,
                    client.signup_submit_password(
                        state, request.form.get("password", "")
                    ),
                )
            else:
                values = {
                    attribute["name"]: request.form.get(attribute["name"], "")
                    for attribute in state.required_attributes
                    if attribute.get("name")
                }
                advance(flow, client.signup_submit_attributes(state, values))
            return redirect(url_for("signup_next"))

        if state.challenge_type is ChallengeType.PASSWORD:
            return render_template("signup_password.html")
        if state.required_attributes:
            return render_template("signup_attributes.html", state=state)
        return finish(client.signin_after_signup(state))

    # -------------------------------------------------------------- #
    # Password reset
    # -------------------------------------------------------------- #
    @app.route("/reset", methods=["GET", "POST"])
    def reset():
        if request.method == "GET":
            return render_template("reset.html")

        username = request.form.get("username", "").strip()
        if not username:
            flash("Email is required.", "error")
            return redirect(url_for("reset"))

        state = guard(client.reset_start(username))
        start_flow("reset", state, username=username)
        return redirect(url_for("reset_verify"))

    @app.route("/reset/verify", methods=["GET", "POST"])
    def reset_verify():
        flow = current_flow("reset")
        state = flow["state"]

        if request.method == "GET":
            return render_template("credential.html", state=state, action="reset")

        code = request.form.get("code", "").strip()
        advance(flow, client.reset_submit_code(state, code))
        return redirect(url_for("reset_password"))

    @app.route("/reset/password", methods=["GET", "POST"])
    def reset_password():
        flow = current_flow("reset")
        if request.method == "GET":
            return render_template("reset_password.html")

        state = flow["state"]
        completed = client.reset_submit_password(
            state, request.form.get("password", "")
        )
        return finish(client.signin_after_reset(completed))

    @app.route("/create/code", methods=["GET", "POST"])
    def create_code():
        if request.method == "GET":
            return render_template("create.html")

        username = request.form.get("username", "").strip()
        if not username:
            flash("Email is required.", "error")
            return redirect(url_for("reset_code"))

        state = guard(client.reset_start(username))
        start_flow("reset_code", state, username=username)
        return redirect(url_for("reset_code_verify"))

    @app.route("/create/code/verify", methods=["GET", "POST"])
    def create_code_verify():
        flow = current_flow("reset_code")
        state = flow["state"]

        if request.method == "GET":
            return render_template("credential.html", state=state, action="reset_code")

        code = request.form.get("code", "").strip()
        verified = client.reset_submit_code(state, code)
        new_password = request.form.get("password", "")
        completed = client.reset_submit_password(verified, new_password)
        return finish(client.signin_after_reset(completed))

    @app.route("/reset/code", methods=["GET", "POST"])
    def reset_code():
        if request.method == "GET":
            return render_template("reset.html")

        username = request.form.get("username", "").strip()
        if not username:
            flash("Email is required.", "error")
            return redirect(url_for("reset_code"))

        state = guard(client.reset_start(username))
        start_flow("reset_code", state, username=username)
        return redirect(url_for("reset_code_verify"))

    @app.route("/reset/code/verify", methods=["GET", "POST"])
    def reset_code_verify():
        flow = current_flow("reset_code")
        state = flow["state"]

        if request.method == "GET":
            return render_template("credential.html", state=state, action="reset_code")

        code = request.form.get("code", "").strip()
        verified = client.reset_submit_code(state, code)
        new_password = request.form.get("password", "")
        completed = client.reset_submit_password(verified, new_password)
        return finish(client.signin_after_reset(completed))

    return app


class _FlowExpired(Exception):
    """Raised when a browser posts to a step whose flow state is gone."""


def _mask(token: str | None) -> str:
    if not token:
        return "-"
    return f"{token[:8]}...{token[-6:]} ({len(token)} chars)"


def _generate_password(length: int = 24) -> str:
    # Ensure mixed character classes to satisfy common password policies.
    if length < 12:
        length = 12
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()-_=+"),
    ]
    remaining = [secrets.choice(alphabet) for _ in range(length - len(required))]
    chars = required + remaining
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)
