# CIAM Native Authentication (Python)

Browser and console app that signs users in against **Microsoft Entra External ID (CIAM)**
using the
[native authentication API](https://learn.microsoft.com/entra/identity-platform/concept-native-authentication) —
no browser redirect, no embedded web view.

## Layout

| Path | Responsibility |
| --- | --- |
| `ciam_auth/client.py` | The only module that calls Azure. Pure HTTP + data objects. |
| `ciam_auth/models.py` | `AuthResult`, `ContinuationState`, `ChallengeType`. |
| `ciam_auth/errors.py` | `NativeAuthError` wrapping API error payloads. |
| `ciam_auth/config.py` | Tenant/client configuration, loaded from env. |
| `ui/web_app.py` | Flask routes + templates. No HTTP to Azure. |
| `ui/console_app.py` | Prompting and printing only. No HTTP to Azure. |
| `web.py` / `main.py` | Wire config → client → UI. |

## Azure setup

1. In the Entra admin center create an **External ID (CIAM)** tenant.
2. Register an app, then under **Authentication → Advanced settings** enable
   **Allow public client flows** and, under **Native authentication**, turn on
   *Enable native authentication*.
3. Create a **sign-up and sign-in** user flow and add the app to it.
4. In the user flow, choose the attribute collection and the authentication
   method (email + password, or email one-time passcode).

> Native authentication must be called as a **public client**. Requests carry
> `client_id` only — never a client secret or assertion — and the app
> registration needs *Allow public client flows* = **Yes**. Configuring
> `CIAM_CLIENT_SECRET` is rejected at startup, and Azure answers
> `unauthorized_client` if the registration is confidential.

### AADSTS550022 — "Confidential Client is not supported"

Entra classifies the registration as confidential. Nothing in this code sends
credentials, so fix it in the portal:

- **Authentication → Advanced settings → Allow public client flows** = *Yes*
- **Certificates & secrets** — delete every client secret and certificate
- **Authentication → Platform configurations** — remove the **Web** platform; a
  Web redirect URI alone makes the app confidential. Use no platform, or
  *Mobile and desktop applications*.
- **Authentication → Native authentication** = *Enabled*, with the app added to
  the user flow

## Run

```bash
make web     # venv + deps + start the server and open http://127.0.0.1:5001
make cli     # same setup, console UI instead
make help    # list all targets
```

`make web` (alias `make watch`) runs with the reloader on: saving a `.py` file
restarts the server and saving a template re-renders on the next request. Use
`make serve` or `make web RELOAD=0` to disable it. Because tokens live in process
memory, a Python-file restart signs you out.

The first `make` run creates `.env` from `.env.example` and stops so you can fill
in `CIAM_TENANT_SUBDOMAIN` and `CIAM_CLIENT_ID`. Override the address with
`make web PORT=8080`.

Without make:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # fill in tenant subdomain + client id
python web.py             # or: python main.py
```

## Supported flows

- Sign in with password
- Sign in with email one-time passcode
- Sign up (code verification, optional password, required attributes)
- Self-service password reset (including completion polling)
- Refresh token redemption

If the API replies with `challenge_type: redirect`, the tenant policy cannot be
satisfied natively and the app reports that a browser-based flow is required.

## Notes

- Tokens and continuation tokens are held in process memory, keyed by an opaque
  id in the Flask cookie — Flask's session cookie is signed but not encrypted, so
  nothing sensitive goes into it. Nothing is written to disk.
- The dev server is for local use only. Put it behind a real WSGI server and TLS
  before exposing it, and set `FLASK_SECRET_KEY` so sessions survive restarts.
- `AuthResult.claims` decodes the `id_token` for display and does **not** verify
  its signature. Validate tokens server-side before trusting them.
