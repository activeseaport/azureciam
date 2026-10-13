"""Entry point for the browser UI: wires configuration into the client and Flask."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from ciam_auth import CiamConfig
from ui.web_app import create_app

load_dotenv()

try:
    app = create_app(CiamConfig.from_env())
except ValueError as exc:
    print(f"Configuration error: {exc}", file=sys.stderr)
    print("Copy .env.example to .env and fill in your tenant values.", file=sys.stderr)
    raise SystemExit(1) from exc


if __name__ == "__main__":
    reload_enabled = os.environ.get("FLASK_DEBUG") == "1"
    # Werkzeug watches imported modules but not templates, so list them explicitly.
    templates = Path(__file__).parent / "ui" / "templates"
    watched = [str(path) for path in templates.rglob("*.html")]
    app.jinja_env.auto_reload = reload_enabled
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5001")),
        debug=reload_enabled,
        use_reloader=reload_enabled,
        extra_files=watched if reload_enabled else None,
    )
