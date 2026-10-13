"""Entry point: wires configuration into the API client and the console UI."""

from __future__ import annotations

import sys

from dotenv import load_dotenv

from ciam_auth import CiamConfig, NativeAuthClient
from ui.console_app import ConsoleApp


def main() -> int:
    load_dotenv()
    try:
        config = CiamConfig.from_env()
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        print("Copy .env.example to .env and fill in your tenant values.", file=sys.stderr)
        return 1

    ConsoleApp(NativeAuthClient(config)).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
