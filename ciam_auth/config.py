"""Configuration for the CIAM native authentication client."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class CiamConfig:
    """Public-client configuration. Native authentication forbids a client secret."""

    tenant_subdomain: str
    client_id: str
    scopes: list[str] = field(default_factory=lambda: ["openid", "offline_access"])
    timeout_seconds: float = 30.0

    @property
    def authority(self) -> str:
        return (
            f"https://{self.tenant_subdomain}.ciamlogin.com/"
            f"{self.tenant_subdomain}.onmicrosoft.com"
        )

    @property
    def scope_string(self) -> str:
        return " ".join(self.scopes)

    @classmethod
    def from_env(cls) -> "CiamConfig":
        tenant = os.environ.get("CIAM_TENANT_SUBDOMAIN", "").strip()
        client_id = os.environ.get("CIAM_CLIENT_ID", "").strip()
        missing = [
            name
            for name, value in (
                ("CIAM_TENANT_SUBDOMAIN", tenant),
                ("CIAM_CLIENT_ID", client_id),
            )
            if not value
        ]
        if missing:
            raise ValueError(
                "Missing required environment variables: " + ", ".join(missing)
            )

        if os.environ.get("CIAM_CLIENT_SECRET", "").strip():
            raise ValueError(
                "CIAM_CLIENT_SECRET is set, but native authentication must be "
                "called as a public client. Remove the secret and enable "
                "'Allow public client flows' on the app registration."
            )

        scopes = os.environ.get("CIAM_SCOPES", "openid offline_access").split()
        return cls(tenant_subdomain=tenant, client_id=client_id, scopes=scopes)
