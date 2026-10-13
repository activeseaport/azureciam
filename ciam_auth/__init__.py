"""Azure Entra External ID (CIAM) native authentication client package."""

from .config import CiamConfig
from .errors import NativeAuthError
from .models import AuthResult, ChallengeType, ContinuationState
from .client import NativeAuthClient

__all__ = [
    "CiamConfig",
    "NativeAuthError",
    "AuthResult",
    "ChallengeType",
    "ContinuationState",
    "NativeAuthClient",
]
