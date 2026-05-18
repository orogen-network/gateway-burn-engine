"""Bearer-token authentication for gateway-burn-engine.

Both `/verify_batch` and `/execute_burn` are operator-only routes (they accept
batches the gateway has sealed). We treat them as `/internal/*` and require a
shared bearer token in `INTERNAL_AUTH_TOKEN`. In production (`OROGEN_ENV=production`)
the service refuses to start without it.
"""

from __future__ import annotations

import os

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_BEARER = HTTPBearer(auto_error=False)


def _is_production() -> bool:
    return os.environ.get("OROGEN_ENV", "").lower() == "production"


def require_internal_token() -> str:
    tok = os.environ.get("INTERNAL_AUTH_TOKEN", "").strip()
    if not tok and _is_production():
        raise RuntimeError(
            "INTERNAL_AUTH_TOKEN must be set in production (OROGEN_ENV=production)"
        )
    return tok


async def require_internal_auth(
    creds: HTTPAuthorizationCredentials | None = Depends(_BEARER),
) -> None:
    expected = require_internal_token()
    if not expected:
        return
    if creds is None or creds.scheme.lower() != "bearer" or creds.credentials != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="internal auth required",
            headers={"WWW-Authenticate": "Bearer"},
        )
