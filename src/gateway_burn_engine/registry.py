"""Gateway public-key registry.

In production this is sourced from `pallet-gateway-registry` on chain. For the
skeleton + tests we expose a small in-process dict that can be populated by
tests or loaded from a JSON file via `GATEWAYS_REGISTRY_PATH`.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


class GatewayRegistry:
    def __init__(self, initial: dict[str, str] | None = None) -> None:
        self._by_gw: dict[str, str] = dict(initial or {})

    @classmethod
    def from_env(cls) -> GatewayRegistry:
        path = os.environ.get("GATEWAYS_REGISTRY_PATH", "").strip()
        if not path:
            return cls()
        p = Path(path)
        if not p.exists():
            return cls()
        data = json.loads(p.read_text())
        if not isinstance(data, dict):
            raise ValueError(f"gateways registry file {path!r} must be a JSON object")
        return cls({str(k): str(v) for k, v in data.items()})

    def register(self, gateway_id: str, public_key_hex: str) -> None:
        self._by_gw[gateway_id] = public_key_hex

    def get(self, gateway_id: str) -> str | None:
        return self._by_gw.get(gateway_id)

    def __len__(self) -> int:
        return len(self._by_gw)
