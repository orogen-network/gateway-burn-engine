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


class OperatorRegistry:
    def __init__(self, initial: dict[str, str] | None = None) -> None:
        self._by_operator: dict[str, str] = dict(initial or {})

    @classmethod
    def from_env(cls) -> OperatorRegistry:
        path = os.environ.get("OPERATORS_REGISTRY_PATH", "").strip()
        if not path:
            return cls()
        p = Path(path)
        if not p.exists():
            return cls()
        data = json.loads(p.read_text())
        if not isinstance(data, dict):
            raise ValueError(f"operators registry file {path!r} must be a JSON object")
        return cls({str(k): str(v) for k, v in data.items()})

    def register(self, operator_id: str, public_key_hex: str) -> None:
        self._by_operator[operator_id] = public_key_hex

    def get(self, operator_id: str) -> str | None:
        return self._by_operator.get(operator_id)

    def __len__(self) -> int:
        return len(self._by_operator)


class OracleRegistry:
    def __init__(self, initial: dict[str, str] | None = None) -> None:
        self._by_oracle: dict[str, str] = dict(initial or {})

    @classmethod
    def from_env(cls) -> OracleRegistry:
        path = os.environ.get("ORACLE_REGISTRY_PATH", "").strip()
        if path:
            p = Path(path)
            if p.exists():
                data = json.loads(p.read_text())
                if not isinstance(data, dict):
                    raise ValueError(f"oracle registry file {path!r} must be a JSON object")
                return cls({str(k): str(v) for k, v in data.items()})
        raw = os.environ.get("ORACLE_PUBKEYS_JSON", "").strip()
        if raw:
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("ORACLE_PUBKEYS_JSON must be a JSON object")
            return cls({str(k): str(v) for k, v in data.items()})
        return cls()

    def register(self, oracle_id: str, public_key_hex: str) -> None:
        self._by_oracle[oracle_id] = public_key_hex

    def get(self, oracle_id: str) -> str | None:
        return self._by_oracle.get(oracle_id)

    def __len__(self) -> int:
        return len(self._by_oracle)
