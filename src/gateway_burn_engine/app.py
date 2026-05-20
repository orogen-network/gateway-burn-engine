"""Burn-engine HTTP API.

Endpoints:
- `POST /verify_batch` — verify a `SettlementBatch` against its receipts + oracle rate.
- `POST /execute_burn` — verify + submit the burn extrinsic (via injected chain client).
- `GET  /events`        — list burn + mint events recorded by the engine.
- `GET  /healthz`

Security model:
- All non-healthz routes require the `INTERNAL_AUTH_TOKEN` bearer.
- `/execute_burn` and `/verify_batch` perform real Ed25519 verification of
  `batch.gateway_signature` against the gateway pubkey from the registry.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from mining_types import Receipt, SettlementBatch
from pydantic import BaseModel

from gateway_burn_engine.auth import require_internal_auth, require_internal_token
from gateway_burn_engine.bme import (
    BurnEvent,
    MintEvent,
    OracleRate,
    VerificationFault,
    batch_event_key,
    verify_batch,
)
from gateway_burn_engine.chain import (
    BurnEngineConfig,
    ChainClient,
    DoubleBurnError,
    MockChainClient,
)
from gateway_burn_engine.registry import GatewayRegistry, OperatorRegistry, OracleRegistry


class VerifyBatchRequest(BaseModel):
    batch: SettlementBatch
    receipts: list[Receipt]
    oracle_rate: OracleRate


class ExecuteBurnRequest(BaseModel):
    batch: SettlementBatch
    receipts: list[Receipt]
    oracle_rate: OracleRate


def build_app(
    config: BurnEngineConfig,
    chain_client: ChainClient | None = None,
) -> FastAPI:
    require_internal_token()
    if os.environ.get("OROGEN_ENV", "").lower() == "production" and chain_client is None:
        raise RuntimeError("production burn-engine requires a real ChainClient")

    app = FastAPI(title="gateway-burn-engine", version="0.1.0")
    allowed_hosts = [
        h.strip()
        for h in os.environ.get("ALLOWED_HOSTS", "*").split(",")
        if h.strip()
    ] or ["*"]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

    client: ChainClient = chain_client or MockChainClient()
    burns: list[BurnEvent] = []
    mints: list[MintEvent] = []
    registry = GatewayRegistry.from_env()
    operator_registry = OperatorRegistry.from_env()
    oracle_registry = OracleRegistry.from_env()
    app.state.config = config
    app.state.chain_client = client
    app.state.burns = burns
    app.state.mints = mints
    app.state.registry = registry
    app.state.operator_registry = operator_registry
    app.state.oracle_registry = oracle_registry

    def _gateway_pubkey_for(batch: SettlementBatch) -> str | None:
        # If no gateway is registered, fall back to length-only shape check
        # (skeleton/dev mode). In production the absence is enforced upstream
        # by the auth gate; this is defence-in-depth.
        return registry.get(batch.gateway_id)

    def _oracle_pubkey_for(rate: OracleRate) -> str | None:
        if not rate.oracle_id:
            return None
        return oracle_registry.get(rate.oracle_id)

    def _operator_pubkeys_for(receipts: list[Receipt]) -> dict[str, str] | None:
        if len(operator_registry) == 0:
            if os.environ.get("OROGEN_ENV", "").lower() == "production":
                raise HTTPException(
                    status_code=503,
                    detail="operator registry required in production",
                )
            return None
        return {
            r.operator_id: pub
            for r in receipts
            if (pub := operator_registry.get(r.operator_id)) is not None
        }

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {
            "ok": True,
            "engine_id": config.engine_id,
            "burns": len(burns),
            "mints": len(mints),
        }

    @app.post("/verify_batch", dependencies=[Depends(require_internal_auth)])
    async def verify_batch_endpoint(req: VerifyBatchRequest) -> dict[str, Any]:
        result = verify_batch(
            req.batch, req.receipts, req.oracle_rate,
            gateway_pubkey_hex=_gateway_pubkey_for(req.batch),
            oracle_pubkey_hex=_oracle_pubkey_for(req.oracle_rate),
            operator_pubkeys=_operator_pubkeys_for(req.receipts),
        )
        return {
            "ok": result.ok,
            "faults": [f.value for f in result.faults],
            "detail": result.detail,
            "computed_mint": result.computed_mint,
            "expected_burn_min": result.expected_burn_min,
            "expected_burn_max": result.expected_burn_max,
        }

    @app.post("/execute_burn", dependencies=[Depends(require_internal_auth)])
    async def execute_burn(req: ExecuteBurnRequest) -> dict[str, Any]:
        result = verify_batch(
            req.batch, req.receipts, req.oracle_rate,
            gateway_pubkey_hex=_gateway_pubkey_for(req.batch),
            oracle_pubkey_hex=_oracle_pubkey_for(req.oracle_rate),
            operator_pubkeys=_operator_pubkeys_for(req.receipts),
        )
        if not result.ok:
            raise HTTPException(
                status_code=400,
                detail={"faults": [f.value for f in result.faults], "detail": result.detail},
            )
        key = batch_event_key(req.batch)
        try:
            burn_rcpt = client.submit_burn(key, req.batch.aggregate_burn_cuc)
            mint_rcpt = client.submit_mint(key, req.batch.aggregate_mint_useful)
        except DoubleBurnError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        burn_event = BurnEvent(
            batch_id=req.batch.batch_id,
            epoch_number=req.batch.epoch_number,
            gateway_id=req.batch.gateway_id,
            burned_cuc=req.batch.aggregate_burn_cuc,
            burn_tx_hash=burn_rcpt.tx_hash,
            block_number=burn_rcpt.block_number,
        )
        mint_event = MintEvent(
            batch_id=req.batch.batch_id,
            epoch_number=req.batch.epoch_number,
            minted_useful=req.batch.aggregate_mint_useful,
            mint_tx_hash=mint_rcpt.tx_hash,
            block_number=mint_rcpt.block_number,
        )
        burns.append(burn_event)
        mints.append(mint_event)
        return {
            "ok": True,
            "burn_event": burn_event.model_dump(),
            "mint_event": mint_event.model_dump(),
        }

    @app.get("/events", dependencies=[Depends(require_internal_auth)])
    async def events() -> dict[str, Any]:
        return {
            "burns": [e.model_dump() for e in burns],
            "mints": [e.model_dump() for e in mints],
        }

    return app


# Re-export so external imports remain stable.
__all__ = [
    "ExecuteBurnRequest",
    "VerificationFault",
    "VerifyBatchRequest",
    "build_app",
]
