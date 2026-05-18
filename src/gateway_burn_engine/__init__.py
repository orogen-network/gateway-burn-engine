"""Auditable burn execution and BME math for batch submission (RFC-0004).

Separates burn execution from the gateway-router HTTP path so the actual on-chain
burn extrinsic is independently verifiable against the gateway's claimed mint.
"""

from gateway_burn_engine.app import build_app
from gateway_burn_engine.bme import (
    BmeVerificationResult,
    BurnEvent,
    MintEvent,
    OracleRate,
    compute_mint_for_receipts,
    verify_batch,
)
from gateway_burn_engine.chain import BurnEngineConfig, ChainClient, MockChainClient

__version__ = "0.1.0"

__all__ = [
    "BmeVerificationResult",
    "BurnEngineConfig",
    "BurnEvent",
    "ChainClient",
    "MintEvent",
    "MockChainClient",
    "OracleRate",
    "build_app",
    "compute_mint_for_receipts",
    "verify_batch",
]
