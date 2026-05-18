"""Chain-client abstraction for burn submission.

The real chain-node isn't booted here; production code will wire a substrate-interface
or polkadot-py client. We expose a `ChainClient` Protocol + an in-memory `MockChainClient`
that tests assert against.

Burn-tx semantics:
- `submit_burn(batch_key, burn_cuc)` returns a tx hash and block number.
- A second call with the same `batch_key` raises `DoubleBurnError`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Protocol

from mining_types.crypto import canonical_json


class DoubleBurnError(RuntimeError):
    """Raised when the same batch_key is burned twice."""


@dataclass(slots=True)
class BurnReceipt:
    tx_hash: str
    block_number: int
    burned_cuc: int


@dataclass(slots=True)
class MintReceipt:
    tx_hash: str
    block_number: int
    minted_useful: int


class ChainClient(Protocol):
    def submit_burn(self, batch_key: str, burn_cuc: int) -> BurnReceipt: ...
    def submit_mint(self, batch_key: str, mint_useful: int) -> MintReceipt: ...
    def get_block_number(self) -> int: ...


@dataclass
class MockChainClient:
    """In-memory chain stub. Deterministic tx-hash; tracks double-burn."""

    block_number: int = 1
    _burned: set[str] = field(default_factory=set)
    _minted: set[str] = field(default_factory=set)
    burns: list[BurnReceipt] = field(default_factory=list)
    mints: list[MintReceipt] = field(default_factory=list)

    def submit_burn(self, batch_key: str, burn_cuc: int) -> BurnReceipt:
        if batch_key in self._burned:
            raise DoubleBurnError(f"batch {batch_key} already burned")
        self._burned.add(batch_key)
        tx_hash = hashlib.sha256(
            canonical_json(["burn", batch_key, burn_cuc])
        ).hexdigest()
        self.block_number += 1
        rcpt = BurnReceipt(
            tx_hash=tx_hash, block_number=self.block_number, burned_cuc=burn_cuc,
        )
        self.burns.append(rcpt)
        return rcpt

    def submit_mint(self, batch_key: str, mint_useful: int) -> MintReceipt:
        if batch_key in self._minted:
            raise DoubleBurnError(f"batch {batch_key} already minted")
        self._minted.add(batch_key)
        tx_hash = hashlib.sha256(
            canonical_json(["mint", batch_key, mint_useful])
        ).hexdigest()
        self.block_number += 1
        rcpt = MintReceipt(
            tx_hash=tx_hash, block_number=self.block_number, minted_useful=mint_useful,
        )
        self.mints.append(rcpt)
        return rcpt

    def get_block_number(self) -> int:
        return self.block_number


@dataclass(slots=True)
class BurnEngineConfig:
    engine_id: str
    chain_endpoint: str = ""
    require_signed_batches: bool = True
    epoch_number: int = 1
