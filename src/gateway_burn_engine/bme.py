"""BME (Burn-Mint-Equilibrium) math, per RFC-0004.

The gateway gathers per-job receipts and produces a `SettlementBatch` summarising
`aggregate_mint_useful` and `aggregate_burn_cuc`. The burn-engine's job is to
verify the batch is internally consistent before submitting the burn extrinsic:

- Sum of receipts → matches `receipt_count`.
- Sum of per-operator subtotals → matches `aggregate_mint_useful`.
- Merkle root matches `SettlementBatch.merkle_root_of(receipts)`.
- Burn ≥ mint × current oracle ratio (oracle gives ratio of CUC value to OROG mint).
- Burn ≤ mint × oracle_max_ratio (anti-overburn cap).
- Gateway signature is well-formed.
"""

from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

from mining_types import Receipt, SettlementBatch, verify_ed25519
from mining_types.crypto import blake2_256, canonical_json
from pydantic import BaseModel


class OracleRate(BaseModel):
    """Snapshot of the CUC↔OROG ratio at batch settlement time."""

    epoch_number: int
    oracle_id: str = ""
    cuc_per_useful: int  # how many CUC units required to mint one OROG unit.
    min_ratio_bps: int = 5_000  # burn ≥ 0.5× mint × cuc_per_useful
    max_ratio_bps: int = 30_000  # burn ≤ 3.0× mint × cuc_per_useful (overburn cap)
    signature: str = ""

    def signing_payload(self) -> bytes:
        d = self.model_dump(mode="json")
        d.pop("signature", None)
        return canonical_json(d)


def compute_mint_for_receipts(receipts: list[Receipt]) -> int:
    """Aggregate-useful-mint in token-units, matching gateway-router's batcher."""
    return sum(max(1, len(r.log_probs_sample)) * 100 for r in receipts)


class VerificationFault(str, Enum):
    RECEIPT_COUNT_MISMATCH = "ReceiptCountMismatch"
    MINT_AGGREGATE_MISMATCH = "MintAggregateMismatch"
    MERKLE_ROOT_MISMATCH = "MerkleRootMismatch"
    UNDERBURN = "Underburn"
    OVERBURN = "Overburn"
    BAD_SIGNATURE = "BadSignature"
    BAD_ORACLE_SIGNATURE = "BadOracleSignature"
    BAD_RECEIPT_SIGNATURE = "BadReceiptSignature"
    PER_OPERATOR_MISMATCH = "PerOperatorMismatch"
    EPOCH_MISMATCH = "EpochMismatch"


@dataclass(slots=True)
class BmeVerificationResult:
    ok: bool
    faults: list[VerificationFault] = field(default_factory=list)
    detail: dict[str, str] = field(default_factory=dict)
    computed_mint: int = 0
    expected_burn_min: int = 0
    expected_burn_max: int = 0


def verify_batch(
    batch: SettlementBatch,
    receipts: list[Receipt],
    oracle_rate: OracleRate,
    *,
    gateway_pubkey_hex: str | None = None,
    oracle_pubkey_hex: str | None = None,
    operator_pubkeys: dict[str, str] | None = None,
) -> BmeVerificationResult:
    """Verify the settlement batch matches the receipts + oracle rate.

    Returns a result with `.ok=True` only if every check passes.

    When `gateway_pubkey_hex` is supplied (production path), the gateway
    signature is checked with real Ed25519 verification. When it is None
    (used only by the legacy verify-only smoke path), the signature is
    accepted iff it is well-formed hex of the right length AND non-zero —
    callers MUST pass `gateway_pubkey_hex` in security-critical contexts.
    """
    result = BmeVerificationResult(ok=True)

    if oracle_pubkey_hex is not None:
        if not verify_ed25519(
            oracle_pubkey_hex, oracle_rate.signing_payload(), oracle_rate.signature,
        ):
            result.ok = False
            result.faults.append(VerificationFault.BAD_ORACLE_SIGNATURE)
            result.detail["oracle_signature"] = "ed25519 verification failed"
    elif os.environ.get("OROGEN_ENV", "").lower() == "production":
        result.ok = False
        result.faults.append(VerificationFault.BAD_ORACLE_SIGNATURE)
        result.detail["oracle_signature"] = (
            "trusted oracle pubkey required in production"
        )

    if operator_pubkeys is not None:
        for r in receipts:
            pub = operator_pubkeys.get(r.operator_id)
            if pub is None:
                result.ok = False
                result.faults.append(VerificationFault.BAD_RECEIPT_SIGNATURE)
                result.detail[f"receipt:{r.job_id}"] = (
                    f"unknown operator {r.operator_id!r}"
                )
                continue
            if not verify_ed25519(pub, r.signing_payload(), r.operator_signature):
                result.ok = False
                result.faults.append(VerificationFault.BAD_RECEIPT_SIGNATURE)
                result.detail[f"receipt:{r.job_id}"] = "operator signature invalid"
    elif os.environ.get("OROGEN_ENV", "").lower() == "production":
        result.ok = False
        result.faults.append(VerificationFault.BAD_RECEIPT_SIGNATURE)
        result.detail["receipt_signatures"] = (
            "operator pubkeys required in production"
        )

    if batch.epoch_number != oracle_rate.epoch_number:
        result.ok = False
        result.faults.append(VerificationFault.EPOCH_MISMATCH)
        result.detail["epoch"] = (
            f"batch.epoch={batch.epoch_number} oracle.epoch={oracle_rate.epoch_number}"
        )

    if batch.receipt_count != len(receipts):
        result.ok = False
        result.faults.append(VerificationFault.RECEIPT_COUNT_MISMATCH)
        result.detail["count"] = (
            f"batch.count={batch.receipt_count} actual={len(receipts)}"
        )

    expected_root = SettlementBatch.merkle_root_of(receipts)
    if expected_root != batch.merkle_root:
        result.ok = False
        result.faults.append(VerificationFault.MERKLE_ROOT_MISMATCH)
        result.detail["merkle"] = f"batch={batch.merkle_root} actual={expected_root}"

    computed_mint = compute_mint_for_receipts(receipts)
    result.computed_mint = computed_mint
    if computed_mint != batch.aggregate_mint_useful:
        result.ok = False
        result.faults.append(VerificationFault.MINT_AGGREGATE_MISMATCH)
        result.detail["mint"] = (
            f"batch={batch.aggregate_mint_useful} computed={computed_mint}"
        )

    # Per-operator subtotal check.
    per_op: dict[str, list[Receipt]] = defaultdict(list)
    for r in receipts:
        per_op[r.operator_id].append(r)
    actual_summaries = {s.operator_id: s for s in batch.per_operator_summary}
    if set(per_op.keys()) != set(actual_summaries.keys()):
        result.ok = False
        result.faults.append(VerificationFault.PER_OPERATOR_MISMATCH)
        result.detail["operators"] = (
            f"batch={sorted(actual_summaries)} actual={sorted(per_op)}"
        )
    else:
        for op_id, rs in per_op.items():
            tokens = sum(max(1, len(r.log_probs_sample)) for r in rs)
            mint = tokens * 100
            summ = actual_summaries[op_id]
            if (
                summ.receipts_count != len(rs)
                or summ.aggregate_tokens_served != tokens
                or summ.aggregate_mint_useful != mint
            ):
                result.ok = False
                result.faults.append(VerificationFault.PER_OPERATOR_MISMATCH)
                result.detail[f"operator:{op_id}"] = (
                    f"summary={summ.model_dump()} actual_tokens={tokens} actual_mint={mint}"
                )

    # Burn-range check vs oracle.
    base_burn_units = computed_mint * oracle_rate.cuc_per_useful
    expected_min = base_burn_units * oracle_rate.min_ratio_bps // 10_000
    expected_max = base_burn_units * oracle_rate.max_ratio_bps // 10_000
    result.expected_burn_min = expected_min
    result.expected_burn_max = expected_max
    if batch.aggregate_burn_cuc < expected_min:
        result.ok = False
        result.faults.append(VerificationFault.UNDERBURN)
        result.detail["burn"] = (
            f"batch.burn={batch.aggregate_burn_cuc} < expected_min={expected_min}"
        )
    elif batch.aggregate_burn_cuc > expected_max:
        result.ok = False
        result.faults.append(VerificationFault.OVERBURN)
        result.detail["burn"] = (
            f"batch.burn={batch.aggregate_burn_cuc} > expected_max={expected_max}"
        )

    # Gateway-signature check (HIGH-SVC-008 / CRIT-SVC-002).
    if not batch.gateway_signature:
        result.ok = False
        result.faults.append(VerificationFault.BAD_SIGNATURE)
        result.detail["signature"] = "empty signature"
    elif gateway_pubkey_hex is not None:
        # Production path: real Ed25519 verification against the known
        # gateway pubkey loaded from the gateway registry.
        if not verify_ed25519(
            gateway_pubkey_hex, batch.signing_payload(), batch.gateway_signature,
        ):
            result.ok = False
            result.faults.append(VerificationFault.BAD_SIGNATURE)
            result.detail["signature"] = "ed25519 verification failed"
    else:
        # No gateway pubkey supplied — the gateway is not registered, or the
        # caller forgot to look it up. In production (OROGEN_ENV=production)
        # we MUST refuse: an authenticated insider could otherwise submit a
        # batch naming an unknown gateway_id with an arbitrary 64-byte hex sig
        # and the shape check would let it through (NEW-SVC-020).
        if os.environ.get("OROGEN_ENV", "").lower() == "production":
            result.ok = False
            result.faults.append(VerificationFault.BAD_SIGNATURE)
            result.detail["signature"] = "unknown gateway; refusing to verify in production"
        else:
            # Non-production: shape check only, but reject zero/short/non-hex.
            try:
                sig_bytes = bytes.fromhex(batch.gateway_signature)
            except ValueError:
                result.ok = False
                result.faults.append(VerificationFault.BAD_SIGNATURE)
                result.detail["signature"] = "non-hex signature"
                sig_bytes = b""
            if sig_bytes and len(sig_bytes) != 64:
                result.ok = False
                result.faults.append(VerificationFault.BAD_SIGNATURE)
                result.detail["signature"] = (
                    f"unexpected signature length: {len(sig_bytes)}"
                )
            if sig_bytes and sig_bytes == bytes(len(sig_bytes)):
                result.ok = False
                result.faults.append(VerificationFault.BAD_SIGNATURE)
                result.detail["signature"] = "all-zero signature"

    return result


class BurnEvent(BaseModel):
    """RFC-0004 burn-event surfaced after the on-chain burn extrinsic succeeds."""

    batch_id: str
    epoch_number: int
    gateway_id: str
    burned_cuc: int
    burn_tx_hash: str
    block_number: int


class MintEvent(BaseModel):
    """RFC-0004 mint-event for the corresponding mint-useful side."""

    batch_id: str
    epoch_number: int
    minted_useful: int
    mint_tx_hash: str
    block_number: int


def batch_event_key(batch: SettlementBatch) -> str:
    """Deterministic key for double-burn detection: blake2(batch_id || epoch || gateway)."""
    return blake2_256(canonical_json([batch.batch_id, batch.epoch_number, batch.gateway_id]))
