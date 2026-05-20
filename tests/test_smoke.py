"""gateway-burn-engine tests."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from mining_types import (
    OperatorSummary,
    Receipt,
    SettlementBatch,
    generate_keypair,
)
from mining_types.crypto import sign_ed25519

from gateway_burn_engine import (
    BurnEngineConfig,
    MockChainClient,
    OracleRate,
    build_app,
    compute_mint_for_receipts,
    verify_batch,
)
from gateway_burn_engine.bme import VerificationFault

INTERNAL_TOKEN = "test-bme-internal"


@pytest.fixture(autouse=True)
def auth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INTERNAL_AUTH_TOKEN", INTERNAL_TOKEN)
    monkeypatch.delenv("OROGEN_ENV", raising=False)


def _hdrs() -> dict[str, str]:
    return {"Authorization": f"Bearer {INTERNAL_TOKEN}"}


def _make_receipts(n: int, op_id: str = "op-1", probs_len: int = 4) -> list[Receipt]:
    return [
        Receipt(
            job_id=f"job-{i}",
            operator_id=op_id,
            model_id="mock-model-7b",
            model_weight_hash="aa" * 32,
            customer_nonce=f"n-{i}",
            request_hash=f"rq-{i}",
            response_hash=f"rs-{i}",
            log_probs_sample=[-0.1] * probs_len,
            kernel_pack_hash="cc" * 32,
            attestation_report_hash="bb" * 32,
            timestamp_ms=int(time.time() * 1000) + i,
            gateway_id="gw-test",
            operator_signature="ee" * 32,
        )
        for i in range(n)
    ]


def _make_batch(
    receipts: list[Receipt],
    *,
    gateway_id: str = "gw-test",
    epoch: int = 1,
    oracle: OracleRate | None = None,
) -> tuple[SettlementBatch, str]:
    priv, pub = generate_keypair()
    mint = compute_mint_for_receipts(receipts)
    oracle = oracle or OracleRate(epoch_number=epoch, cuc_per_useful=2)
    # Build a burn within range: midpoint of min/max.
    base = mint * oracle.cuc_per_useful
    min_b = base * oracle.min_ratio_bps // 10_000
    max_b = base * oracle.max_ratio_bps // 10_000
    burn = (min_b + max_b) // 2

    per_op: dict[str, list[Receipt]] = {}
    for r in receipts:
        per_op.setdefault(r.operator_id, []).append(r)
    summaries = []
    for op_id, rs in per_op.items():
        tokens = sum(max(1, len(r.log_probs_sample)) for r in rs)
        summaries.append(
            OperatorSummary(
                operator_id=op_id,
                receipts_count=len(rs),
                aggregate_tokens_served=tokens,
                aggregate_mint_useful=tokens * 100,
                merkle_subroot=SettlementBatch.merkle_root_of(rs),
            )
        )

    batch = SettlementBatch(
        batch_id="b-1",
        epoch_number=epoch,
        gateway_id=gateway_id,
        receipt_count=len(receipts),
        merkle_root=SettlementBatch.merkle_root_of(receipts),
        aggregate_burn_cuc=burn,
        aggregate_mint_useful=mint,
        per_operator_summary=summaries,
    ).sign(priv)
    return batch, pub


def test_verify_batch_happy_path() -> None:
    rs = _make_receipts(5)
    batch, _ = _make_batch(rs)
    oracle = OracleRate(epoch_number=1, cuc_per_useful=2)
    result = verify_batch(batch, rs, oracle)
    assert result.ok, result.faults
    assert result.faults == []
    assert result.computed_mint == compute_mint_for_receipts(rs)


def test_verify_rejects_mint_aggregate_tampering() -> None:
    rs = _make_receipts(3)
    batch, _ = _make_batch(rs)
    tampered = batch.model_copy(update={"aggregate_mint_useful": batch.aggregate_mint_useful + 9999})
    oracle = OracleRate(epoch_number=1, cuc_per_useful=2)
    result = verify_batch(tampered, rs, oracle)
    assert not result.ok
    assert VerificationFault.MINT_AGGREGATE_MISMATCH in result.faults


def test_verify_rejects_underburn() -> None:
    rs = _make_receipts(3)
    batch, _ = _make_batch(rs)
    tampered = batch.model_copy(update={"aggregate_burn_cuc": 1})
    oracle = OracleRate(epoch_number=1, cuc_per_useful=2)
    result = verify_batch(tampered, rs, oracle)
    assert not result.ok
    assert VerificationFault.UNDERBURN in result.faults


def test_verify_rejects_overburn() -> None:
    rs = _make_receipts(3)
    batch, _ = _make_batch(rs)
    huge_burn = batch.aggregate_burn_cuc * 1000
    tampered = batch.model_copy(update={"aggregate_burn_cuc": huge_burn})
    oracle = OracleRate(epoch_number=1, cuc_per_useful=2)
    result = verify_batch(tampered, rs, oracle)
    assert not result.ok
    assert VerificationFault.OVERBURN in result.faults


def test_verify_rejects_bad_merkle_root() -> None:
    rs = _make_receipts(3)
    batch, _ = _make_batch(rs)
    tampered = batch.model_copy(update={"merkle_root": "00" * 32})
    oracle = OracleRate(epoch_number=1, cuc_per_useful=2)
    result = verify_batch(tampered, rs, oracle)
    assert not result.ok
    assert VerificationFault.MERKLE_ROOT_MISMATCH in result.faults


def test_verify_rejects_bad_signature() -> None:
    rs = _make_receipts(2)
    batch, _ = _make_batch(rs)
    tampered = batch.model_copy(update={"gateway_signature": ""})
    oracle = OracleRate(epoch_number=1, cuc_per_useful=2)
    result = verify_batch(tampered, rs, oracle)
    assert not result.ok
    assert VerificationFault.BAD_SIGNATURE in result.faults


def test_verify_rejects_epoch_mismatch() -> None:
    rs = _make_receipts(2)
    batch, _ = _make_batch(rs, epoch=1)
    oracle = OracleRate(epoch_number=99, cuc_per_useful=2)
    result = verify_batch(batch, rs, oracle)
    assert not result.ok
    assert VerificationFault.EPOCH_MISMATCH in result.faults


def test_verify_rejects_unsigned_oracle_rate_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OROGEN_ENV", "production")
    rs = _make_receipts(2)
    batch, pub = _make_batch(rs)
    oracle = OracleRate(epoch_number=1, cuc_per_useful=2)
    result = verify_batch(batch, rs, oracle, gateway_pubkey_hex=pub)
    assert not result.ok
    assert VerificationFault.BAD_ORACLE_SIGNATURE in result.faults


def test_verify_accepts_signed_oracle_rate_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OROGEN_ENV", "production")
    oracle_priv, oracle_pub = generate_keypair()
    op_priv, op_pub = generate_keypair()
    rs = [r.sign(op_priv) for r in _make_receipts(2)]
    batch, pub = _make_batch(rs)
    oracle = OracleRate(epoch_number=1, oracle_id="oracle-1", cuc_per_useful=2)
    oracle = oracle.model_copy(
        update={"signature": sign_ed25519(oracle_priv, oracle.signing_payload())}
    )
    result = verify_batch(
        batch,
        rs,
        oracle,
        gateway_pubkey_hex=pub,
        oracle_pubkey_hex=oracle_pub,
        operator_pubkeys={"op-1": op_pub},
    )
    assert result.ok, result.detail


def test_verify_checks_operator_receipt_signatures_when_registry_available() -> None:
    op_priv, op_pub = generate_keypair()
    rs = [r.sign(op_priv) for r in _make_receipts(2)]
    batch, pub = _make_batch(rs)
    oracle = OracleRate(epoch_number=1, cuc_per_useful=2)
    result = verify_batch(
        batch,
        rs,
        oracle,
        gateway_pubkey_hex=pub,
        operator_pubkeys={"op-1": op_pub},
    )
    assert result.ok, result.detail
    bad = rs[0].model_copy(update={"operator_signature": "00" * 64})
    result_bad = verify_batch(
        batch,
        [bad, rs[1]],
        oracle,
        gateway_pubkey_hex=pub,
        operator_pubkeys={"op-1": op_pub},
    )
    assert not result_bad.ok
    assert VerificationFault.BAD_RECEIPT_SIGNATURE in result_bad.faults


def test_execute_burn_succeeds_and_double_burn_rejected() -> None:
    rs = _make_receipts(3)
    batch, pub = _make_batch(rs)
    oracle = OracleRate(epoch_number=1, cuc_per_useful=2)
    chain = MockChainClient()
    app = build_app(BurnEngineConfig(engine_id="bme-1"), chain_client=chain)
    app.state.registry.register(batch.gateway_id, pub)
    with TestClient(app) as client:
        body = {
            "batch": batch.model_dump(mode="json"),
            "receipts": [r.model_dump(mode="json") for r in rs],
            "oracle_rate": oracle.model_dump(),
        }
        r = client.post("/execute_burn", json=body, headers=_hdrs())
        assert r.status_code == 200, r.text
        ev = r.json()
        assert ev["burn_event"]["burned_cuc"] == batch.aggregate_burn_cuc
        # Replay → 409 conflict.
        r2 = client.post("/execute_burn", json=body, headers=_hdrs())
        assert r2.status_code == 409


def test_execute_burn_rejects_bad_batch() -> None:
    rs = _make_receipts(2)
    batch, pub = _make_batch(rs)
    bad_batch = batch.model_copy(update={"aggregate_burn_cuc": 1})
    oracle = OracleRate(epoch_number=1, cuc_per_useful=2)
    app = build_app(BurnEngineConfig(engine_id="bme-1"), chain_client=MockChainClient())
    app.state.registry.register(batch.gateway_id, pub)
    with TestClient(app) as client:
        r = client.post(
            "/execute_burn",
            json={
                "batch": bad_batch.model_dump(mode="json"),
                "receipts": [r.model_dump(mode="json") for r in rs],
                "oracle_rate": oracle.model_dump(),
            },
            headers=_hdrs(),
        )
        assert r.status_code == 400


def test_execute_burn_rejects_forged_signature() -> None:
    """A batch with a 64-byte zeros 'signature' must NOT be accepted."""
    rs = _make_receipts(2)
    batch, _ = _make_batch(rs)
    forged = batch.model_copy(update={"gateway_signature": "00" * 64})
    oracle = OracleRate(epoch_number=1, cuc_per_useful=2)
    app = build_app(BurnEngineConfig(engine_id="bme-1"), chain_client=MockChainClient())
    # Register a real pubkey so the signature path is exercised end-to-end.
    _, real_pub = generate_keypair()
    app.state.registry.register(batch.gateway_id, real_pub)
    with TestClient(app) as client:
        r = client.post(
            "/execute_burn",
            json={
                "batch": forged.model_dump(mode="json"),
                "receipts": [r.model_dump(mode="json") for r in rs],
                "oracle_rate": oracle.model_dump(),
            },
            headers=_hdrs(),
        )
        assert r.status_code == 400
        assert "BadSignature" in r.text


def test_execute_burn_requires_internal_auth() -> None:
    rs = _make_receipts(1)
    batch, _ = _make_batch(rs)
    oracle = OracleRate(epoch_number=1, cuc_per_useful=2)
    app = build_app(BurnEngineConfig(engine_id="bme-1"), chain_client=MockChainClient())
    with TestClient(app) as client:
        r = client.post(
            "/execute_burn",
            json={
                "batch": batch.model_dump(mode="json"),
                "receipts": [r.model_dump(mode="json") for r in rs],
                "oracle_rate": oracle.model_dump(),
            },
        )
        assert r.status_code == 401


def test_verify_batch_endpoint_round_trip() -> None:
    rs = _make_receipts(4)
    batch, pub = _make_batch(rs)
    oracle = OracleRate(epoch_number=1, cuc_per_useful=2)
    app = build_app(BurnEngineConfig(engine_id="bme-1"), chain_client=MockChainClient())
    app.state.registry.register(batch.gateway_id, pub)
    with TestClient(app) as client:
        r = client.post(
            "/verify_batch",
            json={
                "batch": batch.model_dump(mode="json"),
                "receipts": [r.model_dump(mode="json") for r in rs],
                "oracle_rate": oracle.model_dump(),
            },
            headers=_hdrs(),
        )
        assert r.status_code == 200
        assert r.json()["ok"] is True


def test_healthz_and_events() -> None:
    app = build_app(BurnEngineConfig(engine_id="bme-x"), chain_client=MockChainClient())
    with TestClient(app) as client:
        h = client.get("/healthz")
        assert h.status_code == 200
        assert h.json()["engine_id"] == "bme-x"
        ev = client.get("/events", headers=_hdrs())
        assert ev.status_code == 200
        assert ev.json() == {"burns": [], "mints": []}
