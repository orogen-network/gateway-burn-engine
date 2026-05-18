# gateway-burn-engine

Auditable burn execution and BME math for batch submission.

Per RFC-0004, the burn-engine is deliberately separated from the gateway-router HTTP path so
that:

1. The gateway can no longer "claim" a burn without producing a receipt for the underlying
   batch.
2. A separate operator (a "burn auditor") can run `verify_batch` against any sealed batch
   and refuse to submit if BME invariants fail.
3. The on-chain burn extrinsic is the only path that mints OROG.

## HTTP API

| Method | Path             | Body                                            | Result |
|--------|------------------|-------------------------------------------------|--------|
| POST   | `/verify_batch`  | `{batch, receipts, oracle_rate}`                | Verification result with faults + computed values. |
| POST   | `/execute_burn`  | same                                            | `BurnEvent` + `MintEvent` if accepted; 400 on verification fault; 409 on double-burn. |
| GET    | `/events`        |                                                 | All recorded burn + mint events. |
| GET    | `/healthz`       |                                                 | Liveness. |

## BME invariants (RFC-0004 §3.2)

- Sum of receipt token counts × 100 = `aggregate_mint_useful`.
- Merkle root over receipts = `batch.merkle_root`.
- Per-operator subtotals match per-operator receipt sums.
- `aggregate_burn_cuc ∈ [mint × oracle.min_ratio, mint × oracle.max_ratio]` to prevent
  underburn (FaultCode `FakeBurn`) and overburn (FaultCode `BatchOvercommit`).
- Gateway signature is well-formed.

## Chain client

`ChainClient` is a Protocol. `MockChainClient` ships with deterministic tx hashes and
double-burn detection — fine for tests + local devnet. Production wires a real substrate
client (substrate-interface or polkadot-py) once `chain-node` is bootable.
