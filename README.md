# Pactum RiskPact V0.2

A Rust implementation of Pactum RiskPact V0.2 - a deterministic protocol for canonical JSON, hashing, and Ed25519 signatures with multi-round envelope support and hardened quorum semantics.

## Overview

Pactum V0 provides:
- **Canonical JSON serialization** with deterministic key ordering
- **Domain-separated SHA-256 hashing** for cryptographic commitments
- **Ed25519 signature verification** for event authentication
- **Deterministic state transitions** for RiskPact execution

## Building

```bash
cargo build
```

## Generating Test Fixtures

Generate deterministic test fixtures with real Ed25519 signatures:

```bash
# Generate primary test case
cargo run --bin gen_fixtures

# Generate edge case test (breach recovery/restart)
cargo run --bin gen_fixtures_case2

# Generate quorum test cases
cargo run --bin gen_fixtures_case3  # Quorum=2 positive test
cargo run --bin gen_fixtures_case4_quorum_not_met  # Negative: quorum not met
cargo run --bin gen_fixtures_case5_duplicate_signer  # Negative: duplicate signer
cargo run --bin gen_fixtures_case6_seq_skip  # Negative: sequence skip
```

This creates canonical JSON fixtures in `tests/fixtures/` and `tests/fixtures_case*/`:
- `pact.json` - Pact IR definition
- `state0.json` - Initial state
- `envelope.json` - Input events
- `expected_state1.json` - Expected final state
- `expected_outputs.json` - Expected effects
- `expected_trace.json` - Expected execution trace
- `expected_receipt.json` - Expected receipt with hashes

## Running Tests

### Quick validation (all tests)

**Rust:**
```bash
cargo fmt --check && cargo clippy -- -D warnings && cargo test
```

**TypeScript:**
```bash
cd ts && npm ci && npm run golden && npm run golden:case2 && npm run golden:case3 && npm run golden:case7 \
  && npm run fail:case4 && npm run fail:case5 && npm run fail:case6 && npm run fail:case8 && npm run fail:case9 && npm run fail:case10 && npm run fail:case11
```

### Individual tests

```bash
# Run all tests
cargo test

# Run specific golden test
cargo test pactum_riskpact_v0_golden
cargo test pactum_riskpact_v0_case2_golden
cargo test pactum_riskpact_v0_case3_golden
```

The golden tests verify:
1. Structural equality of outputs (state, outputs, trace)
2. Cryptographic hash consistency in receipts
3. Deterministic execution across runs
4. Authorization checks (signers must match allowed keys)
5. Quorum integrity (Case3: positive, Case4-6: negative safety invariants)

## TypeScript Conformance

A TypeScript implementation is provided to verify cross-language determinism:

```bash
cd ts
npm install
npm run golden
```

The TypeScript implementation produces identical hashes and state transitions as the Rust implementation, proving Pactum V0 is a true protocol, not a Rust artifact.

## CI/CD

The project includes GitHub Actions CI that runs:
- `cargo fmt --check` - Format checking
- `cargo clippy -- -D warnings` - Linting
- `cargo test` - All tests
- Fixture generation and verification

## Project Structure

- `src/canon.rs` - Canonical JSON serialization
- `src/hash.rs` - Domain-separated SHA-256 hashing
- `src/pactum.rs` - Main step function and event verification (with quorum support)
- `src/bin/gen_fixtures*.rs` - Fixture generators (case1-6)
- `tests/golden*.rs` - Golden tests (case1-3: positive, case4-6: negative)
- `ts/` - TypeScript conformance implementation
- `.github/workflows/ci.yml` - CI/CD pipeline with Rust and TypeScript validation

## Error Codes

Pactum V0.2 uses stable error codes for reliable error detection. Negative test cases (Case4-11) verify these codes are present in error messages:

- **PCT_ERR_QUORUM_NOT_MET** — Quorum não atingido no round alvo
- **PCT_ERR_DUP_SIGNER** — Mesmo signer_pub repetido no mesmo round
- **PCT_ERR_SEQ_SKIP** — Seq diferente do round+1 (gap não permitido)
- **PCT_ERR_SEQ_REPLAY** — Seq <= round atual (replay não permitido)
- **PCT_ERR_ORACLE_ID_MISMATCH** — oracle_id no payload não corresponde ao signer_pub

These codes are embedded in error messages (both human-readable text and stable token), allowing tests to match on the stable substring while error formatting can evolve.

## Specification

See `Here's a canonical JSON + hashing + sign.md` for the complete specification.

