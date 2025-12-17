# Pactum RiskPact V0.2 - Architecture & Design Decisions

This document provides an architectural analysis of Pactum RiskPact V0.2, focusing on the evolution from V0.1 and the critical design decisions that shape the protocol.

## V0.1 vs V0.2: Comparative Analysis

| Aspect | **Pactum V0.1** | **Pactum V0.2** | **Impact** |
| :--- | :--- | :--- | :--- |
| **Execution Model** | Sequential event processing | **Explicit phases (A-E)** with buffering and multi-round | Clearer separation of concerns. Enables batch processing within a round. |
| **Oracle Identity** | `signer_pub` validated against allowlist | **Hardening: `payload.oracle_id == signer_pub`** | Eliminates ambiguity and spoofing. Declared identity must be cryptographically provable. |
| **Sequence Control** | `oracle_seq` per oracle with monotonicity validation | Introduction of **`clock_round` and `metric_round`** in state | Makes round progress an explicit, global pact concept, not just per-oracle. Easier gap detection. |
| **Quorum Mechanism** | Grouping by `seq` | **Multi-round loop** with explicit `SEQ_SKIP` and `SEQ_REPLAY` detection | More robust. Processes all complete rounds in envelope, preventing jumps or replays. |
| **Aggregation Function** | Lower median for quorum >=2 | Explicit specification of **tie-break by `signer_pub`** | Guarantees absolute determinism even with identical `t` or `v` values from different oracles. |
| **Trace** | Application log | **Normative artifact** with defined format for quorum commits | Trace becomes mandatory part of proof of correct execution, not optional for debugging. |
| **Error Handling** | Stable error codes (`PCT_ERR_*`) | Integrated into specification as **conformance requirement** | Makes failure modes part of protocol interface, essential for clients and oracles. |

## Critical Design Decisions & Rationale

### 1. `oracle_id == signer_pub` (Hardening)

**Problem Solved**: In V0.1, an oracle could sign a message declaring to be another (`oracle_id: "X"`, `signer_pub: Y`). This created ambiguity in identity mapping.

**V0.2 Solution**: The declared identity (`oracle_id`) must be cryptographically verifiable. This makes the system **actively incapable** of false representation, a fundamental security principle.

**Security Impact**: Eliminates entire category of identity spoofing attacks and ensures cryptographic identity consistency in oracle tracking maps.

### 2. Phases and Multi-Round per Envelope

**Problem Solved**: In V0.1, quorum logic was applied on-demand for each event. This could lead to inconsistent states if an envelope contained events for multiple future rounds.

**V0.2 Solution**: Segregation into phases and a loop that processes complete rounds (e.g., `seq == round+1`) ensures state advances **monotonically and predictably**. An envelope can now contain catch-up of multiple rounds at once, which is efficient and realistic for batch systems.

**Efficiency Impact**: Enables throughput optimization by batching multiple rounds in a single envelope while maintaining determinism.

### 3. `clock_round` / `metric_round` in State

**Problem Solved**: Tracking `seq` only per oracle (`oracle_seq:{}`) doesn't provide a global view of pact progress.

**V0.2 Solution**: Protocol round becomes an explicit state variable. This is crucial for:

- **Gap Detection**: Trivial to verify `SEQ_SKIP`
- **Synchronization**: New participants can easily verify the last consensused round
- **Business Logic**: Breach logic can be tied to clock round, not just individual events

**Consensus Impact**: Makes round progress a first-class concept, enabling better coordination and state machine reasoning.

### 4. Errors as Stable Tokens (`PCT_ERR_*`)

**Problem Solved**: Natural language error messages are fragile for integration and testing.

**V0.2 Solution**: Encoding failures as stable tokens transforms the protocol into a **verifiable finite state machine**. A client can programmatically distinguish between "quorum not met" and "invalid signature", enabling different recovery strategies.

**Integration Impact**: Enables robust client-side error handling and automated testing with stable assertions.

## Implementation Considerations

### Complexity Management

The multi-round loop algorithm ("while events exist with `seq == round+1`") must be **extremely efficient and deterministic**. Event ordering within a round for median calculation must follow the exact tie-break rule.

**Recommendation**: Implement Phase C (clock rounds) and Phase D (metric rounds) as separate, well-tested functions with explicit loop invariants.

### Test Coverage

The test suite must be expanded to cover new failure modes:
- `PCT_ERR_ORACLE_ID_MISMATCH`
- `PCT_ERR_SEQ_REPLAY`
- `PCT_ERR_SEQ_SKIP` (gap detection)
- Multi-round quorum partial failures

**Current Coverage**: Case1-11 provide comprehensive coverage of positive and negative paths.

### Compatibility Strategy

V0.2 is a **breaking change**. V0.1 states and envelopes will not be processable by a V0.2 runtime. The `pact.runtime` field provides explicit versioning to prevent accidental incompatibility.

**Migration Path**: 
- V0.1 pacts must be explicitly migrated or recreated
- Runtime validation should reject V0.1 pacts when `runtime` field is present
- Consider providing migration utilities if V0.1 adoption exists

## Protocol Evolution Philosophy

Pactum V0.2 represents the transition from a **functional prototype to a proper protocol with formal guarantees and hard invariants**. Key principles:

1. **Determinism First**: Every operation must be deterministic and verifiable
2. **Security by Design**: Hard invariants prevent entire classes of attacks
3. **Explicit State**: Round progress and oracle tracking are first-class state variables
4. **Conformance Testing**: Golden tests and negative tests lock behavior
5. **Cross-Language Parity**: Protocol is language-agnostic; implementations must match

## Next Steps for V0.3+

Potential enhancements while maintaining V0.2 compatibility:

- **Multi-oracle quorum proofs**: Record signature sets that compose quorum
- **Quorum set rotation**: Allow oracle sets to change over time windows
- **ZK integration**: Zero-knowledge proofs for privacy-preserving execution
- **Performance optimizations**: Parallel processing of independent rounds

Each enhancement should:
1. Maintain backward compatibility with V0.2 fixtures
2. Add new test cases (golden + negative)
3. Update specification with clear versioning
4. Preserve all existing invariants

---

This architecture document complements the [SPECIFICATION.md](../SPECIFICATION.md) by providing context, rationale, and implementation guidance for the design decisions that shape Pactum V0.2.

