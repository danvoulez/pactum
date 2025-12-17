use pretty_assertions::assert_eq;
use serde_json::Value;

use pactum::hash::hash_json;
use pactum::pactum::step_risk_pact_v0;

fn load(path: &str) -> Value {
    let s = std::fs::read_to_string(path).expect("read");
    serde_json::from_str(&s).expect("json")
}

#[test]
fn pactum_riskpact_v0_case2_golden() {
    // Load all input and expected output fixtures for case2
    let pact = load("tests/fixtures_case2/pact.json");
    let state0 = load("tests/fixtures_case2/state0.json");
    let envelope = load("tests/fixtures_case2/envelope.json");

    let expected_state1 = load("tests/fixtures_case2/expected_state1.json");
    let expected_outputs = load("tests/fixtures_case2/expected_outputs.json");
    let expected_trace = load("tests/fixtures_case2/expected_trace.json");
    let expected_receipt = load("tests/fixtures_case2/expected_receipt.json");

    // Run the Pactum state transition
    let (state1, outputs, trace, receipt) =
        step_risk_pact_v0(&pact, &state0, &envelope).expect("step_risk_pact_v0 should succeed");

    // 1. Verify structural equality of outputs
    assert_eq!(state1, expected_state1, "State1 mismatch");
    assert_eq!(outputs, expected_outputs, "Outputs mismatch");
    assert_eq!(trace, expected_trace, "Trace mismatch");

    // 2. Verify CRYPTOGRAPHIC HASHES in the receipt
    let pact_hash = hash_json("pactum:pact:0", &pact);
    let prev_state_hash = hash_json("pactum:state:0", &state0);
    let envelope_hash = hash_json("pactum:envelope:0", &envelope);
    let new_state_hash = hash_json("pactum:state:0", &state1);
    let outputs_hash = hash_json("pactum:outputs:0", &outputs);
    let trace_hash = hash_json("pactum:trace:0", &trace);

    let receipt_pact_hash = receipt
        .get("pact_hash")
        .and_then(|v| v.as_str())
        .expect("receipt.pact_hash");
    let receipt_prev_state_hash = receipt
        .get("prev_state_hash")
        .and_then(|v| v.as_str())
        .expect("receipt.prev_state_hash");
    let receipt_envelope_hash = receipt
        .get("envelope_hash")
        .and_then(|v| v.as_str())
        .expect("receipt.envelope_hash");
    let receipt_new_state_hash = receipt
        .get("new_state_hash")
        .and_then(|v| v.as_str())
        .expect("receipt.new_state_hash");
    let receipt_outputs_hash = receipt
        .get("outputs_hash")
        .and_then(|v| v.as_str())
        .expect("receipt.outputs_hash");
    let receipt_trace_hash = receipt
        .get("trace_hash")
        .and_then(|v| v.as_str())
        .expect("receipt.trace_hash");

    assert_eq!(receipt_pact_hash, pact_hash, "pact_hash mismatch");
    assert_eq!(
        receipt_prev_state_hash, prev_state_hash,
        "prev_state_hash mismatch"
    );
    assert_eq!(
        receipt_envelope_hash, envelope_hash,
        "envelope_hash mismatch"
    );
    assert_eq!(
        receipt_new_state_hash, new_state_hash,
        "new_state_hash mismatch"
    );
    assert_eq!(receipt_outputs_hash, outputs_hash, "outputs_hash mismatch");
    assert_eq!(receipt_trace_hash, trace_hash, "trace_hash mismatch");

    // 3. Optional receipt_hash check
    if let Some(expected_receipt_hash) = expected_receipt
        .get("receipt_hash")
        .and_then(|v| v.as_str())
    {
        let actual_receipt_hash = hash_json("pactum:receipt:0", &receipt);
        assert_eq!(
            actual_receipt_hash, expected_receipt_hash,
            "receipt_hash mismatch"
        );
    }

    println!("✅ Case2 golden test passed with full hash verification.");
}
