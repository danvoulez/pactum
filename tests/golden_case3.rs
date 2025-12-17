use pretty_assertions::assert_eq;
use serde_json::Value;

use pactum::hash::hash_json;
use pactum::pactum::step_risk_pact_v0;

fn load(path: &str) -> Value {
    let s = std::fs::read_to_string(path).expect("read");
    serde_json::from_str(&s).expect("json")
}

#[test]
fn pactum_riskpact_v0_case3_golden() {
    let base = "tests/fixtures_case3";

    let pact = load(&format!("{base}/pact.json"));
    let state0 = load(&format!("{base}/state0.json"));
    let envelope = load(&format!("{base}/envelope.json"));

    let expected_state1 = load(&format!("{base}/expected_state1.json"));
    let expected_outputs = load(&format!("{base}/expected_outputs.json"));
    let expected_trace = load(&format!("{base}/expected_trace.json"));
    let expected_receipt = load(&format!("{base}/expected_receipt.json"));

    let (state1, outputs, trace, receipt) =
        step_risk_pact_v0(&pact, &state0, &envelope).expect("step");

    // Structural equality
    assert_eq!(state1, expected_state1, "State1 mismatch");
    assert_eq!(outputs, expected_outputs, "Outputs mismatch");
    assert_eq!(trace, expected_trace, "Trace mismatch");

    // Receipt equality (excluding receipt_hash)
    let mut expected_receipt_no_hash = expected_receipt.clone();
    if let Some(obj) = expected_receipt_no_hash.as_object_mut() {
        obj.remove("receipt_hash");
    }
    assert_eq!(
        receipt, expected_receipt_no_hash,
        "Receipt mismatch (excluding receipt_hash)"
    );

    // Hash verification
    let pact_hash = hash_json("pactum:pact:0", &pact);
    let prev_state_hash = hash_json("pactum:state:0", &state0);
    let envelope_hash = hash_json("pactum:envelope:0", &envelope);
    let new_state_hash = hash_json("pactum:state:0", &state1);
    let outputs_hash = hash_json("pactum:outputs:0", &outputs);
    let trace_hash = hash_json("pactum:trace:0", &trace);

    assert_eq!(receipt["pact_hash"].as_str().unwrap(), pact_hash);
    assert_eq!(
        receipt["prev_state_hash"].as_str().unwrap(),
        prev_state_hash
    );
    assert_eq!(receipt["envelope_hash"].as_str().unwrap(), envelope_hash);
    assert_eq!(receipt["new_state_hash"].as_str().unwrap(), new_state_hash);
    assert_eq!(receipt["outputs_hash"].as_str().unwrap(), outputs_hash);
    assert_eq!(receipt["trace_hash"].as_str().unwrap(), trace_hash);

    // Optional receipt_hash check (non-recursive)
    if let Some(expected_rh) = expected_receipt
        .get("receipt_hash")
        .and_then(|v| v.as_str())
    {
        let actual_rh = hash_json("pactum:receipt:0", &receipt);
        assert_eq!(actual_rh, expected_rh, "receipt_hash mismatch");
    }
}
