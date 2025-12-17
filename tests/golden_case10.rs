use pactum::pactum::step_risk_pact_v0;
use serde_json::Value;

fn load(path: &str) -> Value {
    let s = std::fs::read_to_string(path).expect("read");
    serde_json::from_str(&s).expect("json")
}

#[test]
fn pactum_case10_seq_replay_rejects() {
    let base = "tests/fixtures_case10";
    let pact = load(&format!("{base}/pact.json"));
    let state0 = load(&format!("{base}/state0.json"));
    let envelope = load(&format!("{base}/envelope.json"));

    let expected =
        std::fs::read_to_string(&format!("{base}/expected_error.txt")).expect("expected_error");
    let err = step_risk_pact_v0(&pact, &state0, &envelope).unwrap_err();
    let msg = format!("{err}");

    assert!(
        msg.contains(expected.trim()),
        "expected {:?}, got {:?}",
        expected.trim(),
        msg
    );
}
