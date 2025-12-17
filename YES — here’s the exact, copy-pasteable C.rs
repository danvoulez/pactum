YES — here’s the exact, copy-pasteable Case3 fixture generator + golden test, plus the TypeScript runner update so TS also proves quorum determinism against the new fixtures.

This assumes your runtime already implements V0.1 quorum commit (buffer → commit clock quorum → commit metric quorum → claims).

⸻

Rust: src/bin/gen_fixtures_case3.rs

Creates a quorum=2 pact (2 clock oracles + 2 metric oracles) and a single envelope where:
	•	clock round 1 has two t values → effective_clock_t = lower median
	•	metric round 1 has two v values → effective_metric_v = lower median
	•	duration_d = "0" so trigger becomes true immediately after breach starts
	•	claim succeeds in the same envelope

Writes to tests/fixtures_case3/.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

use pactum::canon::canonical_string;
use pactum::hash::{h_sha256, prefixed_hex_sha256};
use pactum::pactum::{hash_json, step_risk_pact_v0};

fn derive_signing_key(label: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"pactum:fixture:key:0");
    hasher.update([0u8]);
    hasher.update(label.as_bytes());
    let out = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&out[..32]);
    SigningKey::from_bytes(&seed)
}

fn enc_pub(vk: &VerifyingKey) -> String {
    format!("ed25519:{}", URL_SAFE_NO_PAD.encode(vk.to_bytes()))
}

fn enc_sig(sig_bytes: [u8; 64]) -> String {
    format!("ed25519sig:{}", URL_SAFE_NO_PAD.encode(sig_bytes))
}

fn sign_event(kind: &str, pact_hash: &str, payload: Value, signer: &SigningKey) -> Value {
    let signer_pub = enc_pub(&signer.verifying_key());

    let body = json!({
        "v": "pactum-event/0",
        "kind": kind,
        "pact_hash": pact_hash,
        "payload": payload,
        "signer_pub": signer_pub
    });

    let body_hash_prefixed = hash_json("pactum:event:0", &body);
    let body_hex = body_hash_prefixed.strip_prefix("sha256:").unwrap();
    let body_hash_bytes = hex::decode(body_hex).unwrap();

    let mut msg = Vec::with_capacity("pactum:sig:event:0".len() + 1 + 32);
    msg.extend_from_slice(b"pactum:sig:event:0");
    msg.push(0u8);
    msg.extend_from_slice(&body_hash_bytes);

    let sig = signer.sign(&msg);
    let sig_bytes: [u8; 64] = sig.to_bytes();

    let mut ev = body;
    ev.as_object_mut()
        .unwrap()
        .insert("sig".to_string(), Value::String(enc_sig(sig_bytes)));
    ev
}

fn write_canon(path: &str, v: &Value) {
    let s = canonical_string(v);
    fs::write(path, format!("{s}\n")).expect("write");
}

fn main() {
    let out_dir = Path::new("tests/fixtures_case3");
    fs::create_dir_all(out_dir).expect("mkdir tests/fixtures_case3");

    // Parties
    let party_a = derive_signing_key("party:a");
    let party_b = derive_signing_key("party:b");

    // Two clock oracles + two metric oracles
    let clock1 = derive_signing_key("oracle:clock1");
    let clock2 = derive_signing_key("oracle:clock2");
    let metric1 = derive_signing_key("oracle:metric1");
    let metric2 = derive_signing_key("oracle:metric2");

    // Pact: quorum=2 for both clock and metric
    // duration_d = "0" so trigger becomes true immediately on breach start.
    let pact = json!({
        "v":"pactum-ir/0",
        "type":"risk_pact",
        "time":{"unit":"ms_epoch"},
        "hash":{"alg":"sha256"},
        "parties":{
            "a_pub": enc_pub(&party_a.verifying_key()),
            "b_pub": enc_pub(&party_b.verifying_key())
        },
        "assets":{
            "collateral_asset":"asset:USDc",
            "settlement_asset":"asset:USDc"
        },
        "terms":{
            "metric_id":"metric:ETHUSD",
            "threshold_z":"100",
            "duration_d":"0",
            "cap_q":"100"
        },
        "oracles":{
            "clock":{
                "mode":"oracle_feed",
                "quorum":"2",
                "pubkeys":[
                    enc_pub(&clock1.verifying_key()),
                    enc_pub(&clock2.verifying_key())
                ]
            },
            "metric":{
                "quorum":"2",
                "pubkeys":[
                    enc_pub(&metric1.verifying_key()),
                    enc_pub(&metric2.verifying_key())
                ]
            }
        }
    });

    let pact_hash = hash_json("pactum:pact:0", &pact);

    // State includes quorum rounds
    let state0 = json!({
        "v":"pactum-state/0",
        "pact_hash": pact_hash,
        "now":"0",
        "collateral_posted":"0",
        "metric_last":{"t":"0","v":"0"},
        "breach_start_time": null,
        "triggered": false,
        "claim_paid":"0",
        "oracle_seq": {},
        "oracle_time": {},
        "clock_round":"0",
        "metric_round":"0"
    });

    // Round-1 times chosen so lower median is the smaller one.
    let t1 = "1734390000000"; // smaller
    let t2 = "1734390001000"; // larger

    // Metric values: lower median should select 95 (below threshold)
    let mv_low = "95";
    let mv_high = "105";
    let mt1 = "1734390000500";
    let mt2 = "1734390000600";

    let mut events: Vec<Value> = vec![];

    // Collateral
    events.push(sign_event(
        "collateral_post",
        state0["pact_hash"].as_str().unwrap(),
        json!({"from":"party:a","amount":"1000","asset":"asset:USDc","nonce":"1"}),
        &party_a,
    ));

    // Clock quorum round 1 (seq=1): two distinct signers
    events.push(sign_event(
        "clock_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":"oracle:clock1","t":t1,"seq":"1"}),
        &clock1,
    ));
    events.push(sign_event(
        "clock_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":"oracle:clock2","t":t2,"seq":"1"}),
        &clock2,
    ));

    // Metric quorum round 1 (seq=1): two distinct signers
    events.push(sign_event(
        "metric_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":"oracle:metric1","metric_id":"metric:ETHUSD","t":mt1,"v":mv_low,"seq":"1"}),
        &metric1,
    ));
    events.push(sign_event(
        "metric_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":"oracle:metric2","metric_id":"metric:ETHUSD","t":mt2,"v":mv_high,"seq":"1"}),
        &metric2,
    ));

    // Claim should succeed (duration=0 + breach started)
    events.push(sign_event(
        "claim_request",
        state0["pact_hash"].as_str().unwrap(),
        json!({"by":"party:b","amount":"10","nonce":"1"}),
        &party_b,
    ));

    let envelope = json!({"v":"pactum-envelope/0","events":events});

    // Compute expected artifacts via runtime
    let (state1, outputs, trace, receipt) =
        step_risk_pact_v0(&pact, &state0, &envelope).expect("step");

    // Optional receipt_hash (non-recursive)
    let receipt_hash = {
        let canon = canonical_string(&receipt);
        let d = h_sha256("pactum:receipt:0", canon.as_bytes());
        prefixed_hex_sha256(d)
    };
    let mut receipt2 = receipt.clone();
    receipt2.as_object_mut().unwrap().insert("receipt_hash".to_string(), Value::String(receipt_hash));

    // Write fixtures
    write_canon("tests/fixtures_case3/pact.json", &pact);
    write_canon("tests/fixtures_case3/state0.json", &state0);
    write_canon("tests/fixtures_case3/envelope.json", &envelope);

    write_canon("tests/fixtures_case3/expected_state1.json", &state1);
    write_canon("tests/fixtures_case3/expected_outputs.json", &outputs);
    write_canon("tests/fixtures_case3/expected_trace.json", &trace);
    write_canon("tests/fixtures_case3/expected_receipt.json", &receipt2);

    eprintln!("✅ Wrote case3 quorum fixtures to tests/fixtures_case3/");
}

Add it to README scripts (optional) and run:

cargo run --bin gen_fixtures_case3


⸻

Rust: tests/golden_case3.rs

Same pattern as your case1/case2, just points to tests/fixtures_case3.

use pretty_assertions::assert_eq;
use serde_json::Value;

use pactum::pactum::{hash_json, step_risk_pact_v0};

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
    assert_eq!(receipt, expected_receipt_no_hash, "Receipt mismatch (excluding receipt_hash)");

    // Hash verification
    let pact_hash = hash_json("pactum:pact:0", &pact);
    let prev_state_hash = hash_json("pactum:state:0", &state0);
    let envelope_hash = hash_json("pactum:envelope:0", &envelope);
    let new_state_hash = hash_json("pactum:state:0", &state1);
    let outputs_hash = hash_json("pactum:outputs:0", &outputs);
    let trace_hash = hash_json("pactum:trace:0", &trace);

    assert_eq!(receipt["pact_hash"].as_str().unwrap(), pact_hash);
    assert_eq!(receipt["prev_state_hash"].as_str().unwrap(), prev_state_hash);
    assert_eq!(receipt["envelope_hash"].as_str().unwrap(), envelope_hash);
    assert_eq!(receipt["new_state_hash"].as_str().unwrap(), new_state_hash);
    assert_eq!(receipt["outputs_hash"].as_str().unwrap(), outputs_hash);
    assert_eq!(receipt["trace_hash"].as_str().unwrap(), trace_hash);

    // Optional receipt_hash check (non-recursive)
    if let Some(expected_rh) = expected_receipt.get("receipt_hash").and_then(|v| v.as_str()) {
        let actual_rh = hash_json("pactum:receipt:0", &receipt);
        assert_eq!(actual_rh, expected_rh, "receipt_hash mismatch");
    }
}

Run:

cargo test pactum_riskpact_v0_case3_golden


⸻

TypeScript: make golden.ts accept a fixture dir

Update ts/src/golden.ts so you can run case1/case2/case3 without duplicating code.

Replace your FIX computation with:

const fixtureDir = process.argv[2] ?? path.join("..", "tests", "fixtures");

And load from fixtureDir instead of FIX.

Then add scripts:

ts/package.json scripts

"scripts": {
  "golden": "tsx src/golden.ts ../tests/fixtures",
  "golden:case2": "tsx src/golden.ts ../tests/fixtures_case2",
  "golden:case3": "tsx src/golden.ts ../tests/fixtures_case3"
}

Run:

cd ts
npm run golden:case3


⸻

What Case3 locks in

This case makes it impossible to accidentally change:
	•	“commit quorum before claims”
	•	“quorum is based on distinct authorized signers”
	•	“lower median selection for even participant counts”
	•	“one round per envelope (seq rules)”

If you want, next we can add Case4: quorum not met (should hard-fail) and Case5: duplicate signer in same round (reject), which are the two most important safety invariants after Case3.


----


Awesome — Case4 and Case5 are exactly the two “safety rails” that keep quorum from getting fuzzy over time.

Below are two more Rust fixture generators + golden tests. They generate invalid envelopes and assert the runtime rejects with the right class of error.

I’ll keep them lean and deterministic, reusing the same deterministic key derivation and signing approach as Case3.

⸻

Case4: Quorum not met → MUST reject

src/bin/gen_fixtures_case4_quorum_not_met.rs
	•	Pact: clock.quorum="2" but envelope provides only one clock event for seq=1.
	•	Everything else is valid (pact_hash, signature, allowlist) so we hit the intended failure.

Writes:
	•	tests/fixtures_case4/ (inputs only)
	•	tests/fixtures_case4/expected_error.txt

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

use pactum::canon::canonical_string;
use pactum::pactum::{hash_json};

fn derive_signing_key(label: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"pactum:fixture:key:0");
    hasher.update([0u8]);
    hasher.update(label.as_bytes());
    let out = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&out[..32]);
    SigningKey::from_bytes(&seed)
}

fn enc_pub(vk: &VerifyingKey) -> String {
    format!("ed25519:{}", URL_SAFE_NO_PAD.encode(vk.to_bytes()))
}

fn enc_sig(sig_bytes: [u8; 64]) -> String {
    format!("ed25519sig:{}", URL_SAFE_NO_PAD.encode(sig_bytes))
}

fn sign_event(kind: &str, pact_hash: &str, payload: Value, signer: &SigningKey) -> Value {
    let signer_pub = enc_pub(&signer.verifying_key());
    let body = json!({
        "v": "pactum-event/0",
        "kind": kind,
        "pact_hash": pact_hash,
        "payload": payload,
        "signer_pub": signer_pub
    });

    let body_hash_prefixed = hash_json("pactum:event:0", &body);
    let body_hex = body_hash_prefixed.strip_prefix("sha256:").unwrap();
    let body_hash_bytes = hex::decode(body_hex).unwrap();

    let mut msg = Vec::with_capacity("pactum:sig:event:0".len() + 1 + 32);
    msg.extend_from_slice(b"pactum:sig:event:0");
    msg.push(0u8);
    msg.extend_from_slice(&body_hash_bytes);

    let sig = signer.sign(&msg);
    let sig_bytes: [u8; 64] = sig.to_bytes();

    let mut ev = body;
    ev.as_object_mut().unwrap().insert("sig".to_string(), Value::String(enc_sig(sig_bytes)));
    ev
}

fn write_canon(path: &str, v: &Value) {
    fs::write(path, format!("{}\n", canonical_string(v))).expect("write");
}

fn main() {
    let out_dir = Path::new("tests/fixtures_case4");
    fs::create_dir_all(out_dir).expect("mkdir");

    let party_a = derive_signing_key("party:a");
    let party_b = derive_signing_key("party:b");

    let clock1 = derive_signing_key("oracle:clock1");
    let clock2 = derive_signing_key("oracle:clock2");
    let metric1 = derive_signing_key("oracle:metric1");
    let metric2 = derive_signing_key("oracle:metric2");

    let pact = json!({
        "v":"pactum-ir/0",
        "type":"risk_pact",
        "time":{"unit":"ms_epoch"},
        "hash":{"alg":"sha256"},
        "parties":{
            "a_pub": enc_pub(&party_a.verifying_key()),
            "b_pub": enc_pub(&party_b.verifying_key())
        },
        "assets":{"collateral_asset":"asset:USDc","settlement_asset":"asset:USDc"},
        "terms":{"metric_id":"metric:ETHUSD","threshold_z":"100","duration_d":"0","cap_q":"100"},
        "oracles":{
            "clock":{"mode":"oracle_feed","quorum":"2","pubkeys":[enc_pub(&clock1.verifying_key()), enc_pub(&clock2.verifying_key())]},
            "metric":{"quorum":"2","pubkeys":[enc_pub(&metric1.verifying_key()), enc_pub(&metric2.verifying_key())]}
        }
    });

    let pact_hash = hash_json("pactum:pact:0", &pact);

    let state0 = json!({
        "v":"pactum-state/0",
        "pact_hash": pact_hash,
        "now":"0",
        "collateral_posted":"0",
        "metric_last":{"t":"0","v":"0"},
        "breach_start_time": null,
        "triggered": false,
        "claim_paid":"0",
        "oracle_seq": {},
        "oracle_time": {},
        "clock_round":"0",
        "metric_round":"0"
    });

    // Only ONE clock event (quorum=2 => should fail)
    let mut events: Vec<Value> = vec![];
    events.push(sign_event(
        "clock_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":"oracle:clock1","t":"1734390000000","seq":"1"}),
        &clock1,
    ));

    let envelope = json!({"v":"pactum-envelope/0","events":events});

    write_canon("tests/fixtures_case4/pact.json", &pact);
    write_canon("tests/fixtures_case4/state0.json", &state0);
    write_canon("tests/fixtures_case4/envelope.json", &envelope);

    // Error contains a stable substring you choose in your runtime (recommended)
    fs::write("tests/fixtures_case4/expected_error.txt", "oracle quorum not met\n").expect("write expected_error");

    eprintln!("✅ Wrote case4 (quorum not met) inputs to tests/fixtures_case4/");
}

tests/golden_case4.rs

use serde_json::Value;
use pactum::pactum::step_risk_pact_v0;

fn load(path: &str) -> Value {
    let s = std::fs::read_to_string(path).expect("read");
    serde_json::from_str(&s).expect("json")
}

#[test]
fn pactum_case4_quorum_not_met_rejects() {
    let base = "tests/fixtures_case4";
    let pact = load(&format!("{base}/pact.json"));
    let state0 = load(&format!("{base}/state0.json"));
    let envelope = load(&format!("{base}/envelope.json"));

    let expected = std::fs::read_to_string(&format!("{base}/expected_error.txt")).expect("expected_error");
    let err = step_risk_pact_v0(&pact, &state0, &envelope).unwrap_err();
    let msg = format!("{err}");

    assert!(
        msg.contains(expected.trim()),
        "expected error containing {:?}, got {:?}",
        expected.trim(),
        msg
    );
}

Run:

cargo run --bin gen_fixtures_case4_quorum_not_met
cargo test pactum_case4_quorum_not_met_rejects


⸻

Case5: Duplicate signer in same round → MUST reject

src/bin/gen_fixtures_case5_duplicate_signer.rs
	•	Pact: clock.quorum="2"
	•	Envelope includes two clock events seq=1 signed by the same oracle key.
	•	This must reject with a stable message like "duplicate oracle signer".

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

use pactum::canon::canonical_string;
use pactum::pactum::hash_json;

fn derive_signing_key(label: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"pactum:fixture:key:0");
    hasher.update([0u8]);
    hasher.update(label.as_bytes());
    let out = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&out[..32]);
    SigningKey::from_bytes(&seed)
}

fn enc_pub(vk: &VerifyingKey) -> String {
    format!("ed25519:{}", URL_SAFE_NO_PAD.encode(vk.to_bytes()))
}

fn enc_sig(sig_bytes: [u8; 64]) -> String {
    format!("ed25519sig:{}", URL_SAFE_NO_PAD.encode(sig_bytes))
}

fn sign_event(kind: &str, pact_hash: &str, payload: Value, signer: &SigningKey) -> Value {
    let signer_pub = enc_pub(&signer.verifying_key());
    let body = json!({
        "v": "pactum-event/0",
        "kind": kind,
        "pact_hash": pact_hash,
        "payload": payload,
        "signer_pub": signer_pub
    });

    let body_hash_prefixed = hash_json("pactum:event:0", &body);
    let body_hex = body_hash_prefixed.strip_prefix("sha256:").unwrap();
    let body_hash_bytes = hex::decode(body_hex).unwrap();

    let mut msg = Vec::with_capacity("pactum:sig:event:0".len() + 1 + 32);
    msg.extend_from_slice(b"pactum:sig:event:0");
    msg.push(0u8);
    msg.extend_from_slice(&body_hash_bytes);

    let sig = signer.sign(&msg);
    let sig_bytes: [u8; 64] = sig.to_bytes();

    let mut ev = body;
    ev.as_object_mut().unwrap().insert("sig".to_string(), Value::String(enc_sig(sig_bytes)));
    ev
}

fn write_canon(path: &str, v: &Value) {
    fs::write(path, format!("{}\n", canonical_string(v))).expect("write");
}

fn main() {
    let out_dir = Path::new("tests/fixtures_case5");
    fs::create_dir_all(out_dir).expect("mkdir");

    let party_a = derive_signing_key("party:a");
    let party_b = derive_signing_key("party:b");

    let clock1 = derive_signing_key("oracle:clock1");
    let clock2 = derive_signing_key("oracle:clock2");
    let metric1 = derive_signing_key("oracle:metric1");
    let metric2 = derive_signing_key("oracle:metric2");

    let pact = json!({
        "v":"pactum-ir/0",
        "type":"risk_pact",
        "time":{"unit":"ms_epoch"},
        "hash":{"alg":"sha256"},
        "parties":{
            "a_pub": enc_pub(&party_a.verifying_key()),
            "b_pub": enc_pub(&party_b.verifying_key())
        },
        "assets":{"collateral_asset":"asset:USDc","settlement_asset":"asset:USDc"},
        "terms":{"metric_id":"metric:ETHUSD","threshold_z":"100","duration_d":"0","cap_q":"100"},
        "oracles":{
            "clock":{"mode":"oracle_feed","quorum":"2","pubkeys":[enc_pub(&clock1.verifying_key()), enc_pub(&clock2.verifying_key())]},
            "metric":{"quorum":"2","pubkeys":[enc_pub(&metric1.verifying_key()), enc_pub(&metric2.verifying_key())]}
        }
    });

    let pact_hash = hash_json("pactum:pact:0", &pact);

    let state0 = json!({
        "v":"pactum-state/0",
        "pact_hash": pact_hash,
        "now":"0",
        "collateral_posted":"0",
        "metric_last":{"t":"0","v":"0"},
        "breach_start_time": null,
        "triggered": false,
        "claim_paid":"0",
        "oracle_seq": {},
        "oracle_time": {},
        "clock_round":"0",
        "metric_round":"0"
    });

    // Duplicate signer: clock1 signs twice for seq=1
    let mut events: Vec<Value> = vec![];
    events.push(sign_event(
        "clock_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":"oracle:clock1","t":"1734390000000","seq":"1"}),
        &clock1,
    ));
    events.push(sign_event(
        "clock_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":"oracle:clock1","t":"1734390001000","seq":"1"}),
        &clock1,
    ));

    let envelope = json!({"v":"pactum-envelope/0","events":events});

    write_canon("tests/fixtures_case5/pact.json", &pact);
    write_canon("tests/fixtures_case5/state0.json", &state0);
    write_canon("tests/fixtures_case5/envelope.json", &envelope);

    fs::write("tests/fixtures_case5/expected_error.txt", "duplicate oracle signer\n").expect("write expected_error");

    eprintln!("✅ Wrote case5 (duplicate signer) inputs to tests/fixtures_case5/");
}

tests/golden_case5.rs

use serde_json::Value;
use pactum::pactum::step_risk_pact_v0;

fn load(path: &str) -> Value {
    let s = std::fs::read_to_string(path).expect("read");
    serde_json::from_str(&s).expect("json")
}

#[test]
fn pactum_case5_duplicate_signer_rejects() {
    let base = "tests/fixtures_case5";
    let pact = load(&format!("{base}/pact.json"));
    let state0 = load(&format!("{base}/state0.json"));
    let envelope = load(&format!("{base}/envelope.json"));

    let expected = std::fs::read_to_string(&format!("{base}/expected_error.txt")).expect("expected_error");
    let err = step_risk_pact_v0(&pact, &state0, &envelope).unwrap_err();
    let msg = format!("{err}");

    assert!(
        msg.contains(expected.trim()),
        "expected error containing {:?}, got {:?}",
        expected.trim(),
        msg
    );
}

Run:

cargo run --bin gen_fixtures_case5_duplicate_signer
cargo test pactum_case5_duplicate_signer_rejects


⸻

TypeScript parity: negative tests too

You can reuse the exact same fixture folders from Rust and have TS just run and assert it throws.

Add a script that expects failure:

ts/src/expect_fail.ts

import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import { stepRiskPactV0 } from "./pactum";

function load(p: string) { return JSON.parse(fs.readFileSync(p, "utf8")); }

const dir = process.argv[2];
if (!dir) throw new Error("usage: tsx src/expect_fail.ts <fixture_dir>");

const pact = load(path.join(dir, "pact.json"));
const state0 = load(path.join(dir, "state0.json"));
const envelope = load(path.join(dir, "envelope.json"));
const expected = fs.readFileSync(path.join(dir, "expected_error.txt"), "utf8").trim();

let ok = false;
try {
  stepRiskPactV0(pact, state0, envelope);
} catch (e: any) {
  ok = String(e?.message ?? e).includes(expected);
  if (!ok) {
    throw new Error(`Expected error containing "${expected}", got "${String(e?.message ?? e)}"`);
  }
}
assert.equal(ok, true);
console.log("✅ Expected failure observed:", expected);

ts/package.json

"scripts": {
  "fail:case4": "tsx src/expect_fail.ts ../tests/fixtures_case4",
  "fail:case5": "tsx src/expect_fail.ts ../tests/fixtures_case5"
}

Run:

cd ts
npm run fail:case4
npm run fail:case5


⸻

One important durability tweak

Make your Rust errors include stable substrings. For example:
	•	"oracle quorum not met"
	•	"duplicate oracle signer"

Don’t rely on full error formatting (it will drift). Your approach with expected_error.txt containing a substring is perfect.

⸻

If you want, next I’d add Case6: seq skip (event has seq=2 while round=0 → reject). That’s the last “quorum integrity” invariant that prevents weird liveness attacks.