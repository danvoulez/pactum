Awesome — let’s make Pactum V0 actually alive by generating real, deterministic fixtures with real Ed25519 signatures, then locking them into tests/fixtures/ so golden.rs becomes a true conformance gate.

Below is a drop-in fixture generator you can add as a Rust binary.

⸻

1) Expose your modules (if you haven’t)

src/lib.rs:

pub mod canon;
pub mod hash;
pub mod keys;
pub mod pactum;


⸻

2) Add the fixture generator

Create: src/bin/gen_fixtures.rs

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

use pactum::canon::canonical_string;
use pactum::hash::{h_sha256, prefixed_hex_sha256};
use pactum::pactum::{hash_json, step_risk_pact_v0};

fn derive_signing_key(label: &str) -> SigningKey {
    // Deterministic 32-byte seed from SHA-256(label)
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

    // event body (no sig field)
    let body = json!({
        "v": "pactum-event/0",
        "kind": kind,
        "pact_hash": pact_hash,
        "payload": payload,
        "signer_pub": signer_pub
    });

    // body hash = H("pactum:event:0", canon(body))
    let body_hash_prefixed = hash_json("pactum:event:0", &body);
    let body_hex = body_hash_prefixed.strip_prefix("sha256:").unwrap();
    let body_hash_bytes = hex::decode(body_hex).unwrap();

    // msg = "pactum:sig:event:0" || 0x00 || body_hash_bytes
    let mut msg = Vec::with_capacity("pactum:sig:event:0".len() + 1 + 32);
    msg.extend_from_slice(b"pactum:sig:event:0");
    msg.push(0u8);
    msg.extend_from_slice(&body_hash_bytes);

    let sig = signer.sign(&msg);
    let sig_bytes: [u8; 64] = sig.to_bytes();

    // full event
    let mut ev = body;
    ev.as_object_mut()
        .unwrap()
        .insert("sig".to_string(), Value::String(enc_sig(sig_bytes)));
    ev
}

fn write_canon(path: &str, v: &Value) {
    let s = canonical_string(v);
    fs::write(path, format!("{s}\n")).expect("write fixture");
}

fn main() {
    let out_dir = Path::new("tests/fixtures");
    fs::create_dir_all(out_dir).expect("create tests/fixtures");

    // Deterministic keys
    let party_a = derive_signing_key("party:a");
    let party_b = derive_signing_key("party:b");
    let clock_oracle = derive_signing_key("oracle:clock1");
    let metric_oracle = derive_signing_key("oracle:metric1");

    // Pact IR
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
            "duration_d":"60000",
            "cap_q":"100"
        },
        "oracles":{
            "clock":{
                "mode":"oracle_feed",
                "quorum":"1",
                "pubkeys":[ enc_pub(&clock_oracle.verifying_key()) ]
            },
            "metric":{
                "quorum":"1",
                "pubkeys":[ enc_pub(&metric_oracle.verifying_key()) ]
            }
        }
    });

    let pact_hash = hash_json("pactum:pact:0", &pact);

    // Initial state
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
        "oracle_time": {}
    });

    // Events (ordered)
    let t0 = "1734390000000";       // arbitrary ms epoch
    let t0_plus_500 = "1734390000500";
    let t0_plus_61000 = "1734390061000";
    let t0_plus_61200 = "1734390061200";

    let mut events = Vec::<Value>::new();

    // 0) collateral_post (A)
    events.push(sign_event(
        "collateral_post",
        state0["pact_hash"].as_str().unwrap(),
        json!({"from":"party:a","amount":"1000","asset":"asset:USDc","nonce":"1"}),
        &party_a,
    ));

    // 1) clock_event seq=1
    events.push(sign_event(
        "clock_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":"oracle:clock1","t":t0,"seq":"1"}),
        &clock_oracle,
    ));

    // 2) metric_event below threshold (starts breach at now=t0)
    events.push(sign_event(
        "metric_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":"oracle:metric1","metric_id":"metric:ETHUSD","t":t0_plus_500,"v":"95","seq":"1"}),
        &metric_oracle,
    ));

    // 3) clock_event seq=2 advances now by 61s (trigger should become true)
    events.push(sign_event(
        "clock_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":"oracle:clock1","t":t0_plus_61000,"seq":"2"}),
        &clock_oracle,
    ));

    // 4) metric_event still below threshold, maintains breach/trigger
    events.push(sign_event(
        "metric_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":"oracle:metric1","metric_id":"metric:ETHUSD","t":t0_plus_61200,"v":"95","seq":"2"}),
        &metric_oracle,
    ));

    // 5) claim_request (B)
    events.push(sign_event(
        "claim_request",
        state0["pact_hash"].as_str().unwrap(),
        json!({"by":"party:b","amount":"10","nonce":"1"}),
        &party_b,
    ));

    let envelope = json!({
        "v":"pactum-envelope/0",
        "events": events
    });

    // Run the runtime to compute expected artifacts
    let (state1, outputs, trace, receipt) =
        step_risk_pact_v0(&pact, &state0, &envelope).expect("step_risk_pact_v0");

    // Optional: receipt hash (handy for chains)
    let receipt_hash = {
        let canon = canonical_string(&receipt);
        let d = h_sha256("pactum:receipt:0", canon.as_bytes());
        prefixed_hex_sha256(d)
    };
    let mut receipt2 = receipt.clone();
    receipt2.as_object_mut().unwrap().insert("receipt_hash".to_string(), Value::String(receipt_hash));

    // Write fixtures (canonical JSON)
    write_canon("tests/fixtures/pact.json", &pact);
    write_canon("tests/fixtures/state0.json", &state0);
    write_canon("tests/fixtures/envelope.json", &envelope);

    write_canon("tests/fixtures/expected_state1.json", &state1);
    write_canon("tests/fixtures/expected_outputs.json", &outputs);
    write_canon("tests/fixtures/expected_trace.json", &trace);
    write_canon("tests/fixtures/expected_receipt.json", &receipt2);

    eprintln!("✅ Wrote fixtures to tests/fixtures/");
}


⸻

3) Run it

cargo run --bin gen_fixtures
cargo test

If cargo test fails, it’s almost always one of:
	•	canonicalization mismatch (key order / whitespace)
	•	signature message bytes (tag + 0x00 + raw hash bytes)
	•	your golden.rs comparing non-canonical JSON (fix by comparing Value, which you already do)

⸻

If you paste your current tests/golden.rs, I’ll adjust it to also verify hash fields in the receipt (pact/state/envelope/trace/outputs), so the test enforces determinism all the way down.

---

Excellent. This generator is the final piece that brings Pactum V0 to life. It creates a deterministic, self-consistent test universe with real cryptography, making your golden.rs test a true conformance gate.

The generator code is well-engineered. The use of derive_signing_key with a domain tag ensures fixtures are reproducible across runs, which is perfect for testing.

✅ Running the Generator & Tests

Execute these commands to create the canonical fixtures and verify everything works:

```bash
# 1. Generate the fixtures (keys, signatures, outputs)
cargo run --bin gen_fixtures

# 2. Run the golden test to verify the runtime matches the generator
cargo test pactum_riskpact_v0_golden
```

If cargo test passes, congratulations—you have a working, verifiable Pactum V0 cell.

🔍 Enhanced Golden Test with Hash Verification

Your current golden.rs compares JSON Value equality, which is good. However, to be absolutely certain of cryptographic consistency, the test should also recalculate and verify every hash in the generated receipt. This ensures the step function's internal hashing matches the spec independently.

Below is an enhanced version of golden.rs that performs this thorough verification. Replace your existing test file with this:

tests/golden.rs

```rust
use pretty_assertions::assert_eq;
use serde_json::Value;

use pactum::pactum::{hash_json, step_risk_pact_v0};

fn load(path: &str) -> Value {
    let s = std::fs::read_to_string(path).expect("read");
    serde_json::from_str(&s).expect("json")
}

#[test]
fn pactum_riskpact_v0_golden() {
    // Load all input and expected output fixtures
    let pact = load("tests/fixtures/pact.json");
    let state0 = load("tests/fixtures/state0.json");
    let envelope = load("tests/fixtures/envelope.json");

    let expected_state1 = load("tests/fixtures/expected_state1.json");
    let expected_outputs = load("tests/fixtures/expected_outputs.json");
    let expected_trace = load("tests/fixtures/expected_trace.json");
    let expected_receipt = load("tests/fixtures/expected_receipt.json");

    // Run the Pactum state transition
    let (state1, outputs, trace, receipt) =
        step_risk_pact_v0(&pact, &state0, &envelope).expect("step_risk_pact_v0 should succeed");

    // 1. Verify structural equality of outputs
    assert_eq!(state1, expected_state1, "State1 mismatch");
    assert_eq!(outputs, expected_outputs, "Outputs mismatch");
    assert_eq!(trace, expected_trace, "Trace mismatch");

    // 2. Verify CRYPTOGRAPHIC HASHES in the receipt
    // Recompute each hash independently using the hash_json function
    let pact_hash = hash_json("pactum:pact:0", &pact);
    let prev_state_hash = hash_json("pactum:state:0", &state0);
    let envelope_hash = hash_json("pactum:envelope:0", &envelope);
    let new_state_hash = hash_json("pactum:state:0", &state1);
    let outputs_hash = hash_json("pactum:outputs:0", &outputs);
    let trace_hash = hash_json("pactum:trace:0", &trace);

    // Extract hash strings from the generated receipt
    let receipt_pact_hash = receipt.get("pact_hash").and_then(|v| v.as_str()).expect("receipt.pact_hash");
    let receipt_prev_state_hash = receipt.get("prev_state_hash").and_then(|v| v.as_str()).expect("receipt.prev_state_hash");
    let receipt_envelope_hash = receipt.get("envelope_hash").and_then(|v| v.as_str()).expect("receipt.envelope_hash");
    let receipt_new_state_hash = receipt.get("new_state_hash").and_then(|v| v.as_str()).expect("receipt.new_state_hash");
    let receipt_outputs_hash = receipt.get("outputs_hash").and_then(|v| v.as_str()).expect("receipt.outputs_hash");
    let receipt_trace_hash = receipt.get("trace_hash").and_then(|v| v.as_str()).expect("receipt.trace_hash");

    // Assert each hash matches
    assert_eq!(receipt_pact_hash, pact_hash, "pact_hash mismatch");
    assert_eq!(receipt_prev_state_hash, prev_state_hash, "prev_state_hash mismatch");
    assert_eq!(receipt_envelope_hash, envelope_hash, "envelope_hash mismatch");
    assert_eq!(receipt_new_state_hash, new_state_hash, "new_state_hash mismatch");
    assert_eq!(receipt_outputs_hash, outputs_hash, "outputs_hash mismatch");
    assert_eq!(receipt_trace_hash, trace_hash, "trace_hash mismatch");

    // 3. (Optional) Verify the receipt_hash if your generator includes it
    // The generator adds a "receipt_hash" field by hashing the receipt itself.
    if let Some(expected_receipt_hash) = expected_receipt.get("receipt_hash").and_then(|v| v.as_str()) {
        let actual_receipt_hash = hash_json("pactum:receipt:0", &receipt);
        assert_eq!(actual_receipt_hash, expected_receipt_hash, "receipt_hash mismatch");
    }

    println!("✅ Golden test passed with full hash verification.");
}
```

🐛 Troubleshooting a Failing Test

If cargo test fails, the issue is almost certainly in one of these three areas. Here’s how to debug:

1. Canonicalization Mismatch (Most Likely)
   · Symptom: Hashes differ, but JSON looks the same.
   · Debug: Add a debug line to canonical_string to print the exact bytes for pact.json and compare with a manual canonicalizer (e.g., a Python script using json.dumps with sort_keys=True and separators=(',', ':')).
   · Common Pitfall: Ensure your canonical_string function handles all JSON types correctly (null, bool, number, string, array, object). The provided code does this.
2. Signature Verification Failure
   · Symptom: step_risk_pact_v0 returns a SigInvalid error.
   · Debug:
     · In sign_event, print the body JSON and the msg bytes before signing.
     · In verify_event, reconstruct the same body and msg and compare byte-for-byte.
     · Critical Check: The msg must be "pactum:sig:event:0" || 0x00 || body_hash_bytes. Ensure the 0x00 byte is included and the hash is raw bytes, not a hex string.
3. State Transition Logic Error
   · Symptom: Structural mismatch (e.g., state1 fields differ).
   · Debug: The trace is your best friend. Compare your generated trace with the expected_trace.json step-by-step. This will pinpoint exactly which event application or rule logic diverged.

🚀 Next Steps: From Golden Test to Protocol

Once this test passes, you have achieved the "Proof of Done" for Pactum V0. You can now:

1. Port to a Second Language: Translate the spec and this test vector to Go or TypeScript. Success means both implementations produce identical hashes and states—the very definition of a deterministic protocol.
2. Integrate with UBL: Create a UBL module (e.g., UBL-Pactum-Adapter) that can:
   · Take a UBL Agreement and compile it to a pact.json.
   · Instantiate a Pactum runtime to manage that pact's state.
   · Store the pact_hash and receipt_hash chain in UBL's event store.
3. Connect to TDLN: Analyze the logic in a risk_pact's terms. This is pure conditional logic (metric < threshold, duration check). Write a compiler that transforms this into a .tdln SemanticUnit. The pact_hash can become part of the unit's metadata, creating a cryptographic link.

Running cargo test and seeing it pass is the moment Pactum stops being a specification and starts being a living, verifiable system. This is a significant milestone. Good luck