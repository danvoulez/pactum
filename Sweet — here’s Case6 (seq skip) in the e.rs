Sweet — here’s Case6 (seq skip) in the exact same style as Case4/5: deterministic fixtures + a rejection test + TS negative harness hook.

The invariant it locks:

If clock_round == 0, the only acceptable next round in this envelope is seq == 1.
Any seq == 2 must hard-fail (no skipping rounds).

⸻

Rust

1) src/bin/gen_fixtures_case6_seq_skip.rs

Writes inputs to tests/fixtures_case6/ plus expected_error.txt.

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
    ev.as_object_mut()
        .unwrap()
        .insert("sig".to_string(), Value::String(enc_sig(sig_bytes)));
    ev
}

fn write_canon(path: &str, v: &Value) {
    fs::write(path, format!("{}\n", canonical_string(v))).expect("write");
}

fn main() {
    let out_dir = Path::new("tests/fixtures_case6");
    fs::create_dir_all(out_dir).expect("mkdir");

    let party_a = derive_signing_key("party:a");
    let party_b = derive_signing_key("party:b");

    let clock1 = derive_signing_key("oracle:clock1");
    let metric1 = derive_signing_key("oracle:metric1");

    // Keep quorum=1 so the failure is unambiguously "seq skip", not "quorum not met".
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
            "clock":{"mode":"oracle_feed","quorum":"1","pubkeys":[enc_pub(&clock1.verifying_key())]},
            "metric":{"quorum":"1","pubkeys":[enc_pub(&metric1.verifying_key())]}
        }
    });

    let pact_hash = hash_json("pactum:pact:0", &pact);

    // round=0 so next valid seq is 1. We will send seq=2 to force skip error.
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

    let events = vec![
        sign_event(
            "clock_event",
            state0["pact_hash"].as_str().unwrap(),
            json!({"oracle_id":"oracle:clock1","t":"1734390000000","seq":"2"}), // <-- SKIP
            &clock1,
        )
    ];

    let envelope = json!({"v":"pactum-envelope/0","events":events});

    write_canon("tests/fixtures_case6/pact.json", &pact);
    write_canon("tests/fixtures_case6/state0.json", &state0);
    write_canon("tests/fixtures_case6/envelope.json", &envelope);

    // Use a substring that should appear in your error.
    // If your runtime formats it differently, just update this file once (like Case4).
    fs::write("tests/fixtures_case6/expected_error.txt", "Oracle seq\n").expect("write expected_error");

    eprintln!("✅ Wrote case6 (seq skip) inputs to tests/fixtures_case6/");
}

Add the binary entry if you’re listing them explicitly (or just rely on Cargo auto-discovery under src/bin/).

Run:

cargo run --bin gen_fixtures_case6_seq_skip


⸻

2) tests/golden_case6.rs

use serde_json::Value;
use pactum::pactum::step_risk_pact_v0;

fn load(path: &str) -> Value {
    let s = std::fs::read_to_string(path).expect("read");
    serde_json::from_str(&s).expect("json")
}

#[test]
fn pactum_case6_seq_skip_rejects() {
    let base = "tests/fixtures_case6";
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

cargo test pactum_case6_seq_skip_rejects

If it fails due to message mismatch, just edit:
	•	tests/fixtures_case6/expected_error.txt
to match your runtime’s actual stable substring (same workflow you used for Case4).

⸻

TypeScript parity

You already have ts/src/expect_fail.ts. Add:

ts/package.json

"scripts": {
  "fail:case6": "tsx src/expect_fail.ts ../tests/fixtures_case6"
}

Run:

cd ts
npm run fail:case6


⸻

Optional: make this unbreakable long-term

Once you’re happy with the current error text, I strongly recommend emitting a stable token like:
	•	PCT_ERR_SEQ_SKIP

…and set expected_error.txt to that token. It saves you from future refactors changing wording.

If you want, tell me what your current Rust error variants look like for seq mismatch (just the enum names / Display strings), and I’ll suggest the cleanest one-line change to embed stable tokens without making errors ugly.