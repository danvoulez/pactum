use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

use pactum::canon::canonical_string;
use pactum::hash::hash_json;

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
        "runtime":"pactum-riskpact/0.2",
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
    let clock1_pub = enc_pub(&clock1.verifying_key());
    let mut events: Vec<Value> = vec![];
    events.push(sign_event(
        "clock_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":clock1_pub,"t":"1734390000000","seq":"1"}),
        &clock1,
    ));
    events.push(sign_event(
        "clock_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":clock1_pub,"t":"1734390001000","seq":"1"}),
        &clock1,
    ));

    let envelope = json!({"v":"pactum-envelope/0","events":events});

    write_canon("tests/fixtures_case5/pact.json", &pact);
    write_canon("tests/fixtures_case5/state0.json", &state0);
    write_canon("tests/fixtures_case5/envelope.json", &envelope);

    fs::write(
        "tests/fixtures_case5/expected_error.txt",
        "duplicate oracle signer\n",
    )
    .expect("write expected_error");

    eprintln!("✅ Wrote case5 (duplicate signer) inputs to tests/fixtures_case5/");
}
