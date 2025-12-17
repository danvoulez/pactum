use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

use pactum::canon::canonical_string;
use pactum::hash::{h_sha256, hash_json, prefixed_hex_sha256};
use pactum::pactum::step_risk_pact_v0;

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
        "runtime":"pactum-riskpact/0.2",
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
        "oracle_time": {},
        "clock_round":"0",
        "metric_round":"0"
    });

    // Events (ordered)
    let t0 = "1734390000000"; // arbitrary ms epoch
    let t0_plus_500 = "1734390000500";
    let t0_plus_61000 = "1734390061000"; // 61s later - enough to trigger

    let mut events = Vec::<Value>::new();

    // 0) collateral_post (A)
    events.push(sign_event(
        "collateral_post",
        state0["pact_hash"].as_str().unwrap(),
        json!({"from":"party:a","amount":"1000","asset":"asset:USDc","nonce":"1"}),
        &party_a,
    ));

    let clock_oracle_pub = enc_pub(&clock_oracle.verifying_key());
    let metric_oracle_pub = enc_pub(&metric_oracle.verifying_key());

    // 1) clock_event seq=1 sets initial now
    events.push(sign_event(
        "clock_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":clock_oracle_pub,"t":t0,"seq":"1"}),
        &clock_oracle,
    ));

    // 2) metric_event below threshold (starts breach at now=t0)
    events.push(sign_event(
        "metric_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":metric_oracle_pub,"metric_id":"metric:ETHUSD","t":t0_plus_500,"v":"95","seq":"1"}),
        &metric_oracle,
    ));

    // Note: In V0.1, we can only commit 1 round per envelope.
    // To trigger, we need breach_start_time + duration_d <= now.
    // Since breach starts at t0 and duration_d=60000, we need now >= t0+60000.
    // But we can't have seq=2 in the same envelope, so this case demonstrates
    // that trigger requires multiple envelopes (V0.2 will allow multiple rounds).
    // For now, we'll set a state where breach has started but not yet triggered.
    // No claim_request in this envelope since trigger requires multiple rounds.

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
    receipt2
        .as_object_mut()
        .unwrap()
        .insert("receipt_hash".to_string(), Value::String(receipt_hash));

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
