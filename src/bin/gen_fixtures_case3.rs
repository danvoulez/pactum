use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

use pactum::canon::canonical_string;
use pactum::hash::{h_sha256, hash_json, prefixed_hex_sha256};
use pactum::pactum::step_risk_pact_v0;

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

    let clock1_pub = enc_pub(&clock1.verifying_key());
    let clock2_pub = enc_pub(&clock2.verifying_key());
    let metric1_pub = enc_pub(&metric1.verifying_key());
    let metric2_pub = enc_pub(&metric2.verifying_key());

    // Clock quorum round 1 (seq=1): two distinct signers
    events.push(sign_event(
        "clock_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":clock1_pub,"t":t1,"seq":"1"}),
        &clock1,
    ));
    events.push(sign_event(
        "clock_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":clock2_pub,"t":t2,"seq":"1"}),
        &clock2,
    ));

    // Metric quorum round 1 (seq=1): two distinct signers
    events.push(sign_event(
        "metric_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":metric1_pub,"metric_id":"metric:ETHUSD","t":mt1,"v":mv_low,"seq":"1"}),
        &metric1,
    ));
    events.push(sign_event(
        "metric_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":metric2_pub,"metric_id":"metric:ETHUSD","t":mt2,"v":mv_high,"seq":"1"}),
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
    receipt2
        .as_object_mut()
        .unwrap()
        .insert("receipt_hash".to_string(), Value::String(receipt_hash));

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
