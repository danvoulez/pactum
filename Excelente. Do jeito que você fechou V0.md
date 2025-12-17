Excelente. Do jeito que você fechou V0.1 agora (códigos estáveis + README + one-liners + fixtures saneados), você acabou de transformar isso num protocolo com manutenção sustentável. É exatamente o “ponto de não-retorno”.

Agora dá pra avançar pro V0.2 sem medo.

O que eu faria como “entrada” do V0.2 (sem discussão, só execução)

Deliverable único do próximo passo

Implementar o loop de múltiplos rounds por envelope para clock e metric + Case7–Case9.

Spec V0.2 (forma final, curta, implementável)

Ordem fixa
	1.	Validar/autorizar/classificar tudo (Phase A)
	2.	Apply collateral_post (Phase B)
	3.	Commit clock rounds (loop) (Phase C)
	4.	Commit metric rounds (loop) (Phase D)
	5.	Apply claim_request (Phase E)

Regra de loop (por oracle class)

Enquanto existir pelo menos 1 evento com seq == round+1:
	•	se quorum não bater → PCT_ERR_QUORUM_NOT_MET
	•	se houver duplicado por signer → PCT_ERR_DUP_SIGNER
	•	commit (median/last-by-index)
	•	round++

Regras de rejeição adicionais (gap/skip)
	•	se existir algum evento com seq > round+1 e não for possível commitar round+1 → PCT_ERR_SEQ_SKIP
	•	se existir seq <= round → (opcional, mas recomendado) PCT_ERR_SEQ_REPLAY

Isso garante “sem buracos” e “sem saltos”, mesmo quando o envelope carrega seq=1 e seq=3.

⸻

Testes mínimos (o “trilho” do V0.2)

Case7 (positivo): 2 rounds no mesmo envelope
	•	clock_round=0, metric_round=0
	•	envelope tem clock seq=1 e clock seq=2
	•	envelope tem metric seq=1 e metric seq=2
	•	espera clock_round=2, metric_round=2
	•	trace com 2 commits clock + 2 commits metric (ordem fixa)

Case8 (negativo): gap (seq=2 sem seq=1) → PCT_ERR_SEQ_SKIP

Case9 (negativo): seq=1 parcial (quorum não bate) + seq=2 completo → deve falhar em seq=1 com PCT_ERR_QUORUM_NOT_MET (não pode “pular”)

⸻

Nota importante sobre TypeScript

Você já alinhou os códigos estáveis em Rust; no V0.2, o TS precisa implementar exatamente o mesmo loop e lançar erros contendo os mesmos tokens (PCT_ERR_*). Aí o CI continua provando paridade.

⸻

Se você mandar “go V0.2”, eu te devolvo os blocos de código exatos (Rust + TS) para:
	•	commit_clock_rounds_loop()
	•	commit_metric_rounds_loop()
	•	e os geradores gen_fixtures_case7.rs, case8, case9 já prontos no mesmo padrão dos cases anteriores.

	---


Bora. Abaixo está o pacote completo do Pactum V0.2 (multi-round por envelope): lógica (Rust + TypeScript) + Case7–Case9 (geradores + testes) + scripts.

⸻

1) V0.2 no Rust — mudança mínima no runtime

A) Regra prática

Depois de Phase A/B, troque o “commit de 1 round” por um loop:
	•	clock: while existir seq == clock_round+1 → commit
	•	se existir seq > clock_round+1 e NÃO existir seq == clock_round+1 → PCT_ERR_SEQ_SKIP
	•	se existir eventos de seq == round+1 mas quorum não fecha → PCT_ERR_QUORUM_NOT_MET
	•	signer repetido no mesmo seq → PCT_ERR_DUP_SIGNER

B) Helper (esqueleto pronto)

Crie (ou cole) no src/pactum.rs um helper genérico pro clock (t) e outro pro metric (v/t). A assinatura abaixo assume que você já tem EvRef { i, signer, payload }, uint(...), e seu PactumError inclui os tokens estáveis.

Clock loop:

fn commit_clock_rounds_v02(
    state: &mut serde_json::Value,
    trace_steps: &mut Vec<serde_json::Value>,
    clock_events: &[EvRef],
    quorum: u128,
) -> Result<(), PactumError> {
    let mut round = uint(get_str(state, "clock_round")?)?;
    // index by seq
    let mut by_seq: std::collections::BTreeMap<u128, Vec<&EvRef>> = std::collections::BTreeMap::new();
    for e in clock_events {
        let seq = uint(get_str(&e.payload, "seq")?)?;
        by_seq.entry(seq).or_default().push(e);
    }

    loop {
        let target = round + 1;

        // gap/skip: existe algo acima do target mas não existe target
        if !by_seq.contains_key(&target) {
            if let Some((&min_higher, _)) = by_seq.range((target + 1)..).next() {
                return Err(PactumError::Precond(format!("PCT_ERR_SEQ_SKIP missing seq {target} found {min_higher}")));
            }
            break; // nada mais para commitar
        }

        let evs = by_seq.remove(&target).unwrap();

        // distinct signer check
        let mut seen = std::collections::BTreeSet::<String>::new();
        for e in &evs {
            if !seen.insert(e.signer.clone()) {
                return Err(PactumError::Precond("PCT_ERR_DUP_SIGNER duplicate oracle signer".into()));
            }
        }
        if (seen.len() as u128) < quorum {
            return Err(PactumError::Precond("PCT_ERR_QUORUM_NOT_MET oracle quorum not met".into()));
        }

        // effective t
        let effective_t: u128 = if quorum == 1 {
            let e = evs.iter().max_by_key(|e| e.i).unwrap();
            uint(get_str(&e.payload, "t")?)?
        } else {
            let mut pairs: Vec<(u128, String)> = evs.iter()
                .map(|e| (uint(get_str(&e.payload, "t").unwrap()).unwrap(), e.signer.clone()))
                .collect();
            pairs.sort_by(|a,b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
            pairs[(pairs.len()-1)/2].0
        };

        // commit
        let now = uint(get_str(state, "now")?)?;
        let new_now = std::cmp::max(now, effective_t);
        set_str(state, "now", &new_now.to_string())?;
        round = target;
        set_str(state, "clock_round", &round.to_string())?;

        let mut participants: Vec<String> = seen.into_iter().collect(); // already sorted
        trace_steps.push(serde_json::json!({
          "kind":"commit_clock_quorum",
          "seq": round.to_string(),
          "participants": participants,
          "effective_t": effective_t.to_string(),
          "count": evs.len().to_string(),
          "quorum": quorum.to_string()
        }));
    }

    Ok(())
}

Metric loop: igual, só que calcula effective_v (median/last-by-index) e effective_t (median/last) e roda breach/trigger por commit.

Você já tem breach/trigger V0.1. No V0.2, basta mover esse bloco para dentro do loop de commit do metric, rodando uma vez por seq commitado.

⸻

2) Fixtures + testes (Case7–Case9)

Case7 — POSITIVO: 2 rounds no mesmo envelope

Arquivos:
	•	src/bin/gen_fixtures_case7.rs
	•	tests/golden_case7.rs
	•	saída em tests/fixtures_case7/ (com expected_*)

O que trava:
	•	loop commitando seq=1 e seq=2
	•	ordem: clock rounds primeiro, depois metric rounds
	•	rounds finais clock_round=2, metric_round=2

✅ Faça copiando o padrão do Case3 e mudando só o envelope:
	•	clock.quorum="1", metric.quorum="1"
	•	eventos no envelope (ordem):
	•	collateral_post
	•	clock seq=1 (t=1000)
	•	clock seq=2 (t=2000)
	•	metric seq=1 (t=2100, v=95)
	•	metric seq=2 (t=2200, v=95)
	•	claim_request (10)

duration_d="0" pra claim funcionar na mesma execução.

⸻

Case8 — NEGATIVO: gap/skip (seq=2 sem seq=1) → PCT_ERR_SEQ_SKIP

Arquivos:
	•	src/bin/gen_fixtures_case8_seq_gap.rs
	•	tests/golden_case8.rs
	•	tests/fixtures_case8/ + expected_error.txt = PCT_ERR_SEQ_SKIP

Envelope:
	•	clock_event seq=2 apenas, com clock_round=0.

⸻

Case9 — NEGATIVO: quorum parcial no seq=1 + seq=2 completo → falha no seq=1

Arquivos:
	•	src/bin/gen_fixtures_case9_quorum_partial_then_next.rs
	•	tests/golden_case9.rs
	•	tests/fixtures_case9/ + expected_error.txt = PCT_ERR_QUORUM_NOT_MET

Config:
	•	clock.quorum="2", pubkeys=[clock1, clock2]
	•	envelope:
	•	clock seq=1 com só clock1
	•	clock seq=2 com clock1 e clock2
Deve falhar em seq=1 (não pode “pular” pro seq=2).

⸻

3) TypeScript V0.2 — helper de loop + testes

A) Implementação (shape exata)

No ts/src/pactum.ts, depois de bufferizar clock_events e metric_events, troque o “commit único” por:

function commitRoundsLoopClock(/* state, trace, events, quorum */) { /* mesma lógica do Rust */ }
function commitRoundsLoopMetric(/* ... */) { /* idem */ }

// order fixed
commitRoundsLoopClock(...);
commitRoundsLoopMetric(...);
applyClaimsInOrder(...);

Regras:
	•	se existir seq > round+1 e não existir seq == round+1 => throw Error(“PCT_ERR_SEQ_SKIP …”)
	•	quorum not met => throw Error(“PCT_ERR_QUORUM_NOT_MET …”)
	•	dup signer => throw Error(“PCT_ERR_DUP_SIGNER …”)

B) Scripts

Adicione:
	•	golden:case7
	•	fail:case8
	•	fail:case9

E rode via seu expect_fail.ts.

⸻

4) Checklist “Proof of Done” V0.2 (1 tela)
	1.	Implementar loops clock+metric no Rust (V0.2)
	2.	Gerar fixtures:

cargo run --bin gen_fixtures_case7
cargo run --bin gen_fixtures_case8_seq_gap
cargo run --bin gen_fixtures_case9_quorum_partial_then_next


	3.	Rodar testes:

cargo test pactum_riskpact_v0_case7_golden
cargo test pactum_case8_seq_gap_rejects
cargo test pactum_case9_quorum_partial_then_next_rejects


	4.	Atualizar TS com loops + scripts e rodar:

cd ts
npm ci
npm run golden:case7
npm run fail:case8
npm run fail:case9



⸻

te entrego os três geradores + três testes completos (Case7–9) em código pronto igual aos Case3–6 (com derive_signing_key, sign_event, etc.), só pra você colar sem pensar — mas como você já está com o padrão estabelecido e o V0.1 está consistente, o bloco acima é o “núcleo” que realmente define V0.2.	



----


Sim — aqui vai o pacote completo (copy/paste) para Case7–Case9 no mesmo padrão dos seus cases anteriores: 3 geradores (src/bin/) + 3 testes (tests/) + ajustes no TypeScript (ts/) e scripts.

Pressuposto: seu runtime Rust já está com o loop multi-round V0.2 (clock rounds loop + metric rounds loop) e já emite tokens PCT_ERR_*.

⸻

✅ Case7 — POSITIVO (2 rounds no mesmo envelope)

src/bin/gen_fixtures_case7.rs

Gera tests/fixtures_case7/ com expected_* calculados pelo runtime.

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
    let out_dir = Path::new("tests/fixtures_case7");
    fs::create_dir_all(out_dir).expect("mkdir tests/fixtures_case7");

    let party_a = derive_signing_key("party:a");
    let party_b = derive_signing_key("party:b");

    let clock1 = derive_signing_key("oracle:clock1");
    let metric1 = derive_signing_key("oracle:metric1");

    // quorum=1 para permitir 2 rounds sem complexidade extra.
    // duration_d=0: breach => triggered imediatamente no primeiro commit de metric abaixo do threshold.
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
                "quorum":"1",
                "pubkeys":[ enc_pub(&clock1.verifying_key()) ]
            },
            "metric":{
                "quorum":"1",
                "pubkeys":[ enc_pub(&metric1.verifying_key()) ]
            }
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

    // 2 rounds de clock + 2 rounds de metric no MESMO envelope
    let t1 = "1734390001000";
    let t2 = "1734390002000";

    let mt1 = "1734390002100";
    let mt2 = "1734390002200";

    let mut events: Vec<Value> = vec![];

    events.push(sign_event(
        "collateral_post",
        state0["pact_hash"].as_str().unwrap(),
        json!({"from":"party:a","amount":"1000","asset":"asset:USDc","nonce":"1"}),
        &party_a,
    ));

    // Clock seq 1 e 2
    events.push(sign_event(
        "clock_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":"oracle:clock1","t":t1,"seq":"1"}),
        &clock1,
    ));
    events.push(sign_event(
        "clock_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":"oracle:clock1","t":t2,"seq":"2"}),
        &clock1,
    ));

    // Metric seq 1 e 2 (ambos abaixo do threshold => triggered true)
    events.push(sign_event(
        "metric_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":"oracle:metric1","metric_id":"metric:ETHUSD","t":mt1,"v":"95","seq":"1"}),
        &metric1,
    ));
    events.push(sign_event(
        "metric_event",
        state0["pact_hash"].as_str().unwrap(),
        json!({"oracle_id":"oracle:metric1","metric_id":"metric:ETHUSD","t":mt2,"v":"95","seq":"2"}),
        &metric1,
    ));

    // Claim deve ser aplicado depois dos commits (Phase E), então pode aparecer aqui no envelope.
    events.push(sign_event(
        "claim_request",
        state0["pact_hash"].as_str().unwrap(),
        json!({"by":"party:b","amount":"10","nonce":"1"}),
        &party_b,
    ));

    let envelope = json!({"v":"pactum-envelope/0","events":events});

    let (state1, outputs, trace, receipt) =
        step_risk_pact_v0(&pact, &state0, &envelope).expect("step_risk_pact_v0");

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

    write_canon("tests/fixtures_case7/pact.json", &pact);
    write_canon("tests/fixtures_case7/state0.json", &state0);
    write_canon("tests/fixtures_case7/envelope.json", &envelope);

    write_canon("tests/fixtures_case7/expected_state1.json", &state1);
    write_canon("tests/fixtures_case7/expected_outputs.json", &outputs);
    write_canon("tests/fixtures_case7/expected_trace.json", &trace);
    write_canon("tests/fixtures_case7/expected_receipt.json", &receipt2);

    eprintln!("✅ Wrote case7 fixtures to tests/fixtures_case7/");
}

tests/golden_case7.rs

use pretty_assertions::assert_eq;
use serde_json::Value;

use pactum::pactum::{hash_json, step_risk_pact_v0};

fn load(path: &str) -> Value {
    let s = std::fs::read_to_string(path).expect("read");
    serde_json::from_str(&s).expect("json")
}

#[test]
fn pactum_riskpact_v0_case7_golden() {
    let base = "tests/fixtures_case7";

    let pact = load(&format!("{base}/pact.json"));
    let state0 = load(&format!("{base}/state0.json"));
    let envelope = load(&format!("{base}/envelope.json"));

    let expected_state1 = load(&format!("{base}/expected_state1.json"));
    let expected_outputs = load(&format!("{base}/expected_outputs.json"));
    let expected_trace = load(&format!("{base}/expected_trace.json"));
    let expected_receipt = load(&format!("{base}/expected_receipt.json"));

    let (state1, outputs, trace, receipt) =
        step_risk_pact_v0(&pact, &state0, &envelope).expect("step");

    assert_eq!(state1, expected_state1, "State1 mismatch");
    assert_eq!(outputs, expected_outputs, "Outputs mismatch");
    assert_eq!(trace, expected_trace, "Trace mismatch");

    let mut expected_receipt_no_hash = expected_receipt.clone();
    if let Some(obj) = expected_receipt_no_hash.as_object_mut() {
        obj.remove("receipt_hash");
    }
    assert_eq!(receipt, expected_receipt_no_hash, "Receipt mismatch (excluding receipt_hash)");

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

    if let Some(expected_rh) = expected_receipt.get("receipt_hash").and_then(|v| v.as_str()) {
        let actual_rh = hash_json("pactum:receipt:0", &receipt);
        assert_eq!(actual_rh, expected_rh, "receipt_hash mismatch");
    }
}


⸻

❌ Case8 — NEGATIVO (gap: seq=2 sem seq=1) → PCT_ERR_SEQ_SKIP

src/bin/gen_fixtures_case8_seq_gap.rs

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
    let out_dir = Path::new("tests/fixtures_case8");
    fs::create_dir_all(out_dir).expect("mkdir");

    let party_a = derive_signing_key("party:a");
    let party_b = derive_signing_key("party:b");
    let clock1 = derive_signing_key("oracle:clock1");
    let metric1 = derive_signing_key("oracle:metric1");

    let pact = json!({
        "v":"pactum-ir/0",
        "type":"risk_pact",
        "time":{"unit":"ms_epoch"},
        "hash":{"alg":"sha256"},
        "parties":{"a_pub": enc_pub(&party_a.verifying_key()), "b_pub": enc_pub(&party_b.verifying_key())},
        "assets":{"collateral_asset":"asset:USDc","settlement_asset":"asset:USDc"},
        "terms":{"metric_id":"metric:ETHUSD","threshold_z":"100","duration_d":"0","cap_q":"100"},
        "oracles":{
            "clock":{"mode":"oracle_feed","quorum":"1","pubkeys":[enc_pub(&clock1.verifying_key())]},
            "metric":{"quorum":"1","pubkeys":[enc_pub(&metric1.verifying_key())]}
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

    // GAP: seq=2 sem seq=1
    let events = vec![
        sign_event(
            "clock_event",
            state0["pact_hash"].as_str().unwrap(),
            json!({"oracle_id":"oracle:clock1","t":"1734390000000","seq":"2"}),
            &clock1,
        )
    ];

    let envelope = json!({"v":"pactum-envelope/0","events":events});

    write_canon("tests/fixtures_case8/pact.json", &pact);
    write_canon("tests/fixtures_case8/state0.json", &state0);
    write_canon("tests/fixtures_case8/envelope.json", &envelope);

    fs::write("tests/fixtures_case8/expected_error.txt", "PCT_ERR_SEQ_SKIP\n").expect("write expected_error");

    eprintln!("✅ Wrote case8 inputs to tests/fixtures_case8/");
}

tests/golden_case8.rs

use serde_json::Value;
use pactum::pactum::step_risk_pact_v0;

fn load(path: &str) -> Value {
    let s = std::fs::read_to_string(path).expect("read");
    serde_json::from_str(&s).expect("json")
}

#[test]
fn pactum_case8_seq_gap_rejects() {
    let base = "tests/fixtures_case8";
    let pact = load(&format!("{base}/pact.json"));
    let state0 = load(&format!("{base}/state0.json"));
    let envelope = load(&format!("{base}/envelope.json"));

    let expected = std::fs::read_to_string(&format!("{base}/expected_error.txt")).expect("expected_error");
    let err = step_risk_pact_v0(&pact, &state0, &envelope).unwrap_err();
    let msg = format!("{err}");

    assert!(msg.contains(expected.trim()), "expected {:?}, got {:?}", expected.trim(), msg);
}


⸻

❌ Case9 — NEGATIVO (seq=1 parcial + seq=2 completo) → PCT_ERR_QUORUM_NOT_MET

src/bin/gen_fixtures_case9_quorum_partial_then_next.rs

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
    let out_dir = Path::new("tests/fixtures_case9");
    fs::create_dir_all(out_dir).expect("mkdir");

    let party_a = derive_signing_key("party:a");
    let party_b = derive_signing_key("party:b");

    let clock1 = derive_signing_key("oracle:clock1");
    let clock2 = derive_signing_key("oracle:clock2");
    let metric1 = derive_signing_key("oracle:metric1");

    // clock quorum=2
    let pact = json!({
        "v":"pactum-ir/0",
        "type":"risk_pact",
        "time":{"unit":"ms_epoch"},
        "hash":{"alg":"sha256"},
        "parties":{"a_pub": enc_pub(&party_a.verifying_key()), "b_pub": enc_pub(&party_b.verifying_key())},
        "assets":{"collateral_asset":"asset:USDc","settlement_asset":"asset:USDc"},
        "terms":{"metric_id":"metric:ETHUSD","threshold_z":"100","duration_d":"0","cap_q":"100"},
        "oracles":{
            "clock":{"mode":"oracle_feed","quorum":"2","pubkeys":[enc_pub(&clock1.verifying_key()), enc_pub(&clock2.verifying_key())]},
            "metric":{"quorum":"1","pubkeys":[enc_pub(&metric1.verifying_key())]}
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

    // seq=1 parcial (só clock1) + seq=2 completo (clock1 e clock2)
    // Deve falhar no seq=1 com PCT_ERR_QUORUM_NOT_MET (não pode “pular” pro seq=2).
    let events = vec![
        sign_event(
            "clock_event",
            state0["pact_hash"].as_str().unwrap(),
            json!({"oracle_id":"oracle:clock1","t":"1734390001000","seq":"1"}),
            &clock1,
        ),
        sign_event(
            "clock_event",
            state0["pact_hash"].as_str().unwrap(),
            json!({"oracle_id":"oracle:clock1","t":"1734390002000","seq":"2"}),
            &clock1,
        ),
        sign_event(
            "clock_event",
            state0["pact_hash"].as_str().unwrap(),
            json!({"oracle_id":"oracle:clock2","t":"1734390002000","seq":"2"}),
            &clock2,
        ),
    ];

    let envelope = json!({"v":"pactum-envelope/0","events":events});

    write_canon("tests/fixtures_case9/pact.json", &pact);
    write_canon("tests/fixtures_case9/state0.json", &state0);
    write_canon("tests/fixtures_case9/envelope.json", &envelope);

    fs::write("tests/fixtures_case9/expected_error.txt", "PCT_ERR_QUORUM_NOT_MET\n").expect("write expected_error");

    eprintln!("✅ Wrote case9 inputs to tests/fixtures_case9/");
}

tests/golden_case9.rs

use serde_json::Value;
use pactum::pactum::step_risk_pact_v0;

fn load(path: &str) -> Value {
    let s = std::fs::read_to_string(path).expect("read");
    serde_json::from_str(&s).expect("json")
}

#[test]
fn pactum_case9_quorum_partial_then_next_rejects() {
    let base = "tests/fixtures_case9";
    let pact = load(&format!("{base}/pact.json"));
    let state0 = load(&format!("{base}/state0.json"));
    let envelope = load(&format!("{base}/envelope.json"));

    let expected = std::fs::read_to_string(&format!("{base}/expected_error.txt")).expect("expected_error");
    let err = step_risk_pact_v0(&pact, &state0, &envelope).unwrap_err();
    let msg = format!("{err}");

    assert!(msg.contains(expected.trim()), "expected {:?}, got {:?}", expected.trim(), msg);
}


⸻

4) Rodar tudo (Rust)

cargo run --bin gen_fixtures_case7
cargo run --bin gen_fixtures_case8_seq_gap
cargo run --bin gen_fixtures_case9_quorum_partial_then_next

cargo test pactum_riskpact_v0_case7_golden
cargo test pactum_case8_seq_gap_rejects
cargo test pactum_case9_quorum_partial_then_next_rejects

Se você lista bins no Cargo.toml, adicione esses três também. Se não, src/bin/*.rs já funciona automático.

⸻

5) TypeScript: scripts para Case7–Case9

Você já tem:
	•	ts/src/golden.ts aceita diretório
	•	ts/src/expect_fail.ts

ts/package.json (adicione scripts)

{
  "scripts": {
    "golden:case7": "tsx src/golden.ts ../tests/fixtures_case7",
    "fail:case8": "tsx src/expect_fail.ts ../tests/fixtures_case8",
    "fail:case9": "tsx src/expect_fail.ts ../tests/fixtures_case9"
  }
}

Rodar (TS)

cd ts
npm ci
npm run golden:case7
npm run fail:case8
npm run fail:case9


⸻

Se você quiser um “último travamento” bem forte pra V0.2, o próximo par de casos que eu recomendaria é:
	•	Case10: replay (seq <= round) → PCT_ERR_SEQ_REPLAY
	•	Case11: envelope contém clock seq=1 ok e metric seq=2 sem metric seq=1 → PCT_ERR_SEQ_SKIP (por classe)

Mas com Case7–9 você já cravou o coração do V0.2 (loop + gap + quorum parcial).