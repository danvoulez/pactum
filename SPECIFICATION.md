# Pactum RiskPact Protocol Specification (V0.2)

Pactum RiskPact V0.2, com quorum, multi-round por envelope, invariantes e hardening oracle_id == signer_pub.

⸻

Status: Stable (conformance-gated)
Protocol Family: Pactum
Pact Type: risk_pact
Implementation Targets: Rust, TypeScript (cross-language determinism required)

1. Objetivos

1.1 Objetivo principal

O Pactum define um protocolo determinístico onde um “Pact” é executável por construção: um conjunto de inputs (eventos) aplicados sobre um estado prévio produz um único estado sucessor, acompanhado de provas verificáveis via hashing e assinaturas.

O núcleo do protocolo é um state transition function determinística:

(state0, pact, envelope) -> (state1, outputs, trace, receipt)

1.2 Objetivos secundários
	1.	Determinismo cross-language: duas implementações independentes devem produzir os mesmos hashes e o mesmo estado.
	2.	Verificabilidade criptográfica: eventos são assinados; transições são “ancoradas” por hashes (receipt).
	3.	Segurança por invariantes simples: anti-replay, anti-skip, quorum obrigatório, allowlists de oráculos e identidade criptográfica consistente.
	4.	Auditabilidade nativa: o trace não é “log opcional”; é parte do artefato verificável.
	5.	Conformance por fixtures: testes golden e negativos tornam o protocolo “difícil de quebrar” sem perceber.

⸻

2. Definições e Notação
	•	Pact: especificação determinística (ex.: risk_pact) com partes, termos e oráculos.
	•	State: estado corrente associado a um pact_hash.
	•	Envelope: lote (batch) de eventos assinados aplicados em uma transição.
	•	Event: comando/input assinado (ex.: clock_event, metric_event, collateral_post, claim_request).
	•	Trace: explicação determinística da aplicação do envelope (passo a passo).
	•	Receipt: hashes “âncora” dos artefatos da transição.

⸻

3. Codificação e Canonicalização

3.1 JSON canônico (canonical_string)

O protocolo depende de uma serialização JSON determinística. A canonicalização deve:
	•	Serializar como UTF-8
	•	Não conter whitespace extra
	•	Ordenar chaves de objetos lexicograficamente (UTF-8 / bytewise consistent)
	•	Preservar tipos JSON (null/bool/string/array/object)
	•	Inteiros do protocolo são strings (ver §4); não usar JSON numbers para valores do protocolo

Arrays: preservam a ordem original. Onde a spec exigir ordenação (ex.: listas de pubkeys), a implementação deve ordenar explicitamente.

⸻

4. Tipos Primitivos do Protocolo

4.1 uint (inteiro não-negativo em string)

Representado como string decimal, sem sinal.

Validação:
	•	Apenas dígitos [0-9]
	•	Sem zeros à esquerda, exceto "0"
	•	Deve caber no range suportado pela implementação (recomendado: até u128)

Exemplos válidos: "0", "1", "42", "1000"
Inválidos: "", "01", "-1", "1.0", " 1"

4.2 Identificadores criptográficos

Public key Ed25519:

ed25519:<base64url_nopad(pubkey_bytes_32)>

Signature Ed25519:

ed25519sig:<base64url_nopad(sig_bytes_64)>


⸻

5. Hashing

5.1 Função base: domain-separated SHA-256

Defina:

H(tag, bytes) = SHA256( tag || 0x00 || bytes )

	•	tag é string ASCII/UTF-8
	•	0x00 é um separador literal (um byte)
	•	bytes é o payload já serializado (ex.: canonical JSON bytes)

5.2 hash_json(tag, value)
	1.	canon = canonical_string(value)
	2.	digest = H(tag, canon_bytes)
	3.	Output string:

sha256:<lowercase_hex(digest_32)>


⸻

6. Assinaturas e Formato de Evento

6.1 Event body (assinado)

O body (sem sig) é:

{
  "v": "pactum-event/0",
  "kind": "<event_kind>",
  "pact_hash": "sha256:...",
  "payload": { ... },
  "signer_pub": "ed25519:..."
}

6.2 Hash do body

body_hash = hash_json("pactum:event:0", body)

6.3 Mensagem assinada

A mensagem assinada é:

msg = "pactum:sig:event:0" || 0x00 || body_hash_bytes

Onde body_hash_bytes são os 32 bytes do digest (não a string hex).

6.4 Evento completo (transportado)

O evento transportado inclui sig:

{
  "v": "pactum-event/0",
  "kind": "...",
  "pact_hash": "sha256:...",
  "payload": { ... },
  "signer_pub": "ed25519:...",
  "sig": "ed25519sig:..."
}

6.5 Verificação

A implementação deve verificar:
	•	sig é Ed25519 válido para msg e signer_pub
	•	verify_strict (recomendado) ou equivalente estrito

Erros devem incluir token estável: PCT_ERR_SIG_INVALID.

⸻

7. Pact IR (RiskPact)

7.1 Estrutura base (exemplo)

{
  "v": "pactum-ir/0",
  "type": "risk_pact",
  "time": { "unit": "ms_epoch" },
  "hash": { "alg": "sha256" },
  "parties": {
    "a_pub": "ed25519:...",
    "b_pub": "ed25519:..."
  },
  "assets": {
    "collateral_asset": "asset:USDc",
    "settlement_asset": "asset:USDc"
  },
  "terms": {
    "metric_id": "metric:ETHUSD",
    "threshold_z": "100",
    "duration_d": "0",
    "cap_q": "100"
  },
  "oracles": {
    "clock": {
      "mode": "oracle_feed",
      "quorum": "2",
      "pubkeys": ["ed25519:...", "..."]
    },
    "metric": {
      "quorum": "2",
      "pubkeys": ["ed25519:...", "..."]
    }
  }
}

7.2 pact_hash

pact_hash = hash_json("pactum:pact:0", pact)


⸻

8. State (RiskPact State)

8.1 Estrutura

{
  "v": "pactum-state/0",
  "pact_hash": "sha256:...",
  "now": "0",
  "collateral_posted": "0",
  "metric_last": { "t": "0", "v": "0" },
  "breach_start_time": null,
  "triggered": false,
  "claim_paid": "0",

  "oracle_seq": {},
  "oracle_time": {},

  "clock_round": "0",
  "metric_round": "0"
}

8.2 Invariantes básicos
	•	state.pact_hash deve bater com o pact_hash do pacto
	•	now é monotônico não-decrescente
	•	clock_round e metric_round só crescem por +1 via commits

⸻

9. Envelope

9.1 Estrutura

{
  "v": "pactum-envelope/0",
  "events": [ <event>, <event>, ... ]
}


⸻

10. Autorização por tipo de evento

10.1 collateral_post
	•	Assinante deve ser parties.a_pub

10.2 claim_request
	•	Assinante deve ser parties.b_pub

10.3 clock_event
	•	signer_pub deve estar em pact.oracles.clock.pubkeys
	•	Hardening V0.2: payload.oracle_id == signer_pub
Se não: PCT_ERR_ORACLE_ID_MISMATCH

10.4 metric_event
	•	signer_pub deve estar em pact.oracles.metric.pubkeys
	•	payload.metric_id deve bater com terms.metric_id
	•	Hardening V0.2: payload.oracle_id == signer_pub
Se não: PCT_ERR_ORACLE_ID_MISMATCH

⸻

11. Execução Determinística (V0.2)

A transição é feita em fases fixas.

Phase A — Validar e classificar (sem mutar estado)

Para cada evento em ordem:
	1.	Validar event.pact_hash == state.pact_hash
	2.	Validar assinatura
	3.	Validar autorização por tipo
	4.	Classificar em buffers: collateral_posts, clock_events, metric_events, claim_requests

Phase B — Aplicar collateral_post (ordem do envelope)
	•	Aumenta collateral_posted conforme payload.

Phase C — Commit de rounds de clock (loop multi-round)

Define round = uint(state.clock_round).
Agrupa eventos clock_event por seq.

Regras:
	•	Se existir qualquer evento com seq <= round → PCT_ERR_SEQ_REPLAY
	•	Enquanto existir eventos com seq == round+1:
	•	Se signer repetido no mesmo seq → PCT_ERR_DUP_SIGNER
	•	Se distinct_signers < quorum → PCT_ERR_QUORUM_NOT_MET
	•	Computar effective_t:
	•	Se quorum == 1: usar o evento de maior índice no envelope (last-by-index)
	•	Se quorum >= 2: mediana inferior de (t, signer_pub) orden — ordenando por t e tie-break por signer_pub
	•	Commit:
	•	now = max(now, effective_t)
	•	clock_round = clock_round + 1
	•	Append trace: commit_clock_quorum(seq, participants_sorted, effective_t, count, quorum)
	•	Se existir evento com seq > round+1 e não existe seq == round+1 → PCT_ERR_SEQ_SKIP

Phase D — Commit de rounds de metric (loop multi-round)

Mesma lógica do clock, com effective_v (e effective_t), e a cada commit roda breach/trigger:
	•	Se effective_v < threshold_z:
	•	se breach_start_time é null → set breach_start_time = state.now
	•	Se effective_v >= threshold_z:
	•	set breach_start_time = null e triggered = false (ou manter triggered como sticky, conforme sua implementação atual; o protocolo deve fixar essa escolha)
	•	triggered = (breach_start_time != null) && (now - breach_start_time >= duration_d)

Append trace: commit_metric_quorum(...) incluindo campos de breach/trigger conforme implementado.

Phase E — Aplicar claim_request (ordem do envelope)

Regras recomendadas (mínimo viável):
	•	Só paga se triggered == true
	•	claim_paid + amount <= cap_q
	•	claim_paid + amount <= collateral_posted (ou regra equivalente definida pela implementação)
	•	Produz outputs (ex.: asset_flow) determinísticos e incrementa claim_paid

⸻

12. Trace

O trace é um array de steps JSON. Deve ser determinístico:
	•	listas como participants devem ser ordenadas lexicograficamente
	•	números do protocolo como strings uint

Steps típicos:
	•	commit_clock_quorum
	•	commit_metric_quorum
	•	apply_claim (ou equivalente)
	•	opcional: steps de collateral, validações, etc. (desde que determinísticos)

⸻

13. Receipt

13.1 Campos obrigatórios

Receipt deve conter hashes dos artefatos:
	•	pact_hash = hash_json("pactum:pact:0", pact)
	•	prev_state_hash = hash_json("pactum:state:0", state0)
	•	envelope_hash = hash_json("pactum:envelope:0", envelope)
	•	new_state_hash = hash_json("pactum:state:0", state1)
	•	outputs_hash = hash_json("pactum:outputs:0", outputs)
	•	trace_hash = hash_json("pactum:trace:0", trace)

13.2 receipt_hash (opcional, não-recursivo)

Se presente:
	•	Compute hash_json("pactum:receipt:0", receipt_without_receipt_hash)
	•	Armazene como receipt_hash

⸻

14. Códigos de erro estáveis

Erros devem incluir substrings estáveis (tokens) para testes e integração. Lista mínima:
	•	PCT_ERR_SIG_INVALID
	•	PCT_ERR_PACT_HASH_MISMATCH
	•	PCT_ERR_UNAUTHORIZED_SIGNER
	•	PCT_ERR_ORACLE_ID_MISMATCH
	•	PCT_ERR_QUORUM_NOT_MET
	•	PCT_ERR_DUP_SIGNER
	•	PCT_ERR_SEQ_SKIP
	•	PCT_ERR_SEQ_REPLAY
	•	PCT_ERR_UINT_FORMAT (recomendado)

⸻

15. Conformance Testing (Normativo)

O protocolo é considerado conforme quando:
	1.	Golden tests: dado um conjunto de fixtures (pact.json, state0.json, envelope.json) a implementação produz exatamente:
	•	expected_state1.json
	•	expected_outputs.json
	•	expected_trace.json
	•	receipt com hashes corretos
	2.	Negative tests: dado um fixture inválido, a execução deve falhar com um erro contendo o token esperado (expected_error.txt).
	3.	Cross-language parity: Rust e TypeScript devem:
	•	passar nos mesmos fixtures
	•	produzir mesmos hashes/estados nos golden fixtures

⸻

16. Considerações de Segurança
	•	Domain separation em hashes evita confusão de tipos e reuso perigoso de digest.
	•	Assinaturas estritas impedem malleability/edge cases de parsing.
	•	Allowlist de oráculos evita injeção de feeds não autorizados.
	•	Quorum + mediana reduz impacto de um oráculo malicioso.
	•	Anti-replay / anti-skip preserva integridade de sequência e impede “avanços ilegítimos”.
	•	oracle_id == signer_pub elimina spoofing de identidade e inconsistência em maps.
	•	Determinismo auditável: trace e receipt permitem recomputação local e validação.

⸻

17. Compatibilidade e Versionamento
	•	Este documento especifica RiskPact V0.2 como comportamento normativo.
	•	Mudanças que alterem semântica (ex.: regras de quorum subset) devem ser tratadas como V0.3+ e acompanhadas de novos casos golden.

⸻

18. Apêndice: Tags normativas
	•	hash_json tags:
	•	pactum:pact:0
	•	pactum:state:0
	•	pactum:envelope:0
	•	pactum:event:0
	•	pactum:outputs:0
	•	pactum:trace:0
	•	pactum:receipt:0 (opcional)
	•	sig tag:
	•	pactum:sig:event:0

⸻

Se você quiser, eu também posso te entregar uma versão desse mesmo arquivo com:
	•	JSON Schemas (para pact/state/envelope/event/trace/receipt)
	•	uma seção “Reference Algorithms” com pseudocódigo completo por fase
	•	e uma seção “Examples” com um mini-envelope comentado (sem expor fixtures completas).