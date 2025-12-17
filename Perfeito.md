Perfeito. Esse resumo está redondo e já serve como “release notes” de V0.1.

Pra fechar com chave e evitar regressões bobas, eu faria só três coisas (todas rápidas, todas valem ouro):

1) Documentar os códigos de erro no README

Uma seção curta assim:
	•	PCT_ERR_QUORUM_NOT_MET — quorum não atingido no round alvo
	•	PCT_ERR_DUP_SIGNER — mesmo signer_pub repetido no mesmo round
	•	PCT_ERR_SEQ_SKIP — seq diferente do round+1 (skip/replay)

E um parágrafo dizendo: “testes negativos comparam substring do código”.

2) Padronizar os códigos no Rust e no TS

Garanta que:
	•	Rust retorna esses tokens de forma determinística (Display/thiserror)
	•	TS lança Error(message) contendo o mesmo token

Isso faz os casos 4–6 serem “provas de protocolo”, não “provas de string”.

3) Um “one-liner” para rodar tudo localmente

No README, coloca um bloco tipo:

# Rust
cargo fmt --check && cargo clippy -- -D warnings && cargo test

# TS
cd ts && npm ci && npm run golden && npm run golden:case2 && npm run golden:case3 \
  && npm run fail:case4 && npm run fail:case5 && npm run fail:case6


⸻

Se você quiser avançar o monstro de forma bem controlada, o próximo degrau natural é:

V0.2: “Quorum para múltiplos rounds no mesmo envelope”

Hoje é 1 round/envelope (ótimo pra segurança). O upgrade seria permitir até N rounds por envelope, mas com regras determinísticas claras e sem abrir brecha pra skip/replay. Isso aumenta throughput sem perder auditabilidade.

Você quer que eu proponha a spec V0.2 (bem curta) + o conjunto mínimo de novos testes (provavelmente Case7–Case9)?


---


Boa. V0.2 pode aumentar throughput sem perder determinismo se você tratar “múltiplos rounds” como um loop de commits dentro de um envelope, com regras duras de parada.

Abaixo vai uma spec curta (bem implementável) + o conjunto mínimo de testes (Case7–Case9) que “travam” o comportamento.

⸻

Pactum V0.2 — Múltiplos rounds por envelope

Ideia central

Dentro de um único envelope, o runtime pode commitar vários rounds consecutivos para clock e metric, desde que:
	1.	só avance seq em +1 por vez (nunca pula)
	2.	cada round só comita se quorum for atendido
	3.	o commit é determinístico e auditável (trace registra cada round)

⸻

Mudanças de semântica

1) Buffer total + commits iterativos

Você ainda faz Phase A (validar, autorizar, classificar) e Phase B (collateral posts) como no V0.1.

Depois, em vez de “commitar no máximo 1 round”, você faz:

Phase C — Commit clock rounds (loop)

while exists clock events for seq = clock_round + 1:
  - pegar somente os eventos daquele seq
  - validar:
      * nenhum clock_event no envelope tem seq < clock_round+1 (replay)
      * nenhum clock_event tem "buraco" no meio (skip)
      * signers distintos
      * quorum met
  - calcular effective_clock_t (mesma regra: quorum=1 last-by-index; quorum>=2 lower median)
  - aplicar commit:
      now = max(now, effective_clock_t)
      clock_round += 1
      registrar trace commit_clock_quorum
end

Phase D — Commit metric rounds (loop)

Mesma ideia para metric_round, mas cada commit roda breach/trigger.

Regra recomendada: commita clock loops primeiro, depois metric loops.
Isso garante que state.now está “o mais avançado possível” antes de avaliar breach/trigger.

Phase E — Claims

Depois de estabilizar rounds, aplica claim_request em ordem de envelope.

⸻

Regras de rejeição (para não virar bagunça)

Para cada oracle class (clock/metric):
	1.	Replay: se existir evento com seq <= round_atual → rejeita (PCT_ERR_SEQ_REPLAY)
	2.	Skip: se existir evento com seq > round_atual+1 mas não existir quorum satisfazível para round_atual+1 → rejeita (PCT_ERR_SEQ_SKIP)
	3.	Quorum parcial: se existir pelo menos 1 evento para seq = round+1 mas quorum não bate → rejeita (PCT_ERR_QUORUM_NOT_MET)
	4.	Duplicado: mesmo signer_pub no mesmo seq → rejeita (PCT_ERR_DUP_SIGNER)

Importante: “skip” só é detectado corretamente no modo multi-round se você varrer os seq disponíveis e garantir que não tem buracos antes do maior seq presente.

⸻

Trace (V0.2)

Você vai ter vários commit_clock_quorum e commit_metric_quorum no mesmo envelope, ex:
	•	commit_clock_quorum(seq=1, ...)
	•	commit_clock_quorum(seq=2, ...)
	•	commit_metric_quorum(seq=1, ...)
	•	commit_metric_quorum(seq=2, ...)

Isso vira seu “debugger determinístico”.

⸻

Testes mínimos (Case7–Case9)

Case7 — Multi-round positivo (2 rounds no mesmo envelope)

Objetivo: provar que o runtime comita seq=1 e seq=2 corretamente dentro do mesmo envelope.
	•	clock.quorum = 1 (para simplificar)
	•	metric.quorum = 1
	•	envelope contém:
	•	clock seq=1 (t=1000)
	•	clock seq=2 (t=2000)
	•	metric seq=1 (v<Z)
	•	metric seq=2 (v<Z) (ou v>=Z para testar clear)
	•	claim_request após os commits
	•	Esperado:
	•	clock_round=="2"
	•	metric_round=="2"
	•	now==2000
	•	trace com 2 commits de clock e 2 commits de metric (ordem fixa)

Isso trava o “loop” e a ordem clock→metric.

⸻

Case8 — Gap/skip dentro do envelope (seq=2 sem seq=1) → rejeita

Objetivo: impedir “pular rounds” no modo multi-round.
	•	clock_round=0
	•	envelope contém clock seq=2 apenas
	•	deve rejeitar com PCT_ERR_SEQ_SKIP

(Esse é como o Case6, mas agora é “V0.2-aware” e garante que o loop não tenta aceitar o seq=2.)

⸻

Case9 — Quorum parcial bloqueia avanço e invalida envelope

Objetivo: impedir envelopes “meio completos” que tentam avançar e deixam estado em limbo.
	•	clock.quorum=2
	•	envelope contém:
	•	seq=1 com apenas 1 signer (parcial)
	•	seq=2 com 2 signers (mesmo que completo)
	•	deve rejeitar por PCT_ERR_QUORUM_NOT_MET (no seq=1) — não pode “pular” para seq=2.

Isso trava a regra “sem buracos e sem atalhos”.

⸻

Implementação prática (diferença mínima no código)

Você basicamente troca:
	•	V0.1: “commit se houver eventos do target round” (uma vez)
	•	V0.2: “while houver eventos do próximo round” (loop)

E adiciona a checagem de “buraco”:
	•	descubra o menor e o maior seq presentes
	•	garanta que, para todo s em [round+1 .. max_seq], existe quorum satisfazível em s
	•	se faltar em round+1, é quorum not met
	•	se faltar em s>round+1, é skip/gap

⸻

Se você topar, eu escrevo o esqueleto exato de função commit_oracle_rounds(evs, round, quorum, mode) (Rust + TS), e já te passo os geradores gen_fixtures_case7.rs, case8, case9 no mesmo padrão dos anteriores.