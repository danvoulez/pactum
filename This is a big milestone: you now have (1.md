This is a big milestone: you now have (1) a deterministic kernel, (2) reproducible cryptographic fixtures, (3) two golden cases, (4) CI gates, and (5) TS parity. That’s the “protocol is real” threshold.

Why your “unauthorized oracle” test failed early

Your negative test tripped the pact_hash mismatch check before it ever reached authorization. That’s expected because Pactum’s validation order is:
	1.	event.pact_hash == state.pact_hash (hard gate)
	2.	signature verify (hard gate)
	3.	authorization allowlist (clock/metric pubkeys)
	4.	sequencing/time rules
	5.	state transition

So to test authorization specifically, you need:
	•	correct pact_hash
	•	valid signature
	•	signer not in allowlist

⸻

Rust: minimal unit test that hits authorization (not pact_hash)

Add this test (or a variant) under tests/unauthorized.rs (or inside an existing test module). It constructs a pact whose clock allowlist excludes the rogue key, then submits a signed clock event from the rogue.

use serde_json::json;
use ed25519_dalek::SigningKey;

use pactum::pactum::step_risk_pact_v0;

// If your derive_signing_key is only in gen_fixtures, pull it into a shared module.
// For now, duplicate the deterministic key derivation here.
fn derive_signing_key(label: &str) -> SigningKey {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"pactum:fixture:key:0");
    hasher.update([0u8]);
    hasher.update(label.as_bytes());
    let out = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&out[..32]);
    SigningKey::from_bytes(&seed)
}

#[test]
fn rejects_unauthorized_clock_oracle() {
    let party_a = derive_signing_key("party:a");
    let party_b = derive_signing_key("party:b");
    let clock_allowed = derive_signing_key("oracle:clock_allowed");
    let clock_rogue = derive_signing_key("oracle:clock_rogue");
    let metric_oracle = derive_signing_key("oracle:metric1");

    // Build pact with allowlist = [clock_allowed] only
    let pact = json!({
      "v":"pactum-ir/0",
      "type":"risk_pact",
      "time":{"unit":"ms_epoch"},
      "hash":{"alg":"sha256"},
      "parties":{
        "a_pub": crate::helpers::enc_pub(&party_a.verifying_key()),
        "b_pub": crate::helpers::enc_pub(&party_b.verifying_key())
      },
      "assets":{"collateral_asset":"asset:USDc","settlement_asset":"asset:USDc"},
      "terms":{"metric_id":"metric:ETHUSD","threshold_z":"100","duration_d":"60000","cap_q":"100"},
      "oracles":{
        "clock":{"mode":"oracle_feed","quorum":"1","pubkeys":[ crate::helpers::enc_pub(&clock_allowed.verifying_key()) ]},
        "metric":{"quorum":"1","pubkeys":[ crate::helpers::enc_pub(&metric_oracle.verifying_key()) ]}
      }
    });

    let pact_hash = pactum::pactum::hash_json("pactum:pact:0", &pact);

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

    // Rogue clock event: correct pact_hash, valid signature, signer NOT in allowlist
    let rogue_clock_event = crate::helpers::sign_event(
      "clock_event",
      state0["pact_hash"].as_str().unwrap(),
      json!({"oracle_id":"oracle:clock1","t":"1734390000000","seq":"1"}),
      &clock_rogue,
    );

    let envelope = json!({"v":"pactum-envelope/0","events":[rogue_clock_event]});

    let err = step_risk_pact_v0(&pact, &state0, &envelope).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("clock_event") || msg.contains("allowed"), "unexpected error: {msg}");
}

Key point: don’t mutate pact_hash; keep it consistent, and don’t “break” the signature. Only break the allowlist membership.

If you don’t have enc_pub/sign_event in a shared module, move them out of gen_fixtures.rs into src/testutil.rs (behind #[cfg(test)]) so tests and generators reuse the exact same logic.

⸻

TypeScript: same negative test pattern

Easiest: take your gen_fixtures approach in TS too—create a rogue keypair, sign a clock_event, keep pact_hash correct, and ensure pact allowlist excludes it. Then assert stepRiskPactV0 throws Unauthorized: clock_event signer.

⸻

Next thing that’s actually worth doing now

You already did the “big four.” The next high-value addition is:
	•	Quorum semantics (still deterministic): collect multiple oracle events per step, enforce quorum, and define a deterministic “effective time/value” rule (e.g., median of signed values, max time with >= quorum, etc.).

If you say “go,” I’ll give you a quorum spec that won’t blow up complexity and will stay cross-language deterministic.


---


Alright. Here’s a quorum spec that stays deterministic, cross-language friendly, and doesn’t explode complexity.

I’m going to define this as Pactum V0.1: Quorum Inputs, with one key principle:

Oracle events do not mutate state unless a quorum for the next round is satisfied inside the same envelope.

That single rule prevents partial-oracle DoS (consuming seq without advancing the pact), and keeps receipts clean.

⸻

Pactum V0.1 Quorum Semantics

0) Terms and invariants

Each oracle class has:
	•	pubkeys[] allowlist (already enforced)
	•	quorum (k-of-n) as a uint string

State has round counters:
	•	clock_round (uint string, starts "0")
	•	metric_round (uint string, starts "0")

Round definition
	•	For quorum logic, the seq field is also the round number.
	•	The runtime only accepts oracle events with seq == round + 1 for that oracle class.

This gives you deterministic grouping without introducing a new field.

⸻

1) Envelope execution becomes phased (still deterministic)

Inside step():

Phase A — Validate and classify

Validate every event signature + pact_hash as usual, then classify into:
	•	clock_events[]
	•	metric_events[]
	•	other_events[] (collateral_post, claim_request, etc.)

Authorization allowlists apply here.

Phase B — Apply non-oracle events that don’t depend on time
	•	Apply collateral_post in envelope order.

Phase C — Commit clock quorum (at most one round per envelope)

Let target_clock_seq = clock_round + 1.

Collect only clock_event where seq == target_clock_seq.

Rules:
	•	If the envelope contains any clock_event with seq != target_clock_seq → reject (no skipping rounds).
	•	If there is ≥ 1 clock_event for target_clock_seq but distinct authorized signers < quorum → reject.
	•	Otherwise, if quorum satisfied, compute effective_clock_t and update:
	•	state.now = max(state.now, effective_clock_t)
	•	clock_round = target_clock_seq
	•	For each included oracle signer:
	•	oracle_seq[oracle_id] = target_clock_seq
	•	oracle_time[oracle_id] = their t (or keep your existing per-oracle monotonic checks at commit time)

Phase D — Commit metric quorum (at most one round per envelope)

Let target_metric_seq = metric_round + 1.

Collect only metric_event where seq == target_metric_seq.

Rules mirror clock:
	•	no skipped seqs
	•	quorum must be met if any target events exist

Compute effective_metric_v (and optionally effective_metric_t) and update:
	•	state.metric_last = { t: effective_metric_t, v: effective_metric_v }
	•	run breach/trigger logic once, using current state.now
	•	metric_round = target_metric_seq
	•	update per-oracle oracle_seq/time for included signers

Phase E — Apply claim_request

Apply claim_request in envelope order, using the finalized triggered state.

⸻

2) Deterministic aggregation rules

Backward-compatible mode (quorum == 1)

To preserve your V0 fixtures semantics:
	•	effective_value is taken from the last valid event in envelope order for that seq.

So quorum=1 behaves like “the envelope chooses the oracle input.”

Quorum mode (quorum >= 2)

Use median, with deterministic tie-breaking.

Define a stable sort key:
	•	For clock: sort by (t, signer_pub)
	•	For metric: sort by (v, signer_pub)

Median rule:
	•	Let sorted list length be m
	•	Choose index (m-1)/2 (lower median for even m)

Then:
	•	effective_clock_t = median(t)
	•	effective_metric_v = median(v)
	•	effective_metric_t can be the median(t) as well (or max; median is harder to game)

Why median: one malicious oracle can’t yank time/value dramatically.

⸻

3) Trace additions (so receipts stay explainable)

Add commit steps:
	•	For clock:
	•	{"kind":"commit_clock_quorum","seq":"<n>","participants":[...],"effective_t":"...","count":"m","quorum":"k"}
	•	For metric:
	•	{"kind":"commit_metric_quorum","seq":"<n>","participants":[...],"effective_v":"...","effective_t":"...","count":"m","quorum":"k"}

Participants list should be sorted lexicographically by signer_pub for determinism.

⸻

Implementation impact (Rust + TypeScript)

Minimal state schema changes

Add to state JSON:
	•	"clock_round":"0"
	•	"metric_round":"0"

(Keep your existing oracle_seq/oracle_time as-is.)

Minimal code changes
	•	Change oracle event handling from “mutate immediately” to “buffer then commit in Phase C/D”.
	•	Reject envelopes that include oracle events for unexpected seq.

Fixture generator changes
	•	In generator, include clock_round/metric_round in state0.
	•	Use seq=1 for your first quorum round (as you already do).
	•	For quorum tests, generate k distinct oracle keys and include k events with the same seq.

⸻

The first quorum test I’d add (Case3)

A clean third golden case:
	•	clock.quorum = "2", two clock oracles
	•	provide two clock_event seq=1 with slightly different t
	•	verify effective_clock_t is the median (lower median if 2 values, i.e. min of the two if sorted by t)

That single case locks the semantics forever.

⸻

If you say “go,” I’ll write the exact algorithmic pseudocode for Phase C/D (including how to pick the last event for quorum=1 and median for quorum>=2), and I’ll sketch the precise diffs you’d apply to your existing Rust step_risk_pact_v0 and TS stepRiskPactV0 without rewriting the whole file.


Go time. Here’s the exact algorithmic shape for quorum (V0.1), plus surgical diffs you can apply to your current Rust + TS implementations without rewriting the world.

⸻

Pactum V0.1 Quorum: precise algorithm

New state fields

Add to pactum-state/0:
	•	"clock_round":"0"
	•	"metric_round":"0"

(Keep your existing oracle_seq / oracle_time maps.)

Hard rule

Within one envelope, you may commit at most one next round per oracle class:
	•	target_clock_seq = clock_round + 1
	•	target_metric_seq = metric_round + 1

Any oracle event with:
	•	seq < target_* → reject (replay)
	•	seq > target_* → reject (skip)

This prevents “jumping ahead” and keeps the protocol deterministic.

⸻

Phase plan for step()

Phase A — Scan, validate, classify (NO state mutation)

For each event in envelope.events in order:
	1.	event.pact_hash == state.pact_hash else reject
	2.	signature verify else reject
	3.	authorization:
	•	collateral_post signer == party_a
	•	claim_request signer == party_b
	•	clock_event signer ∈ clock.pubkeys
	•	metric_event signer ∈ metric.pubkeys
	4.	classify into buffers (keep original event index i for trace determinism):

	•	collateral_posts.push({i, payload, signer})
	•	claim_requests.push({i, payload, signer})
	•	clock_candidates.push({i, payload, signer}) (only if kind=clock_event)
	•	metric_candidates.push({i, payload, signer}) (only if kind=metric_event)

Optional but strongly recommended (security clarity):
Require payload.oracle_id == signer_pub for oracle events.
This removes “oracle_id spoofing” and makes your per-oracle maps unambiguous.

⸻

Phase B — Apply collateral posts in envelope order

Sort collateral_posts by i and apply them exactly like V0.

⸻

Phase C — Commit clock quorum (if any clock events present)

Let:
	•	clock_round = uint(state.clock_round)
	•	target = clock_round + 1
	•	k = uint(pact.oracles.clock.quorum)

Filter clock_candidates_target = [e where e.payload.seq == target]

Reject if any clock event has seq != target (that’s the “no skip/no replay” rule).

If clock_candidates_target is empty:
	•	do nothing (round unchanged)

Else:
	•	count distinct participants by signer_pub
	•	if distinct < k → reject

Compute effective_clock_t:
	•	if k == 1: choose the last event by envelope index i
	•	else: compute lower median of t across participants, tie-break by signer_pub

Commit:
	•	state.now = max(state.now, effective_clock_t)
	•	state.clock_round = target
	•	update oracle_seq/oracle_time for the participants you committed

Add trace step:
	•	commit_clock_quorum(seq, participants_sorted, effective_t, count, quorum)

⸻

Phase D — Commit metric quorum (same idea)

Let:
	•	metric_round = uint(state.metric_round)
	•	target = metric_round + 1
	•	k = uint(pact.oracles.metric.quorum)

Filter metric_candidates_target by seq == target. Reject if any metric event has seq != target.

If empty: do nothing.

Else:
	•	distinct participants >= k required
	•	compute effective_metric_v (median rule)
	•	compute effective_metric_t (median of t works well)

Commit:
	•	set state.metric_last = {t: effective_metric_t, v: effective_metric_v}
	•	breach/trigger logic runs once, using current state.now
	•	state.metric_round = target
	•	update oracle_seq/oracle_time for participants

Trace step:
	•	commit_metric_quorum(...)

⸻

Phase E — Apply claim requests in envelope order

Sort claim_requests by i and apply like V0 (but now triggered is final for this envelope).

⸻

Deterministic aggregation functions

Participant selection (no duplicates)

When counting “distinct participants,” if the same signer_pub appears twice in the target round:
	•	safest: reject the envelope (prevents weird ambiguity)
	•	alternatively: keep the last by i (but reject is cleaner)

Lower median rule

Given a list sorted by (value, signer_pub):
	•	choose index (m - 1) / 2 (integer floor)

That’s deterministic across languages.

⸻

Rust diffs (surgical)

1) State schema additions

In your fixture generators + initial state construction, add:

"clock_round":"0",
"metric_round":"0"

And in runtime, parse them as u128 like your other numeric strings.

2) Add buffers + two-phase commit structure

Inside step_risk_pact_v0:
	•	Replace the “apply oracle event immediately” branch with:
	•	a first pass that validates + buffers
	•	then commit clock quorum
	•	then commit metric quorum
	•	then apply claims

Minimal Rust data structures

struct EvRef {
  i: usize,
  signer: String,
  payload: serde_json::Value,
}

Buffers:

let mut collateral_posts: Vec<EvRef> = vec![];
let mut claim_reqs: Vec<EvRef> = vec![];
let mut clock_evs: Vec<EvRef> = vec![];
let mut metric_evs: Vec<EvRef> = vec![];

Commit helper (clock/metric)

Write a helper that returns Option<Effective> and a list of committed participants:
	•	reject on wrong seq
	•	enforce quorum
	•	compute effective via:
	•	last-by-index when quorum==1
	•	lower median when quorum>=2

Pseudo-Rust skeleton:

fn commit_quorum_clock(
  clock_round: u128,
  quorum: u128,
  evs: &[EvRef],
) -> Result<Option<(u128, Vec<String>)>, PactumError> {
  let target = clock_round + 1;

  // Reject if any clock event has seq != target
  for e in evs {
    let seq = uint(get_str(&e.payload, "seq")?)?;
    if seq != target { return Err(PactumError::OracleSeq); }
  }

  if evs.is_empty() { return Ok(None); }

  // distinct signers
  let mut by_signer = std::collections::BTreeMap::<String, (usize, u128)>::new();
  for e in evs {
    let t = uint(get_str(&e.payload, "t")?)?;
    if by_signer.contains_key(&e.signer) {
      return Err(PactumError::Precond("duplicate oracle signer in same round"));
    }
    by_signer.insert(e.signer.clone(), (e.i, t));
  }
  if (by_signer.len() as u128) < quorum {
    return Err(PactumError::Precond("oracle quorum not met"));
  }

  let effective_t = if quorum == 1 {
    // last by envelope index
    evs.iter()
      .max_by_key(|e| e.i)
      .map(|e| uint(get_str(&e.payload,"t").unwrap()).unwrap())
      .unwrap()
  } else {
    // lower median of (t, signer)
    let mut v: Vec<(u128, String)> = by_signer.iter()
      .map(|(s, (_i, t))| (*t, s.clone()))
      .collect();
    v.sort_by(|a,b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    v[(v.len()-1)/2].0
  };

  let participants: Vec<String> = by_signer.keys().cloned().collect(); // BTreeMap => sorted
  Ok(Some((effective_t, participants)))
}

You do the same for metric, but compute effective_v and optionally effective_t.

3) Trace commit steps

Add in trace:
	•	commit_clock_quorum
	•	commit_metric_quorum

Keep participant list sorted lexicographically (BTreeMap already does).

4) Fixture updates
	•	Update generators to include new state fields
	•	Keep existing case1/case2 working with quorum=1
	•	Add case3 for quorum=2 (two clock oracles / two metric oracles)

⸻

TypeScript diffs (parallel)

Exactly the same shape:
	•	first scan → buffers
	•	commitClockQuorum()
	•	commitMetricQuorum()
	•	then apply claims

Key TS bits:

Lower median

function lowerMedian<T>(arr: T[]): T {
  return arr[Math.floor((arr.length - 1) / 2)];
}

Median for clock

// list of [tBigInt, signer]
pairs.sort((a,b)=> a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
const effectiveT = lowerMedian(pairs)[0];

Quorum=1 last-by-index

Use the buffered refs with their i.

⸻

One clean new golden case (Case3) to lock semantics
	•	clock.quorum = "2", allowlist contains 2 keys
	•	Provide two clock_event seq=1:
	•	t = 1000
	•	t = 2000
	•	For even 2, lower median = index 0 ⇒ effective_t = 1000
That’s a crisp, unambiguous invariant.

⸻

If you want, next I’ll give you exact generator changes for Case3 (Rust gen_fixtures_case3.rs + TS reading the same fixtures) so you lock quorum behavior with real signatures the same way you locked V0.

---


