Hell yes. If your gen_fixtures run produces fixtures and cargo test pactum_riskpact_v0_golden passes with full hash verification, then Pactum V0 is no longer “a spec” — it’s a deterministic protocol kernel with a conformance gate.

Here are the highest-leverage next moves to make this production-grade (and make the next language port painless):

1) Tighten authorization (don’t just verify signatures)

Right now you correctly verify that something was signed — next you want to verify it was signed by an allowed key for that event type.

Add checks like:
	•	collateral_post signer must equal parties.a_pub
	•	claim_request signer must equal parties.b_pub
	•	clock_event signer must be in pact.oracles.clock.pubkeys
	•	metric_event signer must be in pact.oracles.metric.pubkeys

This closes the biggest “protocol gap” between crypto correctness and pact correctness.

2) Freeze a receipt hashing rule (non-recursive)

Keep this invariant forever:
	•	receipt_hash = H("pactum:receipt:0", canon(receipt_without_receipt_hash))

Then store chains of receipt_hash cheaply (rollup/minimal client story becomes automatic).

3) Add a second golden vector (edge-case)

One more fixture set catches 80% of future regressions:
	•	metric recovers above threshold (breach clears)
	•	then dips again (breach restarts)
	•	claim attempted before trigger (must fail)
	•	then claim succeeds after trigger

Make it tests/fixtures_case2/ and a second test pactum_riskpact_v0_case2_golden.

4) Add CI-grade guardrails

These are worth doing immediately:
	•	cargo fmt --check
	•	cargo clippy -- -D warnings
	•	cargo test
	•	optional: cargo deny (licenses/advisories)

5) Start the second-language port now

Don’t wait. The whole point of Pactum is cross-implementation determinism.

Minimum port target:
	•	canonical JSON
	•	SHA-256 domain hashing
	•	event signature verify
	•	step() producing the same receipt hashes as Rust from your fixtures

Once TS/Go matches the Rust fixtures, you’ve proven “protocolness.”

If you tell me which one you want next (TypeScript or Go), I’ll give you the smallest possible conformance harness that reads tests/fixtures/*.json and asserts all hashes match.

---

Perfect — TypeScript is the right “second implementation” to prove Pactum is a protocol, not a Rust artifact.

Below is a minimal TS conformance harness that:
	•	canonicalizes JSON exactly like your Rust canonical_string
	•	hashes with domain separation: sha256(tag || 0x00 || bytes)
	•	verifies Ed25519 event signatures (raw 32-byte pubkeys) via tweetnacl
	•	runs stepRiskPactV0() and asserts:
	•	state1/outputs/trace match fixtures
	•	receipt hashes match recomputation
	•	optional receipt_hash matches H(pactum:receipt:0, canon(receipt))

Assumes you run it from the same repo where Rust wrote tests/fixtures/*.json.

⸻

1) Create ts/ folder with these files

ts/package.json

{
  "name": "pactum-ts-conformance",
  "private": true,
  "type": "commonjs",
  "scripts": {
    "golden": "tsx src/golden.ts"
  },
  "devDependencies": {
    "@types/node": "^22.0.0",
    "tsx": "^4.19.0",
    "typescript": "^5.6.0"
  },
  "dependencies": {
    "tweetnacl": "^1.0.3"
  }
}

ts/tsconfig.json

{
  "compilerOptions": {
    "target": "ES2020",
    "module": "CommonJS",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  }
}


⸻

2) Core modules

ts/src/canon.ts

export function canonicalString(v: any): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    // Pactum V0 should not use JSON numbers; keep strict.
    throw new Error("JSON numbers are not allowed in Pactum canonical form (use decimal strings).");
  }
  if (typeof v === "string") return JSON.stringify(v);

  if (Array.isArray(v)) {
    return "[" + v.map(canonicalString).join(",") + "]";
  }

  if (typeof v === "object") {
    const keys = Object.keys(v).sort();
    const parts: string[] = [];
    for (const k of keys) {
      parts.push(JSON.stringify(k) + ":" + canonicalString(v[k]));
    }
    return "{" + parts.join(",") + "}";
  }

  throw new Error(`Unsupported JSON type: ${typeof v}`);
}

ts/src/hash.ts

import crypto from "node:crypto";
import { canonicalString } from "./canon";

export function sha256Domain(tag: string, bytes: Buffer): Buffer {
  const h = crypto.createHash("sha256");
  h.update(Buffer.from(tag, "utf8"));
  h.update(Buffer.from([0]));
  h.update(bytes);
  return h.digest();
}

export function prefixedSha256Hex(d: Buffer): string {
  return "sha256:" + d.toString("hex");
}

export function hashJson(tag: string, v: any): string {
  const canon = canonicalString(v);
  const d = sha256Domain(tag, Buffer.from(canon, "utf8"));
  return prefixedSha256Hex(d);
}

ts/src/ed25519.ts

import nacl from "tweetnacl";

function b64urlToBytes(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  return new Uint8Array(Buffer.from(b64, "base64"));
}

export function parseEd25519Pub(s: string): Uint8Array {
  if (!s.startsWith("ed25519:")) throw new Error("bad pubkey prefix");
  const raw = b64urlToBytes(s.slice("ed25519:".length));
  if (raw.length !== 32) throw new Error("bad pubkey length");
  return raw;
}

export function parseEd25519Sig(s: string): Uint8Array {
  if (!s.startsWith("ed25519sig:")) throw new Error("bad sig prefix");
  const raw = b64urlToBytes(s.slice("ed25519sig:".length));
  if (raw.length !== 64) throw new Error("bad sig length");
  return raw;
}

export function verifyEd25519(msg: Uint8Array, sig: Uint8Array, pub: Uint8Array): boolean {
  return nacl.sign.detached.verify(msg, sig, pub);
}

ts/src/pactum.ts

import { hashJson } from "./hash";
import { parseEd25519Pub, parseEd25519Sig, verifyEd25519 } from "./ed25519";

function uintStrToBigInt(s: string): bigint {
  if (!/^(0|[1-9][0-9]*)$/.test(s)) throw new Error(`bad uint string: ${s}`);
  return BigInt(s);
}

function getStr(o: any, k: string): string {
  const v = o?.[k];
  if (typeof v !== "string") throw new Error(`missing string field: ${k}`);
  return v;
}

export function verifyEvent(event: any): void {
  const signerPub = getStr(event, "signer_pub");
  const sigStr = getStr(event, "sig");

  const body = {
    v: getStr(event, "v"),
    kind: getStr(event, "kind"),
    pact_hash: getStr(event, "pact_hash"),
    payload: event?.payload,
    signer_pub: signerPub
  };

  const bodyHash = hashJson("pactum:event:0", body);
  const hex = bodyHash.slice("sha256:".length);
  const bodyHashBytes = Buffer.from(hex, "hex");

  const msg = Buffer.concat([
    Buffer.from("pactum:sig:event:0", "utf8"),
    Buffer.from([0]),
    bodyHashBytes
  ]);

  const pub = parseEd25519Pub(signerPub);
  const sig = parseEd25519Sig(sigStr);

  if (!verifyEd25519(msg, sig, pub)) throw new Error("SigInvalid");
}

export function stepRiskPactV0(pact: any, prevState: any, envelope: any) {
  const pactHash = hashJson("pactum:pact:0", pact);
  const prevStateHash = hashJson("pactum:state:0", prevState);
  const envelopeHash = hashJson("pactum:envelope:0", envelope);

  const state = structuredClone(prevState);
  if (getStr(state, "pact_hash") !== pactHash) throw new Error("PactHashMismatch");

  const aPub = getStr(pact.parties, "a_pub");
  const bPub = getStr(pact.parties, "b_pub");

  const thresholdZ = uintStrToBigInt(getStr(pact.terms, "threshold_z"));
  const durationD = uintStrToBigInt(getStr(pact.terms, "duration_d"));
  const capQ = uintStrToBigInt(getStr(pact.terms, "cap_q"));

  const collateralAsset = getStr(pact.assets, "collateral_asset");

  let now = uintStrToBigInt(getStr(state, "now"));
  let collateralPosted = uintStrToBigInt(getStr(state, "collateral_posted"));
  let claimPaid = uintStrToBigInt(getStr(state, "claim_paid"));
  let triggered = !!state.triggered;

  const oracleSeq: Record<string, string> = state.oracle_seq ?? {};
  const oracleTime: Record<string, string> = state.oracle_time ?? {};
  state.oracle_seq = oracleSeq;
  state.oracle_time = oracleTime;

  const outputs = { v: "pactum-outputs/0", effects: [] as any[] };
  const trace = { v: "pactum-trace/0", steps: [] as any[] };

  const events: any[] = envelope?.events;
  if (!Array.isArray(events)) throw new Error("missing events");

  for (let i = 0; i < events.length; i++) {
    const ev = events[i];
    if (getStr(ev, "pact_hash") !== pactHash) throw new Error("PactHashMismatch");
    verifyEvent(ev);

    const kind = getStr(ev, "kind");
    const signer = getStr(ev, "signer_pub");
    const payload = ev.payload ?? {};

    if (kind === "collateral_post") {
      if (signer !== aPub) throw new Error("Unauthorized");
      const amt = uintStrToBigInt(getStr(payload, "amount"));
      const asset = getStr(payload, "asset");
      if (asset !== collateralAsset) throw new Error("wrong collateral asset");
      collateralPosted += amt;

      trace.steps.push({ i: String(i), kind: "apply_collateral", amount: String(amt), collateral_posted: String(collateralPosted) });
      continue;
    }

    if (kind === "clock_event" || kind === "metric_event") {
      const oracleId = getStr(payload, "oracle_id");
      const seq = uintStrToBigInt(getStr(payload, "seq"));
      const t = uintStrToBigInt(getStr(payload, "t"));

      const lastSeq = oracleSeq[oracleId] ? uintStrToBigInt(oracleSeq[oracleId]) : null;
      if (lastSeq === null) {
        if (seq !== 1n) throw new Error("OracleSeq");
      } else {
        if (seq !== lastSeq + 1n) throw new Error("OracleSeq");
      }

      const lastT = oracleTime[oracleId] ? uintStrToBigInt(oracleTime[oracleId]) : null;
      if (lastT !== null && t < lastT) throw new Error("OracleTime");

      oracleSeq[oracleId] = String(seq);
      oracleTime[oracleId] = String(t);

      if (kind === "clock_event") {
        if (t > now) now = t;
        trace.steps.push({ i: String(i), kind: "apply_clock", oracle_id: oracleId, seq: String(seq), t: String(t), now: String(now) });
        continue;
      }

      // metric_event
      const metricId = getStr(payload, "metric_id");
      if (metricId !== getStr(pact.terms, "metric_id")) throw new Error("metric_id mismatch");

      const v = uintStrToBigInt(getStr(payload, "v"));
      state.metric_last = { t: String(t), v: String(v) };

      let breach = "none";
      if (v < thresholdZ) {
        if (state.breach_start_time === null || state.breach_start_time === undefined) {
          state.breach_start_time = String(now); // IMPORTANT: uses now, not event.t
          breach = "start";
        } else {
          breach = "continue";
        }
      } else {
        state.breach_start_time = null;
        breach = "clear";
      }

      if (state.breach_start_time !== null) {
        const bst = uintStrToBigInt(String(state.breach_start_time));
        if (now >= bst && (now - bst) >= durationD) triggered = true;
      }

      trace.steps.push({
        i: String(i),
        kind: "apply_metric",
        oracle_id: oracleId,
        t: String(t),
        v: String(v),
        now: String(now),
        breach,
        breach_start_time: state.breach_start_time,
        triggered
      });
      continue;
    }

    if (kind === "claim_request") {
      if (signer !== bPub) throw new Error("Unauthorized");
      if (!triggered) throw new Error("not triggered");
      const amt = uintStrToBigInt(getStr(payload, "amount"));
      if (amt > capQ) throw new Error("cap exceeded");
      if (claimPaid + amt > collateralPosted) throw new Error("insufficient collateral");

      const effectIndex = outputs.effects.length;
      outputs.effects.push({ kind: "asset_flow", from: "party:a", to: "party:b", asset: collateralAsset, amount: String(amt) });
      claimPaid += amt;

      trace.steps.push({ i: String(i), kind: "apply_claim", amount: String(amt), claim_paid: String(claimPaid), effect_index: String(effectIndex) });
      continue;
    }

    throw new Error(`unknown kind: ${kind}`);
  }

  state.now = String(now);
  state.collateral_posted = String(collateralPosted);
  state.claim_paid = String(claimPaid);
  state.triggered = triggered;

  const newStateHash = hashJson("pactum:state:0", state);
  const outputsHash = hashJson("pactum:outputs:0", outputs);
  const traceHash = hashJson("pactum:trace:0", trace);

  const receipt = {
    v: "pactum-receipt/0",
    pact_hash: pactHash,
    prev_state_hash: prevStateHash,
    envelope_hash: envelopeHash,
    new_state_hash: newStateHash,
    outputs_hash: outputsHash,
    trace_hash: traceHash
  };

  return { state1: state, outputs, trace, receipt };
}


⸻

3) Golden test runner (reads Rust fixtures)

ts/src/golden.ts

import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";

import { hashJson } from "./hash";
import { stepRiskPactV0 } from "./pactum";

function load(p: string) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

const FIX = path.join("..", "tests", "fixtures");

const pact = load(path.join(FIX, "pact.json"));
const state0 = load(path.join(FIX, "state0.json"));
const envelope = load(path.join(FIX, "envelope.json"));

const expectedState1 = load(path.join(FIX, "expected_state1.json"));
const expectedOutputs = load(path.join(FIX, "expected_outputs.json"));
const expectedTrace = load(path.join(FIX, "expected_trace.json"));
const expectedReceipt = load(path.join(FIX, "expected_receipt.json"));

const { state1, outputs, trace, receipt } = stepRiskPactV0(pact, state0, envelope);

// 1) Structural equality
assert.deepEqual(state1, expectedState1, "State1 mismatch");
assert.deepEqual(outputs, expectedOutputs, "Outputs mismatch");
assert.deepEqual(trace, expectedTrace, "Trace mismatch");

// 2) Receipt equality (excluding receipt_hash)
const expectedReceiptNoHash = structuredClone(expectedReceipt);
delete expectedReceiptNoHash.receipt_hash;
assert.deepEqual(receipt, expectedReceiptNoHash, "Receipt mismatch (excluding receipt_hash)");

// 3) Hash verification
const pactHash = hashJson("pactum:pact:0", pact);
const prevStateHash = hashJson("pactum:state:0", state0);
const envelopeHash = hashJson("pactum:envelope:0", envelope);
const newStateHash = hashJson("pactum:state:0", state1);
const outputsHash = hashJson("pactum:outputs:0", outputs);
const traceHash = hashJson("pactum:trace:0", trace);

assert.equal(receipt.pact_hash, pactHash, "pact_hash mismatch");
assert.equal(receipt.prev_state_hash, prevStateHash, "prev_state_hash mismatch");
assert.equal(receipt.envelope_hash, envelopeHash, "envelope_hash mismatch");
assert.equal(receipt.new_state_hash, newStateHash, "new_state_hash mismatch");
assert.equal(receipt.outputs_hash, outputsHash, "outputs_hash mismatch");
assert.equal(receipt.trace_hash, traceHash, "trace_hash mismatch");

// 4) Optional receipt_hash check (non-recursive)
if (typeof expectedReceipt.receipt_hash === "string") {
  const actualReceiptHash = hashJson("pactum:receipt:0", receipt);
  assert.equal(actualReceiptHash, expectedReceipt.receipt_hash, "receipt_hash mismatch");
}

console.log("✅ TypeScript conformance passed (fixtures + hashes + signatures).");


⸻

4) Run it

From repo root:

cd ts
npm i
npm run golden

If that passes, you’ve achieved the real milestone: two independent implementations agree on hashes, receipts, and state transitions.

If you want the next “tighten the protocol” step, tell me whether you want TS to also enforce oracle pubkey allowlists (clock/metric) the same way Rust should — that’s the first “security-hardening” parity upgrade.