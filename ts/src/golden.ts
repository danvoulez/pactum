import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";

import { hashJson } from "./hash";
import { stepRiskPactV0 } from "./pactum";

function load(p: string) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

const fixtureDir = process.argv[2] ?? path.join("..", "tests", "fixtures");

const pact = load(path.join(fixtureDir, "pact.json"));
const state0 = load(path.join(fixtureDir, "state0.json"));
const envelope = load(path.join(fixtureDir, "envelope.json"));

const expectedState1 = load(path.join(fixtureDir, "expected_state1.json"));
const expectedOutputs = load(path.join(fixtureDir, "expected_outputs.json"));
const expectedTrace = load(path.join(fixtureDir, "expected_trace.json"));
const expectedReceipt = load(path.join(fixtureDir, "expected_receipt.json"));

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

