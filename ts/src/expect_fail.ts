import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import { stepRiskPactV0 } from "./pactum";

function load(p: string) { return JSON.parse(fs.readFileSync(p, "utf8")); }

const dir = process.argv[2];
if (!dir) throw new Error("usage: tsx src/expect_fail.ts <fixture_dir>");

const pact = load(path.join(dir, "pact.json"));
const state0 = load(path.join(dir, "state0.json"));
const envelope = load(path.join(dir, "envelope.json"));
const expected = fs.readFileSync(path.join(dir, "expected_error.txt"), "utf8").trim();

let ok = false;
try {
  stepRiskPactV0(pact, state0, envelope);
} catch (e: any) {
  ok = String(e?.message ?? e).includes(expected);
  if (!ok) {
    throw new Error(`Expected error containing "${expected}", got "${String(e?.message ?? e)}"`);
  }
}
assert.equal(ok, true);
console.log("✅ Expected failure observed:", expected);

