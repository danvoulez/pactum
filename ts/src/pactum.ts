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

export function verifyEvent(event: any, pact: any): void {
  const signerPub = getStr(event, "signer_pub");
  const sigStr = getStr(event, "sig");
  const pactHash = getStr(event, "pact_hash");

  // Verify pact_hash matches
  const expectedPactHash = hashJson("pactum:pact:0", pact);
  if (pactHash !== expectedPactHash) throw new Error("InvalidPactHash");

  const body = {
    v: getStr(event, "v"),
    kind: getStr(event, "kind"),
    pact_hash: pactHash,
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

  // Extract oracle pubkeys for authorization
  const clockPubkeys: string[] = pact.oracles?.clock?.pubkeys || [];
  const metricPubkeys: string[] = pact.oracles?.metric?.pubkeys || [];

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

  let breachStartTime: bigint | null = null;
  if (state.breach_start_time !== null && state.breach_start_time !== undefined) {
    breachStartTime = uintStrToBigInt(String(state.breach_start_time));
  }

  const outputs = { v: "pactum-outputs/0", effects: [] as any[] };
  const trace = { v: "pactum-trace/0", steps: [] as any[] };

  const events: any[] = envelope?.events;
  if (!Array.isArray(events)) throw new Error("missing events");

  // Pre-validate all events
  for (const ev of events) {
    if (getStr(ev, "pact_hash") !== pactHash) throw new Error("PactHashMismatch");
    verifyEvent(ev, pact);
  }

  for (let i = 0; i < events.length; i++) {
    const ev = events[i];
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
      // Authorization for oracle events
      if (kind === "clock_event" && !clockPubkeys.includes(signer)) {
        throw new Error(`Unauthorized: clock_event signer ${signer} not in allowed pubkeys`);
      }
      if (kind === "metric_event" && !metricPubkeys.includes(signer)) {
        throw new Error(`Unauthorized: metric_event signer ${signer} not in allowed pubkeys`);
      }

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
        if (breachStartTime === null) {
          breachStartTime = now; // IMPORTANT: uses now, not event.t
          breach = "start";
        } else {
          breach = "continue";
        }
      } else {
        breachStartTime = null;
        breach = "clear";
      }

      if (breachStartTime !== null) {
        if (now >= breachStartTime && (now - breachStartTime) >= durationD) triggered = true;
      }

      trace.steps.push({
        i: String(i),
        kind: "apply_metric",
        oracle_id: oracleId,
        t: String(t),
        v: String(v),
        now: String(now),
        breach,
        breach_start_time: breachStartTime !== null ? String(breachStartTime) : null,
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
  state.breach_start_time = breachStartTime !== null ? String(breachStartTime) : null;

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

