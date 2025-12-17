use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

use crate::canon::canonical_string;
use crate::hash::{h_sha256, hash_json};

// Event reference for buffering during phased execution
#[derive(Clone)]
struct EvRef {
    i: usize,
    signer: String,
    payload: Value,
}

#[derive(Debug, thiserror::Error)]
pub enum PactumError {
    #[error("Invalid signature")]
    SigInvalid,
    #[error("Invalid pact hash in event")]
    InvalidPactHash,
    #[error("Unknown event kind: {0}")]
    UnknownEventKind(String),
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Invalid numeric field: {0}")]
    InvalidNumeric(String),
    #[error("Oracle sequence violation: {0}")]
    OracleSeqViolation(String),
    #[error("Oracle time violation: {0}")]
    OracleTimeViolation(String),
    #[error("Invalid signer: {0}")]
    InvalidSigner(String),
    #[error("Claim not allowed: {0}")]
    ClaimNotAllowed(String),
}

/// Verify an event signature according to Pactum V0 spec
pub fn verify_event(event: &Value, pact: &Value) -> Result<(), PactumError> {
    // Extract fields
    let kind = event
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PactumError::MissingField("kind".to_string()))?;

    let pact_hash = event
        .get("pact_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PactumError::MissingField("pact_hash".to_string()))?;

    let payload = event
        .get("payload")
        .ok_or_else(|| PactumError::MissingField("payload".to_string()))?;

    let signer_pub = event
        .get("signer_pub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PactumError::MissingField("signer_pub".to_string()))?;

    let sig_str = event
        .get("sig")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PactumError::MissingField("sig".to_string()))?;

    // Verify pact_hash matches
    let expected_pact_hash = hash_json("pactum:pact:0", pact);
    if pact_hash != expected_pact_hash {
        return Err(PactumError::InvalidPactHash);
    }

    // Rebuild event body (without sig field)
    let event_body = json!({
        "v": "pactum-event/0",
        "kind": kind,
        "pact_hash": pact_hash,
        "payload": payload,
        "signer_pub": signer_pub
    });

    // Compute event_body_hash
    let body_canon = canonical_string(&event_body);
    let body_hash_bytes = h_sha256("pactum:event:0", body_canon.as_bytes());

    // Build signature message: "pactum:sig:event:0" || 0x00 || body_hash_bytes
    let mut msg = Vec::with_capacity("pactum:sig:event:0".len() + 1 + 32);
    msg.extend_from_slice(b"pactum:sig:event:0");
    msg.push(0u8);
    msg.extend_from_slice(&body_hash_bytes);

    // Parse signer public key
    let pubkey_str = signer_pub
        .strip_prefix("ed25519:")
        .ok_or_else(|| PactumError::InvalidSigner("Invalid pubkey format".to_string()))?;
    let pubkey_bytes = URL_SAFE_NO_PAD
        .decode(pubkey_str)
        .map_err(|_| PactumError::InvalidSigner("Invalid base64".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(
        pubkey_bytes
            .as_slice()
            .try_into()
            .map_err(|_| PactumError::InvalidSigner("Invalid key length".to_string()))?,
    )
    .map_err(|_| PactumError::InvalidSigner("Invalid key".to_string()))?;

    // Parse signature
    let sig_str_clean = sig_str
        .strip_prefix("ed25519sig:")
        .ok_or_else(|| PactumError::InvalidSigner("Invalid sig format".to_string()))?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_str_clean)
        .map_err(|_| PactumError::InvalidSigner("Invalid sig base64".to_string()))?;
    let signature = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| PactumError::InvalidSigner("Invalid sig length".to_string()))?,
    );

    // Verify signature
    verifying_key
        .verify_strict(&msg, &signature)
        .map_err(|_| PactumError::SigInvalid)?;

    Ok(())
}

/// Parse a uint string, ensuring it matches ^(0|[1-9][0-9]*)$
fn parse_uint(s: &str) -> Result<u64, PactumError> {
    if s == "0" {
        return Ok(0);
    }
    if s.starts_with('0') || !s.chars().all(|c| c.is_ascii_digit()) {
        return Err(PactumError::InvalidNumeric(s.to_string()));
    }
    s.parse::<u64>()
        .map_err(|_| PactumError::InvalidNumeric(s.to_string()))
}

/// Commit clock quorum: returns (effective_t, participants) if quorum met
fn commit_clock_quorum(
    clock_round: u64,
    quorum: u64,
    evs: &[EvRef],
) -> Result<Option<(u64, Vec<String>)>, PactumError> {
    let target = clock_round + 1;

    // Reject if any clock event has seq != target
    for e in evs {
        let seq = parse_uint(
            e.payload
                .get("seq")
                .and_then(|v| v.as_str())
                .ok_or_else(|| PactumError::MissingField("seq".to_string()))?,
        )?;
        if seq != target {
            return Err(PactumError::OracleSeqViolation(format!(
                "PCT_ERR_SEQ_SKIP: Expected seq {target}, got {seq}"
            )));
        }
    }

    if evs.is_empty() {
        return Ok(None);
    }

    // Collect distinct signers (reject duplicates)
    let mut by_signer: BTreeMap<String, (usize, u64)> = BTreeMap::new();
    for e in evs {
        let t = parse_uint(
            e.payload
                .get("t")
                .and_then(|v| v.as_str())
                .ok_or_else(|| PactumError::MissingField("t".to_string()))?,
        )?;
        if by_signer.contains_key(&e.signer) {
            return Err(PactumError::InvalidSigner(
                "PCT_ERR_DUP_SIGNER: duplicate oracle signer in same round".to_string(),
            ));
        }
        by_signer.insert(e.signer.clone(), (e.i, t));
    }

    if (by_signer.len() as u64) < quorum {
        return Err(PactumError::ClaimNotAllowed(format!(
            "PCT_ERR_QUORUM_NOT_MET: Oracle quorum not met: need {quorum}, got {}",
            by_signer.len()
        )));
    }

    // Compute effective_t
    let effective_t = if quorum == 1 {
        // Last by envelope index
        evs.iter()
            .max_by_key(|e| e.i)
            .map(|e| parse_uint(e.payload.get("t").and_then(|v| v.as_str()).unwrap()).unwrap())
            .unwrap()
    } else {
        // Lower median of (t, signer)
        let mut v: Vec<(u64, String)> = by_signer
            .iter()
            .map(|(s, (_i, t))| (*t, s.clone()))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        v[(v.len() - 1) / 2].0
    };

    let mut participants: Vec<String> = by_signer.keys().cloned().collect();
    participants.sort(); // Ensure lexicographic order for deterministic trace
    Ok(Some((effective_t, participants)))
}

/// Commit metric quorum: returns (effective_v, effective_t, participants) if quorum met
fn commit_metric_quorum(
    metric_round: u64,
    quorum: u64,
    evs: &[EvRef],
) -> Result<Option<(u64, u64, Vec<String>)>, PactumError> {
    let target = metric_round + 1;

    // Reject if any metric event has seq != target
    for e in evs {
        let seq = parse_uint(
            e.payload
                .get("seq")
                .and_then(|v| v.as_str())
                .ok_or_else(|| PactumError::MissingField("seq".to_string()))?,
        )?;
        if seq != target {
            return Err(PactumError::OracleSeqViolation(format!(
                "PCT_ERR_SEQ_SKIP: Expected seq {target}, got {seq}"
            )));
        }
    }

    if evs.is_empty() {
        return Ok(None);
    }

    // Collect distinct signers (reject duplicates)
    let mut by_signer: BTreeMap<String, (usize, u64, u64)> = BTreeMap::new();
    for e in evs {
        let t = parse_uint(
            e.payload
                .get("t")
                .and_then(|v| v.as_str())
                .ok_or_else(|| PactumError::MissingField("t".to_string()))?,
        )?;
        let v = parse_uint(
            e.payload
                .get("v")
                .and_then(|val| val.as_str())
                .ok_or_else(|| PactumError::MissingField("v".to_string()))?,
        )?;
        if by_signer.contains_key(&e.signer) {
            return Err(PactumError::InvalidSigner(
                "PCT_ERR_DUP_SIGNER: duplicate oracle signer in same round".to_string(),
            ));
        }
        by_signer.insert(e.signer.clone(), (e.i, t, v));
    }

    if (by_signer.len() as u64) < quorum {
        return Err(PactumError::ClaimNotAllowed(format!(
            "PCT_ERR_QUORUM_NOT_MET: Oracle quorum not met: need {quorum}, got {}",
            by_signer.len()
        )));
    }

    // Compute effective_v (median of v)
    let effective_v = if quorum == 1 {
        // Last by envelope index
        evs.iter()
            .max_by_key(|e| e.i)
            .map(|e| parse_uint(e.payload.get("v").and_then(|v| v.as_str()).unwrap()).unwrap())
            .unwrap()
    } else {
        // Lower median of (v, signer)
        let mut v_pairs: Vec<(u64, String)> = by_signer
            .iter()
            .map(|(s, (_i, _t, v))| (*v, s.clone()))
            .collect();
        v_pairs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        v_pairs[(v_pairs.len() - 1) / 2].0
    };

    // Compute effective_t (median of t)
    let effective_t = if quorum == 1 {
        evs.iter()
            .max_by_key(|e| e.i)
            .map(|e| parse_uint(e.payload.get("t").and_then(|v| v.as_str()).unwrap()).unwrap())
            .unwrap()
    } else {
        let mut t_pairs: Vec<(u64, String)> = by_signer
            .iter()
            .map(|(s, (_i, t, _v))| (*t, s.clone()))
            .collect();
        t_pairs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        t_pairs[(t_pairs.len() - 1) / 2].0
    };

    let mut participants: Vec<String> = by_signer.keys().cloned().collect();
    participants.sort(); // Ensure lexicographic order for deterministic trace
    Ok(Some((effective_v, effective_t, participants)))
}

/// Main step function for RiskPact V0
pub fn step_risk_pact_v0(
    pact: &Value,
    prev_state: &Value,
    envelope: &Value,
) -> Result<(Value, Value, Value, Value), PactumError> {
    // Extract events
    let events = envelope
        .get("events")
        .and_then(|v| v.as_array())
        .ok_or_else(|| PactumError::MissingField("events".to_string()))?;

    // Pre-validate all events
    for event in events {
        verify_event(event, pact)?;

        let kind = event.get("kind").and_then(|v| v.as_str()).unwrap();
        if !matches!(
            kind,
            "clock_event" | "metric_event" | "collateral_post" | "claim_request"
        ) {
            return Err(PactumError::UnknownEventKind(kind.to_string()));
        }
    }

    // Initialize state from prev_state
    let state = prev_state.clone();

    // Extract oracle tracking maps
    let mut oracle_seq: HashMap<String, u64> = HashMap::new();
    let mut oracle_time: HashMap<String, u64> = HashMap::new();

    if let Some(seq_obj) = state.get("oracle_seq").and_then(|v| v.as_object()) {
        for (k, v) in seq_obj {
            if let Some(s) = v.as_str() {
                oracle_seq.insert(k.clone(), parse_uint(s)?);
            }
        }
    }

    if let Some(time_obj) = state.get("oracle_time").and_then(|v| v.as_object()) {
        for (k, v) in time_obj {
            if let Some(s) = v.as_str() {
                oracle_time.insert(k.clone(), parse_uint(s)?);
            }
        }
    }

    // Extract pact fields
    let parties = pact
        .get("parties")
        .ok_or_else(|| PactumError::MissingField("parties".to_string()))?;
    let a_pub = parties.get("a_pub").and_then(|v| v.as_str()).unwrap();
    let b_pub = parties.get("b_pub").and_then(|v| v.as_str()).unwrap();

    let assets = pact
        .get("assets")
        .ok_or_else(|| PactumError::MissingField("assets".to_string()))?;
    let collateral_asset = assets
        .get("collateral_asset")
        .and_then(|v| v.as_str())
        .unwrap();

    let terms = pact
        .get("terms")
        .ok_or_else(|| PactumError::MissingField("terms".to_string()))?;
    let metric_id = terms.get("metric_id").and_then(|v| v.as_str()).unwrap();
    let threshold_z = parse_uint(terms.get("threshold_z").and_then(|v| v.as_str()).unwrap())?;
    let duration_d = parse_uint(terms.get("duration_d").and_then(|v| v.as_str()).unwrap())?;
    let cap_q = parse_uint(terms.get("cap_q").and_then(|v| v.as_str()).unwrap())?;

    // Extract oracle pubkeys for authorization
    let oracles = pact
        .get("oracles")
        .ok_or_else(|| PactumError::MissingField("oracles".to_string()))?;
    let clock_pubkeys: Vec<&str> = oracles
        .get("clock")
        .and_then(|c| c.get("pubkeys"))
        .and_then(|p| p.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let metric_pubkeys: Vec<&str> = oracles
        .get("metric")
        .and_then(|m| m.get("pubkeys"))
        .and_then(|p| p.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    // Extract quorum settings
    let clock_quorum = oracles
        .get("clock")
        .and_then(|c| c.get("quorum"))
        .and_then(|q| q.as_str())
        .map(parse_uint)
        .transpose()?
        .unwrap_or(1);
    let metric_quorum = oracles
        .get("metric")
        .and_then(|m| m.get("quorum"))
        .and_then(|q| q.as_str())
        .map(parse_uint)
        .transpose()?
        .unwrap_or(1);

    // Extract state fields
    let mut now = parse_uint(state.get("now").and_then(|v| v.as_str()).unwrap_or("0"))?;
    let mut collateral_posted = parse_uint(
        state
            .get("collateral_posted")
            .and_then(|v| v.as_str())
            .unwrap_or("0"),
    )?;
    let mut claim_paid = parse_uint(
        state
            .get("claim_paid")
            .and_then(|v| v.as_str())
            .unwrap_or("0"),
    )?;
    let mut breach_start_time: Option<u64> = state
        .get("breach_start_time")
        .and_then(|v| {
            if v.is_null() {
                Some(None)
            } else {
                v.as_str().map(|s| parse_uint(s).ok())
            }
        })
        .flatten();
    let mut triggered = state
        .get("triggered")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Extract round counters (V0.1 quorum support)
    let mut clock_round = state
        .get("clock_round")
        .and_then(|v| v.as_str())
        .map(parse_uint)
        .transpose()?
        .unwrap_or(0);
    let mut metric_round = state
        .get("metric_round")
        .and_then(|v| v.as_str())
        .map(parse_uint)
        .transpose()?
        .unwrap_or(0);

    let mut metric_last_t = parse_uint(
        state
            .get("metric_last")
            .and_then(|v| v.get("t"))
            .and_then(|v| v.as_str())
            .unwrap_or("0"),
    )?;
    let mut metric_last_v = parse_uint(
        state
            .get("metric_last")
            .and_then(|v| v.get("v"))
            .and_then(|v| v.as_str())
            .unwrap_or("0"),
    )?;

    // Track outputs and trace
    let mut effects = Vec::new();
    let mut trace_steps = Vec::new();
    let mut effect_index = 0;

    // Phase A: Validate and classify events into buffers
    let mut collateral_posts: Vec<EvRef> = Vec::new();
    let mut claim_requests: Vec<EvRef> = Vec::new();
    let mut clock_events: Vec<EvRef> = Vec::new();
    let mut metric_events: Vec<EvRef> = Vec::new();

    for (i, event) in events.iter().enumerate() {
        let kind = event.get("kind").and_then(|v| v.as_str()).unwrap();
        let payload = event.get("payload").unwrap().clone();
        let signer_pub = event
            .get("signer_pub")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        match kind {
            "collateral_post" => {
                // Authorization check
                if signer_pub != a_pub {
                    return Err(PactumError::InvalidSigner(
                        "collateral_post must be signed by party A".to_string(),
                    ));
                }
                collateral_posts.push(EvRef {
                    i,
                    signer: signer_pub,
                    payload,
                });
            }
            "claim_request" => {
                // Authorization check
                if signer_pub != b_pub {
                    return Err(PactumError::InvalidSigner(
                        "claim_request must be signed by party B".to_string(),
                    ));
                }
                claim_requests.push(EvRef {
                    i,
                    signer: signer_pub,
                    payload,
                });
            }
            "clock_event" => {
                // Authorization check
                if !clock_pubkeys.contains(&signer_pub.as_str()) {
                    return Err(PactumError::InvalidSigner(format!(
                        "clock_event signer {signer_pub} not in allowed clock pubkeys"
                    )));
                }
                // V0.2 hardening: oracle_id must match signer_pub
                let oracle_id = payload
                    .get("oracle_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| PactumError::MissingField("oracle_id".to_string()))?;
                if oracle_id != signer_pub {
                    return Err(PactumError::InvalidSigner(format!(
                        "PCT_ERR_ORACLE_ID_MISMATCH: oracle_id {oracle_id} != signer_pub {signer_pub}"
                    )));
                }
                clock_events.push(EvRef {
                    i,
                    signer: signer_pub,
                    payload,
                });
            }
            "metric_event" => {
                // Authorization check
                if !metric_pubkeys.contains(&signer_pub.as_str()) {
                    return Err(PactumError::InvalidSigner(format!(
                        "metric_event signer {signer_pub} not in allowed metric pubkeys"
                    )));
                }
                // V0.2 hardening: oracle_id must match signer_pub
                let oracle_id = payload
                    .get("oracle_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| PactumError::MissingField("oracle_id".to_string()))?;
                if oracle_id != signer_pub {
                    return Err(PactumError::InvalidSigner(format!(
                        "PCT_ERR_ORACLE_ID_MISMATCH: oracle_id {oracle_id} != signer_pub {signer_pub}"
                    )));
                }
                metric_events.push(EvRef {
                    i,
                    signer: signer_pub,
                    payload,
                });
            }
            _ => {
                return Err(PactumError::UnknownEventKind(kind.to_string()));
            }
        }
    }

    // Phase B: Apply collateral posts in envelope order
    for ev in &collateral_posts {
        let amount = parse_uint(
            ev.payload
                .get("amount")
                .and_then(|v| v.as_str())
                .ok_or_else(|| PactumError::MissingField("amount".to_string()))?,
        )?;
        let asset = ev
            .payload
            .get("asset")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PactumError::MissingField("asset".to_string()))?;

        if asset != collateral_asset {
            return Err(PactumError::ClaimNotAllowed("Asset mismatch".to_string()));
        }

        collateral_posted += amount;

        trace_steps.push(json!({
            "i": ev.i.to_string(),
            "kind": "apply_collateral",
            "amount": amount.to_string(),
            "collateral_posted": collateral_posted.to_string()
        }));
    }

    // Phase C: Commit clock rounds (V0.2 loop)
    // Index events by seq
    let mut clock_by_seq: BTreeMap<u64, Vec<EvRef>> = BTreeMap::new();
    for e in &clock_events {
        let seq = parse_uint(
            e.payload
                .get("seq")
                .and_then(|v| v.as_str())
                .ok_or_else(|| PactumError::MissingField("seq".to_string()))?,
        )?;
        // Reject replay (seq <= round)
        if seq <= clock_round {
            return Err(PactumError::OracleSeqViolation(format!(
                "PCT_ERR_SEQ_REPLAY: seq {seq} <= clock_round {clock_round}"
            )));
        }
        clock_by_seq.entry(seq).or_default().push(e.clone());
    }

    // Loop: commit rounds sequentially
    loop {
        let target = clock_round + 1;

        // Check for gap/skip: exists seq > target but no seq == target
        if !clock_by_seq.contains_key(&target) {
            if let Some((&min_higher, _)) = clock_by_seq.range((target + 1)..).next() {
                return Err(PactumError::OracleSeqViolation(format!(
                    "PCT_ERR_SEQ_SKIP: missing seq {target}, found {min_higher}"
                )));
            }
            break; // No more rounds to commit
        }

        let evs = clock_by_seq.remove(&target).unwrap();

        // Commit this round
        if let Some((effective_t, participants)) =
            commit_clock_quorum(clock_round, clock_quorum, &evs)?
        {
            now = now.max(effective_t);
            clock_round = target;

            // Update oracle_seq/oracle_time for participants
            for p in &participants {
                oracle_seq.insert(p.clone(), target);
                // Find t for this participant
                if let Some(ev) = evs.iter().find(|e| &e.signer == p) {
                    let t = parse_uint(
                        ev.payload
                            .get("t")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| PactumError::MissingField("t".to_string()))?,
                    )?;
                    oracle_time.insert(p.clone(), t);
                }
            }

            trace_steps.push(json!({
                "kind": "commit_clock_quorum",
                "seq": target.to_string(),
                "participants": participants,
                "effective_t": effective_t.to_string(),
                "count": evs.len().to_string(),
                "quorum": clock_quorum.to_string()
            }));
        } else {
            // Quorum not met - this should have been caught in commit_clock_quorum
            break;
        }
    }

    // Phase D: Commit metric rounds (V0.2 loop)
    // Index events by seq
    let mut metric_by_seq: BTreeMap<u64, Vec<EvRef>> = BTreeMap::new();
    for e in &metric_events {
        let seq = parse_uint(
            e.payload
                .get("seq")
                .and_then(|v| v.as_str())
                .ok_or_else(|| PactumError::MissingField("seq".to_string()))?,
        )?;
        // Reject replay (seq <= round)
        if seq <= metric_round {
            return Err(PactumError::OracleSeqViolation(format!(
                "PCT_ERR_SEQ_REPLAY: seq {seq} <= metric_round {metric_round}"
            )));
        }
        metric_by_seq.entry(seq).or_default().push(e.clone());
    }

    // Loop: commit rounds sequentially
    loop {
        let target = metric_round + 1;

        // Check for gap/skip: exists seq > target but no seq == target
        if !metric_by_seq.contains_key(&target) {
            if let Some((&min_higher, _)) = metric_by_seq.range((target + 1)..).next() {
                return Err(PactumError::OracleSeqViolation(format!(
                    "PCT_ERR_SEQ_SKIP: missing seq {target}, found {min_higher}"
                )));
            }
            break; // No more rounds to commit
        }

        let evs = metric_by_seq.remove(&target).unwrap();

        // Commit this round
        if let Some((effective_v, effective_t, participants)) =
            commit_metric_quorum(metric_round, metric_quorum, &evs)?
        {
            metric_last_t = effective_t;
            metric_last_v = effective_v;
            metric_round = target;

            // Verify metric_id matches (only need to check once, but check each round for safety)
            if let Some(ev) = evs.first() {
                let metric_id_event = ev
                    .payload
                    .get("metric_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| PactumError::MissingField("metric_id".to_string()))?;
                if metric_id_event != metric_id {
                    return Err(PactumError::ClaimNotAllowed(
                        "Metric ID mismatch".to_string(),
                    ));
                }
            }

            // Update breach tracking (runs once per committed round)
            if effective_v < threshold_z {
                if breach_start_time.is_none() {
                    breach_start_time = Some(now);
                }
            } else {
                breach_start_time = None;
            }

            // Update trigger (runs once per committed round)
            if let Some(breach_start) = breach_start_time {
                if now >= breach_start && (now - breach_start) >= duration_d {
                    triggered = true;
                }
            }

            // Update oracle_seq/oracle_time for participants
            for p in &participants {
                oracle_seq.insert(p.clone(), target);
                // Find t for this participant
                if let Some(ev) = evs.iter().find(|e| &e.signer == p) {
                    let t = parse_uint(
                        ev.payload
                            .get("t")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| PactumError::MissingField("t".to_string()))?,
                    )?;
                    oracle_time.insert(p.clone(), t);
                }
            }

            let breach_status = if breach_start_time.is_some() {
                if triggered {
                    "continue"
                } else {
                    "start"
                }
            } else {
                "none"
            };

            trace_steps.push(json!({
                "kind": "commit_metric_quorum",
                "seq": target.to_string(),
                "participants": participants,
                "effective_v": effective_v.to_string(),
                "effective_t": effective_t.to_string(),
                "count": evs.len().to_string(),
                "quorum": metric_quorum.to_string(),
                "breach": breach_status,
                "breach_start_time": breach_start_time.map(|t| t.to_string()).unwrap_or_else(|| "null".to_string()),
                "triggered": triggered
            }));
        } else {
            // Quorum not met - this should have been caught in commit_metric_quorum
            break;
        }
    }

    // Phase E: Apply claim requests in envelope order
    for ev in &claim_requests {
        if !triggered {
            return Err(PactumError::ClaimNotAllowed(
                "Pact not triggered".to_string(),
            ));
        }

        let amount = parse_uint(
            ev.payload
                .get("amount")
                .and_then(|v| v.as_str())
                .ok_or_else(|| PactumError::MissingField("amount".to_string()))?,
        )?;

        if amount > cap_q {
            return Err(PactumError::ClaimNotAllowed(format!(
                "Amount {amount} exceeds cap {cap_q}"
            )));
        }

        let available = collateral_posted - claim_paid;
        if amount > available {
            return Err(PactumError::ClaimNotAllowed(format!(
                "Amount {amount} exceeds available {available}"
            )));
        }

        // Emit asset flow effect
        effects.push(json!({
            "kind": "asset_flow",
            "from": "party:a",
            "to": "party:b",
            "asset": collateral_asset,
            "amount": amount.to_string()
        }));

        claim_paid += amount;

        trace_steps.push(json!({
            "i": ev.i.to_string(),
            "kind": "apply_claim",
            "amount": amount.to_string(),
            "claim_paid": claim_paid.to_string(),
            "effect_index": effect_index.to_string()
        }));

        effect_index += 1;
    }

    // Build new state
    let mut new_state = json!({
        "v": "pactum-state/0",
        "pact_hash": hash_json("pactum:pact:0", pact),
        "now": now.to_string(),
        "collateral_posted": collateral_posted.to_string(),
        "metric_last": {
            "t": metric_last_t.to_string(),
            "v": metric_last_v.to_string()
        },
        "breach_start_time": breach_start_time.map(|t| Value::String(t.to_string())).unwrap_or(Value::Null),
        "triggered": triggered,
        "claim_paid": claim_paid.to_string(),
        "clock_round": clock_round.to_string(),
        "metric_round": metric_round.to_string(),
        "oracle_seq": {},
        "oracle_time": {}
    });

    // Add oracle_seq and oracle_time as objects
    let mut oracle_seq_obj = json!({});
    for (k, v) in &oracle_seq {
        oracle_seq_obj[k] = json!(v.to_string());
    }
    new_state["oracle_seq"] = oracle_seq_obj;

    let mut oracle_time_obj = json!({});
    for (k, v) in &oracle_time {
        oracle_time_obj[k] = json!(v.to_string());
    }
    new_state["oracle_time"] = oracle_time_obj;

    // Build outputs
    let outputs = json!({
        "v": "pactum-outputs/0",
        "effects": effects
    });

    // Build trace
    let trace = json!({
        "v": "pactum-trace/0",
        "steps": trace_steps
    });

    // Build receipt
    let prev_state_hash = hash_json("pactum:state:0", prev_state);
    let envelope_hash = hash_json("pactum:envelope:0", envelope);
    let new_state_hash = hash_json("pactum:state:0", &new_state);
    let outputs_hash = hash_json("pactum:outputs:0", &outputs);
    let trace_hash = hash_json("pactum:trace:0", &trace);

    let receipt = json!({
        "v": "pactum-receipt/0",
        "pact_hash": hash_json("pactum:pact:0", pact),
        "prev_state_hash": prev_state_hash,
        "envelope_hash": envelope_hash,
        "new_state_hash": new_state_hash,
        "outputs_hash": outputs_hash,
        "trace_hash": trace_hash
    });

    Ok((new_state, outputs, trace, receipt))
}
