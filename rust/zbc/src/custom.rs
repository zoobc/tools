// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

//! The hand-written parts the descriptions mark computed or custom (spec/transactions/README.md).

use crate::address::{encode_zbc_address, parse_address, typed_address, ZOOBC};
use crate::body::{parse_integer, split_list, BodyContext, Params};
use crate::errors::{usage, ToolError};
use crate::keys::KeyPair;
use crate::spec::TxDef;
use crate::transaction::{send_zbc_body, signing_digest, unsigned_bytes, SigningContext, Unsigned, Writer, SEND_ZBC};
use serde_json::{json, Map, Value};
use sha3::{Digest, Sha3_256};

/// The block a proof of ownership refers to.
#[derive(Debug, Clone)]
pub struct ReferenceBlock {
    pub hash: Vec<u8>,
    pub height: u32,
}

/// owner (36) || block hash (32) || height u32le, then the owner's signature over those bytes.
pub fn proof_of_ownership(owner: &KeyPair, block: &ReferenceBlock) -> Vec<u8> {
    let msg = Writer::new().bytes(&owner.account_bytes()).bytes(&block.hash).u32(block.height).finish();
    let sig = owner.sign(&msg);
    [msg, sig.to_vec()].concat()
}

pub struct CustomInput<'a> {
    pub def: &'a TxDef,
    pub params: &'a Params,
    pub sender: &'a KeyPair,
    pub ctx: &'a SigningContext,
    pub timestamp: i64,
    pub block: Option<&'a ReferenceBlock>,
}

/// Fill `ctx.computed` for the fields the generic serialiser cannot produce; returns extra output fields.
pub fn compute_fields(input: &CustomInput, ctx: &mut BodyContext) -> Result<Map<String, Value>, ToolError> {
    let p = input.params;
    let get = |k: &str| p.get(k).cloned().unwrap_or_default();
    let mut extra = Map::new();
    match input.def.command.as_str() {
        "store-file" => {
            let pieces = hex::decode(get("piece_ids")).unwrap_or_default();
            if pieces.is_empty() || pieces.len() % 32 != 0 {
                return Err(usage("piece_ids must be a nonzero multiple of 32 bytes"));
            }
            ctx.computed.insert("piece_count".into(), Writer::new().u32((pieces.len() / 32) as u32).finish());
            extra.insert("piece_count".into(), json!(pieces.len() / 32));
        }
        "register-node" | "update-node" | "claim-node" => {
            let block = input.block.ok_or_else(|| ToolError::new(1, "proof of ownership needs the latest block"))?;
            ctx.computed.insert("proof_of_ownership".into(), proof_of_ownership(input.sender, block));
            let node = KeyPair::from_hex(&get("node_privkey")).map_err(usage)?;
            extra.insert("node_znk".into(), json!(node.node_address()));
            extra.insert("owner_zbc".into(), json!(input.sender.address()));
        }
        "fee-vote-reveal" => {
            let h = hex::decode(get("recent_block_hash")).map_err(|_| usage("recent_block_hash must be hex"))?;
            let height = parse_integer(&get("recent_block_height"), "uint32", "recent_block_height")?;
            let vote = parse_integer(&get("fee_vote"), "int64", "fee_vote")?;
            let sig = input.sender.sign(&Writer::new().bytes(&h).u32(height as u32).i64(vote).finish());
            ctx.computed.insert("voter_signature".into(), Writer::new().u32(sig.len() as u32).bytes(&sig).finish());
        }
        "gateway-heartbeat" => {
            let gw = KeyPair::from_hex(&get("gateway_privkey")).map_err(|_| usage("gateway_privkey is not a valid key"))?;
            let height = parse_integer(&get("reference_height"), "uint32", "reference_height")?;
            let h = hex::decode(get("reference_block_hash")).unwrap_or_default();
            if h.len() != 32 {
                return Err(usage("reference_block_hash must be 32 bytes (64 hex)"));
            }
            let sig = gw.sign(&Writer::new().bytes(&gw.public_key).u32(height as u32).bytes(&h).finish());
            ctx.computed.insert("signature".into(), sig.to_vec());
            extra.insert("gateway_key".into(), json!(hex::encode(gw.public_key)));
            extra.insert("reference_height".into(), json!(height));
            extra.insert("reference_block_hash".into(), json!(get("reference_block_hash")));
        }
        _ => {}
    }
    Ok(extra)
}

/// SHA3-256(min u32le || nonce u64le || count u32le || sorted participant addresses).
pub fn multisig_address(participants: &[Vec<u8>], nonce: i64, min_signatures: u32) -> [u8; 32] {
    let mut sorted = participants.to_vec();
    sorted.sort();
    let mut w = Writer::new().u32(min_signatures).i64(nonce).u32(sorted.len() as u32);
    for a in &sorted {
        w = w.bytes(a);
    }
    Sha3_256::digest(w.finish()).into()
}

/// The two fully custom bodies: multisig and app-settle.
pub fn custom_body(input: &CustomInput) -> Result<(Vec<u8>, Map<String, Value>), ToolError> {
    match input.def.command.as_str() {
        "multisig" => multisig_body(input),
        "app-settle" => settle_body(input),
        other => Err(ToolError::new(1, format!("no custom body for {other}"))),
    }
}

fn multisig_body(input: &CustomInput) -> Result<(Vec<u8>, Map<String, Value>), ToolError> {
    let p = input.params;
    let get = |k: &str| p.get(k).cloned().unwrap_or_default();
    let mut participants = Vec::new();
    for a in split_list(&get("participants")) {
        participants.push(parse_address(&a, "").map_err(|_| usage(format!("Invalid participant address: {a}")))?.bytes());
    }
    if participants.is_empty() {
        return Err(usage("Need at least one participant"));
    }
    let min_sigs = parse_integer(&get("min_signatures"), "uint32", "min_signatures")? as u32;
    let nonce_s = get("nonce");
    let nonce = parse_integer(if nonce_s.is_empty() { "0" } else { &nonce_s }, "int64", "nonce")?;
    let signers = split_list(&get("signer_privkeys"));
    if signers.is_empty() {
        return Err(usage("Need at least one signer key"));
    }
    let recipient = parse_address(&get("recipient"), "").map_err(|e| usage(format!("Invalid recipient: {e}")))?;
    let amount = parse_integer(&get("amount"), "int64", "amount")?;
    let fee_s = get("inner_fee");
    let inner_fee = parse_integer(if fee_s.is_empty() { "10000000" } else { &fee_s }, "int64", "inner_fee")?;
    let ms = multisig_address(&participants, nonce, min_sigs);
    let inner = unsigned_bytes(&Unsigned {
        tx_type: SEND_ZBC, timestamp: input.timestamp, sender: typed_address(ZOOBC, &ms), recipient: recipient.bytes(),
        fee: inner_fee, body: send_zbc_body(amount), ..Default::default()
    }).map_err(usage)?;
    let inner_hash: [u8; 32] = Sha3_256::digest(&inner).into();
    let inner_digest = signing_digest(&inner, input.ctx);
    let mut sigs: Vec<(String, [u8; 64])> = Vec::new();
    for sk in signers {
        let kp = KeyPair::from_hex(&sk).map_err(|_| usage("Invalid signer key"))?;
        sigs.push((hex::encode(kp.account_bytes()), kp.sign(&inner_digest)));
    }
    sigs.sort_by(|a, b| a.0.cmp(&b.0)); // the node keeps them in a map ordered by address hex
    let mut w = Writer::new().u32(1).u32(min_sigs).i64(nonce).u32(participants.len() as u32);
    for a in &participants {
        w = w.bytes(a);
    }
    w = w.u32(inner.len() as u32).bytes(&inner).u32(1).bytes(&inner_hash).u32(sigs.len() as u32);
    for (addr, sig) in &sigs {
        w = w.bytes(&hex::decode(addr).unwrap()).u32(sig.len() as u32).bytes(sig);
    }
    let mut extra = Map::new();
    extra.insert("multisig_address".into(), json!(hex::encode(ms)));
    extra.insert("multisig_zbc_address".into(), json!(encode_zbc_address(&ms, "ZBC").unwrap()));
    extra.insert("min_signatures".into(), json!(min_sigs));
    extra.insert("inner_tx_hash".into(), json!(hex::encode(inner_hash)));
    extra.insert("fund_hint".into(), json!("send ZBC to multisig_zbc_address before the signatures complete, else the inner tx stays in mempool"));
    Ok((w.finish(), extra))
}

fn settle_body(input: &CustomInput) -> Result<(Vec<u8>, Map<String, Value>), ToolError> {
    let p = input.params;
    let get = |k: &str| p.get(k).cloned().unwrap_or_default();
    let app_id = parse_integer(&get("app_id"), "int64", "app_id")?;
    let seats = [KeyPair::from_hex(&get("p0_privkey")).map_err(|_| usage("seat keys must be 64 hex"))?,
                 KeyPair::from_hex(&get("p1_privkey")).map_err(|_| usage("seat keys must be 64 hex"))?];
    let turn_s = get("opening_turn");
    let turn = parse_integer(if turn_s.is_empty() { "0" } else { &turn_s }, "uint8", "opening_turn")?;
    if turn != 0 && turn != 1 {
        return Err(usage("opening_turn must be 0 or 1"));
    }
    let mut cells = Vec::new();
    for c in split_list(&get("moves")) {
        cells.push(parse_integer(&c, "uint8", "move")? as usize);
    }
    if cells.is_empty() {
        return Err(usage("no moves given"));
    }
    let mut state = [0u8; 9];
    let mut entries = Writer::new();
    for (k, &cell) in cells.iter().enumerate() {
        let seat = (turn as usize + k) % 2;
        if cell > 8 || state[cell] != 0 {
            return Err(usage(format!("illegal move at seq {}", k + 1)));
        }
        let mv = [cell as u8];
        let state_hash: [u8; 32] = Sha3_256::digest(state).into();
        let digest: [u8; 32] = Sha3_256::digest(Writer::new().i64(app_id).u32((k + 1) as u32).bytes(&state_hash).bytes(&mv).finish()).into();
        entries = entries.u8(seat as u8).u16(1).bytes(&mv).bytes(&seats[seat].sign(&digest));
        state[cell] = seat as u8 + 1;
    }
    let body = Writer::new().i64(app_id).u32(cells.len() as u32).u32(cells.len() as u32).bytes(&entries.finish()).finish();
    let mut extra = Map::new();
    extra.insert("app_id".into(), json!(app_id));
    extra.insert("opening_turn".into(), json!(turn));
    extra.insert("final_seq".into(), json!(cells.len()));
    Ok((body, extra))
}
