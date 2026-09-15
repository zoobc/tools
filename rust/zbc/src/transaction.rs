// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

//! The transaction envelope, escrow block, chain-bound digest, signature, hash and submit payload (spec/signing.md).

use crate::address::{parse_address, EMPTY};
use crate::encoding::is_hex;
use crate::keys::KeyPair;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub const SEND_ZBC: u32 = 1;
pub const APPROVAL_ESCROW: u32 = 4;
pub const APPROVE: u32 = 0;
pub const REJECT: u32 = 1;
pub const EXPIRE: u32 = 2;

/// Little-endian byte-string builder.
#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    pub fn new() -> Self {
        Writer(Vec::new())
    }
    pub fn bytes(mut self, b: &[u8]) -> Self {
        self.0.extend_from_slice(b);
        self
    }
    pub fn u8(mut self, v: u8) -> Self {
        self.0.push(v);
        self
    }
    pub fn u16(self, v: u16) -> Self {
        self.bytes(&v.to_le_bytes())
    }
    pub fn u32(self, v: u32) -> Self {
        self.bytes(&v.to_le_bytes())
    }
    /// int64 as 8 bytes LE (two's complement).
    pub fn i64(self, v: i64) -> Self {
        self.bytes(&v.to_le_bytes())
    }
    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

pub fn empty_account() -> Vec<u8> {
    EMPTY.to_le_bytes().to_vec()
}

/// Escrow terms of a transfer (the --escrow-* options); `timeout` is an absolute Unix time in seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Escrow {
    pub approver: String,
    pub commission: i64,
    pub timeout: i64,
    pub instruction: String,
}

impl Escrow {
    /// The escrow block of the envelope (spec/signing.md section 3).
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let approver = parse_address(&self.approver, "")?;
        Ok(Writer::new().bytes(&approver.bytes()).i64(self.commission).i64(self.timeout)
            .u32(self.instruction.len() as u32).bytes(self.instruction.as_bytes()).u8(0).finish())
    }
}

/// Which chain a signature is for: version 2 with its genesis hash, or 1 (legacy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningContext {
    pub version: u8,
    pub genesis_hash: Vec<u8>,
}

impl SigningContext {
    /// Reads --genesis: 64 hex, or "v1"/"legacy".
    pub fn of(genesis: &str) -> Result<SigningContext, String> {
        if genesis == "v1" || genesis == "legacy" {
            return Ok(SigningContext { version: 1, genesis_hash: Vec::new() });
        }
        if !is_hex(genesis, 64) {
            return Err("--genesis must be the 64-hex genesis block hash (or 'v1' for the legacy digest)".into());
        }
        Ok(SigningContext { version: 2, genesis_hash: hex::decode(genesis).unwrap() })
    }
}

/// A transaction before signing.
#[derive(Debug, Clone, Default)]
pub struct Unsigned {
    pub tx_type: u32,
    pub timestamp: i64,
    /// 36-byte typed sender account.
    pub sender: Vec<u8>,
    /// Typed recipient bytes, or empty for none.
    pub recipient: Vec<u8>,
    pub fee: i64,
    pub body: Vec<u8>,
    pub escrow: Option<Escrow>,
    pub message: Vec<u8>,
    pub version: u8,
}

/// Fields 1–11 of the envelope: what the digest covers.
pub fn unsigned_bytes(tx: &Unsigned) -> Result<Vec<u8>, String> {
    let version = if tx.version == 0 { 1 } else { tx.version };
    let mut w = Writer::new().u32(tx.tx_type).u8(version).i64(tx.timestamp).bytes(&tx.sender);
    w = if tx.recipient.is_empty() || tx.recipient.iter().all(|&b| b == 0) { w.bytes(&empty_account()) } else { w.bytes(&tx.recipient) };
    w = w.i64(tx.fee).u32(tx.body.len() as u32).bytes(&tx.body);
    w = match &tx.escrow {
        Some(e) => w.bytes(&e.to_bytes()?),
        None => w.bytes(&empty_account()),
    };
    Ok(w.u32(tx.message.len() as u32).bytes(&tx.message).finish())
}

/// SHA3-256("ZBC-TX" || genesis || unsigned) for version 2; SHA3-256(unsigned) for version 1.
pub fn signing_digest(unsigned: &[u8], ctx: &SigningContext) -> [u8; 32] {
    let mut h = Sha3_256::new();
    if ctx.version == 2 {
        h.update(b"ZBC-TX");
        h.update(&ctx.genesis_hash);
    }
    h.update(unsigned);
    h.finalize().into()
}

pub fn transaction_hash(unsigned: &[u8], signature: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(unsigned);
    h.update(signature);
    h.finalize().into()
}

/// The int64 id: the first 8 bytes of the hash, little-endian, signed.
pub fn transaction_id(hash: &[u8]) -> i64 {
    i64::from_le_bytes(hash[..8].try_into().unwrap())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EscrowPayload {
    pub approver_address: String,
    pub commission: i64,
    pub timeout: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction: Option<String>,
}

/// The JSON object POST /api/v1/transactions takes (spec/api.md section 2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Payload {
    pub version: u8,
    pub timestamp: i64,
    pub sender_account_address: String,
    pub recipient_account_address: String,
    pub transaction_type: u32,
    pub fee: i64,
    pub transaction_body_bytes: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escrow: Option<EscrowPayload>,
}

/// A built, signed and hashed transaction.
#[derive(Debug, Clone)]
pub struct Signed {
    pub unsigned: Vec<u8>,
    pub digest: [u8; 32],
    pub signature: [u8; 64],
    pub bytes: Vec<u8>,
    pub hash: [u8; 32],
    pub payload: Payload,
    pub signing_version: u8,
    pub genesis_hash: Vec<u8>,
}

/// Build, sign and hash a transaction for the chain of `ctx`.
pub fn sign_transaction(tx: &Unsigned, kp: &KeyPair, ctx: &SigningContext) -> Result<Signed, String> {
    let unsigned = unsigned_bytes(tx)?;
    let digest = signing_digest(&unsigned, ctx);
    let signature = kp.sign(&digest);
    let mut bytes = unsigned.clone();
    bytes.extend_from_slice(&signature);
    let recipient = if tx.recipient.is_empty() {
        String::new()
    } else if tx.recipient.len() == 36 && tx.recipient[..4] == [0, 0, 0, 0] {
        hex::encode(&tx.recipient[4..])
    } else {
        hex::encode(&tx.recipient)
    };
    let escrow = match &tx.escrow {
        Some(e) => Some(EscrowPayload {
            approver_address: hex::encode(parse_address(&e.approver, "")?.bytes()),
            commission: e.commission,
            timeout: e.timeout,
            instruction: if e.instruction.is_empty() { None } else { Some(e.instruction.clone()) },
        }),
        None => None,
    };
    let payload = Payload {
        version: if tx.version == 0 { 1 } else { tx.version },
        timestamp: tx.timestamp,
        sender_account_address: hex::encode(&tx.sender[4..]),
        recipient_account_address: recipient,
        transaction_type: tx.tx_type,
        fee: tx.fee,
        transaction_body_bytes: hex::encode(&tx.body),
        signature: hex::encode(signature),
        message_hex: if tx.message.is_empty() { None } else { Some(hex::encode(&tx.message)) },
        escrow,
    };
    let hash = Sha3_256::digest(&bytes).into();
    Ok(Signed { unsigned, digest, signature, bytes, hash, payload, signing_version: ctx.version, genesis_hash: ctx.genesis_hash.clone() })
}

/// The 8-byte amount.
pub fn send_zbc_body(amount: i64) -> Vec<u8> {
    Writer::new().i64(amount).finish()
}

/// approval u32le then the 32-byte escrowed transaction hash.
pub fn approval_escrow_body(approval: u32, escrowed_hash: &[u8]) -> Result<Vec<u8>, String> {
    if escrowed_hash.len() != 32 {
        return Err("Transaction hash must be 64 hex characters (the escrowed transaction's SHA3-256 hash)".into());
    }
    Ok(Writer::new().u32(approval).bytes(escrowed_hash).finish())
}
