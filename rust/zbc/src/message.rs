// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

//! ZBC-MSG-v2 message signing (spec/signing.md sections 5 and 5a): the digest binds the message
//! to one chain's genesis. v1 (no genesis) is only verified, and only until `V1_SUNSET`.

use crate::address::decode_zbc_address;
use crate::encoding::is_hex;
use crate::keys::KeyPair;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha3::{Digest, Sha3_256};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEME: &str = "ZBC-MSG-v2";
pub const SCHEME_V1: &str = "ZBC-MSG-v1";
/// What verify-message reports for a v1 signature it still accepts.
pub const SCHEME_V1_ACCEPTED: &str = "ZBC-MSG-v1 (accepted until 2026-12-01)";
/// 2026-12-01T00:00:00Z: v1 signatures are refused from this unix time on.
pub const V1_SUNSET: i64 = 1796083200;

/// SHA3-256("ZBC-MSG-v2" || genesis_hash (32) || message).
pub fn message_digest(message: &[u8], genesis_hash: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"ZBC-MSG-v2");
    h.update(genesis_hash);
    h.update(message);
    h.finalize().into()
}

/// SHA3-256("ZBC-MSG" || message): the legacy v1 digest, verify-only.
pub fn message_digest_v1(message: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"ZBC-MSG");
    h.update(message);
    h.finalize().into()
}

#[derive(Debug, Clone)]
pub struct SignedMessage {
    pub scheme: &'static str,
    pub genesis_hash: String,
    pub address: String,
    pub public_key: String,
    pub message_hex: String,
    pub digest: String,
    pub signature: String,
}

/// Signs `message` for the chain whose genesis block hash is `genesis_hash` (32 bytes).
pub fn sign_message(kp: &KeyPair, message: &[u8], genesis_hash: &[u8]) -> SignedMessage {
    let digest = message_digest(message, genesis_hash);
    SignedMessage {
        scheme: SCHEME,
        genesis_hash: hex::encode(genesis_hash),
        address: kp.address(),
        public_key: hex::encode(kp.public_key),
        message_hex: hex::encode(message),
        digest: hex::encode(digest),
        signature: hex::encode(kp.sign(&digest)),
    }
}

/// The public key behind a ZBC_ address or 64 hex, or None.
pub fn public_key_of_address(address: &str) -> Option<[u8; 32]> {
    if is_hex(address, 64) {
        return hex::decode(address).ok()?.try_into().ok();
    }
    let (prefix, payload) = decode_zbc_address(address)?;
    if prefix != "ZBC" {
        return None;
    }
    payload.try_into().ok()
}

/// The outcome of verify-message: which scheme matched (v2 when nothing did) and the digest checked.
#[derive(Debug, Clone)]
pub struct Verification {
    pub valid: bool,
    pub scheme: &'static str,
    pub digest: [u8; 32],
}

fn verifies(pub_key: &[u8; 32], digest: &[u8; 32], signature: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pub_key) else { return false };
    let Ok(sig) = Signature::from_slice(signature) else { return false };
    vk.verify(digest, &sig).is_ok()
}

/// v2 first (needs the genesis), then v1 while `now` is before `V1_SUNSET`. Never panics.
pub fn verify_message_at(address: &str, message: &[u8], signature: &[u8], genesis_hash: Option<&[u8]>, now: i64) -> Verification {
    let pub_key = public_key_of_address(address);
    if let (Some(pk), Some(g)) = (pub_key, genesis_hash) {
        let digest = message_digest(message, g);
        if verifies(&pk, &digest, signature) {
            return Verification { valid: true, scheme: SCHEME, digest };
        }
    }
    let digest_v1 = message_digest_v1(message);
    if let Some(pk) = pub_key {
        if now < V1_SUNSET && verifies(&pk, &digest_v1, signature) {
            return Verification { valid: true, scheme: SCHEME_V1_ACCEPTED, digest: digest_v1 };
        }
    }
    let digest = genesis_hash.map(|g| message_digest(message, g)).unwrap_or(digest_v1);
    Verification { valid: false, scheme: SCHEME, digest }
}

/// False for anything that does not verify (v2 against `genesis_hash`, or v1 before its sunset).
pub fn verify_message(address: &str, message: &[u8], signature: &[u8], genesis_hash: Option<&[u8]>) -> bool {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(i64::MAX);
    verify_message_at(address, message, signature, genesis_hash, now).valid
}
