// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

//! ZBC-MSG-v1 message signing (spec/signing.md section 5).

use crate::address::decode_zbc_address;
use crate::encoding::is_hex;
use crate::keys::KeyPair;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha3::{Digest, Sha3_256};

pub const SCHEME: &str = "ZBC-MSG-v1";

/// SHA3-256("ZBC-MSG" || message).
pub fn message_digest(message: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"ZBC-MSG");
    h.update(message);
    h.finalize().into()
}

#[derive(Debug, Clone)]
pub struct SignedMessage {
    pub scheme: &'static str,
    pub address: String,
    pub public_key: String,
    pub message_hex: String,
    pub digest: String,
    pub signature: String,
}

pub fn sign_message(kp: &KeyPair, message: &[u8]) -> SignedMessage {
    let digest = message_digest(message);
    SignedMessage {
        scheme: SCHEME,
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

/// False for anything that does not verify; never panics.
pub fn verify_message(address: &str, message: &[u8], signature: &[u8]) -> bool {
    let Some(pub_key) = public_key_of_address(address) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pub_key) else { return false };
    let Ok(sig) = Signature::from_slice(signature) else { return false };
    vk.verify(&message_digest(message), &sig).is_ok()
}
