// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
//! Sealed transaction messages (spec/signing.md section 8): `ZBE1` || libsodium sealed box to the
//! recipient's Ed25519 key converted to X25519. X25519 from x25519-dalek, HSalsa20 from salsa20,
//! XSalsa20-Poly1305 from crypto_secretbox, the nonce from blake2.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::XSalsa20Poly1305;
use ed25519_dalek::VerifyingKey;
use rand_core::{OsRng, RngCore};
use salsa20::cipher::generic_array::GenericArray;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

/// The 4-byte marker in front of a sealed message field.
pub const SEALED_MAGIC: [u8; 4] = *b"ZBE1";
/// How much longer a sealed field is than its plaintext: marker 4 + ephemeral key 32 + tag 16.
pub const SEALED_OVERHEAD: usize = 52;

/// Ed25519 public key -> X25519 public key of the same point: u = (1 + y) / (1 - y) mod p.
pub fn ed25519_public_key_to_x25519(pk: &[u8]) -> Result<[u8; 32], String> {
    let bytes: [u8; 32] = pk.try_into().map_err(|_| "public key must be 32 bytes".to_string())?;
    let vk = VerifyingKey::from_bytes(&bytes).map_err(|e| e.to_string())?;
    Ok(vk.to_montgomery().to_bytes())
}

/// Ed25519 seed -> X25519 secret key: the clamped first half of SHA-512(seed).
pub fn ed25519_seed_to_x25519(seed: &[u8]) -> [u8; 32] {
    let h = Sha512::digest(seed);
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&h[..32]);
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    sk
}

/// The X25519 public key of a scalar: X25519(scalar, 9).
pub fn x25519_base(scalar: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*scalar)).to_bytes()
}

fn box_key(sk: &[u8; 32], pk: &[u8; 32]) -> [u8; 32] {
    let shared = StaticSecret::from(*sk).diffie_hellman(&PublicKey::from(*pk));
    let key = salsa20::hsalsa::<salsa20::cipher::consts::U10>(GenericArray::from_slice(shared.as_bytes()), &GenericArray::default());
    key.into()
}

fn sealed_nonce(ephemeral_pk: &[u8; 32], recipient_pk_x: &[u8; 32]) -> [u8; 24] {
    let mut h = Blake2bVar::new(24).expect("24-byte BLAKE2b");
    h.update(ephemeral_pk);
    h.update(recipient_pk_x);
    let mut out = [0u8; 24];
    h.finalize_variable(&mut out).expect("24 bytes");
    out
}

/// True when the field starts with the marker (it may still fail to open).
pub fn is_sealed(field: &[u8]) -> bool {
    field.len() >= 4 && field[..4] == SEALED_MAGIC
}

/// Seal `plaintext` to the recipient's 32-byte Ed25519 public key. The ephemeral secret key is drawn at random unless given (tests).
pub fn seal(plaintext: &[u8], recipient_public_key: &[u8], ephemeral_secret_key: Option<&[u8; 32]>) -> Result<Vec<u8>, String> {
    let rpk = ed25519_public_key_to_x25519(recipient_public_key)?;
    let esk = match ephemeral_secret_key {
        Some(k) => *k,
        None => {
            let mut k = [0u8; 32];
            OsRng.fill_bytes(&mut k);
            k
        }
    };
    let epk = x25519_base(&esk);
    let nonce = sealed_nonce(&epk, &rpk);
    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(&box_key(&esk, &rpk)));
    let boxed = cipher.encrypt(GenericArray::from_slice(&nonce), plaintext).map_err(|_| "sealing failed".to_string())?;
    let mut out = Vec::with_capacity(SEALED_OVERHEAD + plaintext.len());
    out.extend_from_slice(&SEALED_MAGIC);
    out.extend_from_slice(&epk);
    out.extend_from_slice(&boxed);
    Ok(out)
}

/// Open a sealed field with the recipient's 32-byte Ed25519 seed: the plaintext, or None when it is not a sealed message or the key does not open it.
pub fn open_sealed(field: &[u8], recipient_seed: &[u8]) -> Option<Vec<u8>> {
    if !is_sealed(field) || field.len() < SEALED_OVERHEAD || recipient_seed.len() != 32 {
        return None;
    }
    let sk = ed25519_seed_to_x25519(recipient_seed);
    let pk = x25519_base(&sk);
    let epk: [u8; 32] = field[4..36].try_into().ok()?;
    let cipher = XSalsa20Poly1305::new(GenericArray::from_slice(&box_key(&sk, &epk)));
    cipher.decrypt(GenericArray::from_slice(&sealed_nonce(&epk, &pk)), &field[36..]).ok()
}
