// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

//! Keys: seed -> key pair -> addresses; BIP-39 + SLIP-10 wallets (spec/signing.md section 1).

use crate::address::{encode_zbc_address, typed_address, ZOOBC};
use crate::bip39_words::WORDS;
use crate::encoding::is_hex;
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

pub const ZOOBC_COIN_TYPE: u32 = 883;

/// A 32-byte seed with its public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    pub seed: [u8; 32],
    pub public_key: [u8; 32],
}

impl KeyPair {
    pub fn from_seed(seed: &[u8]) -> Result<KeyPair, String> {
        let seed: [u8; 32] = seed.try_into().map_err(|_| "Private key must be 64 hex characters (32 bytes)".to_string())?;
        let sk = SigningKey::from_bytes(&seed);
        Ok(KeyPair { seed, public_key: sk.verifying_key().to_bytes() })
    }
    pub fn from_hex(seed_hex: &str) -> Result<KeyPair, String> {
        if !is_hex(seed_hex, 64) {
            return Err("Private key must be 64 hex characters (32 bytes)".into());
        }
        KeyPair::from_seed(&hex::decode(seed_hex).unwrap())
    }
    /// The ZBC_ form of the public key.
    pub fn address(&self) -> String {
        encode_zbc_address(&self.public_key, "ZBC").unwrap()
    }
    /// The ZNK_ form of the same key.
    pub fn node_address(&self) -> String {
        encode_zbc_address(&self.public_key, "ZNK").unwrap()
    }
    /// 36-byte typed account address: 00000000 || public key.
    pub fn account_bytes(&self) -> Vec<u8> {
        typed_address(ZOOBC, &self.public_key)
    }
    /// Detached Ed25519 signature (64 bytes).
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.seed).sign(msg).to_bytes()
    }
}

/// True for 12, 15, 18, 21 or 24 English words with a valid checksum.
pub fn validate_mnemonic(mnemonic: &str) -> bool {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    if ![12, 15, 18, 21, 24].contains(&words.len()) {
        return false;
    }
    let mut bits = String::new();
    for w in &words {
        match WORDS.iter().position(|x| x == w) {
            Some(i) => bits.push_str(&format!("{i:011b}")),
            None => return false,
        }
    }
    let cs = words.len() / 3;
    let entropy: Vec<u8> = (0..(bits.len() - cs) / 8).map(|i| u8::from_str_radix(&bits[8 * i..8 * i + 8], 2).unwrap()).collect();
    let sum = Sha256::digest(&entropy);
    bits[bits.len() - cs..] == format!("{:08b}", sum[0])[..cs]
}

/// Entropy (16–32 bytes, a multiple of 4) -> mnemonic.
pub fn mnemonic_from_entropy(entropy: &[u8]) -> Result<String, String> {
    if entropy.len() < 16 || entropy.len() > 32 || entropy.len() % 4 != 0 {
        return Err("entropy must be 16-32 bytes, a multiple of 4".into());
    }
    let mut bits: String = entropy.iter().map(|b| format!("{b:08b}")).collect();
    let sum = Sha256::digest(entropy);
    bits.push_str(&format!("{:08b}", sum[0])[..entropy.len() / 4]);
    Ok((0..bits.len() / 11).map(|i| WORDS[usize::from_str_radix(&bits[11 * i..11 * i + 11], 2).unwrap()]).collect::<Vec<_>>().join(" "))
}

/// PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048, 64).
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let norm = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<Sha512>(norm.as_bytes(), format!("mnemonic{passphrase}").as_bytes(), 2048, &mut out);
    out
}

/// SLIP-10 for Ed25519 along a hardened-only path such as m/44'/883'/0'; the 32-byte key.
pub fn slip10_derive(path: &str, seed: &[u8]) -> Result<[u8; 32], String> {
    let segs: Vec<&str> = path.split('/').collect();
    if segs.first() != Some(&"m") || segs.len() < 2 || segs[1..].iter().any(|s| !s.ends_with('\'') || s.len() < 2 || !s[..s.len() - 1].bytes().all(|c| c.is_ascii_digit())) {
        return Err(format!("invalid derivation path: {path}"));
    }
    let mut mac = Hmac::<Sha512>::new_from_slice(b"ed25519 seed").unwrap();
    mac.update(seed);
    let digest = mac.finalize().into_bytes();
    let (mut key, mut chain) = ([0u8; 32], [0u8; 32]);
    key.copy_from_slice(&digest[..32]);
    chain.copy_from_slice(&digest[32..]);
    for seg in &segs[1..] {
        let index: u64 = seg[..seg.len() - 1].parse().map_err(|_| "path index too large".to_string())?;
        if index >= 0x8000_0000 {
            return Err("path index too large".into());
        }
        let mut data = vec![0u8];
        data.extend_from_slice(&key);
        data.extend_from_slice(&((index as u32) + 0x8000_0000).to_be_bytes());
        let mut mac = Hmac::<Sha512>::new_from_slice(&chain).unwrap();
        mac.update(&data);
        let digest = mac.finalize().into_bytes();
        key.copy_from_slice(&digest[..32]);
        chain.copy_from_slice(&digest[32..]);
    }
    Ok(key)
}

/// Account `index` of a mnemonic wallet: m/44'/883'/index'. Returns the key pair and its path.
pub fn wallet_account(mnemonic: &str, index: u32, passphrase: &str) -> Result<(KeyPair, String), String> {
    let path = format!("m/44'/{ZOOBC_COIN_TYPE}'/{index}'");
    let key = slip10_derive(&path, &mnemonic_to_seed(mnemonic, passphrase))?;
    Ok((KeyPair::from_seed(&key)?, path))
}
