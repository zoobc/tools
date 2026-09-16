// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

//! Account addresses: the ZBC_/ZNK_/ZBS_ text form and every recipient form of spec/addresses.md.

use crate::encoding::*;
use sha3::{Digest, Sha3_256};

pub const ZOOBC: i32 = 0;
pub const BITCOIN: i32 = 1;
pub const EMPTY: i32 = 2;
pub const ESTONIA_EID: i32 = 3;
pub const ETHEREUM: i32 = 4;
pub const BITCOIN_P2PKH: i32 = 5;
pub const BITCOIN_P2SH: i32 = 6;
pub const BITCOIN_P2WPKH: i32 = 7;
pub const BITCOIN_P2WSH: i32 = 8;
pub const BITCOIN_TAPROOT: i32 = 9;
pub const DATASET: i32 = 10;
pub const SOLANA: i32 = 11;
pub const POLKADOT: i32 = 12;
pub const CARDANO: i32 = 13;
pub const RIPPLE: i32 = 14;
pub const TRON: i32 = 15;
pub const TEZOS: i32 = 16;

pub fn account_type_name(t: i32) -> String {
    match t {
        0 => "ZooBC",
        1 => "Bitcoin",
        3 => "Estonia eID",
        4 => "Ethereum",
        5 => "Bitcoin P2PKH",
        6 => "Bitcoin P2SH",
        7 => "Bitcoin P2WPKH",
        8 => "Bitcoin P2WSH",
        9 => "Bitcoin Taproot",
        10 => "DataSet",
        11 => "Solana",
        12 => "Polkadot",
        13 => "Cardano",
        14 => "Ripple",
        15 => "Tron",
        16 => "Tezos",
        _ => return format!("type {t}"),
    }
    .to_string()
}

/// The 4-byte little-endian type followed by the payload.
pub fn typed_address(t: i32, payload: &[u8]) -> Vec<u8> {
    let mut out = t.to_le_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

/// PREFIX_ + base32(payload || SHA3-256(payload || prefix)[..3]) in seven groups of eight.
pub fn encode_zbc_address(payload: &[u8], prefix: &str) -> Result<String, String> {
    if payload.len() != 32 || prefix.len() != 3 {
        return Err("address payload must be 32 bytes and the prefix 3 characters".into());
    }
    let mut h = Sha3_256::new();
    h.update(payload);
    h.update(prefix.as_bytes());
    let sum = h.finalize();
    let mut raw = payload.to_vec();
    raw.extend_from_slice(&sum[..3]);
    let s = base32_encode(&raw);
    let mut out = prefix.to_string();
    for i in 0..7 {
        out.push('_');
        out.push_str(&s[8 * i..8 * i + 8]);
    }
    Ok(out)
}

/// (upper-case prefix, 32-byte payload) of PREFIX_... (separators _ or -, any case), or None.
/// The 59 significant characters of a ZooBC address: separators (_ -) and whitespace dropped, upper case (addresses.md 2).
pub fn zbc_significant(text: &str) -> String {
    text.chars().filter(|c| *c != '_' && *c != '-' && !c.is_whitespace()).collect::<String>().to_uppercase()
}

/// (upper-case prefix, 32-byte payload) of a ZooBC address in any spelling, or None.
pub fn decode_zbc_address(text: &str) -> Option<(String, Vec<u8>)> {
    let norm = zbc_significant(text);
    if norm.len() < 3 || !norm.is_ascii() {
        return None;
    }
    let prefix = &norm[..3];
    let body = &norm[3..];
    if body.len() != 56 {
        return None;
    }
    let raw = base32_decode(&body)?;
    if raw.len() != 35 {
        return None;
    }
    let mut h = Sha3_256::new();
    h.update(&raw[..32]);
    h.update(prefix.as_bytes());
    let sum = h.finalize();
    if sum[..3] != raw[32..] {
        return None;
    }
    Some((prefix.to_string(), raw[..32].to_vec()))
}

/// A recipient as the envelope carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAddress {
    pub account_type: i32,
    pub payload: Vec<u8>,
    pub display: String,
}

impl ParsedAddress {
    /// The typed bytes: 4-byte type LE then the payload (36 bytes for a ZooBC account).
    pub fn bytes(&self) -> Vec<u8> {
        typed_address(self.account_type, &self.payload)
    }
    pub fn type_name(&self) -> String {
        account_type_name(self.account_type)
    }
}

fn chain_of(name: &str) -> Option<&'static str> {
    Some(match name.to_lowercase().as_str() {
        "zbc" | "zoobc" => "zbc",
        "btc" | "bitcoin" => "btc",
        "eth" | "ethereum" | "evm" => "eth",
        "sol" | "solana" => "sol",
        "dot" | "polkadot" | "substrate" => "dot",
        "ada" | "cardano" => "ada",
        "xrp" | "ripple" => "xrp",
        "trx" | "tron" => "trx",
        "xtz" | "tezos" => "xtz",
        "zbs" | "dataset" => "zbs",
        _ => return None,
    })
}

/// Shape only: PREFIX then a separator, or the bare form: 59 significant characters, ZBC/ZBS prefix, base32 body.
fn looks_zbc(a: &str) -> bool {
    let b = a.as_bytes();
    if a.len() > 4 && (b[3] == b'_' || b[3] == b'-') {
        return true;
    }
    let n = zbc_significant(a);
    n.len() == 59
        && n.is_ascii()
        && (n.starts_with("ZBC") || n.starts_with("ZBS"))
        && n[3..].bytes().all(|c| b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".contains(&c))
}

fn zbc_form(a: &str) -> Result<ParsedAddress, String> {
    let (prefix, payload) = decode_zbc_address(a).ok_or("invalid ZooBC address checksum")?;
    let t = if prefix == "ZBS" { DATASET } else { ZOOBC };
    Ok(ParsedAddress { account_type: t, payload, display: a.to_string() })
}

fn parse_hinted(a: &str, hint: &str) -> Result<ParsedAddress, String> {
    match hint {
        "eth" => {
            let h = a.strip_prefix("0x").or_else(|| a.strip_prefix("0X")).unwrap_or(a);
            if !is_hex(h, 40) {
                return Err("not a 20-byte Ethereum address".into());
            }
            Ok(ParsedAddress { account_type: ETHEREUM, payload: hex::decode(h).unwrap(), display: a.to_string() })
        }
        "sol" => match base58_decode(a, BITCOIN_ALPHABET) {
            Some(d) if d.len() == 32 => Ok(ParsedAddress { account_type: SOLANA, payload: d, display: a.to_string() }),
            _ => Err("not a 32-byte Solana address".into()),
        },
        "dot" => match ss58_decode(a) {
            Some((_, id)) => Ok(ParsedAddress { account_type: POLKADOT, payload: id, display: a.to_string() }),
            None => Err("not a valid SS58 address".into()),
        },
        "zbc" | "zbs" => zbc_form(a),
        _ => parse_auto(a),
    }
}

fn parse_auto(a: &str) -> Result<ParsedAddress, String> {
    let b = a.as_bytes();
    if a.len() == 42 && (a.starts_with("0x") || a.starts_with("0X")) && is_hex(&a[2..], 40) {
        return Ok(ParsedAddress { account_type: ETHEREUM, payload: hex::decode(&a[2..]).unwrap(), display: a.to_string() });
    }
    if looks_zbc(a) {
        return zbc_form(a);
    }
    let low5: String = a.chars().take(5).collect::<String>().to_lowercase();
    if low5.starts_with("bc1") || low5.starts_with("tb1") || low5.starts_with("bcrt1") {
        let (_, version, prog) = segwit_decode(a).ok_or("invalid Bitcoin bech32 address")?;
        return match (version, prog.len()) {
            (0, 20) => Ok(ParsedAddress { account_type: BITCOIN_P2WPKH, payload: prog, display: a.to_string() }),
            (0, 32) => Ok(ParsedAddress { account_type: BITCOIN_P2WSH, payload: prog, display: a.to_string() }),
            (1, 32) => Ok(ParsedAddress { account_type: BITCOIN_TAPROOT, payload: prog, display: a.to_string() }),
            _ => Err("unsupported Bitcoin witness program".into()),
        };
    }
    if (b[0] == b'1' || b[0] == b'3') && (26..=35).contains(&a.len()) {
        if let Some(raw) = base58_decode(a, BITCOIN_ALPHABET) {
            if raw.len() == 25 {
                if let Some(body) = base58check_decode(a, BITCOIN_ALPHABET) {
                    if body.len() == 21 && body[0] == 0x00 {
                        return Ok(ParsedAddress { account_type: BITCOIN_P2PKH, payload: body[1..].to_vec(), display: a.to_string() });
                    }
                    if body.len() == 21 && body[0] == 0x05 {
                        return Ok(ParsedAddress { account_type: BITCOIN_P2SH, payload: body[1..].to_vec(), display: a.to_string() });
                    }
                }
            }
        }
    }
    if a.len() > 5 && a[..5].to_lowercase() == "addr1" {
        if let Some((hrp, bytes)) = bech32_decode_plain(a) {
            if hrp == "addr" && bytes.len() == 29 && bytes[0] == 0x61 {
                return Ok(ParsedAddress { account_type: CARDANO, payload: bytes[1..].to_vec(), display: a.to_string() });
            }
        }
        return Err("invalid Cardano address (expected a mainnet enterprise addr1… address)".into());
    }
    if b[0] == b'T' && a.len() == 34 {
        if let Some(body) = base58check_decode(a, BITCOIN_ALPHABET) {
            if body.len() == 21 && body[0] == 0x41 {
                return Ok(ParsedAddress { account_type: TRON, payload: body[1..].to_vec(), display: a.to_string() });
            }
        }
        return Err("invalid Tron address".into());
    }
    if b[0] == b'r' && (25..=35).contains(&a.len()) {
        if let Some(body) = base58check_decode(a, RIPPLE_ALPHABET) {
            if body.len() == 21 && body[0] == 0x00 {
                return Ok(ParsedAddress { account_type: RIPPLE, payload: body[1..].to_vec(), display: a.to_string() });
            }
        }
        return Err("invalid Ripple address".into());
    }
    if a.starts_with("tz1") {
        if let Some(body) = base58check_decode(a, BITCOIN_ALPHABET) {
            if body.len() == 23 && body[..3] == [0x06, 0xa1, 0x9f] {
                return Ok(ParsedAddress { account_type: TEZOS, payload: body[3..].to_vec(), display: a.to_string() });
            }
        }
        return Err("invalid Tezos address".into());
    }
    if let Some((_, id)) = ss58_decode(a) {
        if id.len() == 32 {
            return Ok(ParsedAddress { account_type: POLKADOT, payload: id, display: a.to_string() });
        }
    }
    if (32..=44).contains(&a.len()) {
        if let Some(d) = base58_decode(a, BITCOIN_ALPHABET) {
            if d.len() == 32 {
                return Ok(ParsedAddress { account_type: SOLANA, payload: d, display: a.to_string() });
            }
        }
    }
    if is_hex(a, 64) {
        let key = hex::decode(a).unwrap();
        let display = encode_zbc_address(&key, "ZBC")?;
        return Ok(ParsedAddress { account_type: ZOOBC, payload: key, display });
    }
    Err("unrecognised address. Supported: ZooBC (ZBC_/ZBS_), Bitcoin, Ethereum, Solana, Polkadot, Cardano, Ripple, Tron, Tezos".into())
}

/// Read a recipient in the order of spec/addresses.md section 3; `chain` forces one reading (--chain).
pub fn parse_address(text: &str, chain: &str) -> Result<ParsedAddress, String> {
    let a = text.trim();
    if a.is_empty() {
        return Err("empty address".into());
    }
    if !chain.is_empty() {
        let hint = chain_of(chain).ok_or_else(|| format!("unknown chain {chain}"))?;
        return match parse_hinted(a, hint) {
            Ok(p) => Ok(p),
            Err(e) => {
                let up = a.to_uppercase();
                let low = a.to_lowercase();
                let plain = (a.len() == 42 && (a.starts_with("0x") || a.starts_with("0X")))
                    || up.starts_with("ZBC") || up.starts_with("ZNK") || up.starts_with("ZBS")
                    || a.starts_with('1') || a.starts_with('3')
                    || low.starts_with("bc1") || low.starts_with("tb1") || low.starts_with("bcrt1") || a.len() == 64;
                if plain { parse_auto(a) } else { Err(e) }
            }
        };
    }
    parse_auto(a)
}

/// A registry key parameter: 64 hex (optionally 0x) or a ZNK_/ZBG_/ZBR_/ZBC_ text address; 32 bytes.
pub fn parse_key32(text: &str) -> Result<Vec<u8>, String> {
    if text.len() == 66 && text.as_bytes()[3] == b'_' {
        return decode_zbc_address(text).map(|(_, p)| p).ok_or_else(|| "invalid address checksum".into());
    }
    let h = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
    if !is_hex(h, 64) {
        return Err("key must be a 64-hex string or a ZNK_/ZBG_/ZBR_ address".into());
    }
    Ok(hex::decode(h).unwrap())
}
