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
    /// Set by the fallback reading, which names the type its own way ("ETH (compact)", "ZBC", ...).
    pub label: Option<String>,
}

impl ParsedAddress {
    /// The typed bytes: 4-byte type LE then the payload (36 bytes for a ZooBC account).
    pub fn bytes(&self) -> Vec<u8> {
        typed_address(self.account_type, &self.payload)
    }
    /// The recipient_type the tools print: the account type's name, or the fallback reading's label.
    pub fn type_name(&self) -> String {
        self.label.clone().unwrap_or_else(|| account_type_name(self.account_type))
    }
}

fn pa(account_type: i32, payload: Vec<u8>, display: impl Into<String>) -> ParsedAddress {
    ParsedAddress { account_type, payload, display: display.into(), label: None }
}

/// The reference's fallback reading names a Bitcoin account by its script (tx_common.h get_btc_recipient_label).
fn btc_label(t: i32) -> &'static str {
    match t {
        BITCOIN_P2PKH => "BTC P2PKH",
        BITCOIN_P2SH => "BTC P2SH",
        BITCOIN_P2WPKH => "BTC P2WPKH",
        BITCOIN_P2WSH => "BTC P2WSH",
        BITCOIN_TAPROOT => "BTC P2TR",
        BITCOIN => "BTC (legacy)",
        _ => "BTC",
    }
}

/// The chain each account type is written in: a --chain btc/ada/xrp/trx/xtz reading must agree with it.
fn chain_of_type(t: i32) -> &'static str {
    match t {
        ZOOBC => "zbc",
        DATASET => "zbs",
        BITCOIN | BITCOIN_P2PKH | BITCOIN_P2SH | BITCOIN_P2WPKH | BITCOIN_P2WSH | BITCOIN_TAPROOT => "btc",
        ETHEREUM => "eth",
        SOLANA => "sol",
        POLKADOT => "dot",
        CARDANO => "ada",
        RIPPLE => "xrp",
        TRON => "trx",
        TEZOS => "xtz",
        _ => "",
    }
}

fn chain_name(hint: &str) -> &'static str {
    match hint {
        "btc" => "Bitcoin",
        "ada" => "Cardano",
        "xrp" => "Ripple",
        "trx" => "Tron",
        "xtz" => "Tezos",
        _ => "matching",
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
    Ok(pa(t, payload, a))
}

fn bech32_prefixed(a: &str) -> bool {
    let low5: String = a.chars().take(5).collect::<String>().to_lowercase();
    low5.starts_with("bc1") || low5.starts_with("tb1") || low5.starts_with("bcrt1")
}

fn bech32_bitcoin(a: &str) -> Result<ParsedAddress, String> {
    let (_, version, prog) = segwit_decode(a).ok_or("invalid Bitcoin bech32 address")?;
    match (version, prog.len()) {
        (0, 20) => Ok(pa(BITCOIN_P2WPKH, prog, a)),
        (0, 32) => Ok(pa(BITCOIN_P2WSH, prog, a)),
        (1, 32) => Ok(pa(BITCOIN_TAPROOT, prog, a)),
        _ => Err("unsupported Bitcoin witness program".into()),
    }
}

fn base58_bitcoin(a: &str) -> Option<ParsedAddress> {
    let raw = base58_decode(a, BITCOIN_ALPHABET)?;
    if raw.len() != 25 {
        return None;
    }
    let body = base58check_decode(a, BITCOIN_ALPHABET)?;
    match (body.len(), body.first()) {
        (21, Some(0x00)) => Some(pa(BITCOIN_P2PKH, body[1..].to_vec(), a)),
        (21, Some(0x05)) => Some(pa(BITCOIN_P2SH, body[1..].to_vec(), a)),
        _ => None,
    }
}

/// The reference's second reading (parse_address in tx_common.h), on the string as given, when the first one fails:
/// None when no form of it applies; Some(Err) when one applies and the string is not that form.
fn fallback(s: &str) -> Option<Result<ParsedAddress, String>> {
    let labelled = |mut p: ParsedAddress, label: &str| {
        p.label = Some(label.to_string());
        p
    };
    if s.len() == 42 && (s.starts_with("0x") || s.starts_with("0X")) {
        if !is_hex(&s[2..], 40) {
            return Some(Err("invalid hex character in ETH address".into()));
        }
        return Some(Ok(labelled(pa(ETHEREUM, hex::decode(&s[2..]).unwrap(), s), "ETH (compact)")));
    }
    let bitcoin = |p: ParsedAddress| {
        let label = btc_label(p.account_type);
        labelled(p, label)
    };
    if s.starts_with('1') || s.starts_with('3') {
        return Some(base58_bitcoin(s).map(bitcoin).ok_or_else(|| "failed to decode BTC address".into()));
    }
    if bech32_prefixed(s) {
        return Some(bech32_bitcoin(s).map(bitcoin));
    }
    let up = s.to_uppercase();
    if up.starts_with("ZBC") || up.starts_with("ZNK") || up.starts_with("ZBS") {
        let Some((_, payload)) = decode_zbc_address(s) else {
            return Some(Err("address checksum validation failed".into()));
        };
        return Some(Ok(if up.starts_with("ZBS") {
            labelled(pa(DATASET, payload, s), "DATASET")
        } else {
            labelled(pa(ZOOBC, payload, s), "ZBC")
        }));
    }
    if is_hex(s, 64) {
        let key = hex::decode(s).unwrap();
        return Some(encode_zbc_address(&key, "ZBC").map(|d| labelled(pa(ZOOBC, key, d), "ZBC")));
    }
    None
}

fn parse_hinted(a: &str, hint: &str) -> Result<ParsedAddress, String> {
    match hint {
        "eth" => {
            let h = a.strip_prefix("0x").or_else(|| a.strip_prefix("0X")).unwrap_or(a);
            if !is_hex(h, 40) {
                return Err("not a 20-byte Ethereum address".into());
            }
            Ok(pa(ETHEREUM, hex::decode(h).unwrap(), a))
        }
        "sol" => match base58_decode(a, BITCOIN_ALPHABET) {
            Some(d) if d.len() == 32 => Ok(pa(SOLANA, d, a)),
            _ => Err("not a 32-byte Solana address".into()),
        },
        "dot" => match ss58_decode(a) {
            Some((_, id)) => Ok(pa(POLKADOT, id, a)),
            None => Err("not a valid SS58 address".into()),
        },
        "zbc" | "zbs" => zbc_form(a),
        // btc, ada, xrp, trx, xtz: detection reads the address; the hint is a check, never a reading
        _ => {
            let p = parse_auto(a)?;
            if chain_of_type(p.account_type) != hint {
                return Err(format!("not a {} address: it reads as {}", chain_name(hint), account_type_name(p.account_type)));
            }
            Ok(p)
        }
    }
}

fn parse_auto(a: &str) -> Result<ParsedAddress, String> {
    let b = a.as_bytes();
    if a.len() == 42 && (a.starts_with("0x") || a.starts_with("0X")) && is_hex(&a[2..], 40) {
        return Ok(pa(ETHEREUM, hex::decode(&a[2..]).unwrap(), a));
    }
    if looks_zbc(a) {
        return zbc_form(a);
    }
    if bech32_prefixed(a) {
        return bech32_bitcoin(a);
    }
    if (b[0] == b'1' || b[0] == b'3') && (26..=35).contains(&a.len()) {
        if let Some(p) = base58_bitcoin(a) {
            return Ok(p);
        }
    }
    if a.len() > 5 && a[..5].to_lowercase() == "addr1" {
        if let Some((hrp, bytes)) = bech32_decode_plain(a) {
            if hrp == "addr" && bytes.len() == 29 && bytes[0] == 0x61 {
                return Ok(pa(CARDANO, bytes[1..].to_vec(), a));
            }
        }
        return Err("invalid Cardano address (expected a mainnet enterprise addr1… address)".into());
    }
    if b[0] == b'T' && a.len() == 34 {
        if let Some(body) = base58check_decode(a, BITCOIN_ALPHABET) {
            if body.len() == 21 && body[0] == 0x41 {
                return Ok(pa(TRON, body[1..].to_vec(), a));
            }
        }
        return Err("invalid Tron address".into());
    }
    if b[0] == b'r' && (25..=35).contains(&a.len()) {
        if let Some(body) = base58check_decode(a, RIPPLE_ALPHABET) {
            if body.len() == 21 && body[0] == 0x00 {
                return Ok(pa(RIPPLE, body[1..].to_vec(), a));
            }
        }
        return Err("invalid Ripple address".into());
    }
    if a.starts_with("tz1") {
        if let Some(body) = base58check_decode(a, BITCOIN_ALPHABET) {
            if body.len() == 23 && body[..3] == [0x06, 0xa1, 0x9f] {
                return Ok(pa(TEZOS, body[3..].to_vec(), a));
            }
        }
        return Err("invalid Tezos address".into());
    }
    if let Some((_, id)) = ss58_decode(a) {
        if id.len() == 32 {
            return Ok(pa(POLKADOT, id, a));
        }
    }
    if (32..=44).contains(&a.len()) {
        if let Some(d) = base58_decode(a, BITCOIN_ALPHABET) {
            if d.len() == 32 {
                return Ok(pa(SOLANA, d, a));
            }
        }
    }
    if is_hex(a, 64) {
        let key = hex::decode(a).unwrap();
        let display = encode_zbc_address(&key, "ZBC")?;
        return Ok(pa(ZOOBC, key, display));
    }
    Err("unrecognised address. Supported: ZooBC (ZBC_/ZBS_), Bitcoin, Ethereum, Solana, Polkadot, Cardano, Ripple, Tron, Tezos".into())
}

/// Read a recipient as spec/addresses.md section 3 says; `chain` forces one reading (--chain). When the reading fails,
/// the fallback the reference keeps still takes 0x+40 hex, a Bitcoin address, ZBC/ZNK/ZBS text and 64 hex, and
/// `type_name` is then its label ("ETH (compact)", "BTC P2PKH", "ZBC", "DATASET").
pub fn parse_address(text: &str, chain: &str) -> Result<ParsedAddress, String> {
    let a = text.trim();
    if a.is_empty() {
        return Err("empty address".into());
    }
    let first = if chain.is_empty() {
        parse_auto(a)
    } else {
        let hint = chain_of(chain).ok_or_else(|| format!("unknown chain {chain}"))?;
        parse_hinted(a, hint)
    };
    match first {
        Ok(p) => Ok(p),
        Err(e) => fallback(text).unwrap_or(Err(e)),
    }
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
