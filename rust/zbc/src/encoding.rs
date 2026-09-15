// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

//! Base32 (no padding), base58/base58check (Bitcoin and Ripple alphabets), bech32/bech32m, SS58.

use blake2::{Blake2b512, Digest};
use sha2::Sha256;

pub const BITCOIN_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
pub const RIPPLE_ALPHABET: &[u8] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
const B32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// True for even-length hex, of exactly `n` characters when `n > 0`.
pub fn is_hex(s: &str, n: usize) -> bool {
    s.len() % 2 == 0 && (n == 0 || s.len() == n) && s.bytes().all(|c| c.is_ascii_hexdigit())
}

/// RFC 4648 base32 without padding.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = ((buf << 8) | b as u32) & 0x1fff;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = B32.iter().position(|&x| x == c)? as u32;
        buf = ((buf << 5) | v) & 0x1fff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

pub fn base58_decode(s: &str, alphabet: &[u8]) -> Option<Vec<u8>> {
    let mut big: Vec<u32> = Vec::new(); // little-endian base-256 digits
    for c in s.bytes() {
        let mut carry = alphabet.iter().position(|&x| x == c)? as u32;
        for d in big.iter_mut() {
            let v = *d * 58 + carry;
            *d = v & 0xff;
            carry = v >> 8;
        }
        while carry > 0 {
            big.push(carry & 0xff);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|&c| c == alphabet[0]).count();
    let mut out = vec![0u8; zeros];
    out.extend(big.iter().rev().map(|&d| d as u8));
    Some(out)
}

pub fn base58_encode(data: &[u8], alphabet: &[u8]) -> String {
    let mut digits: Vec<u32> = Vec::new(); // little-endian base-58 digits
    for &b in data {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            let v = (*d << 8) + carry;
            *d = v % 58;
            carry = v / 58;
        }
        while carry > 0 {
            digits.push(carry % 58);
            carry /= 58;
        }
    }
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    let mut s: String = std::iter::repeat(alphabet[0] as char).take(zeros).collect();
    s.extend(digits.iter().rev().map(|&d| alphabet[d as usize] as char));
    s
}

/// The payload without its 4-byte SHA-256d checksum, or None.
pub fn base58check_decode(s: &str, alphabet: &[u8]) -> Option<Vec<u8>> {
    let raw = base58_decode(s, alphabet)?;
    if raw.len() < 5 {
        return None;
    }
    let (body, check) = raw.split_at(raw.len() - 4);
    let sum = Sha256::digest(Sha256::digest(body));
    if sum[..4] != *check {
        return None;
    }
    Some(body.to_vec())
}

const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn polymod(values: impl Iterator<Item = u32>) -> u32 {
    let mut chk = 1u32;
    for v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u32> {
    hrp.bytes().map(|c| (c >> 5) as u32).chain(std::iter::once(0)).chain(hrp.bytes().map(|c| (c & 31) as u32)).collect()
}

/// (hrp, 5-bit data without checksum, "bech32" | "bech32m").
pub fn bech32_decode_raw(s: &str) -> Option<(String, Vec<u8>, &'static str)> {
    if s.len() > 1023 || (s.to_lowercase() != s && s.to_uppercase() != s) {
        return None;
    }
    let low = s.to_lowercase();
    let pos = low.rfind('1')?;
    if pos < 1 || pos + 7 > low.len() {
        return None;
    }
    let hrp = &low[..pos];
    let mut data = Vec::new();
    for c in low[pos + 1..].bytes() {
        data.push(CHARSET.iter().position(|&x| x == c)? as u8);
    }
    let pm = polymod(hrp_expand(hrp).into_iter().chain(data.iter().map(|&d| d as u32)));
    let enc = match pm {
        1 => "bech32",
        0x2bc830a3 => "bech32m",
        _ => return None,
    };
    data.truncate(data.len() - 6);
    Some((hrp.to_string(), data, enc))
}

pub fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let (mut acc, mut bits) = (0u32, 0u32);
    let maxv = (1u32 << to) - 1;
    let mut out = Vec::new();
    for &v in data {
        if (v as u32) >> from != 0 {
            return None;
        }
        acc = (acc << from) | v as u32;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

/// (hrp, witness version, program) of a segwit address.
pub fn segwit_decode(s: &str) -> Option<(String, u8, Vec<u8>)> {
    let (hrp, data, enc) = bech32_decode_raw(s)?;
    let version = *data.first()?;
    let prog = convert_bits(&data[1..], 5, 8, false)?;
    if !(2..=40).contains(&prog.len()) || version > 16 {
        return None;
    }
    if version == 0 && prog.len() != 20 && prog.len() != 32 {
        return None;
    }
    if (version == 0) != (enc == "bech32") {
        return None;
    }
    Some((hrp, version, prog))
}

/// Plain bech32 with an 8-bit payload (Cardano addresses).
pub fn bech32_decode_plain(s: &str) -> Option<(String, Vec<u8>)> {
    let (hrp, data, enc) = bech32_decode_raw(s)?;
    if enc != "bech32" {
        return None;
    }
    Some((hrp, convert_bits(&data, 5, 8, false)?))
}

/// (prefix, 32-byte account id) of an SS58 address; checksum = BLAKE2b-512("SS58PRE" || body)[..2].
pub fn ss58_decode(s: &str) -> Option<(u16, Vec<u8>)> {
    let raw = base58_decode(s, BITCOIN_ALPHABET)?;
    let (plen, prefix) = if raw.len() >= 35 && raw[0] < 64 {
        (1, raw[0] as u16)
    } else if raw.len() >= 36 && (64..128).contains(&raw[0]) {
        (2, (((raw[0] & 0x3f) as u16) << 2) | ((raw[1] >> 6) as u16) | (((raw[1] & 0x3f) as u16) << 8))
    } else {
        return None;
    };
    let body = &raw[..raw.len() - 2];
    if body.len() - plen != 32 {
        return None;
    }
    let mut h = Blake2b512::new();
    h.update(b"SS58PRE");
    h.update(body);
    let sum = h.finalize();
    if sum[0] != raw[raw.len() - 2] || sum[1] != raw[raw.len() - 1] {
        return None;
    }
    Some((prefix, body[plen..].to_vec()))
}
