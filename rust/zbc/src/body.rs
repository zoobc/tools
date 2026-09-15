// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

//! Parameter validation and the generic body serialiser driven by spec/transactions (encodings of index.json).

use crate::address::{parse_address, parse_key32};
use crate::encoding::is_hex;
use crate::errors::{usage, ToolError};
use crate::keys::KeyPair;
use crate::spec::{FieldDef, ParamDef, TxDef};
use crate::transaction::Writer;
use std::collections::HashMap;

pub type Params = HashMap<String, String>;

pub fn parse_integer(value: &str, kind: &str, name: &str) -> Result<i64, ToolError> {
    let v = value.trim();
    let digits = v.strip_prefix('-').unwrap_or(v);
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return Err(usage(format!("{name} must be a whole number, got \"{value}\"")));
    }
    let n: i128 = v.parse().map_err(|_| usage(format!("{name} is out of range for {kind}")))?;
    let (lo, hi): (i128, i128) = match kind {
        "uint64" => (0, u64::MAX as i128),
        "uint32" => (0, u32::MAX as i128),
        "uint8" => (0, 255),
        _ => (i64::MIN as i128, i64::MAX as i128),
    };
    if n < lo || n > hi {
        return Err(usage(format!("{name} is out of range for {kind}")));
    }
    Ok(n as u64 as i64)
}

pub fn split_list(s: &str) -> Vec<String> {
    s.split(',').map(str::trim).filter(|x| !x.is_empty()).map(String::from).collect()
}

/// Check one value against its parameter kind; returns the value to keep.
pub fn validate_param(p: &ParamDef, value: &str) -> Result<String, ToolError> {
    match p.kind.as_str() {
        "privkey" => {
            if !is_hex(value, 64) {
                return Err(usage(format!("{} must be 64 hex characters (a 32-byte private key)", p.name)));
            }
        }
        "address" => {
            parse_address(value, "").map_err(|e| usage(format!("invalid {}: {e}", p.name)))?;
        }
        "address_list" => {
            for a in split_list(value) {
                parse_address(&a, "").map_err(|e| usage(format!("invalid {} entry {a}: {e}", p.name)))?;
            }
        }
        "key" => {
            parse_key32(value).map_err(|e| usage(format!("invalid {}: {e}", p.name)))?;
        }
        "int64" | "uint64" | "uint32" | "uint8" => {
            let n = parse_integer(value, &p.kind, &p.name)?;
            if p.min.is_some_and(|m| n < m) || p.max.is_some_and(|m| n > m) {
                let lo = p.min.map_or("-inf".to_string(), |m| m.to_string());
                let hi = p.max.map_or("inf".to_string(), |m| m.to_string());
                return Err(usage(format!("{} must be between {lo} and {hi}", p.name)));
            }
            return Ok(value.trim().to_string());
        }
        "hex32" => {
            if !is_hex(value, 64) {
                return Err(usage(format!("{} must be 64 hex characters (32 bytes)", p.name)));
            }
        }
        "hexbytes" => {
            if !is_hex(value, 0) {
                return Err(usage(format!("{} must be hex", p.name)));
            }
        }
        _ => {}
    }
    Ok(value.to_string())
}

/// What the generic serialiser cannot read from the parameters.
#[derive(Default)]
pub struct BodyContext {
    pub sender: Option<KeyPair>,
    pub files: HashMap<String, Vec<u8>>,
    pub computed: HashMap<String, Vec<u8>>,
}

fn condition_holds(when: &str, params: &Params) -> Result<bool, ToolError> {
    let (name, rest) = when.split_once(" != ").ok_or_else(|| ToolError::new(1, format!("unsupported condition {when}")))?;
    let v = params.get(name).cloned().unwrap_or_default();
    Ok(match rest {
        "0" => !v.is_empty() && v.parse::<i64>().map_or(false, |n| n != 0),
        "''" => !v.is_empty(),
        _ => return Err(ToolError::new(1, format!("unsupported condition {when}"))),
    })
}

/// Serialise one body field.
pub fn encode_field(f: &FieldDef, params: &Params, ctx: &BodyContext) -> Result<Vec<u8>, ToolError> {
    if let Some(v) = ctx.computed.get(&f.name) {
        return Ok(v.clone());
    }
    let mut value = params.get(&f.from).cloned().unwrap_or_default();
    if let Some(wz) = &f.when_zero {
        if value.is_empty() || value.parse::<i64>().map_or(false, |n| n <= 0) {
            value = params.get(wz).cloned().unwrap_or_else(|| "0".into());
        }
    }
    let w = Writer::new();
    Ok(match f.encoding.as_str() {
        "u8" => w.u8(parse_integer(&value, "uint8", &f.name)? as u8).finish(),
        "u16le" => w.u16(parse_integer(&value, "uint32", &f.name)? as u16).finish(),
        "u32le" => w.u32(parse_integer(&value, "uint32", &f.name)? as u32).finish(),
        "u64le" => w.i64(parse_integer(&value, "int64", &f.name)?).finish(),
        "hex" => {
            let b = hex::decode(&value).map_err(|_| usage(format!("{} must be hex", f.from)))?;
            if let Some(size) = f.size {
                if b.len() != size {
                    return Err(usage(format!("{} must be {size} bytes ({} hex)", f.from, 2 * size)));
                }
            }
            b
        }
        "hex16" => {
            let b = hex::decode(&value).map_err(|_| usage(format!("{} must be hex", f.from)))?;
            w.u16(b.len() as u16).bytes(&b).finish()
        }
        "bytes32" => {
            let b = match ctx.files.get(&f.from) {
                Some(b) => b.clone(),
                None => hex::decode(&value).map_err(|_| usage(format!("{} must be hex", f.from)))?,
            };
            w.u32(b.len() as u32).bytes(&b).finish()
        }
        "str16" => w.u16(value.len() as u16).bytes(value.as_bytes()).finish(),
        "str32" => w.u32(value.len() as u32).bytes(value.as_bytes()).finish(),
        "address" => parse_address(&value, "").map_err(|e| usage(format!("invalid {}: {e}", f.from)))?.bytes(),
        "address_list" | "address_list8" => {
            let items = split_list(&value);
            let mut w = w;
            if f.encoding == "address_list8" {
                if items.len() > 255 {
                    return Err(usage(format!("{}: at most 255 entries", f.from)));
                }
                w = w.u8(items.len() as u8);
            }
            for a in items {
                w = w.bytes(&parse_address(&a, "").map_err(|e| usage(format!("invalid {} entry {a}: {e}", f.from)))?.bytes());
            }
            w.finish()
        }
        "sender_address" => ctx.sender.as_ref().ok_or_else(|| ToolError::new(1, "no sender"))?.account_bytes(),
        "pubkey_of_key" => KeyPair::from_hex(&value).map_err(|_| usage(format!("{} must be 64 hex characters (a 32-byte private key)", f.from)))?.public_key.to_vec(),
        "key32" => parse_key32(&value).map_err(|e| usage(format!("invalid {}: {e}", f.from)))?,
        "literal" => hex::decode(f.value.clone().unwrap_or_default()).unwrap_or_default(),
        "custom" => return Err(ToolError::new(1, format!("field {} needs a custom hook", f.name))),
        other => return Err(ToolError::new(1, format!("unknown encoding {other}"))),
    })
}

/// The whole body of a non-custom transaction.
pub fn build_body(def: &TxDef, params: &Params, ctx: &BodyContext) -> Result<Vec<u8>, ToolError> {
    let mut out = Vec::new();
    for f in &def.body {
        if let Some(when) = &f.when {
            if !condition_holds(when, params)? {
                continue;
            }
        }
        out.extend(encode_field(f, params, ctx)?);
    }
    Ok(out)
}
