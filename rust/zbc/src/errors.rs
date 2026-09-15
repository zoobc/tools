// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

//! Exit codes and error classes of spec/cli-contract.md section 5.

use serde_json::{json, Map, Value};
use std::fmt;

pub const OK: i32 = 0;
pub const INTERNAL: i32 = 1;
pub const USAGE: i32 = 2;
pub const NODE_UNREACHABLE: i32 = 3;
pub const INSUFFICIENT_BALANCE: i32 = 4;
pub const FEE_TOO_LOW: i32 = 5;
pub const REJECTED: i32 = 6;
pub const NOT_FOUND: i32 = 7;
pub const TIMEOUT: i32 = 8;
pub const NODE_BUSY: i32 = 9;
pub const VERIFY_FAILED: i32 = 10;

/// The contract's name of an exit code.
pub fn error_class(code: i32) -> &'static str {
    match code {
        0 => "ok",
        2 => "usage",
        3 => "node_unreachable",
        4 => "insufficient_balance",
        5 => "fee_too_low",
        6 => "rejected",
        7 => "not_found",
        8 => "timeout",
        9 => "node_busy",
        10 => "verify_failed",
        _ => "internal",
    }
}

/// An error that carries its exit code; `extra` is merged into the JSON error object.
#[derive(Debug, Clone)]
pub struct ToolError {
    pub code: i32,
    pub message: String,
    pub extra: Map<String, Value>,
}

impl ToolError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        ToolError { code, message: message.into(), extra: Map::new() }
    }
    pub fn with(mut self, key: &str, value: Value) -> Self {
        self.extra.insert(key.to_string(), value);
        self
    }
    /// The JSON error object of the contract (section 4).
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("success".into(), json!(false));
        m.insert("error".into(), json!(self.message));
        m.insert("exit_code".into(), json!(self.code));
        m.insert("error_class".into(), json!(error_class(self.code)));
        for (k, v) in &self.extra {
            m.insert(k.clone(), v.clone());
        }
        Value::Object(m)
    }
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ToolError {}

/// A usage error (exit 2).
pub fn usage(message: impl Into<String>) -> ToolError {
    ToolError::new(USAGE, message)
}

/// An internal error (exit 1).
pub fn internal(message: impl Into<String>) -> ToolError {
    ToolError::new(INTERNAL, message)
}

/// Classify a node's rejection into an exit code (spec/api.md section 2).
pub fn classify_node_error(http_code: u16, text: &str) -> i32 {
    if http_code == 0 {
        return NODE_UNREACHABLE;
    }
    if http_code >= 500 {
        return NODE_BUSY;
    }
    let t = text.to_lowercase();
    if t.contains("fee too low") {
        FEE_TOO_LOW
    } else if t.contains("insufficient balance") || t.contains("insufficient spendable") || t.contains("account does not exist") {
        INSUFFICIENT_BALANCE
    } else if t.contains("not found") || t.contains("unknown token") || t.contains("unknown or expired token") || t.contains("unknown app") {
        NOT_FOUND
    } else {
        REJECTED
    }
}
