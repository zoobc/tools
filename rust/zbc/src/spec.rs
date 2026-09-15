// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

//! The transaction descriptions of spec/transactions, embedded by `gen` into commands_gen.rs.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Debug, Clone, Deserialize)]
pub struct ParamDef {
    pub name: String,
    pub kind: String,
    pub required: bool,
    #[serde(default)]
    pub default: Option<String>,
    pub help: String,
    #[serde(default)]
    pub min: Option<i64>,
    #[serde(default)]
    pub max: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FieldDef {
    pub name: String,
    pub encoding: String,
    pub from: String,
    #[serde(default)]
    pub size: Option<usize>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub when: Option<String>,
    #[serde(default)]
    pub computed: Option<String>,
    #[serde(default)]
    pub default_from: Option<String>,
    #[serde(default)]
    pub when_zero: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TxDef {
    pub name: String,
    #[serde(rename = "type")]
    pub tx_type: u32,
    pub command: String,
    #[serde(default)]
    pub binary: Option<String>,
    pub description: String,
    pub sender_key: String,
    pub recipient: String,
    #[serde(default)]
    pub options: Vec<String>,
    pub needs_node: bool,
    #[serde(default)]
    pub custom: Option<String>,
    pub params: Vec<ParamDef>,
    pub body: Vec<FieldDef>,
    #[serde(default)]
    pub example: HashMap<String, String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

/// Every transaction description, in command order.
pub fn commands() -> &'static [TxDef] {
    static CELL: OnceLock<Vec<TxDef>> = OnceLock::new();
    CELL.get_or_init(|| serde_json::from_str(crate::commands_gen::COMMANDS_JSON).expect("commands_gen.rs"))
}

/// One description by command name.
pub fn command(name: &str) -> Option<&'static TxDef> {
    commands().iter().find(|c| c.command == name)
}
