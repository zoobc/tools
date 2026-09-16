// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

//! ZooBC tools: keys, addresses, message signing, transactions, the node client and the zbc-cli
//! command line. Every byte layout follows `spec/` of github.com/zoobc/tools and is checked
//! against `spec/vectors` in the tests.

pub mod address;
pub mod api;
pub mod bip39_words;
pub mod body;
pub mod cli;
mod commands_gen;
pub mod custom;
pub mod encryption;
pub mod encoding;
pub mod errors;
pub mod keys;
pub mod message;
pub mod spec;
pub mod transaction;

pub use address::{decode_zbc_address, encode_zbc_address, parse_address, parse_key32, ParsedAddress};
pub use api::Client;
pub use custom::{multisig_address, proof_of_ownership, ReferenceBlock};
pub use encryption::{ed25519_public_key_to_x25519, ed25519_seed_to_x25519, is_sealed, open_sealed, seal, x25519_base, SEALED_MAGIC, SEALED_OVERHEAD};
pub use errors::ToolError;
pub use keys::{mnemonic_to_seed, slip10_derive, validate_mnemonic, wallet_account, KeyPair};
pub use message::{sign_message, verify_message};
pub use spec::{command, commands, TxDef};
pub use transaction::{approval_escrow_body, send_zbc_body, sign_transaction, Escrow, Payload, Signed, SigningContext, Unsigned};
