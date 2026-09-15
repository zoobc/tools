// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#pragma once
// Bitcoin transaction parser + BIP-143 (SegWit v0) signature verifier for the ZooBC bridge.
// Phase 1 targets native P2WPKH (bech32 bc1q…, account type 7) — the common modern single-sig case.
// The crypto is reuse: crypto::Hash::DoubleSHA256 + crypto::BitcoinSignature (secp256k1 ECDSA) + HASH160.
// See docs/BITCOIN_BRIDGE.md for the synthetic-UTXO model (why input_amount is supplied externally:
// BIP-143's sighash commits to the spent output's amount, which is NOT carried in the tx).
#include <cstdint>
#include <string>
#include <vector>

#include "zoobc/common/result.h"

namespace zoobc {
namespace crypto {

struct BitcoinTxInput {
    std::vector<uint8_t> outpoint;                 // 36 bytes: prev txid (LE) + vout index (LE)
    std::vector<uint8_t> script_sig;               // empty for native segwit inputs
    uint32_t sequence = 0;
    std::vector<std::vector<uint8_t>> witness;     // witness stack items (P2WPKH: [sig+hashtype, pubkey])
};
struct BitcoinTxOutput {
    uint64_t value = 0;                            // satoshis
    std::vector<uint8_t> script;                   // scriptPubKey
};
struct BitcoinTx {
    bool ok = false;
    std::string error;
    uint32_t version = 0;
    bool segwit = false;
    std::vector<BitcoinTxInput> vin;
    std::vector<BitcoinTxOutput> vout;
    uint32_t locktime = 0;
};

// Result of verifying a native P2WPKH spend for the bridge.
struct BitcoinTransfer {
    bool ok = false;
    std::vector<uint8_t> from_pubkey;              // 33-byte compressed witness pubkey
    std::vector<uint8_t> from_hash160;             // HASH160(pubkey) = the P2WPKH program spent
    std::vector<uint8_t> to_hash160;               // recipient (output[0]) 20-byte hash (P2WPKH or P2PKH)
    uint64_t satoshis = 0;                         // recipient output[0] value
    std::string error;
};

// Structural parse of a Bitcoin tx (legacy or segwit-serialized). Bounds-checked; never throws.
BitcoinTx ParseBitcoinTx(const std::vector<uint8_t>& raw);

// BIP-143 sighash preimage for input idx. script_code is the raw script WITHOUT its length prefix
// (this function serializes the CompactSize length). The 32-byte sighash is DoubleSHA256(preimage).
std::vector<uint8_t> BIP143Preimage(const BitcoinTx& tx, size_t idx,
    const std::vector<uint8_t>& script_code, uint64_t amount, uint32_t hash_type);

// Verify input idx's P2WPKH witness signature under BIP-143. amount = value of the spent UTXO.
// Only SIGHASH_ALL (0x01) is accepted, and the DER signature must be low-s (BIP-146, anti-malleability)
// in phase 1. err (optional) gets a reason on failure.
bool VerifyP2WPKHInput(const BitcoinTx& tx, size_t idx, uint64_t amount, std::string* err = nullptr);

// Extract the 20-byte HASH160 from a P2WPKH (0x0014<20>) or P2PKH (0x76a914<20>88ac) scriptPubKey;
// returns empty for any other script (so the bridge only mirrors hash-form outputs it can represent).
std::vector<uint8_t> BitcoinOutputHash160(const std::vector<uint8_t>& script);

// Parse a signed single-input P2WPKH tx + verify its signature, then extract the bridge transfer
// (sender = the witness key's program; recipient = output[0]; amount = output[0] value).
BitcoinTransfer ParseAndVerifyP2WPKHTransfer(const std::vector<uint8_t>& raw, uint64_t input_amount);

// --- Legacy P2PKH (account type 5, base58 "1…") -----------------------------------------------------
// Legacy (pre-SegWit) sighash preimage for input idx under SIGHASH_ALL: the tx re-serialized with
// input[idx]'s scriptSig replaced by script_code and ALL other scriptSigs emptied, followed by the
// 4-byte hash_type. The 32-byte sighash is DoubleSHA256(preimage). Unlike BIP-143 it does NOT commit
// to the spent input amount (so no amount parameter).
std::vector<uint8_t> LegacySighashPreimage(const BitcoinTx& tx, size_t idx,
    const std::vector<uint8_t>& script_code, uint32_t hash_type);

// Extract the pubkey from a standard P2PKH scriptSig (the two-push form <sig+hashtype> <pubkey>);
// returns empty for any non-standard scriptSig.
std::vector<uint8_t> P2PKHScriptSigPubkey(const std::vector<uint8_t>& script_sig);

// Verify input idx's P2PKH scriptSig signature under the legacy sighash. Standard <sig><pubkey> form,
// SIGHASH_ALL only, DER signature must be low-s (BIP-146). err (optional) gets a reason on failure.
bool VerifyP2PKHInput(const BitcoinTx& tx, size_t idx, std::string* err = nullptr);

// Parse a signed single-input P2PKH tx + verify its signature, then extract the bridge transfer
// (sender = the scriptSig key's program; recipient = output[0]; amount = output[0] value).
BitcoinTransfer ParseAndVerifyP2PKHTransfer(const std::vector<uint8_t>& raw);


/// A decoded bech32/bech32m SegWit address: witness version + witness program.
struct Bech32Segwit {
    uint8_t witness_version = 0;
    std::vector<uint8_t> program;
};
/// Decode bc1…/tb1…/bcrt1… — validates the bech32 checksum, so a non-Bitcoin base58 or bech32
/// string cannot be mistaken for one.
Result<Bech32Segwit> Bech32SegwitDecode(const std::string& address);

}  // namespace crypto
}  // namespace zoobc
