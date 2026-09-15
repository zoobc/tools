// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_CRYPTO_SIGNATURE_H
#define ZOOBC_CRYPTO_SIGNATURE_H

#include <cstdint>
#include <vector>
#include "zoobc/common/result.h"
#include "zoobc/common/constants.h"
#include "zoobc/common/types.h"

namespace zoobc {
namespace crypto {

// Key pair structure
struct KeyPair {
    std::vector<uint8_t> public_key;   // 32 bytes (Ed25519)
    std::vector<uint8_t> private_key;  // 64 bytes (Ed25519)
};

// Account address size constants (matching Go implementation + compact format)
// Format: [4 bytes AccountType (LE)] + [public key bytes OR address hash]
//
// TWO-PHASE ADDRESS SYSTEM:
// - Compact format: [type] + [20-byte address hash] - before first send
// - Full format: [type] + [full public key] - after first send or when pubkey known
//
// This allows receiving funds to standard ETH/BTC addresses without knowing pubkey.
// When owner signs first transaction, pubkey is recovered and can be attached.
namespace AccountAddressSize {
    constexpr size_t TYPE_PREFIX = 4;           // Account type prefix (int32 LE)

    // ZBC (Ed25519) - always full, no compact
    constexpr size_t ZBC_PUBKEY = 32;           // Ed25519 public key

    // ETH (secp256k1) - compact or full
    constexpr size_t ETH_HASH = 20;             // Keccak256 hash (last 20 bytes)
    constexpr size_t ETH_PUBKEY = 64;           // Uncompressed ECDSA (no 0x04 prefix)

    // BTC (secp256k1) - compact or full
    constexpr size_t BTC_HASH = 20;             // HASH160 (RIPEMD160(SHA256))
    constexpr size_t BTC_WITNESS32 = 32;        // SegWit witness program (P2WSH/P2TR)
    constexpr size_t BTC_PUBKEY_COMPRESSED = 33;    // Compressed secp256k1
    constexpr size_t BTC_PUBKEY_UNCOMPRESSED = 65;  // Uncompressed secp256k1

    // Estonia eID (P-384) - always full
    constexpr size_t ESTONIA_EID_PUBKEY = 97;   // DER-encoded P-384

    // Full address sizes (type + full pubkey)
    constexpr size_t ZBC_FULL = TYPE_PREFIX + ZBC_PUBKEY;           // 36 bytes
    constexpr size_t ETH_FULL = TYPE_PREFIX + ETH_PUBKEY;           // 68 bytes
    constexpr size_t BTC_FULL_COMPRESSED = TYPE_PREFIX + BTC_PUBKEY_COMPRESSED;   // 37 bytes
    constexpr size_t BTC_FULL_UNCOMPRESSED = TYPE_PREFIX + BTC_PUBKEY_UNCOMPRESSED; // 69 bytes

    // Compact address sizes (type + address hash)
    constexpr size_t ETH_COMPACT = TYPE_PREFIX + ETH_HASH;          // 24 bytes
    constexpr size_t BTC_COMPACT = TYPE_PREFIX + BTC_HASH;          // 24 bytes
    constexpr size_t BTC_COMPACT_WITNESS32 = TYPE_PREFIX + BTC_WITNESS32; // 36 bytes
}

// Signature size constants (matching Go implementation)
namespace SignatureSize {
    constexpr size_t ZBC = 64;      // Ed25519 signature
    constexpr size_t ETH = 65;      // ECDSA r,s,v (includes recovery ID)
    // BTC signature is variable: [2 bytes pubkey len] + [pubkey] + [signature]
}

// Multi-type signature operations (matching Go common/crypto/signature.go)
class Signature {
public:
    // Generate a new Ed25519 key pair
    static Result<KeyPair> GenerateKeyPair();

    // Sign a message with Ed25519
    static Result<std::vector<uint8_t>> Sign(const std::vector<uint8_t>& message,
                                              const std::vector<uint8_t>& private_key);

    // Verify an Ed25519 signature (legacy - for backward compatibility)
    static Result<bool> Verify(const std::vector<uint8_t>& message,
                               const std::vector<uint8_t>& signature,
                               const std::vector<uint8_t>& public_key);

    /**
     * Multi-type signature verification (matching Go crypto.Signature.VerifySignature)
     *
     * Extracts account type from address prefix and dispatches to appropriate verifier.
     * This is the main entry point for transaction signature verification.
     *
     * @param payload The message/payload that was signed (usually tx hash)
     * @param signature The signature bytes (size depends on account type)
     * @param account_address Full account address: [4 bytes type] + [public key bytes]
     * @return Result<bool> true if signature is valid
     */
    static Result<bool> VerifySignature(
        const std::vector<uint8_t>& payload,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& account_address);

    /**
     * Extract account type from account address
     *
     * @param account_address Full account address bytes
     * @return AccountType enum value
     */
    static AccountType GetAccountType(const std::vector<uint8_t>& account_address);

    /**
     * Extract public key from account address
     *
     * @param account_address Full account address: [4 bytes type] + [public key bytes]
     * @return Public key bytes (without type prefix)
     */
    static std::vector<uint8_t> GetPublicKeyFromAddress(
        const std::vector<uint8_t>& account_address);

    /**
     * Get expected signature size for account type
     *
     * @param account_type The account type
     * @return Expected signature size in bytes (0 if variable/unknown)
     */
    static size_t GetSignatureSize(AccountType account_type);

    /**
     * Check if signature size is valid for account type
     *
     * @param signature The signature bytes
     * @param account_type The account type
     * @return true if signature size is valid
     */
    static bool IsValidSignatureSize(
        const std::vector<uint8_t>& signature,
        AccountType account_type);

    /**
     * Check if an address is in compact format (hash-only)
     *
     * Compact addresses store only the address hash (20 bytes) instead of
     * the full public key. Used for receiving funds before first send.
     *
     * @param account_address Full account address bytes
     * @return true if compact format
     */
    static bool IsCompactAddress(const std::vector<uint8_t>& account_address);

    /**
     * Parse a standard ETH address string to ZooBC compact format
     *
     * Converts "0x70d16C7c88..." to [0x04,0,0,0] + [20-byte hash]
     *
     * @param eth_address Standard Ethereum address (0x + 40 hex chars)
     * @return Result containing ZooBC account address bytes
     */
    static Result<std::vector<uint8_t>> ParseEthAddress(const std::string& eth_address);

    /**
     * Parse a standard BTC address string to ZooBC compact format
     *
     * Supports P2PKH (1...), P2SH (3...), and Bech32 (bc1...) formats.
     * Converts to [0x01,0,0,0] + [20-byte hash]
     *
     * @param btc_address Standard Bitcoin address
     * @return Result containing ZooBC account address bytes
     */
    static Result<std::vector<uint8_t>> ParseBtcAddress(const std::string& btc_address);

    /**
     * Get the address hash from an account address
     *
     * For compact addresses: returns the stored hash
     * For full addresses: computes the hash from pubkey
     *
     * @param account_address Full or compact account address
     * @return Address hash (20 bytes for ETH/BTC)
     */
    static std::vector<uint8_t> GetAddressHash(const std::vector<uint8_t>& account_address);

    // Extract public key from private key (Ed25519)
    static Result<std::vector<uint8_t>> ExtractPublicKey(
        const std::vector<uint8_t>& private_key);

    // Generate block seed (VRF signature of previous seed)
    // This creates a deterministic but unpredictable seed for the next block
    static Result<std::vector<uint8_t>> GenerateBlockSeed(
        const std::vector<uint8_t>& previous_seed_hash,
        const std::vector<uint8_t>& private_key);

private:
    // Type-specific verification helpers
    static Result<bool> VerifyZbcSignature(
        const std::vector<uint8_t>& payload,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& public_key);

    // ETH verification - handles both compact and full formats
    // For compact: recovers pubkey from signature, verifies hash matches
    // For full: uses stored pubkey directly
    static Result<bool> VerifyEthSignature(
        const std::vector<uint8_t>& payload,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& account_address,
        bool is_compact);

    // BTC verification - handles both compact and full formats
    // For both: extracts pubkey from signature, verifies hash matches stored
    // Note: is_compact parameter reserved for future non-compact signature handling
    static Result<bool> VerifyBtcSignature(
        const std::vector<uint8_t>& payload,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& account_address,
        [[maybe_unused]] bool is_compact);

    // Taproot (P2TR, type 9): BIP-340 schnorr over the payload, verified against the account's
    // 32-byte x-only output key. Signature is a bare 64-byte schnorr sig (no pubkey carried).
    static Result<bool> VerifyTaprootSignature(
        const std::vector<uint8_t>& payload,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& account_address);

    /**
     * Verify a Tezos (tz1) signature.
     *
     * A tz1 address is base58check(0x06a19f || blake2b-160(pubkey)), so the account carries a HASH
     * and the public key cannot be recovered from it. The key therefore travels in the signature,
     * in the same envelope Bitcoin and Ripple already use:
     *
     *     [2-byte LE pubkey length = 32] || 32-byte ed25519 pubkey || 64-byte ed25519 signature
     *
     * Both halves must hold: the signature verifies under the embedded key, AND
     * blake2b-160(embedded key) equals the address payload. Checking only the first would let
     * anyone spend from any tz1 account with a key of their own choosing.
     */
    static Result<bool> VerifyTezosSignature(
        const std::vector<uint8_t>& payload,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& account_address);

    /**
     * Cardano (type 13): the account is a REAL Cardano enterprise address, 4-byte type + 28-byte
     * blake2b-224(pubkey). Same envelope as Tezos: [2-byte LE pubkey length = 32] || pubkey ||
     * 64-byte ed25519 signature. Both halves must hold: the signature verifies under the embedded
     * key AND blake2b-224(embedded key) equals the address payload.
     */
    static Result<bool> VerifyCardanoSignature(
        const std::vector<uint8_t>& payload,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& account_address);

    // Polkadot (type 12): sr25519 (Schnorrkel) over the payload with signing context "substrate",
    // verified against the account's 32-byte AccountId. Signature is a bare 64-byte schnorrkel sig.
    static Result<bool> VerifyPolkadotSignature(
        const std::vector<uint8_t>& payload,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& account_address);

    // Helper to convert hex string to bytes
    static std::vector<uint8_t> HexToBytes(const std::string& hex);
};

}  // namespace crypto
}  // namespace zoobc

#endif  // ZOOBC_CRYPTO_SIGNATURE_H
