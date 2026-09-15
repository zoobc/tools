// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#pragma once

#include <array>
#include <string>
#include <vector>
#include <cstdint>
#include "zoobc/common/result.h"

namespace zoobc {
namespace crypto {

/**
 * SLIP-10 implementation for Ed25519 HD wallet key derivation
 * Based on: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
 *
 * ZooBC uses BIP-44 path format: m/44'/883'/account'
 * - 883 is the ZooBC coin type
 * - All indices are hardened (Ed25519 doesn't support non-hardened derivation)
 */
class SLIP10 {
public:
    static constexpr uint32_t HARDENED_OFFSET = 0x80000000;
    static constexpr uint32_t ZOOBC_COIN_TYPE = 883;
    static constexpr const char* ZOOBC_PRIMARY_PATH = "m/44'/883'/0'";
    static constexpr const char* ED25519_SEED_MODIFIER = "ed25519 seed";

    struct Key {
        std::array<uint8_t, 32> key;
        std::array<uint8_t, 32> chain_code;

        // Get Ed25519 public key from private key
        std::vector<uint8_t> GetPublicKey() const;

        // Derive child key at index i (must be hardened for Ed25519)
        Result<Key> Derive(uint32_t index) const;
    };

    /**
     * Generate master key from seed
     * @param seed Random seed bytes (typically from BIP-39 mnemonic)
     * @return Master key with chain code
     */
    static Result<Key> NewMasterKey(const std::vector<uint8_t>& seed);

    /**
     * Derive key for a BIP-44 path
     * @param path Derivation path (e.g., "m/44'/883'/0'")
     * @param seed Random seed bytes
     * @return Derived key
     */
    static Result<Key> DeriveForPath(const std::string& path, const std::vector<uint8_t>& seed);

    /**
     * Derive ZooBC account key
     * @param account_index Account index (0 for primary account)
     * @param seed Random seed bytes
     * @return Account key
     */
    static Result<Key> DeriveZoobcAccount(uint32_t account_index, const std::vector<uint8_t>& seed);

    /**
     * Validate BIP-44 path format
     * @param path Path string to validate
     * @return true if valid
     */
    static bool IsValidPath(const std::string& path);

private:
    /**
     * Parse path segment (e.g., "44'" -> 44 + HARDENED_OFFSET)
     */
    static Result<uint32_t> ParsePathSegment(const std::string& segment);
};

/**
 * BIP-39 mnemonic support
 */
class BIP39 {
public:
    /**
     * Generate seed from mnemonic phrase and optional password
     * @param mnemonic BIP-39 mnemonic phrase (12 or 24 words)
     * @param password Optional password (empty string if none)
     * @return 64-byte seed for SLIP-10 derivation
     */
    static Result<std::vector<uint8_t>> MnemonicToSeed(
        const std::string& mnemonic,
        const std::string& password = ""
    );

    /**
     * Generate random mnemonic phrase
     * @param word_count Number of words (12, 15, 18, 21, or 24)
     * @return BIP-39 mnemonic phrase
     */
    static Result<std::string> GenerateMnemonic(int word_count = 24);

    /**
     * Validate mnemonic phrase
     * @param mnemonic Phrase to validate
     * @return true if valid
     */
    static bool ValidateMnemonic(const std::string& mnemonic);
};

/**
 * ZooBC address encoding/decoding
 */
class ZoobcAddress {
public:
    /**
     * Encode public key to ZooBC address format
     * Format: Base32(pubkey[32] + checksum[1]) with underscores every 8 chars
     * Checksum: Sum of all public key bytes (mod 256)
     * Example: ZBC_7XVBQ6HB_XIHS5IM6_ZBYXWICI_AMCCFIBX_DJUTT3YE_OFRXHE7E_RMQR3E4S
     *
     * @param public_key 32-byte Ed25519 public key
     * @param prefix "ZBC" for wallet, "ZNK" for node
     * @return Base32-encoded address with prefix
     */
    static std::string Encode(const std::vector<uint8_t>& public_key, const std::string& prefix = "ZBC");

    /**
     * Decode ZooBC address to public key
     * @param address Base64-encoded address (with or without prefix)
     * @return 32-byte public key (if checksum valid)
     */
    static Result<std::vector<uint8_t>> Decode(const std::string& address);

    /**
     * True if `address` is a formatted ZooBC address with the given 3-char prefix
     * (e.g. "ZBC", "ZNK", "ZBS"), tolerant of case and of '_' OR '-' separators.
     * Use this instead of `len==66 && substr(0,4)=="ZBC_"` so dash/lowercase forms
     * are recognized before dispatching to Decode().
     */
    static bool IsFormatted(const std::string& address, const std::string& prefix);

    /**
     * Validate address checksum
     * @param address Address to validate
     * @return true if checksum is valid
     */
    static bool ValidateChecksum(const std::string& address);

    /**
     * Legacy 1-byte additive sum of the key bytes. NOT the address checksum: ZooBC addresses carry
     * the first 3 bytes of SHA3-256(public_key ‖ prefix), computed inside Encode() and checked by
     * Decode(). Unused by the address format; kept only so old callers still link.
     * @deprecated Use Encode()/Decode()/ValidateChecksum().
     */
    static uint8_t CalculateChecksum(const std::vector<uint8_t>& public_key);
};

}  // namespace crypto
}  // namespace zoobc
