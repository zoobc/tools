// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_CRYPTO_SIGNATURE_TYPE_H
#define ZOOBC_CRYPTO_SIGNATURE_TYPE_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include "zoobc/common/result.h"

namespace zoobc {
namespace crypto {

/**
 * Signature Type ID
 *
 * Identifies the cryptographic signature scheme used.
 * The first byte of account addresses encodes this type.
 */
enum class SignatureTypeID : int32_t {
    Ed25519 = 0,      // ZBC default (libsodium)
    Bitcoin = 1,      // secp256k1 (libsecp256k1)
    Ethereum = 2,     // secp256k1 with Keccak256 addresses
    EstoniaEID = 3    // Estonian eID signature
};

/**
 * Account Type Prefixes
 *
 * First byte of account addresses identifies the signature type.
 */
namespace AccountPrefix {
    constexpr uint8_t ZBC = 0x00;
    constexpr uint8_t Bitcoin = 0x01;
    constexpr uint8_t Ethereum = 0x02;
    constexpr uint8_t EstoniaEID = 0x03;
}

/**
 * Key Sizes
 */
namespace KeySize {
    // Ed25519
    constexpr size_t ED25519_PUBLIC_KEY = 32;
    constexpr size_t ED25519_PRIVATE_KEY = 64;
    constexpr size_t ED25519_SEED = 32;
    constexpr size_t ED25519_SIGNATURE = 64;

    // secp256k1 (Bitcoin/Ethereum)
    constexpr size_t SECP256K1_PRIVATE_KEY = 32;
    constexpr size_t SECP256K1_PUBLIC_KEY_COMPRESSED = 33;
    constexpr size_t SECP256K1_PUBLIC_KEY_UNCOMPRESSED = 65;
    constexpr size_t SECP256K1_SIGNATURE = 64;  // r,s format
    constexpr size_t SECP256K1_SIGNATURE_DER_MAX = 72;
}

/**
 * SignatureType Interface
 *
 * Abstract base class for signature implementations.
 * Each signature type provides key generation, signing, and verification.
 *
 * GO equivalent: common/signaturetype/signatureType.go
 */
class SignatureType {
public:
    virtual ~SignatureType() = default;

    // ==================== Type Information ====================

    /**
     * Get the signature type identifier
     */
    virtual SignatureTypeID GetTypeID() const = 0;

    /**
     * Get human-readable name
     */
    virtual std::string GetName() const = 0;

    /**
     * Get the account address prefix byte
     */
    virtual uint8_t GetAddressPrefix() const = 0;

    /**
     * Get expected public key size in bytes
     */
    virtual size_t GetPublicKeySize() const = 0;

    /**
     * Get expected private key size in bytes
     */
    virtual size_t GetPrivateKeySize() const = 0;

    /**
     * Get expected signature size in bytes
     */
    virtual size_t GetSignatureSize() const = 0;

    // ==================== Key Generation ====================

    /**
     * Derive private key from seed phrase
     * @param seed The seed phrase or mnemonic
     * @return Private key bytes
     */
    virtual Result<std::vector<uint8_t>> GetPrivateKeyFromSeed(
        const std::string& seed) = 0;

    /**
     * Extract public key from private key
     * @param private_key The private key
     * @return Public key bytes
     */
    virtual Result<std::vector<uint8_t>> GetPublicKeyFromPrivateKey(
        const std::vector<uint8_t>& private_key) = 0;

    /**
     * Derive public key directly from seed
     * @param seed The seed phrase or mnemonic
     * @return Public key bytes
     */
    virtual Result<std::vector<uint8_t>> GetPublicKeyFromSeed(
        const std::string& seed) = 0;

    // ==================== Signing and Verification ====================

    /**
     * Sign a payload
     * @param private_key The signing private key
     * @param payload The data to sign
     * @return Signature bytes
     */
    virtual Result<std::vector<uint8_t>> Sign(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& payload) = 0;

    /**
     * Verify a signature
     * @param public_key The signer's public key
     * @param payload The signed data
     * @param signature The signature to verify
     * @return true if signature is valid
     */
    virtual Result<bool> Verify(
        const std::vector<uint8_t>& public_key,
        const std::vector<uint8_t>& payload,
        const std::vector<uint8_t>& signature) = 0;

    // ==================== Address Operations ====================

    /**
     * Generate address from public key
     * @param prefix Address prefix (e.g., "ZBC", "1", "0x")
     * @param public_key The public key
     * @return Address string
     */
    virtual std::string GetAddressFromPublicKey(
        const std::string& prefix,
        const std::vector<uint8_t>& public_key) = 0;

    /**
     * Extract public key from address
     * Note: Not all address formats support this (e.g., Ethereum hashes the key)
     * @param address The address string
     * @return Public key bytes (may be empty if not recoverable)
     */
    virtual Result<std::vector<uint8_t>> GetPublicKeyFromAddress(
        const std::string& address) = 0;

    /**
     * Generate full account address (with prefix byte)
     * @param public_key The public key
     * @return Account address with type prefix
     */
    virtual std::vector<uint8_t> GetAccountAddress(
        const std::vector<uint8_t>& public_key) = 0;
};

/**
 * Signature Type Factory
 *
 * Creates signature type implementations based on type ID or account address.
 */
class SignatureTypeFactory {
public:
    /**
     * Create signature type by ID
     * @param type The signature type ID
     * @return Signature type instance or nullptr if unsupported
     */
    static std::unique_ptr<SignatureType> Create(SignatureTypeID type);

    /**
     * Create signature type from account address
     * Uses the first byte (type prefix) to determine type
     * @param address Account address bytes
     * @return Signature type instance or nullptr if invalid
     */
    static std::unique_ptr<SignatureType> CreateFromAccountAddress(
        const std::vector<uint8_t>& address);

    /**
     * Get signature type ID from account address prefix
     * @param prefix First byte of account address
     * @return Signature type ID
     */
    static SignatureTypeID GetTypeFromPrefix(uint8_t prefix);

    /**
     * Check if a signature type is supported
     * @param type The signature type ID
     * @return true if supported
     */
    static bool IsSupported(SignatureTypeID type);

    /**
     * Get list of all supported signature types
     */
    static std::vector<SignatureTypeID> GetSupportedTypes();
};

}  // namespace crypto
}  // namespace zoobc

#endif  // ZOOBC_CRYPTO_SIGNATURE_TYPE_H
