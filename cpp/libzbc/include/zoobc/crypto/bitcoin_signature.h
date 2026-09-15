// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_CRYPTO_BITCOIN_SIGNATURE_H
#define ZOOBC_CRYPTO_BITCOIN_SIGNATURE_H

#include "zoobc/crypto/signature_type.h"
#include <cstdint>

namespace zoobc {
namespace crypto {

enum class BitcoinAddressScriptType : uint8_t {
    P2PKH = 0,
    P2SH = 1,
    P2WPKH = 2,
    P2WSH = 3,
    P2TR = 4,
};

struct BitcoinDecodedAddress {
    BitcoinAddressScriptType script_type;
    std::vector<uint8_t> payload;  // 20-byte hash/program, or 32-byte witness program
};

/**
 * Bitcoin Signature Type
 *
 * Implements secp256k1 ECDSA signature scheme used by Bitcoin.
 * Uses libsecp256k1 for cryptographic operations.
 *
 * Key characteristics:
 * - Private key: 32 bytes
 * - Public key: 33 bytes (compressed) or 65 bytes (uncompressed)
 * - Signature: 64 bytes (r,s format) or up to 72 bytes (DER encoded)
 *
 * GO equivalent: common/signaturetype/bitcoin.go
 */
class BitcoinSignature : public SignatureType {
public:
    BitcoinSignature();
    ~BitcoinSignature() override;

    // Disable copy (secp256k1 context is not copyable)
    BitcoinSignature(const BitcoinSignature&) = delete;
    BitcoinSignature& operator=(const BitcoinSignature&) = delete;

    // Move is allowed
    BitcoinSignature(BitcoinSignature&& other) noexcept;
    BitcoinSignature& operator=(BitcoinSignature&& other) noexcept;

    // ==================== Type Information ====================

    SignatureTypeID GetTypeID() const override { return SignatureTypeID::Bitcoin; }
    std::string GetName() const override { return "Bitcoin"; }
    uint8_t GetAddressPrefix() const override { return AccountPrefix::Bitcoin; }

    size_t GetPublicKeySize() const override { return KeySize::SECP256K1_PUBLIC_KEY_COMPRESSED; }
    size_t GetPrivateKeySize() const override { return KeySize::SECP256K1_PRIVATE_KEY; }
    size_t GetSignatureSize() const override { return KeySize::SECP256K1_SIGNATURE; }

    // ==================== Key Generation ====================

    /**
     * Derive private key from seed using SHA256
     * Bitcoin uses SHA256 of seed as private key material
     */
    Result<std::vector<uint8_t>> GetPrivateKeyFromSeed(
        const std::string& seed) override;

    /**
     * Extract compressed public key from private key
     */
    Result<std::vector<uint8_t>> GetPublicKeyFromPrivateKey(
        const std::vector<uint8_t>& private_key) override;

    Result<std::vector<uint8_t>> GetPublicKeyFromSeed(
        const std::string& seed) override;

    /**
     * Get uncompressed public key (65 bytes)
     */
    Result<std::vector<uint8_t>> GetUncompressedPublicKey(
        const std::vector<uint8_t>& private_key);

    // ==================== Signing and Verification ====================

    /**
     * Sign using secp256k1 ECDSA
     * Returns signature in compact (r,s) format (64 bytes)
     */
    Result<std::vector<uint8_t>> Sign(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& payload) override;

    /**
     * Sign and return DER-encoded signature
     */
    Result<std::vector<uint8_t>> SignDER(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& payload);

    Result<bool> Verify(
        const std::vector<uint8_t>& public_key,
        const std::vector<uint8_t>& payload,
        const std::vector<uint8_t>& signature) override;

    /**
     * Verify DER-encoded signature
     */
    Result<bool> VerifyDER(
        const std::vector<uint8_t>& public_key,
        const std::vector<uint8_t>& payload,
        const std::vector<uint8_t>& signature);

    /**
     * Verify a BIP-340 schnorr signature (Taproot key-path spend). The account's 32-byte program IS
     * the x-only output key, so no pubkey is carried in the signature. xonly_pubkey=32, message=32,
     * signature=64. Used for ACCOUNT_TYPE_BTC_P2TR (type 9).
     */
    Result<bool> VerifySchnorr(
        const std::vector<uint8_t>& xonly_pubkey,
        const std::vector<uint8_t>& message,
        const std::vector<uint8_t>& signature) const;

    // ==================== Address Operations ====================

    /**
     * Generate Bitcoin address (Base58Check encoded)
     * Standard P2PKH address format
     */
    std::string GetAddressFromPublicKey(
        const std::string& prefix,
        const std::vector<uint8_t>& public_key) override;

    /**
     * Public key cannot be recovered from Bitcoin address
     * (address is hash of public key)
     */
    Result<std::vector<uint8_t>> GetPublicKeyFromAddress(
        const std::string& address) override;

    std::vector<uint8_t> GetAccountAddress(
        const std::vector<uint8_t>& public_key) override;

    // ==================== Bitcoin-Specific Operations ====================

    /**
     * Compute HASH160 (RIPEMD160(SHA256(data)))
     * Used for Bitcoin address generation
     */
    static Result<std::vector<uint8_t>> Hash160(const std::vector<uint8_t>& data);

    /**
     * Encode bytes as Base58Check
     */
    static std::string Base58CheckEncode(const std::vector<uint8_t>& data);

    /**
     * Decode Base58Check string
     */
    static Result<std::vector<uint8_t>> Base58CheckDecode(const std::string& encoded);

    /**
     * Check if private key is valid for secp256k1
     */
    bool IsValidPrivateKey(const std::vector<uint8_t>& private_key) const;

    // ==================== Transaction Parsing ====================

    /**
     * Parsed Bitcoin transaction structure
     */
    struct ParsedTransaction {
        uint32_t version;
        struct TxInput {
            std::vector<uint8_t> prev_txid;  // 32 bytes, reversed
            uint32_t prev_vout;
            std::vector<uint8_t> script_sig;
            uint32_t sequence;
        };
        struct TxOutput {
            int64_t value;  // In satoshis
            std::vector<uint8_t> script_pubkey;
        };
        std::vector<TxInput> inputs;
        std::vector<TxOutput> outputs;
        uint32_t locktime;
        bool has_witness;
    };

    /**
     * Parse raw Bitcoin transaction
     * @param raw_tx Raw transaction bytes
     * @return Parsed transaction structure
     */
    static Result<ParsedTransaction> ParseSignedTransaction(const std::vector<uint8_t>& raw_tx);

    /**
     * Decode Bitcoin address to pubkey hash
     * Supports P2PKH (1...) and P2SH (3...) addresses
     * @param address Base58Check encoded address
     * @return 20-byte pubkey hash (or script hash for P2SH)
     */
    static Result<std::vector<uint8_t>> DecodeAddress(const std::string& address);

    /**
     * Decode Bitcoin address and preserve script type (ZooBC extension)
     * Supports Base58Check (P2PKH/P2SH), Bech32 (v0 P2WPKH/P2WSH), and Bech32m (v1 P2TR).
     */
    static Result<BitcoinDecodedAddress> DecodeAddressWithType(const std::string& address);

private:
    void* ctx_;  // secp256k1_context* (opaque pointer for header independence)

    void InitContext();
    void DestroyContext();
};

}  // namespace crypto
}  // namespace zoobc

#endif  // ZOOBC_CRYPTO_BITCOIN_SIGNATURE_H
