// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_CRYPTO_ETHEREUM_SIGNATURE_H
#define ZOOBC_CRYPTO_ETHEREUM_SIGNATURE_H

#include "zoobc/crypto/signature_type.h"
#include "zoobc/crypto/bitcoin_signature.h"

namespace zoobc {
namespace crypto {

/**
 * Ethereum Signature Type
 *
 * Implements secp256k1 ECDSA signature scheme used by Ethereum.
 * Similar to Bitcoin but uses Keccak-256 for address generation.
 *
 * Key characteristics:
 * - Private key: 32 bytes
 * - Public key: 64 bytes (uncompressed without prefix) or 65 bytes (with 0x04 prefix)
 * - Signature: 65 bytes (r,s,v format with recovery ID)
 * - Address: 20 bytes (last 20 bytes of Keccak-256 of public key)
 *
 * GO equivalent: common/signaturetype/ethereum.go
 */
class EthereumSignature : public SignatureType {
public:
    EthereumSignature();
    ~EthereumSignature() override;

    // Disable copy
    EthereumSignature(const EthereumSignature&) = delete;
    EthereumSignature& operator=(const EthereumSignature&) = delete;

    // Move is allowed
    EthereumSignature(EthereumSignature&& other) noexcept;
    EthereumSignature& operator=(EthereumSignature&& other) noexcept;

    // ==================== Type Information ====================

    SignatureTypeID GetTypeID() const override { return SignatureTypeID::Ethereum; }
    std::string GetName() const override { return "Ethereum"; }
    uint8_t GetAddressPrefix() const override { return AccountPrefix::Ethereum; }

    // Ethereum uses uncompressed public keys (64 bytes without 0x04 prefix)
    size_t GetPublicKeySize() const override { return 64; }
    size_t GetPrivateKeySize() const override { return KeySize::SECP256K1_PRIVATE_KEY; }
    // Ethereum signatures include recovery ID (r,s,v = 65 bytes)
    size_t GetSignatureSize() const override { return 65; }

    // ==================== Key Generation ====================

    /**
     * Derive private key from seed using Keccak-256
     */
    Result<std::vector<uint8_t>> GetPrivateKeyFromSeed(
        const std::string& seed) override;

    /**
     * Get uncompressed public key (64 bytes, no 0x04 prefix)
     */
    Result<std::vector<uint8_t>> GetPublicKeyFromPrivateKey(
        const std::vector<uint8_t>& private_key) override;

    Result<std::vector<uint8_t>> GetPublicKeyFromSeed(
        const std::string& seed) override;

    // ==================== Signing and Verification ====================

    /**
     * Sign using secp256k1 ECDSA with recovery ID
     * Returns signature in (r,s,v) format (65 bytes)
     */
    Result<std::vector<uint8_t>> Sign(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& payload) override;

    Result<bool> Verify(
        const std::vector<uint8_t>& public_key,
        const std::vector<uint8_t>& payload,
        const std::vector<uint8_t>& signature) override;

    /**
     * Recover public key from signature
     * @param payload The signed data (or its hash)
     * @param signature The signature (65 bytes with recovery ID)
     * @return Recovered public key
     */
    Result<std::vector<uint8_t>> RecoverPublicKey(
        const std::vector<uint8_t>& payload,
        const std::vector<uint8_t>& signature);

    // ==================== Address Operations ====================

    /**
     * Generate Ethereum address (0x-prefixed hex)
     * Address is last 20 bytes of Keccak-256(public_key)
     */
    std::string GetAddressFromPublicKey(
        const std::string& prefix,
        const std::vector<uint8_t>& public_key) override;

    /**
     * Public key cannot be recovered from Ethereum address
     * (address is hash of public key)
     */
    Result<std::vector<uint8_t>> GetPublicKeyFromAddress(
        const std::string& address) override;

    std::vector<uint8_t> GetAccountAddress(
        const std::vector<uint8_t>& public_key) override;

    // ==================== Ethereum-Specific Operations ====================

    /**
     * Compute Keccak-256 hash
     * Note: Ethereum uses Keccak-256, not standard SHA3-256
     */
    static Result<std::vector<uint8_t>> Keccak256(const std::vector<uint8_t>& data);

    /**
     * Get 20-byte Ethereum address from public key
     * @param public_key 64-byte uncompressed public key (without 0x04 prefix)
     * @return 20-byte address
     */
    static std::vector<uint8_t> GetAddress20(const std::vector<uint8_t>& public_key);

    /**
     * Convert address to EIP-55 checksummed format
     */
    static std::string ToChecksumAddress(const std::vector<uint8_t>& address);

    /**
     * Verify EIP-55 checksum
     */
    static bool VerifyChecksumAddress(const std::string& address);

    /**
     * Sign with EIP-191 prefix (personal_sign)
     */
    Result<std::vector<uint8_t>> PersonalSign(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& message);

    /**
     * Check if private key is valid for secp256k1
     */
    bool IsValidPrivateKey(const std::vector<uint8_t>& private_key) const;

    // ==================== Transaction Parsing ====================

    /**
     * Parsed Ethereum transaction structure
     */
    struct ParsedTransaction {
        uint64_t nonce;
        uint64_t gas_price;
        uint64_t gas_limit;
        std::vector<uint8_t> to;        // 20 bytes, or empty for contract creation
        uint64_t value;                  // In wei (TRUNCATED to 64 bits — legacy; use value_be for amounts)
        std::vector<uint8_t> value_be;   // Full-precision big-endian wei (no 64-bit cap)
        std::vector<uint8_t> data;       // Input data
        uint64_t chain_id;               // EIP-155 chain ID (0 for legacy)
        std::vector<uint8_t> signature;  // 65 bytes (r, s, v)
        // Typed-transaction support (EIP-2718): 0 = legacy/EIP-155, 1 = EIP-2930,
        // 2 = EIP-1559 (MetaMask's default). For typed txs gas_price holds maxFeePerGas.
        int tx_type = 0;
        uint64_t max_priority_fee_per_gas = 0;  // EIP-1559 only
    };

    /**
     * Convert a big-endian wei amount to ZooBC atomic units. 1 ZBC = 1e8 atomic
     * = 1e18 wei, so this divides by 1e10 at full precision (NO 64-bit truncation:
     * a uint64 caps at ~18.4 ZBC and silently wraps). Returns an error if the
     * resulting atomic amount would exceed INT64_MAX (caller rejects, never wraps).
     * Used identically by the node validator (consensus) and the eth-rpc adapter
     * so both compute the same SendZBC amount.
     */
    static Result<int64_t> WeiToAtomicZbc(const std::vector<uint8_t>& wei_be);

    /**
     * Parse RLP-encoded signed Ethereum transaction
     * Supports both legacy and EIP-155 transactions
     * @param raw_tx RLP-encoded signed transaction bytes
     * @return Parsed transaction structure
     */
    static Result<ParsedTransaction> ParseSignedTransaction(const std::vector<uint8_t>& raw_tx);

    /**
     * Recover sender address from signed transaction
     * @param raw_tx RLP-encoded signed transaction bytes
     * @return 20-byte sender address
     */
    static Result<std::vector<uint8_t>> RecoverSender(const std::vector<uint8_t>& raw_tx);

    /**
     * The 64-byte uncompressed public key (no 0x04 prefix) that signed a raw Ethereum transaction.
     * RecoverSender is keccak-256 of this, last 20 bytes. Exposed so the node can tell a stranger
     * the key behind an Ethereum-format account that has sent a MetaMask transaction.
     */
    static Result<std::vector<uint8_t>> RecoverPublicKeyFromRawTx(const std::vector<uint8_t>& raw_tx);

private:
    void* ctx_;  // secp256k1_context* (opaque pointer)

    void InitContext();
    void DestroyContext();
};

}  // namespace crypto
}  // namespace zoobc

#endif  // ZOOBC_CRYPTO_ETHEREUM_SIGNATURE_H
