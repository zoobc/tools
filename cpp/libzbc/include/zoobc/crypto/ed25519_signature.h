// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_CRYPTO_ED25519_SIGNATURE_H
#define ZOOBC_CRYPTO_ED25519_SIGNATURE_H

#include "zoobc/crypto/signature_type.h"
#include "zoobc/crypto/signature.h"

namespace zoobc {
namespace crypto {

/**
 * Ed25519 Signature Type
 *
 * Default ZooBC signature scheme using libsodium's Ed25519 implementation.
 * Provides 128-bit security with 32-byte keys and 64-byte signatures.
 *
 * GO equivalent: common/signaturetype/ed25519.go
 */
class Ed25519Signature : public SignatureType {
public:
    Ed25519Signature() = default;
    ~Ed25519Signature() override = default;

    // ==================== Type Information ====================

    SignatureTypeID GetTypeID() const override { return SignatureTypeID::Ed25519; }
    std::string GetName() const override { return "Ed25519"; }
    uint8_t GetAddressPrefix() const override { return AccountPrefix::ZBC; }

    size_t GetPublicKeySize() const override { return KeySize::ED25519_PUBLIC_KEY; }
    size_t GetPrivateKeySize() const override { return KeySize::ED25519_PRIVATE_KEY; }
    size_t GetSignatureSize() const override { return KeySize::ED25519_SIGNATURE; }

    // ==================== Key Generation ====================

    Result<std::vector<uint8_t>> GetPrivateKeyFromSeed(
        const std::string& seed) override;

    Result<std::vector<uint8_t>> GetPublicKeyFromPrivateKey(
        const std::vector<uint8_t>& private_key) override;

    Result<std::vector<uint8_t>> GetPublicKeyFromSeed(
        const std::string& seed) override;

    // ==================== Signing and Verification ====================

    Result<std::vector<uint8_t>> Sign(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& payload) override;

    Result<bool> Verify(
        const std::vector<uint8_t>& public_key,
        const std::vector<uint8_t>& payload,
        const std::vector<uint8_t>& signature) override;

    // ==================== Address Operations ====================

    std::string GetAddressFromPublicKey(
        const std::string& prefix,
        const std::vector<uint8_t>& public_key) override;

    Result<std::vector<uint8_t>> GetPublicKeyFromAddress(
        const std::string& address) override;

    std::vector<uint8_t> GetAccountAddress(
        const std::vector<uint8_t>& public_key) override;
};

}  // namespace crypto
}  // namespace zoobc

#endif  // ZOOBC_CRYPTO_ED25519_SIGNATURE_H
