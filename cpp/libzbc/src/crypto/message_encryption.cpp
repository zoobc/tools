// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/crypto/message_encryption.h"

#include <sodium.h>
#include <cstring>

namespace zoobc {
namespace crypto {

constexpr uint8_t MessageEncryption::kMagic[4];

bool MessageEncryption::IsEncrypted(const std::vector<uint8_t>& message_field) {
    return message_field.size() >= sizeof(kMagic) &&
           std::memcmp(message_field.data(), kMagic, sizeof(kMagic)) == 0;
}

Result<std::vector<uint8_t>> MessageEncryption::Encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& recipient_ed25519_pubkey) {

    if (recipient_ed25519_pubkey.size() != crypto_sign_ed25519_PUBLICKEYBYTES) {
        return ZOOBC_ERROR(ErrorCode::InvalidPublicKey,
                           "Recipient Ed25519 public key must be 32 bytes");
    }

    // Convert the recipient's Ed25519 public key to a Curve25519 public key.
    unsigned char curve_pk[crypto_box_PUBLICKEYBYTES];
    if (crypto_sign_ed25519_pk_to_curve25519(curve_pk, recipient_ed25519_pubkey.data()) != 0) {
        return ZOOBC_ERROR(ErrorCode::CryptoError,
                           "Failed to convert recipient key to Curve25519");
    }

    // Anonymous sealed box: ciphertext = sealed(plaintext) -> only the recipient
    // (holder of the matching secret key) can open it.
    std::vector<uint8_t> sealed(plaintext.size() + crypto_box_SEALBYTES);
    if (crypto_box_seal(sealed.data(), plaintext.data(), plaintext.size(), curve_pk) != 0) {
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Sealed-box encryption failed");
    }

    std::vector<uint8_t> out;
    out.reserve(sizeof(kMagic) + sealed.size());
    out.insert(out.end(), kMagic, kMagic + sizeof(kMagic));
    out.insert(out.end(), sealed.begin(), sealed.end());
    return out;
}

Result<std::vector<uint8_t>> MessageEncryption::Decrypt(
    const std::vector<uint8_t>& message_field,
    const std::vector<uint8_t>& recipient_ed25519_privkey_seed) {

    if (!IsEncrypted(message_field)) {
        return ZOOBC_ERROR(ErrorCode::ValidationError,
                           "Message is not encrypted (missing magic)");
    }
    if (recipient_ed25519_privkey_seed.size() != crypto_sign_ed25519_SEEDBYTES) {
        return ZOOBC_ERROR(ErrorCode::InvalidArgument,
                           "Recipient private key seed must be 32 bytes");
    }

    // Rebuild the recipient's Ed25519 keypair from the seed, then derive the
    // Curve25519 keypair needed to open the sealed box.
    unsigned char ed_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char ed_sk[crypto_sign_ed25519_SECRETKEYBYTES];
    if (crypto_sign_ed25519_seed_keypair(ed_pk, ed_sk,
                                         recipient_ed25519_privkey_seed.data()) != 0) {
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Failed to derive keypair from seed");
    }
    unsigned char curve_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char curve_sk[crypto_box_SECRETKEYBYTES];
    if (crypto_sign_ed25519_pk_to_curve25519(curve_pk, ed_pk) != 0 ||
        crypto_sign_ed25519_sk_to_curve25519(curve_sk, ed_sk) != 0) {
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Failed to convert keys to Curve25519");
    }

    const uint8_t* sealed = message_field.data() + sizeof(kMagic);
    size_t sealed_len = message_field.size() - sizeof(kMagic);
    if (sealed_len < crypto_box_SEALBYTES) {
        return ZOOBC_ERROR(ErrorCode::ValidationError, "Encrypted message too short");
    }

    std::vector<uint8_t> plaintext(sealed_len - crypto_box_SEALBYTES);
    if (crypto_box_seal_open(plaintext.data(), sealed, sealed_len, curve_pk, curve_sk) != 0) {
        return ZOOBC_ERROR(ErrorCode::CryptoError,
                           "Decryption failed (wrong key or corrupted message)");
    }
    return plaintext;
}

}  // namespace crypto
}  // namespace zoobc
