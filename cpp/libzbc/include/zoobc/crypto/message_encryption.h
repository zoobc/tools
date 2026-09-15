// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_CRYPTO_MESSAGE_ENCRYPTION_H
#define ZOOBC_CRYPTO_MESSAGE_ENCRYPTION_H

#include <cstdint>
#include <vector>
#include "zoobc/common/result.h"

namespace zoobc {
namespace crypto {

/**
 * Encrypted transaction messages.
 *
 * A transaction's `message` field is normally plaintext. This adds optional
 * end-to-end encryption to the RECIPIENT: the sender encrypts to the recipient's
 * Ed25519 public key, and only the holder of the matching private key can read
 * it. Built on libsodium sealed boxes (crypto_box_seal) over the Curve25519
 * keys converted from the account's Ed25519 keys, so the sender needs no
 * keypair and leaves no sender identity in the ciphertext.
 *
 * Wire format of an encrypted message field:
 *   [4-byte magic 'Z','B','E','1'] [sealed box ciphertext]
 * The magic lets readers distinguish encrypted from plaintext messages.
 */
class MessageEncryption {
public:
    // 4-byte marker prefixing an encrypted message field.
    static constexpr uint8_t kMagic[4] = {'Z', 'B', 'E', '1'};

    // Encrypt `plaintext` to `recipient_ed25519_pubkey` (32 bytes). Returns the
    // magic-prefixed sealed ciphertext to store in the tx message field.
    static Result<std::vector<uint8_t>> Encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& recipient_ed25519_pubkey);

    // Decrypt a message field produced by Encrypt() using the recipient's
    // Ed25519 private key (the 32-byte seed). Fails if the field is not
    // encrypted (missing magic) or the key does not match.
    static Result<std::vector<uint8_t>> Decrypt(
        const std::vector<uint8_t>& message_field,
        const std::vector<uint8_t>& recipient_ed25519_privkey_seed);

    // True if `message_field` carries the encrypted-message magic prefix.
    static bool IsEncrypted(const std::vector<uint8_t>& message_field);
};

}  // namespace crypto
}  // namespace zoobc

#endif  // ZOOBC_CRYPTO_MESSAGE_ENCRYPTION_H
