// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_CRYPTO_HASH_H
#define ZOOBC_CRYPTO_HASH_H

#include <cstdint>
#include <vector>
#include "zoobc/common/result.h"
#include "zoobc/common/constants.h"

namespace zoobc {
namespace crypto {

// Hash algorithms
class Hash {
public:
    // SHA3-256 hash (NIST standardized)
    static Result<std::vector<uint8_t>> SHA3_256(const std::vector<uint8_t>& data);

    // Keccak-256 hash (pre-NIST, used by Ethereum)
    static Result<std::vector<uint8_t>> Keccak256(const std::vector<uint8_t>& data);

    // SHA256 hash
    static Result<std::vector<uint8_t>> SHA256(const std::vector<uint8_t>& data);

    // RIPEMD-160 hash
    static Result<std::vector<uint8_t>> RIPEMD160(const std::vector<uint8_t>& data);

    // Double SHA256 (SHA256(SHA256(data)))
    static Result<std::vector<uint8_t>> DoubleSHA256(const std::vector<uint8_t>& data);
};

}  // namespace crypto
}  // namespace zoobc

#endif  // ZOOBC_CRYPTO_HASH_H
