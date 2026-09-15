// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#pragma once

#include <vector>
#include <cstdint>
#include <string>

namespace zoobc {
namespace crypto {

/**
 * Reed-Solomon error correction for ZooBC addresses
 *
 * Implements RS encoding compatible with original ZooBC format:
 * - Input: 32-byte public key
 * - Output: 40-byte data (32 bytes + 8-byte checksum)
 * - Base32 encoded to 64 characters
 *
 * Format: ZBC_XXXXXXXX_XXXXXXXX_... (8 groups of 8 chars)
 *         ZNK_XXXXXXXX_XXXXXXXX_... (for node addresses)
 */
class ReedSolomon {
public:
    /**
     * Encode data with Reed-Solomon error correction
     * Adds 8-byte checksum to input data
     *
     * @param data Input data (32 bytes for public key)
     * @return Encoded data with checksum (40 bytes)
     */
    static std::vector<uint8_t> Encode(const std::vector<uint8_t>& data);

    /**
     * Decode and verify Reed-Solomon encoded data
     *
     * @param encoded_data Data with checksum (40 bytes)
     * @return Original data if valid, empty vector if checksum failed
     */
    static std::vector<uint8_t> Decode(const std::vector<uint8_t>& encoded_data);

    /**
     * Verify Reed-Solomon checksum
     *
     * @param encoded_data Data with checksum to verify
     * @return true if checksum is valid
     */
    static bool Verify(const std::vector<uint8_t>& encoded_data);

private:
    // GF(2^8) Galois Field operations
    static constexpr int GF_SIZE = 256;
    static constexpr int CHECKSUM_SIZE = 8;

    // Generator polynomial coefficients for RS(40,32)
    static const std::vector<uint8_t> generator_poly_;

    // GF(2^8) multiplication
    static uint8_t gf_mul(uint8_t a, uint8_t b);

    // GF(2^8) division
    static uint8_t gf_div(uint8_t a, uint8_t b);

    // GF(2^8) power
    static uint8_t gf_pow(uint8_t x, int power);

    // GF(2^8) logarithm tables (for faster multiplication)
    static const uint8_t gf_log_[GF_SIZE];
    static const uint8_t gf_exp_[GF_SIZE];

    // Calculate Reed-Solomon checksum
    static std::vector<uint8_t> calculate_checksum(const std::vector<uint8_t>& data);
};

} // namespace crypto
} // namespace zoobc
