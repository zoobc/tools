// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_CRYPTO_RNG_H
#define ZOOBC_CRYPTO_RNG_H

#include <cstdint>
#include <vector>
#include <string>

namespace zoobc {
namespace crypto {

// Splitmix64 PRNG - used to seed xoroshiro128+
// This is a fixed-increment version of Java 8's SplittableRandom generator
class Splitmix64 {
public:
    Splitmix64();
    explicit Splitmix64(int64_t seed);

    void Seed(int64_t seed);
    uint64_t Next();
    int64_t NextInt63();

private:
    uint64_t state_;
};

// Xoroshiro128+ pseudo-random number generator
// Used for deterministic blocksmith selection and coinbase lottery
class Xoroshiro128Plus {
public:
    Xoroshiro128Plus();

    // Seed the RNG with two 64-bit values
    void Seed(uint64_t s0, uint64_t s1);

    // Seed from a hash (32 bytes) - original method
    void SeedFromHash(const std::vector<uint8_t>& hash);

    // Seed using splitmix64 from int64 seed (matches Go implementation)
    void SeedFromInt64(int64_t seed);

    // Generate next random 64-bit number
    uint64_t Next();

    // Generate next random 63-bit non-negative integer (matches Go Int63)
    int64_t NextInt63();

    // Jump function (equivalent to 2^64 calls to Next())
    void Jump();

private:
    uint64_t state_[2];

    static uint64_t Rotl(uint64_t x, int k);
};

// RandomNumberGenerator - matches Go's RandomNumberGenerator interface
// Used for coinbase lottery winner selection
class RandomNumberGenerator {
public:
    RandomNumberGenerator();

    // Reset the RNG with a prefix and seed (matches Go Reset function)
    // Computes SHA3-256(prefix + seed), converts to int64, and seeds xoroshiro128+
    void Reset(const std::string& prefix, const std::vector<uint8_t>& seed);

    // Get next random int63 value
    int64_t Next();

private:
    Xoroshiro128Plus rng_;
};

}  // namespace crypto
}  // namespace zoobc

#endif  // ZOOBC_CRYPTO_RNG_H
