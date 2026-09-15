// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/crypto/rng.h"
#include "zoobc/crypto/hash.h"
#include <cstring>

namespace zoobc {
namespace crypto {

// ============================================================================
// Splitmix64 implementation
// ============================================================================

Splitmix64::Splitmix64() : state_(0) {}

Splitmix64::Splitmix64(int64_t seed) : state_(static_cast<uint64_t>(seed)) {}

void Splitmix64::Seed(int64_t seed) {
    state_ = static_cast<uint64_t>(seed);
}

uint64_t Splitmix64::Next() {
    state_ += 0x9E3779B97F4A7C15ULL;
    uint64_t z = state_;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

int64_t Splitmix64::NextInt63() {
    return static_cast<int64_t>(Next() >> 1);
}

// ============================================================================
// Xoroshiro128Plus implementation
// ============================================================================

Xoroshiro128Plus::Xoroshiro128Plus() {
    state_[0] = 0;
    state_[1] = 0;
}

void Xoroshiro128Plus::Seed(uint64_t s0, uint64_t s1) {
    state_[0] = s0;
    state_[1] = s1;
}

void Xoroshiro128Plus::SeedFromHash(const std::vector<uint8_t>& hash) {
    if (hash.size() >= 16) {
        uint64_t s0, s1;
        std::memcpy(&s0, hash.data(), 8);
        std::memcpy(&s1, hash.data() + 8, 8);
        Seed(s0, s1);
    } else {
        Seed(0, 0);
    }
}

void Xoroshiro128Plus::SeedFromInt64(int64_t seed) {
    // Use splitmix64 to generate s0 and s1 (matches Go implementation)
    Splitmix64 sm(seed);
    state_[0] = sm.Next();
    state_[1] = sm.Next();
}

uint64_t Xoroshiro128Plus::Next() {
    uint64_t s0 = state_[0];
    uint64_t s1 = state_[1];
    uint64_t result = s0 + s1;

    s1 ^= s0;
    state_[0] = Rotl(s0, 24) ^ s1 ^ (s1 << 16);
    state_[1] = Rotl(s1, 37);

    return result;
}

int64_t Xoroshiro128Plus::NextInt63() {
    return static_cast<int64_t>(Next() >> 1);
}

void Xoroshiro128Plus::Jump() {
    static const uint64_t JUMP[] = {0xdf900294d8f554a5, 0x170865df4b3201fc};

    uint64_t s0 = 0;
    uint64_t s1 = 0;

    for (size_t i = 0; i < sizeof(JUMP) / sizeof(*JUMP); i++) {
        for (int b = 0; b < 64; b++) {
            if (JUMP[i] & UINT64_C(1) << b) {
                s0 ^= state_[0];
                s1 ^= state_[1];
            }
            Next();
        }
    }

    state_[0] = s0;
    state_[1] = s1;
}

uint64_t Xoroshiro128Plus::Rotl(uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

// ============================================================================
// RandomNumberGenerator implementation
// ============================================================================

RandomNumberGenerator::RandomNumberGenerator() {}

void RandomNumberGenerator::Reset(const std::string& prefix, const std::vector<uint8_t>& seed) {
    // Concatenate prefix + seed
    std::vector<uint8_t> buffer;
    buffer.insert(buffer.end(), prefix.begin(), prefix.end());
    buffer.insert(buffer.end(), seed.begin(), seed.end());

    // Hash with SHA3-256
    auto hash_result = Hash::SHA3_256(buffer);
    if (hash_result.IsErr()) {
        rng_.Seed(0, 0);
        return;
    }
    auto hash = hash_result.Value();

    // Convert first 8 bytes of hash to int64 (big-endian to match Go's big.Int)
    // Actually, Go's SetBytes creates a big-endian number, then Int64() returns it
    // But we need to be careful here. Let me check the Go code again...
    // In Go: randSeedBigInt := new(big.Int).SetBytes(randSeedHash[:])
    //        r.rand.Seed(randSeedBigInt.Int64())
    // big.Int.SetBytes interprets the bytes as big-endian unsigned integer
    // Int64() returns the low 64 bits as int64
    // So we need to interpret the full 32-byte hash as big-endian and take low 64 bits
    // This is essentially just the last 8 bytes in big-endian order

    int64_t seed_value = 0;
    if (hash.size() >= 8) {
        // Take last 8 bytes (low 64 bits of big-endian number)
        // and convert from big-endian to host order
        for (int i = 0; i < 8; i++) {
            seed_value = (seed_value << 8) | hash[hash.size() - 8 + i];
        }
    }

    // Seed the xoroshiro128+ using splitmix64
    rng_.SeedFromInt64(seed_value);
}

int64_t RandomNumberGenerator::Next() {
    return rng_.NextInt63();
}

}  // namespace crypto
}  // namespace zoobc
