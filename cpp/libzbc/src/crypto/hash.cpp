// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/crypto/hash.h"
#include <openssl/evp.h>
#include <cstdint>
#include <cstring>

namespace zoobc {
namespace crypto {

namespace {

// ---------------------------------------------------------------------------
// Self-contained Keccak-256 (Ethereum's pre-NIST SHA3 variant).
//
// OpenSSL 3.x does not expose the original "KECCAK-256" algorithm in its
// default provider (it provides NIST SHA3-256, which uses a different padding
// byte), so EVP_MD_fetch(..., "KECCAK-256", ...) returns null on stock builds
// and all Ethereum address/signature handling fails. Keccak-256 and SHA3-256
// share the Keccak-f[1600] permutation and differ only in the domain-suffix
// padding (0x01 for Keccak, 0x06 for SHA3-256), so we implement it directly.
//
// Lane XOR aliases the 64-bit state as bytes, which assumes a little-endian
// host; that matches the x86_64 targets this node runs on.
// ---------------------------------------------------------------------------

constexpr uint64_t kKeccakRC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

constexpr int kKeccakRotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};

constexpr int kKeccakPiln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

inline uint64_t Rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

void KeccakF1600(uint64_t st[25]) {
    for (int round = 0; round < 24; ++round) {
        uint64_t bc[5];

        // Theta
        for (int i = 0; i < 5; ++i) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        for (int i = 0; i < 5; ++i) {
            uint64_t t = bc[(i + 4) % 5] ^ Rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) {
                st[j + i] ^= t;
            }
        }

        // Rho and Pi
        uint64_t t = st[1];
        for (int i = 0; i < 24; ++i) {
            int j = kKeccakPiln[i];
            uint64_t tmp = st[j];
            st[j] = Rotl64(t, kKeccakRotc[i]);
            t = tmp;
        }

        // Chi
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; ++i) {
                bc[i] = st[j + i];
            }
            for (int i = 0; i < 5; ++i) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        // Iota
        st[0] ^= kKeccakRC[round];
    }
}

// Keccak-256: rate = 136 bytes (1088 bits), capacity = 512 bits, output = 32 bytes.
std::vector<uint8_t> Keccak256Raw(const uint8_t* in, size_t inlen) {
    constexpr size_t kRate = 136;
    uint64_t st[25] = {0};
    auto* state_bytes = reinterpret_cast<uint8_t*>(st);

    size_t offset = 0;
    while (inlen >= kRate) {
        for (size_t k = 0; k < kRate; ++k) {
            state_bytes[k] ^= in[offset + k];
        }
        KeccakF1600(st);
        offset += kRate;
        inlen -= kRate;
    }

    // Final partial block with pad10*1 padding (Keccak suffix 0x01).
    uint8_t block[kRate] = {0};
    for (size_t k = 0; k < inlen; ++k) {
        block[k] = in[offset + k];
    }
    block[inlen] ^= 0x01;
    block[kRate - 1] ^= 0x80;
    for (size_t k = 0; k < kRate; ++k) {
        state_bytes[k] ^= block[k];
    }
    KeccakF1600(st);

    std::vector<uint8_t> out(32);
    std::memcpy(out.data(), state_bytes, 32);
    return out;
}

}  // namespace

Result<std::vector<uint8_t>> Hash::SHA3_256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(32);  // SHA3-256 produces 32 bytes

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Failed to initialize SHA3-256 digest");
    }

    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Failed to update SHA3-256 digest");
    }

    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash.data(), &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Failed to finalize SHA3-256 digest");
    }

    EVP_MD_CTX_free(ctx);

    if (hash_len != 32) {
        return ZOOBC_ERROR(ErrorCode::CryptoError,
                           "Unexpected SHA3-256 hash length: " + std::to_string(hash_len));
    }

    return hash;
}

Result<std::vector<uint8_t>> Hash::Keccak256(const std::vector<uint8_t>& data) {
    // Self-contained Keccak-256 (see anonymous-namespace note above): OpenSSL's
    // default provider does not expose the pre-NIST Keccak-256 that Ethereum
    // uses, so we compute it directly rather than via EVP_MD_fetch.
    return Keccak256Raw(data.data(), data.size());
}

Result<std::vector<uint8_t>> Hash::SHA256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(32);  // SHA256 produces 32 bytes

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Failed to initialize SHA256 digest");
    }

    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Failed to update SHA256 digest");
    }

    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash.data(), &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Failed to finalize SHA256 digest");
    }

    EVP_MD_CTX_free(ctx);

    if (hash_len != 32) {
        return ZOOBC_ERROR(ErrorCode::CryptoError,
                           "Unexpected SHA256 hash length: " + std::to_string(hash_len));
    }

    return hash;
}

Result<std::vector<uint8_t>> Hash::RIPEMD160(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(20);  // RIPEMD-160 produces 20 bytes

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_ripemd160(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Failed to initialize RIPEMD-160 digest");
    }

    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Failed to update RIPEMD-160 digest");
    }

    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash.data(), &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Failed to finalize RIPEMD-160 digest");
    }

    EVP_MD_CTX_free(ctx);

    if (hash_len != 20) {
        return ZOOBC_ERROR(ErrorCode::CryptoError,
                           "Unexpected RIPEMD-160 hash length: " + std::to_string(hash_len));
    }

    return hash;
}

Result<std::vector<uint8_t>> Hash::DoubleSHA256(const std::vector<uint8_t>& data) {
    auto first_hash_result = SHA256(data);
    if (first_hash_result.IsErr()) {
        return first_hash_result;
    }

    return SHA256(first_hash_result.Value());
}

}  // namespace crypto
}  // namespace zoobc
