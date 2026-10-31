// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) over libsodium's Ed25519 group arithmetic. See vrf.h.
#include "zoobc/crypto/vrf.h"

#include <cstring>
#include <sodium.h>

namespace zoobc::crypto {
namespace {

constexpr uint8_t kSuite = 0x03;
constexpr size_t kPoint = 32, kScalar = 32, kChallenge = 16;

// x = clamp(SHA-512(seed)[0..32)), the Ed25519 private scalar; h2 = SHA-512(seed)[32..64) feeds the nonce.
bool ExpandKey(const std::vector<uint8_t>& sk, uint8_t x[32], uint8_t h2[32], uint8_t pk[32]) {
    if (sk.size() != crypto_sign_ed25519_SECRETKEYBYTES) return false;
    uint8_t h[64];
    crypto_hash_sha512(h, sk.data(), 32);
    h[0] &= 248; h[31] &= 127; h[31] |= 64;
    std::memcpy(x, h, 32); std::memcpy(h2, h + 32, 32); std::memcpy(pk, sk.data() + 32, 32);
    uint8_t check[32];
    if (crypto_scalarmult_ed25519_base_noclamp(check, x) != 0) return false;
    return std::memcmp(check, pk, 32) == 0;   // the key's halves belong together
}

// RFC 9381 §5.4.1.1 (try-and-increment), restricted to prime-order subgroup points (see vrf.h).
thread_local int g_last_counter = -1;   // the counter the last EncodeToCurve stopped at on this thread (for CurveCounter; dzoobc-de on 5d4052e3: the node proves and verifies on several threads)
bool EncodeToCurve(const uint8_t pk[32], const std::vector<uint8_t>& alpha, uint8_t H[32]) {
    std::vector<uint8_t> m;
    m.reserve(2 + 32 + alpha.size() + 2);
    g_last_counter = -1;
    for (unsigned ctr = 0; ctr < 256; ++ctr) {
        m.clear();
        m.push_back(kSuite); m.push_back(0x01);
        m.insert(m.end(), pk, pk + 32);
        m.insert(m.end(), alpha.begin(), alpha.end());
        m.push_back(static_cast<uint8_t>(ctr)); m.push_back(0x00);
        uint8_t hs[64];
        crypto_hash_sha512(hs, m.data(), m.size());
        std::memcpy(H, hs, 32);
        if (crypto_core_ed25519_is_valid_point(H)) { g_last_counter = static_cast<int>(ctr); return true; }
    }
    return false;
}

// RFC 9381 §5.4.3: c = SHA-512(suite | 0x02 | Y | H | Gamma | U | V | 0x00)[0..16), as a little-endian scalar.
void Challenge(const uint8_t pk[32], const uint8_t H[32], const uint8_t G[32], const uint8_t U[32], const uint8_t V[32], uint8_t c[32]) {
    uint8_t m[2 + 5 * 32 + 1];
    size_t o = 0;
    m[o++] = kSuite; m[o++] = 0x02;
    for (const uint8_t* p : {pk, H, G, U, V}) { std::memcpy(m + o, p, 32); o += 32; }
    m[o++] = 0x00;
    uint8_t hs[64];
    crypto_hash_sha512(hs, m, o);
    std::memset(c, 0, 32);
    std::memcpy(c, hs, kChallenge);
}

bool IsZero(const uint8_t* s, size_t n) { uint8_t acc = 0; for (size_t i = 0; i < n; ++i) acc |= s[i]; return acc == 0; }

Result<std::vector<uint8_t>> ProveWith(const std::vector<uint8_t>& sk, const std::vector<uint8_t>& alpha, const uint8_t k[32]) {
    uint8_t x[32], h2[32], pk[32];
    if (!ExpandKey(sk, x, h2, pk)) return Error{ErrorCode::InvalidPrivateKey, "VRF: the secret key is not a 64-byte Ed25519 key"};
    uint8_t H[32];
    if (!EncodeToCurve(pk, alpha, H)) return Error{ErrorCode::Internal, "VRF: no curve point for this input"};
    uint8_t G[32], U[32], V[32];
    if (crypto_scalarmult_ed25519_noclamp(G, x, H) != 0) return Error{ErrorCode::Internal, "VRF: Gamma"};
    if (IsZero(k, 32)) return Error{ErrorCode::Internal, "VRF: zero nonce"};
    if (crypto_scalarmult_ed25519_base_noclamp(U, k) != 0) return Error{ErrorCode::Internal, "VRF: U"};
    if (crypto_scalarmult_ed25519_noclamp(V, k, H) != 0) return Error{ErrorCode::Internal, "VRF: V"};
    uint8_t c[32], cx[32], s[32];
    Challenge(pk, H, G, U, V, c);
    crypto_core_ed25519_scalar_mul(cx, c, x);
    crypto_core_ed25519_scalar_add(s, k, cx);
    std::vector<uint8_t> pi;
    pi.reserve(Vrf::kProofSize);
    pi.insert(pi.end(), G, G + 32);
    pi.insert(pi.end(), c, c + kChallenge);
    pi.insert(pi.end(), s, s + 32);
    return pi;
}

}  // namespace

Result<std::vector<uint8_t>> Vrf::Prove(const std::vector<uint8_t>& secret_key, const std::vector<uint8_t>& alpha) {
    uint8_t x[32], h2[32], pk[32];
    if (!ExpandKey(secret_key, x, h2, pk)) return Error{ErrorCode::InvalidPrivateKey, "VRF: the secret key is not a 64-byte Ed25519 key"};
    uint8_t H[32];
    if (!EncodeToCurve(pk, alpha, H)) return Error{ErrorCode::Internal, "VRF: no curve point for this input"};
    // RFC 9381 §5.4.2.2: k = SHA-512(h2 | H) mod q, the deterministic nonce (any nonce gives the same output).
    uint8_t km[64], ks[64], k[32];
    std::memcpy(km, h2, 32); std::memcpy(km + 32, H, 32);
    crypto_hash_sha512(ks, km, 64);
    crypto_core_ed25519_scalar_reduce(k, ks);
    return ProveWith(secret_key, alpha, k);
}

Result<std::vector<uint8_t>> Vrf::ProveWithNonce(const std::vector<uint8_t>& secret_key, const std::vector<uint8_t>& alpha,
                                                 const std::vector<uint8_t>& nonce) {
    if (nonce.size() != 32) return Error{ErrorCode::InvalidArgument, "VRF: the nonce must be 32 bytes"};
    uint8_t wide[64] = {0}, k[32];
    std::memcpy(wide, nonce.data(), 32);
    crypto_core_ed25519_scalar_reduce(k, wide);
    return ProveWith(secret_key, alpha, k);
}

int Vrf::CurveCounter(const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& alpha) {
    if (public_key.size() != 32) return -1;
    uint8_t H[32];
    return EncodeToCurve(public_key.data(), alpha, H) ? g_last_counter : -1;
}

Result<std::vector<uint8_t>> Vrf::ProofToHash(const std::vector<uint8_t>& proof) {
    if (proof.size() != kProofSize) return Error{ErrorCode::ValidationError, "VRF: the proof must be 80 bytes"};
    if (!crypto_core_ed25519_is_valid_point(proof.data())) return Error{ErrorCode::ValidationError, "VRF: Gamma is not a valid point"};
    // beta = SHA-512(suite | 0x03 | cofactor * Gamma | 0x00); the cofactor is 8.
    uint8_t eight[32] = {8}, cG[32];
    if (crypto_scalarmult_ed25519_noclamp(cG, eight, proof.data()) != 0) return Error{ErrorCode::ValidationError, "VRF: Gamma has small order"};
    uint8_t m[2 + 32 + 1];
    m[0] = kSuite; m[1] = 0x03; std::memcpy(m + 2, cG, 32); m[34] = 0x00;
    std::vector<uint8_t> out(kOutputSize);
    crypto_hash_sha512(out.data(), m, sizeof m);
    return out;
}

Result<std::vector<uint8_t>> Vrf::Verify(const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& alpha,
                                         const std::vector<uint8_t>& proof) {
    if (public_key.size() != kPoint || !crypto_core_ed25519_is_valid_point(public_key.data()))
        return Error{ErrorCode::InvalidPublicKey, "VRF: the public key is not a valid point"};
    if (proof.size() != kProofSize) return Error{ErrorCode::ValidationError, "VRF: the proof must be 80 bytes"};
    const uint8_t* G = proof.data();
    if (!crypto_core_ed25519_is_valid_point(G)) return Error{ErrorCode::ValidationError, "VRF: Gamma is not a valid point"};
    uint8_t c[32] = {0}, s[32];
    std::memcpy(c, proof.data() + kPoint, kChallenge);
    std::memcpy(s, proof.data() + kPoint + kChallenge, kScalar);
    {   // s must be a canonical scalar (< q): its reduction is itself.
        uint8_t wide[64] = {0}, red[32];
        std::memcpy(wide, s, 32);
        crypto_core_ed25519_scalar_reduce(red, wide);
        if (std::memcmp(red, s, 32) != 0) return Error{ErrorCode::ValidationError, "VRF: s is not a canonical scalar"};
    }
    if (IsZero(c, 32)) return Error{ErrorCode::ValidationError, "VRF: zero challenge"};
    uint8_t H[32];
    if (!EncodeToCurve(public_key.data(), alpha, H)) return Error{ErrorCode::Internal, "VRF: no curve point for this input"};
    // U = s*B - c*Y ; V = s*H - c*Gamma
    uint8_t sB[32], cY[32], U[32], sH[32], cG[32], V[32];
    if (crypto_scalarmult_ed25519_base_noclamp(sB, s) != 0) return Error{ErrorCode::ValidationError, "VRF: s*B"};
    if (crypto_scalarmult_ed25519_noclamp(cY, c, public_key.data()) != 0) return Error{ErrorCode::ValidationError, "VRF: c*Y"};
    if (crypto_core_ed25519_sub(U, sB, cY) != 0) return Error{ErrorCode::ValidationError, "VRF: U"};
    if (crypto_scalarmult_ed25519_noclamp(sH, s, H) != 0) return Error{ErrorCode::ValidationError, "VRF: s*H"};
    if (crypto_scalarmult_ed25519_noclamp(cG, c, G) != 0) return Error{ErrorCode::ValidationError, "VRF: c*Gamma"};
    if (crypto_core_ed25519_sub(V, sH, cG) != 0) return Error{ErrorCode::ValidationError, "VRF: V"};
    uint8_t c2[32];
    Challenge(public_key.data(), H, G, U, V, c2);
    if (sodium_memcmp(c2, c, kChallenge) != 0) return Error{ErrorCode::ValidationError, "VRF: the proof does not verify"};
    return ProofToHash(proof);
}

}  // namespace zoobc::crypto
