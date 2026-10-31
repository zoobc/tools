// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#pragma once
// ECVRF over Ed25519 with SHA-512 (RFC 9381, the TAI suite, suite string 0x03): a verifiable random
// function whose output is unique per (key, input). Proof = Gamma (32) | c (16) | s (32) = 80 bytes;
// output = SHA-512(suite | 0x03 | cofactor * Gamma | 0x00) = 64 bytes, which the verifier recomputes.
// The block seed (10 F1, D2) becomes this output: a producer can choose among many valid Ed25519
// signatures of the same message, but every valid proof for one (key, input) hashes to the same
// output, so there is nothing to grind.
//
// Hash-to-curve: the RFC's try-and-increment, restricted to candidates libsodium accepts as valid
// points of the prime-order subgroup (crypto_core_ed25519_is_valid_point: canonical encoding, on the
// curve, not of small order, of order l, in that order); the RFC takes any curve point and
// multiplies by the cofactor. About one candidate in sixteen passes, so essentially every input
// distinguishes the variant from the RFC (tools/spec/vrf-vectors.json). Same proof system, same format, no bit-compatibility with
// the RFC's test vectors for inputs whose first candidate lies outside the subgroup (D2 records it).
#include <cstddef>
#include <cstdint>
#include <vector>

#include "zoobc/common/result.h"

namespace zoobc::crypto {

class Vrf {
public:
    static constexpr size_t kProofSize = 80;
    static constexpr size_t kOutputSize = 64;
    // The suite's name, ZooBC's own (dzoobc-de on 8d44222b): the RFC's TAI with candidates outside the
    // prime-order subgroup skipped rather than cofactor-cleared. Not the RFC's vectors: see
    // tools/spec/vrf-vectors.json for this variant's.
    static constexpr const char* kSuiteName = "ECVRF-EDWARDS25519-SHA512-TAI/ZooBC-subgroup";

    // secret_key: the 64-byte libsodium Ed25519 secret key (seed | public key).
    static Result<std::vector<uint8_t>> Prove(const std::vector<uint8_t>& secret_key, const std::vector<uint8_t>& alpha);
    // Verifies the proof under the 32-byte public key and returns the 64-byte output.
    static Result<std::vector<uint8_t>> Verify(const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& alpha,
                                               const std::vector<uint8_t>& proof);
    // The output of a proof without verifying it (for a consumer that verified it already).
    static Result<std::vector<uint8_t>> ProofToHash(const std::vector<uint8_t>& proof);
    // The try-and-increment counter at which the input landed on a curve point (0 = the first
    // candidate), -1 when none did; a counter above 0 marks an input where the variant and the RFC
    // part ways. For the vectors and the ports.
    static int CurveCounter(const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& alpha);
    // Testing: a proof with an explicit nonce (32 bytes, reduced mod the group order). Any nonce
    // yields a verifying proof with the same Gamma and the same output.
    static Result<std::vector<uint8_t>> ProveWithNonce(const std::vector<uint8_t>& secret_key, const std::vector<uint8_t>& alpha,
                                                       const std::vector<uint8_t>& nonce);
};

}  // namespace zoobc::crypto
