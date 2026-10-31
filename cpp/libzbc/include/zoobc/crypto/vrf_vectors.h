// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#pragma once
// 10 F1-1b — deterministic vectors of ZooBC's VRF variant (Vrf::kSuiteName), shared by the generator
// tool (zbc-vrf-vectors writes tools/spec/vrf-vectors.json) and the test that pins the file.
// Keys come from fixed 32-byte seeds through crypto_sign_seed_keypair; the last vector searches,
// deterministically, for an input whose first curve candidate lies outside the prime-order subgroup,
// the one place this variant and RFC 9381 part ways.
#include <cstdint>
#include <string>
#include <vector>
#include <sodium.h>

#include "zoobc/crypto/vrf.h"

namespace zoobc::crypto {

struct VrfVector {
    std::string note;
    std::vector<uint8_t> seed, public_key, alpha, proof, output;
    int curve_counter = -1;
};

inline std::vector<VrfVector> GenerateVrfVectors() {
    std::vector<VrfVector> out;
    auto make = [&](const std::string& note, uint8_t seed_byte, const std::vector<uint8_t>& alpha) {
        VrfVector v; v.note = note; v.seed.assign(32, seed_byte); v.alpha = alpha;
        std::vector<uint8_t> pk(32), sk(64);
        crypto_sign_seed_keypair(pk.data(), sk.data(), v.seed.data());
        v.public_key = pk;
        auto p = Vrf::Prove(sk, alpha); if (p.IsOk()) v.proof = p.Value();
        auto o = Vrf::Verify(pk, alpha, v.proof); if (o.IsOk()) v.output = o.Value();
        v.curve_counter = Vrf::CurveCounter(pk, alpha);
        return v;
    };
    out.push_back(make("empty input", 0x01, {}));
    out.push_back(make("one byte", 0x01, {0x00}));
    out.push_back(make("the word zoobc", 0x02, {'z', 'o', 'o', 'b', 'c'}));
    out.push_back(make("32 bytes of 0xA5 (a previous seed's SHA3 shape)", 0x03, std::vector<uint8_t>(32, 0xA5)));
    out.push_back(make("64 bytes of 0xFF", 0x04, std::vector<uint8_t>(64, 0xFF)));
    out.push_back(make("the zero seed's hash shape: 32 zero bytes", 0x05, std::vector<uint8_t>(32, 0x00)));
    // The variant's mark: the first input (counting up from 0 in one byte) whose first curve candidate
    // libsodium refuses, so the RFC (cofactor-cleared) and this variant (skipped) give different points.
    {
        std::vector<uint8_t> pk(32), sk(64), seed(32, 0x06);
        crypto_sign_seed_keypair(pk.data(), sk.data(), seed.data());
        for (unsigned k = 0; k < 256; ++k) {
            std::vector<uint8_t> alpha = {static_cast<uint8_t>(k)};
            if (Vrf::CurveCounter(pk, alpha) > 0) { out.push_back(make("first candidate outside the subgroup: skipped here, cofactor-cleared by the RFC", 0x06, alpha)); break; }
        }
    }
    return out;
}

}  // namespace zoobc::crypto
