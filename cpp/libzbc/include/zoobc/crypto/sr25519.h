// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#pragma once
// sr25519 (Schnorrkel) signature VERIFICATION for Polkadot/Substrate accounts (account type 12).
// A faithful C++ port of the relevant parts of paritytech/schnorrkel + dalek's merlin:
//   - Keccak-f[1600]  (STROBE permutation)
//   - STROBE-128      (merlin/src/strobe.rs)
//   - Merlin Transcript (merlin/src/transcript.rs)
//   - schnorrkel verify equation  R == s·B − k·PK   (schnorrkel/src/sign.rs)
// Group arithmetic (Ristretto255 scalar/point ops) is libsodium's, already linked.
// Validated against official @polkadot/util-crypto vectors (tests/vectors/polkadot_sr25519.md).
#include <cstdint>
#include <string>
#include <vector>

namespace zoobc {
namespace crypto {

// Verify a 64-byte schnorrkel signature (R‖s) over `message` under signing `context`
// (Polkadot uses context "substrate") against the 32-byte sr25519 public key.
// Returns true iff the signature is valid. Never throws.
bool Sr25519Verify(const std::vector<uint8_t>& public_key,
                   const std::vector<uint8_t>& context,
                   const std::vector<uint8_t>& message,
                   const std::vector<uint8_t>& signature);

}  // namespace crypto
}  // namespace zoobc
