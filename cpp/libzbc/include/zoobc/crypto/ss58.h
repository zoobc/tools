// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#pragma once
// SS58 address codec for Polkadot/Substrate (account type 12). An SS58 address is
// base58( prefix_bytes || 32-byte AccountId || checksum ), where checksum = the first 2 bytes of
// blake2b-512("SS58PRE" || prefix_bytes || AccountId). Network prefix 0 = Polkadot, 2 = Kusama,
// 42 = generic Substrate. We encode/decode the 32-byte AccountId form (single-byte prefix 0..63).
// The consensus node stores the raw 32-byte AccountId ([12,0,0,0]+id); this codec is for tools/display.
#include <cstdint>
#include <string>
#include <vector>

namespace zoobc {
namespace crypto {

struct Ss58Decoded {
    bool ok = false;
    std::string error;
    uint16_t prefix = 0;
    std::vector<uint8_t> account_id;   // 32 bytes
};

// Encode a 32-byte AccountId as an SS58 address for the given network prefix (default 0 = Polkadot).
// Returns "" if account_id is not 32 bytes or prefix > 63 (single-byte-prefix form only).
std::string Ss58Encode(const std::vector<uint8_t>& account_id, uint16_t prefix = 0);

// Decode an SS58 address (single-byte prefix, 32-byte AccountId). Validates the blake2b checksum.
Ss58Decoded Ss58Decode(const std::string& address);

/// Raw base58 (Bitcoin alphabet). ok=false when the string contains a non-base58 character.
std::vector<uint8_t> Base58Decode(const std::string& s, bool& ok);
std::string Base58Encode(const std::vector<uint8_t>& data);

}  // namespace crypto
}  // namespace zoobc
