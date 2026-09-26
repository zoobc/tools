// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// The one stateless function of the ZooBC node's AccountState that the tools need: the canonical
// account key (a bare 32-byte ZBC key becomes the typed 36-byte form). Same code as the node.
#pragma once

#include <cstdint>
#include <vector>

namespace zoobc {
namespace transaction {

class AccountState {
public:
    static std::vector<uint8_t> CanonicalAccountKey(const std::vector<uint8_t>& account_address);
};

}  // namespace transaction
}  // namespace zoobc
