// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/transaction/escrow_request_rules.h"

namespace zoobc {
namespace transaction {

std::vector<uint8_t> EncodeDeclineEscrowRequestBody(const DeclineEscrowRequestBody& b) {
    std::vector<uint8_t> out;
    uint64_t id = static_cast<uint64_t>(b.request_id);
    for (int i = 0; i < 8; i++) out.push_back(static_cast<uint8_t>((id >> (8 * i)) & 0xff));
    const uint16_t n = static_cast<uint16_t>(b.reason.size() > 0xffff ? 0xffff : b.reason.size());
    out.push_back(static_cast<uint8_t>(n & 0xff));
    out.push_back(static_cast<uint8_t>(n >> 8));
    out.insert(out.end(), b.reason.begin(), b.reason.begin() + n);
    if (b.target == DeclineTarget::Escrow) out.push_back(static_cast<uint8_t>(DeclineTarget::Escrow));
    return out;
}

}  // namespace transaction
}  // namespace zoobc
