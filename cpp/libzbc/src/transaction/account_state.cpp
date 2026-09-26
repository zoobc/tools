// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/transaction/account_state.h"
#include "zoobc/util/transaction_util.h"

namespace zoobc {
namespace transaction {

std::vector<uint8_t> AccountState::CanonicalAccountKey(const std::vector<uint8_t>& account_address) {
    if (account_address.size() == util::TransactionUtil::PUBLIC_KEY_SIZE) {
        std::vector<uint8_t> typed;
        typed.reserve(util::TransactionUtil::ACCOUNT_TYPE_SIZE + util::TransactionUtil::PUBLIC_KEY_SIZE);
        util::TransactionUtil::WriteInt32LE(typed, util::TransactionUtil::ACCOUNT_TYPE_ZBC);
        typed.insert(typed.end(), account_address.begin(), account_address.end());
        return typed;
    }
    return account_address;
}

}  // namespace transaction
}  // namespace zoobc
