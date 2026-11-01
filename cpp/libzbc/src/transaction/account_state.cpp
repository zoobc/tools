// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/transaction/account_state.h"
#include "zoobc/util/transaction_util.h"

namespace zoobc {
namespace transaction {

std::vector<uint8_t> AccountState::CanonicalAccountKey(const std::vector<uint8_t>& account_address) {
    // Rule typed_accounts_only (0.6.0): accounts are typed, one form; a bare key is not typed into one (below the rule a
    // bare key was the ZBC account with that key).
    if (util::TransactionUtil::IsBareLegacyKey(account_address) && !util::TransactionUtil::BareAccountsRefused()) {   // decision 4: a Cardano account keeps its own type
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
