// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// Byte-level helpers of the ZooBC multisignature service, as used by zbc-cli and zbc-multisig:
// the multisig account address and the MultiSignature transaction body. Same code as the node,
// without the node's state access.
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "zoobc/model/transaction.h"

namespace zoobc {
namespace transaction {

class MultisignatureService {
public:
    static std::vector<uint8_t> HexToBytes(const std::string& hex);

    // SHA3-256(min_signatures LE32 ‖ nonce LE64 ‖ count LE32 ‖ sorted participant addresses)
    static std::vector<uint8_t> GenerateMultisigAddress(
        const std::vector<std::vector<uint8_t>>& addresses,
        int64_t nonce,
        uint32_t minimum_signatures);

    // Serialised MultiSignature transaction body (info ‖ inner tx bytes ‖ signatures).
    static std::vector<uint8_t> GetBodyBytes(const model::MultiSignatureTransactionBody& body);
};

}  // namespace transaction
}  // namespace zoobc
