// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// Byte-level helpers of the ZooBC multisignature service, as used by zbc-cli and zbc-multisig:
// the multisig account address and the MultiSignature transaction body. Same code as the node,
// without the node's state access.
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "zoobc/common/result.h"
#include "zoobc/model/transaction.h"

namespace zoobc {
namespace transaction {

class MultisignatureService {
public:
    static std::vector<uint8_t> HexToBytes(const std::string& hex);
    static std::string BytesToHex(const std::vector<uint8_t>& bytes);

    // SHA3-256(min_signatures LE32 ‖ nonce LE64 ‖ count LE32 ‖ sorted participant addresses)
    static std::vector<uint8_t> GenerateMultisigAddress(
        const std::vector<std::vector<uint8_t>>& addresses,
        int64_t nonce,
        uint32_t minimum_signatures);

    // Serialised MultiSignature transaction body (info ‖ inner tx bytes ‖ signatures).
    static std::vector<uint8_t> GetBodyBytes(const model::MultiSignatureTransactionBody& body);

    // Parse a MultiSignature transaction body (the inverse of GetBodyBytes).
    static Result<model::MultiSignatureTransactionBody> ParseBodyBytes(const std::vector<uint8_t>& body_bytes);
};

}  // namespace transaction
}  // namespace zoobc
