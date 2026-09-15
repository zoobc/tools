// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/transaction/multisignature_service.h"
#include "zoobc/crypto/hash.h"
#include "zoobc/util/transaction_util.h"
#include <algorithm>

namespace zoobc {
namespace transaction {

std::vector<uint8_t> MultisignatureService::HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byte_str.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::vector<uint8_t> MultisignatureService::GenerateMultisigAddress(
    const std::vector<std::vector<uint8_t>>& addresses,
    int64_t nonce,
    uint32_t minimum_signatures) {

    // Reference: originals/zoobc-core-develop/common/transaction/transactionGeneral.go
    // func (u *Util) GenerateMultiSigAddress(info *model.MultiSignatureInfo) ([]byte, error)
    //
    // Go implementation order (lines 458-483):
    //   1. Sort addresses
    //   2. Write minimum_signatures (4 bytes, little-endian)
    //   3. Write nonce (8 bytes, little-endian)
    //   4. Write address count (4 bytes, little-endian)
    //   5. Write all sorted addresses
    //   6. SHA3-256 hash the result

    // Sort addresses for deterministic address generation
    std::vector<std::vector<uint8_t>> sorted_addresses = addresses;
    std::sort(sorted_addresses.begin(), sorted_addresses.end());

    // Build data to hash - MUST match Go order exactly!
    std::vector<uint8_t> data;

    // 1. minimum_signatures (4 bytes, little-endian)
    util::TransactionUtil::WriteUint32LE(data, minimum_signatures);

    // 2. nonce (8 bytes, little-endian)
    // Note: Go uses ConvertIntToBytes which is int64
    util::TransactionUtil::WriteInt64LE(data, nonce);

    // 3. address count (4 bytes, little-endian)
    util::TransactionUtil::WriteUint32LE(data, static_cast<uint32_t>(sorted_addresses.size()));

    // 4. All sorted addresses
    for (const auto& addr : sorted_addresses) {
        data.insert(data.end(), addr.begin(), addr.end());
    }

    // Hash to get multisig address
    auto hash_result = crypto::Hash::SHA3_256(data);
    if (hash_result.IsErr()) {
        return {};
    }

    return hash_result.Value();
}

std::vector<uint8_t> MultisignatureService::GetBodyBytes(
    const model::MultiSignatureTransactionBody& body) {

    // Reference: originals/zoobc-core-develop/common/transaction/multiSignature.go
    // func (tx *MultiSignatureTransaction) GetBodyBytes() ([]byte, error) - lines 801-839
    //
    // Format:
    // 1. MultisigInfo:
    //    - field_present (4 bytes): 1=present, 0=missing
    //    - If present: min_sigs(4) + nonce(8) + addr_count(4) + addresses
    // 2. TransactionBytes:
    //    - length (4 bytes) + bytes
    // 3. SignatureInfo:
    //    - field_present (4 bytes): 1=present, 0=missing
    //    - If present: tx_hash(32) + sig_count(4) + for each: address + sig_len(4) + signature

    std::vector<uint8_t> buffer;

    // Constants matching Go: constant.MultiSigFieldPresent = 1, constant.MultiSigFieldMissing = 0
    constexpr uint32_t FIELD_PRESENT = 1;
    constexpr uint32_t FIELD_MISSING = 0;

    // 1. MultiSignatureInfo
    if (body.multi_signature_info.has_value()) {
        const auto& info = body.multi_signature_info.value();

        // Field present marker (4 bytes)
        util::TransactionUtil::WriteUint32LE(buffer, FIELD_PRESENT);

        // minimum_signatures (4 bytes)
        util::TransactionUtil::WriteUint32LE(buffer, info.minimum_signatures);

        // nonce (8 bytes)
        util::TransactionUtil::WriteUint64LE(buffer, static_cast<uint64_t>(info.nonce));

        // address count (4 bytes)
        util::TransactionUtil::WriteUint32LE(buffer, static_cast<uint32_t>(info.addresses.size()));

        // addresses (each is full account address with type prefix)
        for (const auto& addr : info.addresses) {
            buffer.insert(buffer.end(), addr.begin(), addr.end());
        }
    } else {
        // No multisig info - write field missing marker
        util::TransactionUtil::WriteUint32LE(buffer, FIELD_MISSING);
    }

    // 2. Unsigned transaction bytes
    util::TransactionUtil::WriteUint32LE(buffer, static_cast<uint32_t>(body.unsigned_transaction_bytes.size()));
    if (!body.unsigned_transaction_bytes.empty()) {
        buffer.insert(buffer.end(),
                      body.unsigned_transaction_bytes.begin(),
                      body.unsigned_transaction_bytes.end());
    }

    // 3. SignatureInfo
    if (body.signature_info.has_value()) {
        const auto& sig_info = body.signature_info.value();

        // Field present marker (4 bytes)
        util::TransactionUtil::WriteUint32LE(buffer, FIELD_PRESENT);

        // transaction_hash (32 bytes)
        if (sig_info.transaction_hash.size() >= 32) {
            buffer.insert(buffer.end(),
                          sig_info.transaction_hash.begin(),
                          sig_info.transaction_hash.begin() + 32);
        } else {
            // Pad with zeros if needed
            buffer.insert(buffer.end(), sig_info.transaction_hash.begin(), sig_info.transaction_hash.end());
            size_t current_size = buffer.size();
            buffer.resize(current_size + (32 - sig_info.transaction_hash.size()), 0);
        }

        // signature count (4 bytes)
        util::TransactionUtil::WriteUint32LE(buffer, static_cast<uint32_t>(sig_info.signatures.size()));

        // signatures - each has: address + signature_length(4) + signature
        for (const auto& [addr_hex, sig] : sig_info.signatures) {
            auto addr = HexToBytes(addr_hex);
            buffer.insert(buffer.end(), addr.begin(), addr.end());
            // Signature length (4 bytes) - Go writes this before each signature
            util::TransactionUtil::WriteUint32LE(buffer, static_cast<uint32_t>(sig.size()));
            buffer.insert(buffer.end(), sig.begin(), sig.end());
        }
    } else {
        // No signature info - write field missing marker
        util::TransactionUtil::WriteUint32LE(buffer, FIELD_MISSING);
    }

    return buffer;
}

}  // namespace transaction
}  // namespace zoobc
