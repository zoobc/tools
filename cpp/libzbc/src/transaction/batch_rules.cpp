// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/transaction/batch_rules.h"

#include <string>

namespace zoobc {
namespace transaction {
namespace batch {

namespace {

Error bad(const std::string& what) { return Error{ErrorCode::ValidationError, what}; }

uint16_t rdU16(const std::vector<uint8_t>& b, size_t p) {
    return static_cast<uint16_t>(b[p] | (static_cast<uint16_t>(b[p + 1]) << 8));
}
int64_t rdI64(const std::vector<uint8_t>& b, size_t p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= static_cast<uint64_t>(b[p + i]) << (8 * i);
    return static_cast<int64_t>(v);
}
void putU16(std::vector<uint8_t>& b, uint16_t v) { b.push_back(static_cast<uint8_t>(v & 0xff)); b.push_back(static_cast<uint8_t>(v >> 8)); }
void putI64(std::vector<uint8_t>& b, int64_t v) {
    const uint64_t u = static_cast<uint64_t>(v);
    for (int i = 0; i < 8; i++) b.push_back(static_cast<uint8_t>(u >> (8 * i)));
}

// count(u16): at least one action, at most `max`, and no more than the remaining bytes can hold at
// `min_bytes` each -- checked before anything is reserved.
Result<size_t> readCount(const std::vector<uint8_t>& b, size_t& p, size_t max, size_t min_bytes, const char* what) {
    if (p + 2 > b.size()) return bad(std::string(what) + ": body too short for the action count");
    const size_t count = rdU16(b, p);
    p += 2;
    if (count == 0) return bad(std::string(what) + ": a batch carries at least one action");
    if (count > max) return bad(std::string(what) + ": more than " + std::to_string(max) + " actions");
    if (count > (b.size() - p) / min_bytes) return bad(std::string(what) + ": the body is shorter than its action count");
    return count;
}

// addr_len(u8) | address: at least the smallest typed address, all bytes present.
Result<std::vector<uint8_t>> readAddress(const std::vector<uint8_t>& b, size_t& p, const char* what) {
    if (p + 1 > b.size()) return bad(std::string(what) + ": truncated recipient");
    const size_t len = b[p++];
    if (len < kMinAddressBytes || p + len > b.size()) return bad(std::string(what) + ": truncated or too short recipient");
    std::vector<uint8_t> a(b.begin() + static_cast<std::ptrdiff_t>(p), b.begin() + static_cast<std::ptrdiff_t>(p + len));
    p += len;
    return a;
}

}  // namespace

TransactionType OneActionType(TransactionType batch_type) {
    switch (batch_type) {
        case TransactionType::SendZBCBatch: return TransactionType::SendZBC;
        case TransactionType::TransferTokenBatch: return TransactionType::TransferToken;
        case TransactionType::SubmitStorageProofBatch: return TransactionType::SubmitStorageProof;
        default: return batch_type;
    }
}

uint32_t OneActionBodyLength(TransactionType batch_type) {
    switch (batch_type) {
        case TransactionType::SendZBCBatch: return 8;              // amount
        case TransactionType::TransferTokenBatch: return 16;       // token_id + amount
        case TransactionType::SubmitStorageProofBatch: return 72;  // piece_id + epoch + proof
        default: return 0;
    }
}

Result<std::vector<Payment>> ParsePayments(const std::vector<uint8_t>& b) {
    size_t p = 0;
    auto count = readCount(b, p, kMaxPayments, kMinPaymentBytes, "SendZBCBatch");
    if (count.IsErr()) return count.GetError();
    std::vector<Payment> out;
    out.reserve(count.Value());
    for (size_t i = 0; i < count.Value(); ++i) {
        auto a = readAddress(b, p, "SendZBCBatch");
        if (a.IsErr()) return a.GetError();
        if (p + 8 > b.size()) return bad("SendZBCBatch: truncated amount");
        Payment pay;
        pay.recipient = std::move(a.Value());
        pay.amount = rdI64(b, p);
        p += 8;
        out.push_back(std::move(pay));
    }
    if (p != b.size()) return bad("SendZBCBatch: trailing bytes after the last payment");
    return out;
}

std::vector<uint8_t> EncodePayments(const std::vector<Payment>& payments) {
    std::vector<uint8_t> b;
    putU16(b, static_cast<uint16_t>(payments.size()));
    for (const auto& pay : payments) {
        b.push_back(static_cast<uint8_t>(pay.recipient.size()));
        b.insert(b.end(), pay.recipient.begin(), pay.recipient.end());
        putI64(b, pay.amount);
    }
    return b;
}

Result<std::vector<TokenTransfer>> ParseTokenTransfers(const std::vector<uint8_t>& b) {
    size_t p = 0;
    auto count = readCount(b, p, kMaxTokenTransfers, kMinTokenTransferBytes, "TransferTokenBatch");
    if (count.IsErr()) return count.GetError();
    std::vector<TokenTransfer> out;
    out.reserve(count.Value());
    for (size_t i = 0; i < count.Value(); ++i) {
        if (p + 8 > b.size()) return bad("TransferTokenBatch: truncated token id");
        TokenTransfer t;
        t.token_id = rdI64(b, p);
        p += 8;
        auto a = readAddress(b, p, "TransferTokenBatch");
        if (a.IsErr()) return a.GetError();
        t.recipient = std::move(a.Value());
        if (p + 8 > b.size()) return bad("TransferTokenBatch: truncated amount");
        t.amount = rdI64(b, p);
        p += 8;
        out.push_back(std::move(t));
    }
    if (p != b.size()) return bad("TransferTokenBatch: trailing bytes after the last transfer");
    return out;
}

std::vector<uint8_t> EncodeTokenTransfers(const std::vector<TokenTransfer>& transfers) {
    std::vector<uint8_t> b;
    putU16(b, static_cast<uint16_t>(transfers.size()));
    for (const auto& t : transfers) {
        putI64(b, t.token_id);
        b.push_back(static_cast<uint8_t>(t.recipient.size()));
        b.insert(b.end(), t.recipient.begin(), t.recipient.end());
        putI64(b, t.amount);
    }
    return b;
}

Result<StorageProofBatch> ParseStorageProofs(const std::vector<uint8_t>& b) {
    if (b.size() < 8) return bad("SubmitStorageProofBatch: body too short for the epoch");
    StorageProofBatch out;
    out.epoch = static_cast<uint64_t>(rdI64(b, 0));
    size_t p = 8;
    auto count = readCount(b, p, kMaxStorageProofs, kStorageProofBytes, "SubmitStorageProofBatch");
    if (count.IsErr()) return count.GetError();
    if (b.size() - p != count.Value() * kStorageProofBytes)
        return bad("SubmitStorageProofBatch: the body must hold exactly its proofs (64 bytes each)");
    out.proofs.reserve(count.Value());
    for (size_t i = 0; i < count.Value(); ++i, p += kStorageProofBytes) {
        StorageProof sp;
        sp.piece_id.assign(b.begin() + static_cast<std::ptrdiff_t>(p), b.begin() + static_cast<std::ptrdiff_t>(p + 32));
        sp.proof.assign(b.begin() + static_cast<std::ptrdiff_t>(p + 32), b.begin() + static_cast<std::ptrdiff_t>(p + 64));
        out.proofs.push_back(std::move(sp));
    }
    return out;
}

std::vector<uint8_t> EncodeStorageProofs(const StorageProofBatch& batch) {
    std::vector<uint8_t> b;
    putI64(b, static_cast<int64_t>(batch.epoch));
    putU16(b, static_cast<uint16_t>(batch.proofs.size()));
    for (const auto& sp : batch.proofs) {
        b.insert(b.end(), sp.piece_id.begin(), sp.piece_id.end());
        b.insert(b.end(), sp.proof.begin(), sp.proof.end());
    }
    return b;
}

size_t ActionCount(const model::Transaction& tx) {
    switch (tx.transaction_type) {
        case TransactionType::SendZBCBatch: {
            auto r = ParsePayments(tx.transaction_body_bytes);
            return r.IsOk() ? r.Value().size() : 0;
        }
        case TransactionType::TransferTokenBatch: {
            auto r = ParseTokenTransfers(tx.transaction_body_bytes);
            return r.IsOk() ? r.Value().size() : 0;
        }
        case TransactionType::SubmitStorageProofBatch: {
            auto r = ParseStorageProofs(tx.transaction_body_bytes);
            return r.IsOk() ? r.Value().proofs.size() : 0;
        }
        default:
            return 0;
    }
}

size_t CeilingCount(const model::Transaction& tx) {
    // Payments and token transfers count every action: each credit may be forwarded to ten accounts,
    // so an action costs about what a one-action transaction costs in a quarter of its bytes. A storage
    // proof costs a few microseconds, far under the per-byte ceiling: its batch counts one, and the
    // block's bytes bound it like any transaction.
    if (tx.transaction_type != TransactionType::SendZBCBatch && tx.transaction_type != TransactionType::TransferTokenBatch)
        return 1;
    const size_t n = ActionCount(tx);
    return n > 0 ? n : 1;
}

size_t CeilingCount(const std::vector<model::Transaction>& txs) {
    size_t total = 0;
    for (const auto& tx : txs) total += CeilingCount(tx);
    return total;
}

}  // namespace batch
}  // namespace transaction
}  // namespace zoobc
