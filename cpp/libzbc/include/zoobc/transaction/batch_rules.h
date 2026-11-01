// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_TRANSACTION_BATCH_RULES_H
#define ZOOBC_TRANSACTION_BATCH_RULES_H

// Same-kind batches (owner decisions TX2 and TX3, 2026-10-24; b39, b40).
//
// One transaction carries several actions of ONE kind: ZBC payments (SendZBCBatch, 257), token
// transfers (TransferTokenBatch, 267), or a node's storage proofs for one epoch
// (SubmitStorageProofBatch, 297). All or nothing: every action is checked before any applies, and if
// one fails none does (a paid no-op, or an invalid block for an overspend, as for the one-action
// types). The minimum fee is the sum of the minimum fees the actions would pay as separate one-action
// transactions (TransactionValidator::CalculateMinimumFee). Mixed bundles (actions of different kinds)
// are not offered (DN6). The byte layouts are next to the types in common/types.h.
//
// The parsers are the only definition of a well-formed body, shared by admission, block validation
// and execution, so they cannot disagree. A declared count is checked against the bytes that actually
// arrived before anything is reserved (the SettleApp lesson: a count is attacker-controlled).

#include <cstddef>
#include <cstdint>
#include <vector>

#include "zoobc/common/result.h"
#include "zoobc/common/types.h"
#include "zoobc/model/transaction.h"

namespace zoobc {
namespace transaction {
namespace batch {

struct Payment {
    std::vector<uint8_t> recipient;   // typed address bytes (01 §4.1)
    int64_t amount = 0;               // atomic ZBC, > 0
};
struct TokenTransfer {
    int64_t token_id = 0;             // != 0 (0 is ZBC, which SendZBCBatch moves)
    std::vector<uint8_t> recipient;
    int64_t amount = 0;               // token units, > 0
};
struct StorageProof {
    std::vector<uint8_t> piece_id;    // 32 bytes
    std::vector<uint8_t> proof;       // 32 bytes: SHA3-256(piece_bytes ‖ the epoch's challenge nonce)
};
struct StorageProofBatch {
    uint64_t epoch = 0;
    std::vector<StorageProof> proofs;
};

// The most actions one batch may carry, measured (tests/batch_cost_benchmark.cpp, 2026-10-26, four runs
// on the dev box under load) the way SettleApp's move list is sized (app_rules.cpp kMaxSettleMoves): a
// batch at its worst may not cost more to apply than the costliest transaction the chain already
// accepts, a settlement of 1,024 moves (1,024 signature verifications, 45-53 ms there). The worst case
// is a batch whose every recipient forwards each credit to ten others (the split policy): one such
// payment costs 1.1-1.5 ms, one such token transfer 0.7-1.2 ms, so a maximal settlement's time holds
// 30-47 payments and 37-70 token transfers; a storage proof costs 3-11 us and only the 64 KiB body
// bounds it (1,023). Each maximum is under the lowest measurement.
//
// The per-byte ceiling itself (one verification per 67 bytes) cannot hold for a batch whose recipients
// forward their credits: an action costs what the one-action transaction costs (measured: within
// 1.2x for payments to forwarding accounts) in a quarter of its bytes. So a block's transaction
// ceiling (max_transactions_per_block) counts every action of a payment or token-transfer batch
// (CeilingCount, enforced by block validation, PushBlock and block assembly): a block of batches is
// bounded like a block of the one-action transactions it replaces. Storage proofs stay far under the
// per-byte ceiling (0.1x) and count one batch as one transaction.
constexpr size_t kMaxPayments = 25;
constexpr size_t kMaxTokenTransfers = 32;
constexpr size_t kMaxStorageProofs = 1000;

// The smallest each action can be on the wire, for the structural bound on a declared count.
constexpr size_t kMinAddressBytes = 24;   // a 20-byte payload with its 4-byte type (BTC, ETH)
constexpr size_t kMinPaymentBytes = 1 + kMinAddressBytes + 8;
constexpr size_t kMinTokenTransferBytes = 8 + 1 + kMinAddressBytes + 8;
constexpr size_t kStorageProofBytes = 32 + 32;

inline bool IsBatchType(TransactionType t) {
    return t == TransactionType::SendZBCBatch || t == TransactionType::TransferTokenBatch ||
           t == TransactionType::SubmitStorageProofBatch;
}

// The one-action type each batch's actions belong to, and that type's body length for one action
// (SendZBC: amount; TransferToken: token_id + amount; SubmitStorageProof: piece_id + epoch + proof).
TransactionType OneActionType(TransactionType batch_type);
uint32_t OneActionBodyLength(TransactionType batch_type);

Result<std::vector<Payment>> ParsePayments(const std::vector<uint8_t>& body);
std::vector<uint8_t> EncodePayments(const std::vector<Payment>& payments);
Result<std::vector<TokenTransfer>> ParseTokenTransfers(const std::vector<uint8_t>& body);
std::vector<uint8_t> EncodeTokenTransfers(const std::vector<TokenTransfer>& transfers);
Result<StorageProofBatch> ParseStorageProofs(const std::vector<uint8_t>& body);
std::vector<uint8_t> EncodeStorageProofs(const StorageProofBatch& batch);

// How many actions a batch carries; 0 when the body does not parse (or the type is not a batch).
size_t ActionCount(const model::Transaction& tx);

// What a block's transaction ceiling (max_transactions_per_block) counts for a transaction: one, or
// every action of a payment or token-transfer batch (a storage-proof batch counts one: its proofs cost
// far less than the per-byte ceiling allows, so its bytes bound it).
size_t CeilingCount(const model::Transaction& tx);
size_t CeilingCount(const std::vector<model::Transaction>& txs);

}  // namespace batch
}  // namespace transaction
}  // namespace zoobc

#endif  // ZOOBC_TRANSACTION_BATCH_RULES_H
