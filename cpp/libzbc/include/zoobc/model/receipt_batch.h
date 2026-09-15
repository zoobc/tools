// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_MODEL_RECEIPT_BATCH_H
#define ZOOBC_MODEL_RECEIPT_BATCH_H

#include <cstdint>
#include <vector>
#include "zoobc/common/types.h"
#include "zoobc/model/transaction.h"  // For Receipt, BatchReceipt

namespace zoobc {
namespace model {

/**
 * Receipt Batch (C++ specific - for managing receipt collections)
 *
 * Group of receipts with computed Merkle root.
 * Used for efficient storage and proof generation.
 *
 * NOTE: This is different from Go's model.BatchReceipt which is a SINGLE
 * receipt with batch metadata. That struct is defined in transaction.h as BatchReceipt.
 * This ReceiptBatch is for managing collections of receipts and their Merkle roots.
 */
struct ReceiptBatch {
    int64_t id = 0;
    uint32_t block_height = 0;           // Height when batch was created
    std::vector<uint8_t> merkle_root;    // Root of Merkle tree
    int64_t receipt_count = 0;           // Number of receipts in batch
    int64_t created_at = 0;

    std::vector<Receipt> receipts;       // Receipts in this batch

    ReceiptBatch() = default;
};

/**
 * Receipt Record
 *
 * Database record for a receipt, including metadata.
 * Used internally by ReceiptManager for storage.
 */
struct ReceiptRecord {
    int64_t id = 0;
    Receipt receipt;                     // Core receipt data
    int64_t batch_id = 0;                // ID of batch this receipt belongs to (0 if unbatched)
    int64_t batch_index = 0;             // Index within batch
    int64_t created_at = 0;              // Unix timestamp
    bool published = false;              // Whether included in a block
    uint32_t published_height = 0;       // Height where published

    ReceiptRecord() = default;
};

/**
 * Merkle Proof
 *
 * Proof that a receipt exists in a Merkle tree.
 * Used for proving receipt pre-existence.
 */
struct MerkleProof {
    std::vector<uint8_t> receipt_hash;   // Hash of the receipt being proven
    std::vector<std::vector<uint8_t>> siblings; // Sibling hashes in proof path
    std::vector<bool> directions;         // true = right, false = left
    std::vector<uint8_t> root;           // Expected Merkle root

    MerkleProof() = default;
};

}  // namespace model
}  // namespace zoobc

#endif  // ZOOBC_MODEL_RECEIPT_BATCH_H
