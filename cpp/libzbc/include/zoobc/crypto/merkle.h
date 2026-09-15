// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_CRYPTO_MERKLE_H
#define ZOOBC_CRYPTO_MERKLE_H

#include <vector>
#include <cstdint>
#include <array>
#include "zoobc/common/result.h"
#include "zoobc/model/transaction.h"  // For Receipt
#include "zoobc/model/receipt_batch.h"  // For MerkleProof

namespace zoobc {
namespace crypto {

/**
 * NULL_MERKLE_ROOT - The canonical empty Merkle tree root hash.
 *
 * This is the standard representation for an empty tree (zero transactions,
 * zero receipts, etc.). Using a deterministic constant ensures consensus
 * compatibility across all nodes - every node produces the same root hash
 * for empty inputs.
 *
 * Value: 32 bytes of zeros (0x00 repeated 32 times)
 *
 * This constant should be used whenever:
 * - A block contains no transactions
 * - A receipt batch is empty
 * - Any Merkle tree computation has zero leaves
 */
constexpr std::array<uint8_t, 32> NULL_MERKLE_ROOT_ARRAY = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/**
 * Helper function to get NULL_MERKLE_ROOT as a vector.
 * Use this when interfacing with APIs that require std::vector<uint8_t>.
 */
inline std::vector<uint8_t> GetNullMerkleRoot() {
    return std::vector<uint8_t>(NULL_MERKLE_ROOT_ARRAY.begin(), NULL_MERKLE_ROOT_ARRAY.end());
}

/**
 * Merkle Tree Utilities
 *
 * Implements Merkle tree operations for receipt batching and proof generation.
 * Uses SHA3-256 for hashing.
 */
class Merkle {
public:
    /**
     * Compute the Merkle root of a list of receipt hashes.
     * Returns 32-byte root hash.
     *
     * Empty Input Handling:
     * - If leaf_hashes is empty, returns NULL_MERKLE_ROOT (32 bytes of zeros)
     * - This ensures deterministic behavior and consensus compatibility
     */
    static Result<std::vector<uint8_t>> ComputeRoot(
        const std::vector<std::vector<uint8_t>>& leaf_hashes);

    /**
     * Compute the Merkle root of a list of receipts.
     * First hashes each receipt, then computes tree root.
     *
     * Empty Input Handling:
     * - If receipts is empty, returns NULL_MERKLE_ROOT (32 bytes of zeros)
     * - This ensures deterministic behavior and consensus compatibility
     */
    static Result<std::vector<uint8_t>> ComputeRootFromReceipts(
        const std::vector<model::Receipt>& receipts);

    /**
     * Generate a Merkle proof for a specific leaf
     * leaf_index: 0-based index of the leaf to prove
     * Returns proof path (sibling hashes and directions)
     */
    static Result<model::MerkleProof> GenerateProof(
        const std::vector<std::vector<uint8_t>>& leaf_hashes,
        size_t leaf_index);

    /**
     * Verify a Merkle proof
     * Returns true if the proof is valid for the given root
     */
    static Result<bool> VerifyProof(
        const model::MerkleProof& proof);

    /**
     * Verify intermediate hashes to reconstruct Merkle root
     *
     * Matches Go's GetMerkleRootFromIntermediateHashes (merkleRoot.go)
     * Given a leaf hash and intermediate hashes, reconstruct the root
     * and compare with the expected root.
     *
     * @param leaf_hash The hash of the leaf node (receipt hash)
     * @param leaf_index Index of the leaf in the tree (0-based)
     * @param intermediate_hashes Flattened intermediate hashes (32 bytes each)
     * @param expected_root The expected merkle root to verify against
     * @return true if computed root matches expected_root
     */
    static Result<bool> VerifyIntermediateHashes(
        const std::vector<uint8_t>& leaf_hash,
        uint32_t leaf_index,
        const std::vector<uint8_t>& intermediate_hashes,
        const std::vector<uint8_t>& expected_root);

    /**
     * Restore intermediate hashes from flattened bytes
     *
     * Matches Go's RestoreIntermediateHashes (merkleRoot.go)
     * Converts flattened bytes into a vector of 32-byte hashes
     *
     * @param flattened Flattened intermediate hashes
     * @return Vector of intermediate hash buffers
     */
    static Result<std::vector<std::vector<uint8_t>>> RestoreIntermediateHashes(
        const std::vector<uint8_t>& flattened);

    /**
     * Get Merkle root from intermediate hashes
     *
     * Matches Go's GetMerkleRootFromIntermediateHashes (merkleRoot.go)
     * Walks up the tree using intermediate hashes to compute root
     *
     * @param leaf_hash The leaf node hash
     * @param leaf_index Index of the leaf
     * @param intermediate_hashes Vector of intermediate hash buffers
     * @return Computed merkle root
     */
    static Result<std::vector<uint8_t>> GetMerkleRootFromIntermediateHashes(
        const std::vector<uint8_t>& leaf_hash,
        uint32_t leaf_index,
        const std::vector<std::vector<uint8_t>>& intermediate_hashes);

    /**
     * Hash a receipt to create a leaf hash
     * Hashes all fields except metadata (id, created_at, published, etc.)
     */
    static Result<std::vector<uint8_t>> HashReceipt(
        const model::Receipt& receipt);

private:
    /**
     * Hash two nodes together (internal Merkle tree node)
     * Always concatenates left || right before hashing
     */
    static Result<std::vector<uint8_t>> HashNodes(
        const std::vector<uint8_t>& left,
        const std::vector<uint8_t>& right);

    /**
     * Build Merkle tree and return all levels.
     * Used internally for proof generation.
     *
     * Empty Input Handling:
     * - If leaf_hashes is empty, returns a single-level tree containing NULL_MERKLE_ROOT
     */
    static Result<std::vector<std::vector<std::vector<uint8_t>>>> BuildTree(
        const std::vector<std::vector<uint8_t>>& leaf_hashes);
};

}  // namespace crypto
}  // namespace zoobc

#endif  // ZOOBC_CRYPTO_MERKLE_H
