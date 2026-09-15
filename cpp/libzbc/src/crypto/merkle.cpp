// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/crypto/merkle.h"
#include "zoobc/crypto/hash.h"
#include <cstring>
#include <iostream>

namespace zoobc {
namespace crypto {

Result<std::vector<uint8_t>> Merkle::HashReceipt(const model::Receipt& receipt) {
    // Hash all fields in the receipt (200-byte structure)
    // CRITICAL: Field order must match Go's GetSignedReceiptBytes from receiptUtil.go:396-405
    // Go order:
    // 1. SenderPublicKey (32 bytes)
    // 2. RecipientPublicKey (32 bytes)
    // 3. ReferenceBlockHeight (4 bytes)
    // 4. ReferenceBlockHash (32 bytes)
    // 5. DatumType (4 bytes)
    // 6. DatumHash (32 bytes)
    // 7. RMR (32 bytes)
    // 8. RecipientSignature (64 bytes)

    std::vector<uint8_t> data;
    data.reserve(232);  // 32+32+4+32+4+32+32+64 = 232 bytes

    // 1. Sender public key (32 bytes)
    if (receipt.sender_public_key.size() != 32) {
        return Error{ErrorCode::InvalidArgument, "Invalid sender public key size"};
    }
    data.insert(data.end(), receipt.sender_public_key.begin(), receipt.sender_public_key.end());

    // 2. Recipient public key (32 bytes)
    if (receipt.recipient_public_key.size() != 32) {
        return Error{ErrorCode::InvalidArgument, "Invalid recipient public key size"};
    }
    data.insert(data.end(), receipt.recipient_public_key.begin(), receipt.recipient_public_key.end());

    // 3. Reference block height (4 bytes) - CORRECT POSITION
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&receipt.reference_block_height),
                           reinterpret_cast<const uint8_t*>(&receipt.reference_block_height) + 4);

    // 4. Reference block hash (32 bytes) - CORRECT POSITION
    if (receipt.reference_block_hash.size() != 32) {
        return Error{ErrorCode::InvalidArgument, "Invalid reference block hash size"};
    }
    data.insert(data.end(), receipt.reference_block_hash.begin(), receipt.reference_block_hash.end());

    // 5. Datum type (4 bytes) - CORRECT POSITION
    uint32_t datum_type_val = static_cast<uint32_t>(receipt.datum_type);
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&datum_type_val),
                           reinterpret_cast<const uint8_t*>(&datum_type_val) + 4);

    // 6. Datum hash (32 bytes) - CORRECT POSITION
    if (receipt.datum_hash.size() != 32) {
        return Error{ErrorCode::InvalidArgument, "Invalid datum hash size"};
    }
    data.insert(data.end(), receipt.datum_hash.begin(), receipt.datum_hash.end());

    // 7. Receipt Merkle root (rmr) (32 bytes) - optional, may be empty
    if (!receipt.rmr.empty()) {
        if (receipt.rmr.size() != 32) {
            return Error{ErrorCode::InvalidArgument, "Invalid receipt merkle root size"};
        }
        data.insert(data.end(), receipt.rmr.begin(), receipt.rmr.end());
    } else {
        // Insert zeros if rmr is empty
        data.insert(data.end(), 32, 0);
    }

    // 8. Recipient signature (64 bytes)
    if (receipt.recipient_signature.size() != 64) {
        return Error{ErrorCode::InvalidArgument, "Invalid recipient signature size"};
    }
    data.insert(data.end(), receipt.recipient_signature.begin(), receipt.recipient_signature.end());

    // Hash the concatenated data
    return Hash::SHA3_256(data);
}

Result<std::vector<uint8_t>> Merkle::HashNodes(
    const std::vector<uint8_t>& left,
    const std::vector<uint8_t>& right) {

    // Concatenate left || right
    std::vector<uint8_t> data;
    data.reserve(left.size() + right.size());
    data.insert(data.end(), left.begin(), left.end());
    data.insert(data.end(), right.begin(), right.end());

    return Hash::SHA3_256(data);
}

Result<std::vector<std::vector<std::vector<uint8_t>>>> Merkle::BuildTree(
    const std::vector<std::vector<uint8_t>>& leaf_hashes) {

    // Handle empty input: return a tree with only the NULL_MERKLE_ROOT
    // This ensures deterministic behavior for empty trees (e.g., blocks with no transactions)
    if (leaf_hashes.empty()) {
        std::vector<std::vector<std::vector<uint8_t>>> empty_tree;
        empty_tree.push_back({GetNullMerkleRoot()});  // Single level with null root
        return empty_tree;
    }

    std::vector<std::vector<std::vector<uint8_t>>> levels;
    levels.push_back(leaf_hashes);  // Level 0: leaves

    // Build tree bottom-up
    size_t current_level = 0;
    while (levels[current_level].size() > 1) {
        const auto& current = levels[current_level];
        std::vector<std::vector<uint8_t>> next_level;

        // Process pairs
        for (size_t i = 0; i < current.size(); i += 2) {
            if (i + 1 < current.size()) {
                // Hash pair
                auto hash_result = HashNodes(current[i], current[i + 1]);
                if (hash_result.IsErr()) {
                    return Error{hash_result.GetError()};
                }
                next_level.push_back(hash_result.Value());
            } else {
                // Odd number of nodes - duplicate last node
                auto hash_result = HashNodes(current[i], current[i]);
                if (hash_result.IsErr()) {
                    return Error{hash_result.GetError()};
                }
                next_level.push_back(hash_result.Value());
            }
        }

        levels.push_back(next_level);
        current_level++;
    }

    return levels;
}

Result<std::vector<uint8_t>> Merkle::ComputeRoot(
    const std::vector<std::vector<uint8_t>>& leaf_hashes) {

    // Handle empty input: return the canonical NULL_MERKLE_ROOT (32 bytes of zeros)
    // This ensures deterministic behavior and consensus compatibility for empty trees
    if (leaf_hashes.empty()) {
        return GetNullMerkleRoot();
    }

    if (leaf_hashes.size() == 1) {
        return leaf_hashes[0];
    }

    auto tree_result = BuildTree(leaf_hashes);
    if (tree_result.IsErr()) {
        return Error{tree_result.GetError()};
    }

    auto tree = tree_result.Value();
    return tree.back()[0];  // Root is the single node at the top level
}

Result<std::vector<uint8_t>> Merkle::ComputeRootFromReceipts(
    const std::vector<model::Receipt>& receipts) {

    // Handle empty input: return the canonical NULL_MERKLE_ROOT (32 bytes of zeros)
    // This ensures deterministic behavior for blocks with no receipts
    if (receipts.empty()) {
        return GetNullMerkleRoot();
    }

    // Hash all receipts to create leaf nodes
    std::vector<std::vector<uint8_t>> leaf_hashes;
    leaf_hashes.reserve(receipts.size());

    for (const auto& receipt : receipts) {
        auto hash_result = HashReceipt(receipt);
        if (hash_result.IsErr()) {
            return Error{hash_result.GetError()};
        }
        leaf_hashes.push_back(hash_result.Value());
    }

    return ComputeRoot(leaf_hashes);
}

Result<model::MerkleProof> Merkle::GenerateProof(
    const std::vector<std::vector<uint8_t>>& leaf_hashes,
    size_t leaf_index) {

    if (leaf_index >= leaf_hashes.size()) {
        return Error{ErrorCode::OutOfRange, "Leaf index out of range"};
    }

    auto tree_result = BuildTree(leaf_hashes);
    if (tree_result.IsErr()) {
        return Error{tree_result.GetError()};
    }

    auto tree = tree_result.Value();
    model::MerkleProof proof;
    proof.receipt_hash = leaf_hashes[leaf_index];
    proof.root = tree.back()[0];

    // Traverse tree from leaf to root, collecting sibling hashes
    size_t current_index = leaf_index;

    for (size_t level = 0; level < tree.size() - 1; level++) {
        const auto& level_nodes = tree[level];
        size_t sibling_index;
        bool is_right;

        if (current_index % 2 == 0) {
            // Current node is left child
            sibling_index = current_index + 1;
            is_right = true;  // Sibling is on the right
        } else {
            // Current node is right child
            sibling_index = current_index - 1;
            is_right = false;  // Sibling is on the left
        }

        // Handle odd number of nodes (last node duplicated)
        if (sibling_index >= level_nodes.size()) {
            sibling_index = current_index;
        }

        proof.siblings.push_back(level_nodes[sibling_index]);
        proof.directions.push_back(is_right);

        // Move to parent node
        current_index = current_index / 2;
    }

    return proof;
}

Result<bool> Merkle::VerifyProof(const model::MerkleProof& proof) {
    if (proof.siblings.size() != proof.directions.size()) {
        return Error{ErrorCode::InvalidArgument, "Proof siblings and directions size mismatch"};
    }

    if (proof.siblings.empty()) {
        // Single-node tree
        return proof.receipt_hash == proof.root;
    }

    // Start with the receipt hash
    std::vector<uint8_t> current_hash = proof.receipt_hash;

    // Traverse up the tree using sibling hashes
    for (size_t i = 0; i < proof.siblings.size(); i++) {
        const auto& sibling = proof.siblings[i];
        bool is_right = proof.directions[i];

        Result<std::vector<uint8_t>> hash_result = is_right
            ? HashNodes(current_hash, sibling)  // Sibling is on the right
            : HashNodes(sibling, current_hash);  // Sibling is on the left

        if (hash_result.IsErr()) {
            return Error{hash_result.GetError()};
        }

        current_hash = hash_result.Value();
    }

    // Check if computed root matches expected root
    return current_hash == proof.root;
}

Result<std::vector<std::vector<uint8_t>>> Merkle::RestoreIntermediateHashes(
    const std::vector<uint8_t>& flattened) {

    // Matches Go's RestoreIntermediateHashes (merkleRoot.go)
    // Converts flattened bytes into a vector of 32-byte hashes

    constexpr size_t HASH_SIZE = 32;

    if (flattened.empty()) {
        return std::vector<std::vector<uint8_t>>{};
    }

    if (flattened.size() % HASH_SIZE != 0) {
        return Error{ErrorCode::InvalidArgument,
                     "Intermediate hashes length not a multiple of hash size"};
    }

    std::vector<std::vector<uint8_t>> hashes;
    size_t num_hashes = flattened.size() / HASH_SIZE;
    hashes.reserve(num_hashes);

    for (size_t i = 0; i < num_hashes; i++) {
        std::vector<uint8_t> hash(
            flattened.begin() + (i * HASH_SIZE),
            flattened.begin() + ((i + 1) * HASH_SIZE)
        );
        hashes.push_back(hash);
    }

    return hashes;
}

Result<std::vector<uint8_t>> Merkle::GetMerkleRootFromIntermediateHashes(
    const std::vector<uint8_t>& leaf_hash,
    uint32_t leaf_index,
    const std::vector<std::vector<uint8_t>>& intermediate_hashes) {

    // Matches Go's GetMerkleRootFromIntermediateHashes (merkleRoot.go)
    // Walks up the tree using intermediate hashes to compute root

    if (intermediate_hashes.empty()) {
        // Single-node tree - leaf is the root
        return leaf_hash;
    }

    std::vector<uint8_t> current_hash = leaf_hash;
    uint32_t current_index = leaf_index;

    // Walk up the tree
    for (const auto& sibling : intermediate_hashes) {
        // Determine if we're the left or right child based on index parity
        // Even index = left child, odd index = right child
        bool is_left_child = (current_index % 2) == 0;

        auto hash_result = is_left_child
            ? HashNodes(current_hash, sibling)   // We're left, sibling is right: hash(us || sibling)
            : HashNodes(sibling, current_hash);  // We're right, sibling is left: hash(sibling || us)

        if (hash_result.IsErr()) {
            return Error{hash_result.GetError()};
        }

        current_hash = hash_result.Value();

        // Move up to parent index
        current_index = current_index / 2;
    }

    return current_hash;
}

Result<bool> Merkle::VerifyIntermediateHashes(
    const std::vector<uint8_t>& leaf_hash,
    uint32_t leaf_index,
    const std::vector<uint8_t>& intermediate_hashes,
    const std::vector<uint8_t>& expected_root) {

    // Matches Go's GetMerkleRootFromIntermediateHashes validation

    // Restore intermediate hashes from flattened bytes
    auto restore_result = RestoreIntermediateHashes(intermediate_hashes);
    if (restore_result.IsErr()) {
        return Error{restore_result.GetError()};
    }

    auto hashes = restore_result.Value();

    // Compute the root from intermediate hashes
    auto root_result = GetMerkleRootFromIntermediateHashes(leaf_hash, leaf_index, hashes);
    if (root_result.IsErr()) {
        return Error{root_result.GetError()};
    }

    auto computed_root = root_result.Value();

    // Compare with expected root
    return computed_root == expected_root;
}

}  // namespace crypto
}  // namespace zoobc
