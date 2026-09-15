// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_COMMON_CONSTANTS_H
#define ZOOBC_COMMON_CONSTANTS_H

#include <cstddef>
#include <cstdint>
#include <array>
#include <vector>
#include <cstring>
#include <algorithm>  // For std::min

#include "zoobc/common/types.h"  // TransactionType, IsNodeFeeExemptType

namespace zoobc {

// 128-bit intermediate for money arithmetic that would overflow int64 on the way to a result that
// fits. Used where a balance is scaled by a share (deposit x price, pool x participation score):
// the operands are each well inside int64 but their product is not, and the alternatives are worse —
// long double silently loses precision on values this large, and the q/r split this codebase uses
// elsewhere still overflows when both factors are large.
//
// __int128 is a GCC/Clang extension rather than ISO C++, so a bare use draws -Wpedantic on every
// line that mentions it. __extension__ is the sanctioned way to say "this is deliberate": it
// silences the diagnostic for the alias without disabling the warning anywhere else, and it changes
// nothing about the code generated.
__extension__ typedef __int128 int128_t;

namespace constants {

// Genesis Account Address (matching Go: common/constant/genesis.go)
// This is the special account used for genesis block transactions
// ZBC_ODR3YPWN_FQBDD6SV_OJ3YO3PK_E5UVSXW3_5DYQ3PTL_AXSJKNQ4_UDLNXYXC
// The genesis account is exempt from certain validations (e.g., balance checks)
constexpr std::array<uint8_t, 36> MAINCHAIN_GENESIS_ACCOUNT_ADDRESS = {
    0, 0, 0, 0,  // Account type prefix (ZBC = 0)
    4, 38, 67, 253, 92, 95, 59, 100, 189, 107, 56, 136,
    47, 119, 39, 253, 197, 214, 238, 227, 195, 84, 243, 171,
    157, 123, 143, 247, 193, 132, 1, 64
};

// Helper function to check if an address is the genesis account
inline bool IsGenesisAccount(const std::vector<uint8_t>& address) {
    if (address.size() != MAINCHAIN_GENESIS_ACCOUNT_ADDRESS.size()) {
        return false;
    }
    return std::memcmp(address.data(), MAINCHAIN_GENESIS_ACCOUNT_ADDRESS.data(),
                       MAINCHAIN_GENESIS_ACCOUNT_ADDRESS.size()) == 0;
}

// Cryptography constants
constexpr size_t PUBLIC_KEY_SIZE  = 32;
constexpr size_t PRIVATE_KEY_SIZE = 64;
constexpr size_t SIGNATURE_SIZE   = 64;
constexpr size_t HASH_SIZE        = 32;

// ZBC Unit (matching Go's OneZBC = 100000000)
constexpr int64_t ONE_ZBC = 100000000LL;  // 10^8 - smallest unit

// Participation Score constants (matching genesis-builder.cpp values)
// These must match the values in genesis-builder.cpp to avoid score/penalty mismatch!
// CRITICAL: If MAX_PARTICIPATION_SCORE is too high, penalties will instantly expel nodes.
constexpr int64_t SCALAR_RECEIPT_SCORE = 1;  // Simplified - no need for ONE_ZBC scaling
// MaxParticipationScore = 10 trillion (matches genesis-builder.cpp)
constexpr int64_t MAX_PARTICIPATION_SCORE     = 10000000000000LL;  // 10^13 = 10 trillion
constexpr int64_t DEFAULT_PARTICIPATION_SCORE = 2000000000000LL;   // 2 trillion (20% of max)
constexpr int64_t GENESIS_PARTICIPATION_SCORE = MAX_PARTICIPATION_SCORE;  // 100% of max for genesis nodes
constexpr int64_t MIN_PARTICIPATION_SCORE     = 0;

// Receipt score constants (matching Go: LinkedReceiptScore = 1, UnlinkedReceiptScore = 1)
constexpr uint32_t LINKED_RECEIPT_SCORE   = 1;
constexpr uint32_t UNLINKED_RECEIPT_SCORE = 1;

// Priority strategy (matching Go's PriorityStrategyMaxPriorityPeers = 5). This is the DEFAULT seed;
// the effective value is genesis-tunable via `max_assigned_peers` and read through the accessors
// below (GetMaxPriorityPeers / ReceiptScorePivot / MaxReceiptCount). All PoP receipt/topology/scoring
// math derives from it, so every node must use the identical genesis value (committed to the hash).
constexpr uint32_t PRIORITY_STRATEGY_MAX_PRIORITY_PEERS = 5;
constexpr uint32_t RECEIPT_SCORE_PIVOT = PRIORITY_STRATEGY_MAX_PRIORITY_PEERS - 1;  // legacy default = 4
constexpr uint32_t MAX_RECEIPT_COUNT = PRIORITY_STRATEGY_MAX_PRIORITY_PEERS;        // legacy default = 5

// Genesis-tunable priority-peer count. Set once at startup from the loaded consensus params
// (SetMaxPriorityPeers), exactly like g_network_mode. Defaults to the Go value 5 so behavior is
// unchanged when `max_assigned_peers` is unset.
inline uint32_t g_max_priority_peers = PRIORITY_STRATEGY_MAX_PRIORITY_PEERS;
// Clamp to a floor of 2: the participation-score formula divides by MaxReceiptCount()/2, so a value
// of 1 would divide by zero. 2 is the smallest meaningful priority-peer set anyway.
inline void SetMaxPriorityPeers(uint32_t n) { g_max_priority_peers = (n >= 2) ? n : 2; }
inline uint32_t GetMaxPriorityPeers() { return g_max_priority_peers; }
inline uint32_t ReceiptScorePivot() { return g_max_priority_peers - 1; }  // = MaxPriorityPeers - 1
inline uint32_t MaxReceiptCount()   { return g_max_priority_peers; }      // = MaxPriorityPeers

// Score update threshold (matching Go's BatchReceiptLookBackHeight = 40)
constexpr uint32_t BATCH_RECEIPT_LOOKBACK_HEIGHT = 40;  // Score updates start at block 40

// Wall-clock seconds in a week. Used to DERIVE the nominal "blocks per week" from the block-time
// interval (blocks_per_week = SECONDS_PER_WEEK / block_time_interval), so score-timing tracks the
// configured block cadence automatically instead of being a second hand-entered number.
constexpr int64_t SECONDS_PER_WEEK = 7 * 24 * 60 * 60;  // 604800

// Time constants (blocks) - Go uses 1440 * 4 * 7 = 40320 blocks per week (assuming 15s blocks)
constexpr uint32_t BLOCKS_PER_PERIOD = 1440 * 4 * 7;    // = 40320 blocks/week (Go: BlocksPerPeriod)
constexpr uint32_t BLOCKS_PER_WEEK   = BLOCKS_PER_PERIOD;
constexpr uint32_t BLOCKS_PER_DAY    = BLOCKS_PER_PERIOD / 7;
constexpr uint32_t BLOCKS_PER_HOUR   = BLOCKS_PER_DAY / 24;
constexpr uint32_t BLOCKS_PER_MINUTE = BLOCKS_PER_HOUR / 60;

// Score dynamics constants (matching Go exactly)
constexpr int INCREASE_SCORE_DIVIDER = 12;  // 12 weeks to reach max from zero
constexpr int DECREASE_SCORE_DIVIDER = 2;   // 2 weeks to drop from max to zero

// Score change units (matching genesis-builder proportions)
// MaxScoreChange = proportional to MAX_PARTICIPATION_SCORE (roughly 0.1% of max per block penalty)
constexpr int64_t MAX_SCORE_CHANGE = MAX_PARTICIPATION_SCORE / 10000;  // 1 billion
// ParticipationScorePunishAmount = -MaxScoreChange / 2
constexpr int64_t PARTICIPATION_SCORE_PUNISH_AMOUNT = -1 * MAX_SCORE_CHANGE / 2;
// ScoreChangeUnit = MaxParticipationScore / BlocksPerPeriod
constexpr int64_t SCORE_CHANGE_UNIT = MAX_PARTICIPATION_SCORE / BLOCKS_PER_PERIOD;
// IncreaseScoreUnit = ScoreChangeUnit / IncreaseScoreDivider
constexpr int64_t INCREASE_SCORE_UNIT = SCORE_CHANGE_UNIT / INCREASE_SCORE_DIVIDER;
// DecreaseScoreUnit = ScoreChangeUnit / DecreaseScoreDivider
constexpr int64_t DECREASE_SCORE_UNIT = SCORE_CHANGE_UNIT / DECREASE_SCORE_DIVIDER;

// Block constants - PoP specification
// DO NOT "FIX" THIS TO 15. Blocks land 15 seconds apart, so this looks wrong and has been changed
// to 15 at least three times — each time breaking the chain. The 15-second spacing comes from
// SMITHING_PERIOD below (the wait before the first blocksmith may publish), NOT from this.
// This is PoP's ΔBt: it feeds participation-score timing and the validator's minimum-interval
// bound, where 10 is correct. Two constants, similar names, different jobs.
constexpr int64_t BLOCK_TIME_INTERVAL = 10;  // PoP: ΔBt = 10 seconds per block
constexpr uint32_t MAX_BLOCK_SIZE     = 2 * 1024 * 1024;  // 2 MB

// Incomplete block queue timeouts (matching Go's TimeOutBlockWaitingTransactions)
constexpr int64_t TIMEOUT_BLOCK_WAITING_TRANSACTIONS = 2 * 60;  // 2 minutes
constexpr int64_t CHECK_TIMEOUT_BLOCK_WAITING_TRANSACTIONS = 30;  // seconds

// Smithing time windows (matching Go implementation exactly)
// These define when each blocksmith can produce their block
// NOTE: These are DEFAULTS - can be overridden in genesis config via consensus_params
constexpr int64_t SMITHING_PERIOD = 15;           // Go: MainChainSmithingPeriod - wait after previous block
constexpr int64_t BLOCK_CREATION_TIME = 30;       // Go: MainSmithingBlockCreationTime - window to create block
constexpr int64_t NETWORK_TOLERANCE = 15;         // Go: MainSmithingNetworkTolerance - propagation tolerance
constexpr int64_t BLOCKSMITH_TIME_GAP = 10;       // Go: MainSmithingBlocksmithTimeGap - gap between turns

// Timing design (from Go blocksmithStrategyMain.go):
// - First blocksmith: starts at previousBlock.Timestamp + SMITHING_PERIOD (15s)
//   Valid window: 15s to 60s (SMITHING_PERIOD to SMITHING_PERIOD + BLOCK_CREATION_TIME + NETWORK_TOLERANCE)
// - Each subsequent blocksmith: starts BLOCKSMITH_TIME_GAP (10s) later
//   Each has a 45s window (BLOCK_CREATION_TIME + NETWORK_TOLERANCE)
// - Windows OVERLAP by 35s (45s window - 10s gap), allowing multiple valid producers
// - Cumulative difficulty favors blocks produced by earlier/higher-priority blocksmiths
constexpr int64_t EMPTY_BLOCK_SKIPPED_LIMIT = 10; // Go: EmptyBlockSkippedBlocksmithLimit

// Transaction constants (matching Go: common/constant/transaction.go)
constexpr int MAX_MESSAGE_LENGTH = 64000;  // 64kb
constexpr int MAX_MESSAGE_LENGTH_ESCROW_INSTRUCTION = 128000;  // 128kb
constexpr int MAX_NUMBER_OF_TRANSACTIONS_IN_BLOCK = 500;
constexpr int MIN_TRANSACTION_SIZE_IN_BLOCK = 176;
constexpr int MAX_PAYLOAD_LENGTH_IN_BLOCK = MIN_TRANSACTION_SIZE_IN_BLOCK * MAX_NUMBER_OF_TRANSACTIONS_IN_BLOCK;
constexpr int64_t TRANSACTION_EXPIRATION_OFFSET = 3600;  // 3600 seconds
constexpr int64_t ONE_FEE_PER_BYTE_TRANSACTION = 10000;  // Used for fee per byte accuracy
constexpr int COMPLETE_MINUTES_UNIT = 60;  // 60 seconds

// Fee constants (matching Go: common/fee/constant.go)
// SendZBCFeeConstant = OneZBC / 100 = 1,000,000
constexpr int64_t SEND_ZBC_FEE_CONSTANT = ONE_ZBC / 100;
// InitialFeeScale = OneZBC / 100 = 1,000,000
constexpr int64_t INITIAL_FEE_SCALE = ONE_ZBC / 100;
constexpr double FEE_SCALE_LOWER_CONSTRAINTS = 0.5;
constexpr double FEE_SCALE_UPPER_CONSTRAINTS = 2.0;
constexpr double FEE_PER_CHARACTER_MULTIPLIER = 0.1;  // 1000 char = 1 ZBC with initial fee
constexpr int ESCROW_LIFETIME_DIVIDER = 24;  // 24 hours

// Node registration constants
constexpr int64_t MIN_NODE_REGISTRATION_BALANCE = 100000000;  // 1 ZBC
constexpr uint32_t NODE_REGISTRATION_PERIOD     = BLOCKS_PER_WEEK * 52;  // 1 year

// Database constants
constexpr int DATABASE_SCHEMA_VERSION = 1;

// Network constants
constexpr uint16_t DEFAULT_P2P_PORT  = 7000;
constexpr uint16_t DEFAULT_API_PORT  = 7001;
constexpr uint32_t MAX_PEER_COUNT    = 100;
constexpr uint32_t MIN_PEER_COUNT    = 4;

// Consensus constants (matching Go: common/constant/blockchainSync.go)
// MinRollbackBlocks = 1440: circa half week for a network generating ~2 blocks/minute
constexpr uint32_t MIN_ROLLBACK_BLOCKS = 1440;  // Go: MinRollbackBlocks
constexpr uint32_t SAFE_BLOCK_GAP = MIN_ROLLBACK_BLOCKS / 2;  // Go: SafeBlockGap = 720

// Confirmation depth: the chain keeps producing at the tip, but the last few
// blocks routinely churn (single-block forks resolve in seconds), so any state
// READ or settlement that surfaces to users/wallets should treat
//   confirmed_height = max(0, tip_height - CONFIRMATION_DEPTH)
// as the source of truth. This excludes the reorg-prone tail, so balances,
// token holdings, liquid vesting and cross-node quorum stop flapping. Block
// PRODUCTION/validation still works at the tip; only reads lag by this much.
// 3 blocks ≈ ~1.5 minutes at ~2 blocks/min — users wait ~2 blocks for finality.
constexpr uint32_t CONFIRMATION_DEPTH = 3;

// ============================================================================
// Network Mode Configuration
// ============================================================================
// Network mode affects various parameters like snapshot chunk size, pruning
// intervals, and timing tolerances. Detected from genesis config "is_test_chain".

enum class NetworkMode : uint8_t {
    Mainnet = 0,
    Testnet = 1
};

// Global network mode (set at startup from genesis config)
// Default to Testnet for safety - mainnet requires explicit configuration
inline NetworkMode g_network_mode = NetworkMode::Testnet;

// Helper to check network mode
inline bool IsTestnet() { return g_network_mode == NetworkMode::Testnet; }
inline bool IsMainnet() { return g_network_mode == NetworkMode::Mainnet; }

// Set network mode from genesis config "is_test_chain" field
inline void SetNetworkMode(bool is_test_chain) {
    g_network_mode = is_test_chain ? NetworkMode::Testnet : NetworkMode::Mainnet;
}

// ============================================================================
// Snapshot Constants (matching Go: common/constant/snapshot.go)
// ============================================================================
// Values differ between testnet and mainnet for practical reasons:
// - Testnet: smaller chunks, more frequent snapshots for faster testing
// - Mainnet: larger chunks, monthly snapshots for production efficiency

// Snapshot chunk size: Testnet=100KB, Mainnet=1MB
constexpr uint32_t SNAPSHOT_CHUNK_SIZE_BYTES_TESTNET = 100 * 1024;   // 100 KB
constexpr uint32_t SNAPSHOT_CHUNK_SIZE_BYTES_MAINNET = 1024 * 1024;  // 1 MB

inline uint32_t GetSnapshotChunkSize() {
    return IsTestnet() ? SNAPSHOT_CHUNK_SIZE_BYTES_TESTNET : SNAPSHOT_CHUNK_SIZE_BYTES_MAINNET;
}

// Snapshot generation timeout: Testnet=10min, Mainnet=30min
constexpr int64_t SNAPSHOT_GENERATION_TIMEOUT_TESTNET = 10 * 60;   // 10 minutes
constexpr int64_t SNAPSHOT_GENERATION_TIMEOUT_MAINNET = 30 * 60;   // 30 minutes

inline int64_t GetSnapshotGenerationTimeout() {
    return IsTestnet() ? SNAPSHOT_GENERATION_TIMEOUT_TESTNET : SNAPSHOT_GENERATION_TIMEOUT_MAINNET;
}

// Snapshot interval in blocks: Testnet=1440 (~12h), Mainnet=172800 (~30 days)
constexpr uint32_t SNAPSHOT_INTERVAL_TESTNET = 1440;        // ~12 hours at 2 blocks/min
constexpr uint32_t SNAPSHOT_INTERVAL_MAINNET = 172800;      // ~30 days at 2 blocks/min

inline uint32_t GetSnapshotInterval() {
    return IsTestnet() ? SNAPSHOT_INTERVAL_TESTNET : SNAPSHOT_INTERVAL_MAINNET;
}

// Legacy constants for backward compatibility (use functions above instead)
constexpr uint32_t SNAPSHOT_CHUNK_SIZE_BYTES = 100 * 1024;  // Deprecated: use GetSnapshotChunkSize()
constexpr int64_t SNAPSHOT_GENERATION_TIMEOUT_SECONDS = 10 * 60;  // Deprecated

// Lifetime of a snapshot manifest (how long peers advertise it as a valid fast-sync
// target). This MUST outlast the gap to the NEXT snapshot, otherwise the latest manifest
// expires before the next snapshot is created, leaving a recurring window in which
// ShouldUseFastSync() finds no valid manifest -> a node that lost its DB falls back to
// linear block-replay and gets stuck on already-pruned block payloads (unrecoverable).
//
// The lifetime is AUTO-DERIVED from the actual cadence so it can never go stale when the
// snapshot interval changes (e.g. monthly vs. every 240 blocks):
//     lifetime = max( configured_override,
//                     SNAPSHOT_MANIFEST_SAFETY_FACTOR * snapshot_interval_blocks * block_time_s,
//                     SNAPSHOT_MANIFEST_MIN_EXPIRATION_SECONDS )
// The SAFETY_FACTOR term is what guarantees no dead zone; the MIN floor is a comfort
// minimum for tiny dev intervals; a config override is honored only if LARGER (the genesis
// validator rejects a smaller explicit override). GetLatestManifest always returns the
// newest manifest, so a long lifetime only ever keeps the latest one usable.
constexpr int64_t SNAPSHOT_MANIFEST_SAFETY_FACTOR = 3;                          // >= 2 keeps continuity
constexpr int64_t SNAPSHOT_MANIFEST_MIN_EXPIRATION_SECONDS = 30LL * 24 * 60 * 60;  // 30-day floor

// ============================================================================
// Data Pruning Constants
// ============================================================================

// PruningChunkedSize = 500: deletes records in chunks to prevent large transactions
constexpr uint32_t PRUNING_CHUNKED_SIZE = 500;  // Go: PruningChunkedSize

// Number of snapshots to keep for rollback safety
// We keep 2 snapshots: current + one previous for rollback
constexpr uint32_t SNAPSHOTS_TO_KEEP = 2;

// Calculate pruning height based on snapshot intervals
// Data older than (2 * snapshot_interval) can be pruned
inline uint32_t GetSnapshotBasedPruneHeight(uint32_t current_height) {
    uint32_t interval = GetSnapshotInterval();
    uint32_t keep_blocks = SNAPSHOTS_TO_KEEP * interval;
    if (current_height <= keep_blocks) {
        return 0;  // Not enough blocks yet
    }
    return current_height - keep_blocks;
}

// For rollback safety, use the more conservative of:
// - 2 * MIN_ROLLBACK_BLOCKS (for fork safety)
// - 2 * snapshot_interval (for rebuild safety)
inline uint32_t GetSafePruneHeight(uint32_t current_height) {
    uint32_t rollback_based = (current_height > 2 * MIN_ROLLBACK_BLOCKS)
        ? current_height - 2 * MIN_ROLLBACK_BLOCKS : 0;
    uint32_t snapshot_based = GetSnapshotBasedPruneHeight(current_height);
    // Use the LOWER height (more conservative - keep more data)
    return std::min(rollback_based, snapshot_based);
}

// Blocksmith selection constants (PoP consensus)
// Only top X nodes in priority list can produce normal blocks
// Nodes beyond this can only produce empty blocks
constexpr uint32_t MAX_PRIORITY_BLOCKSMITHS = 10;  // TBD: exact number pending

// Cumulative difficulty calculation
// Difficulty for a block = DIVISOR / (number of blocksmiths that could have produced it)
// Higher difficulty = block produced on time by high-priority blocksmith
// Lower difficulty = block produced late after many missed turns
constexpr int64_t CUMULATIVE_DIFFICULTY_DIVISOR = 1000000;  // 1 million

// Time constants for admission and coinbase
constexpr int64_t ONE_HOUR = 3600;  // seconds
constexpr int64_t ONE_DAY = 24 * ONE_HOUR;
constexpr int64_t ONE_YEAR = 365 * ONE_DAY;  // seconds per year

// ============================================================================
// Blocksmith Selection Constants (PoP Consensus)
// ============================================================================

// Seed prefix for blocksmith RNG selection (matching Go: common/constant/smith.go)
// Used to deterministically select blocksmiths from the node registry
constexpr const char* BLOCKSMITH_SELECTION_SEED_PREFIX = "zbc-blocksmith";

// Salt for turn-based randomness derivation
// Tr0 = hash(block_seed || BLOCKSMITH_TURN_SALT)
// Tri = hash(Tri-1) for i > 0
constexpr const char* BLOCKSMITH_TURN_SALT = "saltbcs";
constexpr size_t BLOCKSMITH_TURN_SALT_LENGTH = 7;

// Coinbase constants (matching Go: common/constant/smith.go)
constexpr const char* COINBASE_SELECTION_SEED_PREFIX = "zbc-coinbase";
constexpr int64_t COINBASE_TOTAL_DISTRIBUTION = 33000000LL * ONE_ZBC;  // 33 million ZBC total
constexpr int64_t COINBASE_TIME = 15 * ONE_YEAR;                       // 15 years distribution period
constexpr double COINBASE_SIGMOID_START = 3.0;
constexpr double COINBASE_SIGMOID_END = 6.0;
constexpr int64_t COINBASE_NUMBER_REWARDS_PER_SECOND = 1;              // 1 reward per second elapsed
constexpr int64_t COINBASE_MAX_NUMBER_REWARDS_PER_BLOCK = 600;         // Max rewards per block
// Large-fee smoothing: a big reward pool shouldn't be a jackpot for the few
// time-based lottery winners. Spread it across ~1 extra winner per this much pool
// (bounded by the 600 cap and the active node count). 0 disables. Stateless and
// deterministic — depends only on the pool size + active count, so all nodes agree.
constexpr int64_t COINBASE_SMOOTHING_PER_WINNER = ONE_ZBC;            // ~1 winner per 1 ZBC of pool

// PoP Consensus - Network Topology
// Network topology is reshuffled every ΔΥh blocks to ensure fairness
constexpr uint32_t TOPOLOGY_PERIOD_BLOCKS = 240;  // PoP: ΔΥh = 240 blocks (~1 hour at 15s/block)

// PoP Consensus - Receipt System
constexpr uint32_t RECEIPT_BATCH_SIZE = 100;           // Receipts per batch for Merkle tree
constexpr uint32_t RECEIPT_MERKLE_TREE_DEPTH = 10;     // Merkle tree depth (supports up to 1024 receipts)

// PoP Consensus - Node Admission Queue (matching Go implementation)
// Time-based admission: one node admitted per cycle
// Cycle interval = BaseDelay / numActiveNodes (bounded by min/max)

// Node admission timing (matching Go's node.go constants)
constexpr uint32_t MAX_NODE_ADMITTANCE_PER_CYCLE = 1;  // Go: MaxNodeAdmittancePerCycle = 1
constexpr int64_t NODE_ADMISSION_GENESIS_DELAY = 0;   // Go: NodeAdmissionGenesisDelay = 0
constexpr int64_t NODE_ADMISSION_BASE_DELAY = ONE_HOUR;  // Go: NodeAdmissionBaseDelay = 1 hour
constexpr int64_t NODE_ADMISSION_MIN_DELAY = 60;      // Go: NodeAdmissionMinDelay = 60 seconds
constexpr int64_t NODE_ADMISSION_MAX_DELAY = 72 * ONE_HOUR;  // Go: NodeAdmissionMaxDelay = 72 hours

// Queue expiry: nodes in queue > 30 days are removed
constexpr int64_t NODE_QUEUE_EXPIRY_SECONDS = 30 * ONE_DAY;

// Legacy admission rate constants (deprecated - use time-based admission instead)
constexpr uint32_t BASE_ADMISSION_RATE = 1;
constexpr uint32_t MAX_ADMISSION_RATE = 10;
constexpr uint32_t MAX_RATE_THRESHOLD = 1000;
constexpr uint32_t MIN_REGISTRY_SIZE = 10;

// ============================================================================
// AccountDataset Storage Billing Constants
// ============================================================================

// Monthly billing period in blocks (assuming ~15s per block, ~4 blocks/minute)
// 4 blocks/min * 60 min/hour * 24 hours/day * 30 days = 172,800 blocks/month
constexpr uint32_t DATASET_BILLING_PERIOD_BLOCKS = 4 * 60 * 24 * 30;  // ~30 days

// Storage fee rate: cost per byte per billing period (in atomic units)
// Base rate: 1 ZBC per 1 MB per month = 100,000,000 / 1,048,576 ≈ 95 per byte
// This makes storing 1 KB cost ~0.001 ZBC/month
constexpr int64_t DATASET_STORAGE_FEE_PER_BYTE = ONE_ZBC / (1024 * 1024);  // ~95 per byte per month

// Minimum prepaid balance required to setup a dataset (covers ~1 month of 1KB storage)
constexpr int64_t DATASET_MIN_PREPAID_BALANCE = ONE_ZBC / 100;  // 0.01 ZBC

// Grace period blocks before account datasets are disabled for non-payment
// ~7 days grace period
constexpr uint32_t DATASET_BILLING_GRACE_PERIOD_BLOCKS = 4 * 60 * 24 * 7;

// Event type for dataset billing ledger entries
constexpr int32_t EVENT_TYPE_DATASET_STORAGE_FEE = 17;  // New event type for storage fees
constexpr int32_t EVENT_TYPE_DATASET_PRUNED = 18;       // Dataset pruned: owner could not pay storage rent
constexpr int32_t EVENT_TYPE_DATASET_RENT_REWARD = 19;  // Storage rent credited to the block producer
constexpr int32_t EVENT_TYPE_DATASET_DEPOSIT_REFUND = 32; // unused ZBS_ deposit returned to owner on prune/delete
constexpr int32_t EVENT_TYPE_DATASET_TRANSFERRED = 33;    // dataset object ownership transfer accepted
// (20, 21 reserved for token survival-financing events on epsilon-survival-financing)
constexpr int32_t EVENT_TYPE_FEE_REFUND = 22;          // Honest-fee: excess over the floor returned to sender
constexpr int32_t EVENT_TYPE_TRIGGER_FIRED = 23;       // Event trigger fired: scheduled amount released to recipient

// ---- Token survival financing (longevity) — TOKEN_DESIGN.md §8a ----------
// A token's registry costs storage rent over time. Each token op's FEE buys
// persistence: funded_blocks = fee * billing_period / period_cost, added to the
// token's persist_height. In use → auto-finances (the fee they already pay).
// Unused → persist_height passes the tip → the token is pruned and its unused
// ZBC backing is returned to the creator. Legacy tokens (persist_height==0) are
// never pruned. period_cost is the consensus param `token_persist_period_cost`
// (atomic ZBC to keep one token alive for one billing period); default 1 ZBC/mo.
constexpr int64_t TOKEN_PERSIST_PERIOD_COST = ONE_ZBC;          // 1 ZBC ≈ 30 days of life
constexpr uint32_t MIN_TOKEN_PERSIST_BLOCKS = 4 * 60 * 24;      // floor at issue: ~1 day
constexpr int32_t EVENT_TYPE_TOKEN_EXPIRED = 20;               // token pruned: persistence financing ran out
constexpr int32_t EVENT_TYPE_TOKEN_BACKING_RETURNED = 21;      // expired token's unused backing returned to creator

// ---- Account survival financing (longevity) — same period/rate as tokens --------
// An ETH-style / regular account costs storage rent over time (it carries a balance
// and a persistent nonce). Every billing period the account pays ACCOUNT_RENT_PERIOD_COST
// out of its balance; while it can pay it persists, when it cannot it is pruned (the row
// + nonce are tombstoned, then reclaimed by snapshot pruning). A re-funded address starts
// fresh at nonce 0. Same period + rate as the token longevity model (owner decision).
constexpr uint32_t ACCOUNT_RENT_PERIOD_BLOCKS = DATASET_BILLING_PERIOD_BLOCKS;  // ~30 days
// Bound the per-block account-rent sweep so a spam wave (a million dust accounts all maturing in the
// same block) can't produce a monster block. Overflow rolls to the next block (oldest-due first).
constexpr uint32_t ACCOUNT_RENT_MAX_PER_BLOCK = 2000;
constexpr int64_t ACCOUNT_RENT_PERIOD_COST = TOKEN_PERSIST_PERIOD_COST;        // 1 ZBC / period
constexpr int32_t EVENT_TYPE_ACCOUNT_RENT_PAID = 24;          // account paid a period of storage rent
constexpr int32_t EVENT_TYPE_ACCOUNT_PRUNED = 25;            // account pruned: could not pay rent / abandoned

// ---- Gateway-oracle (event triggers Phase C) — EVENT_TRIGGERS.md ----------------
// External facts (bridge confirmations, prices) are attested on-chain by the per-block
// authorized blocksmith set (the deterministic priority blocksmiths). The top
// ORACLE_ATTESTER_SET nodes of that turn may attest; an event resolves once
// ORACLE_QUORUM of them agree on the same value (owner decision: 3-of-5 majority).
// Resolution runs in block context (deterministic); a resolved event fires the triggers
// conditioned on it. If <quorum attest this turn, it carries to the next turn's set.
constexpr uint32_t ORACLE_ATTESTER_SET = 5;                  // attesters = top 5 priority blocksmiths
constexpr uint32_t ORACLE_QUORUM = 3;                        // 3-of-5 majority resolves an event
constexpr int32_t EVENT_TYPE_ORACLE_RESOLVED = 26;          // an external event reached quorum + resolved

// ----- Bridge inbound (Plane A: foreign deposit -> mint wrapper coin) -----
// A deposit attestation is an AttestEvent whose event_id starts with this reserved prefix.
// event_id = "ZBRDEP1:<chain>:<ext_txid>:<log_index>"  (uniquely the foreign deposit)
// value    = "<token_id>:<amount>:<recipient_account_hex>"  (the AGREED mint parameters)
// Unlike the gateway-oracle (top-5 blocksmiths), a deposit is authorized by a SUPERMAJORITY
// of the FULL ACTIVE REGISTRY, so forging a mint needs to corrupt that fraction of stake-locked
// nodes. Quorum = ceil(active_size * BRIDGE_QUORUM_NUM / BRIDGE_QUORUM_DEN). Default 2/3.
// oracle_result (keyed by event_id) is the one-shot replay guard: a deposit mints exactly once.
constexpr char     BRIDGE_DEPOSIT_PREFIX[] = "ZBRDEP1:";
constexpr uint32_t BRIDGE_QUORUM_NUM = 2;                    // supermajority numerator   (2/3)
constexpr uint32_t BRIDGE_QUORUM_DEN = 3;                    // supermajority denominator
constexpr int32_t  EVENT_TYPE_BRIDGE_MINT = 27;             // wrapper coin minted on a resolved deposit
// Longest event_id that may ride the FEE-EXEMPT deposit path. A real deposit id is
// "ZBRDEP1:<chain>:<ext_txid>:<log_index>" — a 64-hex txid plus a short chain name, comfortably
// under this. The cap is what keeps the exemption from becoming free unbounded storage: see
// IsFeeExemptBridgeAttestation below.
constexpr uint32_t BRIDGE_DEPOSIT_EVENT_ID_MAX = 200;

// ----- Bridge OUTBOUND (Plane B: burn wrapper coin -> release the foreign asset) -----
// The mirror image of a deposit, and deliberately the same machinery.
//
// A user withdraws by sending the wrapper token INTO custody with a `ZBW1|<dest>` memo. That
// transfer is the WITHDRAWAL TRIGGER: it is on-chain, the user paid for it, and its hash names the
// request. Each registry node then attests
//     event_id = "ZBWDR1:<trigger_tx_hash_hex>"
//     value    = "<token_id>:<amount>:<dest>|<foreign_signature_hex>"
// and at a 2/3 supermajority the chain burns the wrapper from custody.
//
// Two things make the value's split at '|' necessary. Everything BEFORE the '|' is the AGREED
// payload and must match byte-for-byte across nodes — that is what quorum is counted on. Everything
// AFTER is that node's own foreign-chain (EIP-712) signature, which is necessarily DIFFERENT per
// node; if it were part of the agreed payload no two nodes would ever tally together. Publishing it
// here is the point: the chain becomes the collection bus, so ONE submitter can read a whole quorum
// of signatures off-chain state and make a single BridgeCustody.withdraw call. Before this they
// were written to each keeper's local state file, where nothing could ever gather them.
//
// Why this replaced a multisig co-sign: the old path submitted a MultiSignature wrapper from the
// node's own key. MultiSignature REQUIRES a positive fee (and must — it carries an arbitrary inner
// transaction), but the node account holds no balance, so every co-sign was rejected. Funding node
// accounts would have made quorum depend on operators remembering to top up — a liveness failure
// waiting to happen, and it puts spendable funds behind a key stored in plaintext in node.conf.
// How long a bridge event stays live for resolution, counted in blocks since its MOST RECENT
// attestation. Past this, the resolver stops retrying it and it costs nothing per block.
//
// Why an idle window is needed at all: GetUnresolvedEventIds returns every event that has
// attestations and no result, so an event that can NEVER resolve — a forged withdrawal naming a
// trigger that does not exist — was retried on every node at every block, forever, each retry
// costing an attestation query plus a trigger lookup. Attestations are fee-exempt, so a registry
// member could plant those for free and add permanent per-block work to the whole network.
//
// Anchored to the LAST attestation, deliberately, not the first. Anchoring to the first would make
// expiry PERMANENT: re-attesting cannot lower a minimum, so a legitimate withdrawal that missed
// quorum would be dead forever with the user's wrapper stranded in custody. Anchored to the last,
// any keeper can revive a stalled event by attesting again, and an attacker has to keep paying
// block space to keep a junk event alive instead of planting it once and walking away.
//
// 720 blocks is ~3 hours at 15s. The happy path needs about a minute — keepers poll every 15s
// (bridge.json poll_sec) after 2 confirmations — so this is roughly two orders of magnitude of
// headroom, which is what a node that is restarting or resyncing actually needs. It is sized for
// the failure that matters: expiring a real withdrawal strands real money, whereas an over-long
// window only wastes bounded queries.
//
// NOT applied to governance votes, which share the same tables: those are cast by humans through
// the wallet and can legitimately take days to reach 2/3. Their window would have to be far longer.
constexpr uint32_t BRIDGE_EVENT_IDLE_WINDOW = 720;

constexpr char     BRIDGE_WITHDRAWAL_PREFIX[] = "ZBWDR1:";
constexpr char     BRIDGE_WITHDRAWAL_MEMO[]   = "ZBW1|";   // memo that marks a transfer as a trigger
constexpr int32_t  EVENT_TYPE_BRIDGE_BURN = 36;            // wrapper burned on a resolved withdrawal

// ---- Scheduler / vested transfers (on-chain scheduler) ----
// Scheduled transfers can be recurring (pull-mode) or vested (push on schedule).
// Events are fired at each scheduled block height or finalization, depending on mode.
constexpr int32_t EVENT_TYPE_VESTING_RELEASE = 28;   // vesting tranche credited to recipient
constexpr int32_t EVENT_TYPE_SCHEDULE_PAID   = 29;   // recurring scheduled payment credited
constexpr int32_t EVENT_TYPE_SCHEDULE_SKIPPED= 30;   // pull-mode fire skipped (owner underfunded)
constexpr int32_t EVENT_TYPE_SCHEDULE_CANCELLED = 34; // schedule cancelled: locked remainder refunded to owner
// Governance: an economic consensus parameter reached a 2/3 registry supermajority and was applied.
constexpr int32_t EVENT_TYPE_CONSENSUS_PARAM_CHANGED = 35;
constexpr int32_t SCHEDULE_MAX_FIRES = 520;          // cap fires/schedule (weekly for ~10y)
constexpr int32_t SCHEDULE_MAX_CONSECUTIVE_SKIPS = 4;// pull-mode auto-cancel threshold
// Upper bound (~100 years) on any ScheduledTransfer time field (cliff_seconds, interval_seconds,
// end_time). These are consensus inputs summed into fire_time arithmetic (current_block_timestamp_
// + cliff_seconds, then += interval_seconds on every re-arm); an unbounded value near INT64_MAX
// would let that arithmetic overflow. Bounding here (on top of the CheckedAddInt64 use at the
// arithmetic sites) keeps both a defense-in-depth belt-and-suspenders and a sane product limit.
constexpr int64_t SCHEDULE_MAX_SECONDS = 100LL * 365 * 24 * 3600;

// ---- On-chain gateway registry (Track B) ------------------------------------
// A gateway registers by locking a stake (refunded when it unregisters) and must prove
// liveness periodically with a GatewayHeartbeat carrying a recent, unforgeable reference
// block hash. A gateway that stops beating is pruned (stake refunded) after a grace window.
// These are the defaults; Task B.4 seeds them into the consensus_parameters table so
// governance can tune them. Until then the code reads these constants directly.
constexpr int64_t GATEWAY_REGISTRATION_COST = 10 * ONE_ZBC;  // 10 ZBC locked at registration

// Exchange (docs/EXCHANGE_DESIGN.md). Taker fee in basis points, charged on the asset the taker
// RECEIVES and paid to the block producer; makers pay nothing. Seeded into consensus_parameters at
// genesis as `exchange_taker_fee_bps` and governable within 1..100 bps, so this is only the fallback
// when the parameter row is missing (e.g. a chain built before the param existed).
constexpr int64_t EXCHANGE_TAKER_FEE_BPS = 10;               // 0.1%

// Cost to OPEN a trading pair (CreateMarket). NON-REFUNDABLE by design: a market is permanent
// state — there is no close or prune path — so it is a creation fee, not a deposit. Free creation
// would let anyone open a market for every possible pair, forever. Seeded at genesis as
// `market_creation_cost` and governable; this is the fallback when the row is missing.
// NOTE: this is unrelated to the funds an ORDER holds, which are always refunded on cancel/expiry.
constexpr int64_t MARKET_CREATION_COST = 50 * ONE_ZBC;       // 50 ZBC

// Decentralized storage (Phase 6b). Minimum rent deposit to anchor a file manifest. Real
// per-MiB pricing + slashing is Phase 6c; this is a floor so a StoreFile isn't free. Dev value.
constexpr int64_t STORE_FILE_MIN_DEPOSIT = ONE_ZBC / 100;   // 0.01 ZBC (dev; 6c calibrates)
constexpr uint32_t STORE_FILE_MAX_PIECES = 100000;          // bound the manifest size (piece_ids)

// Phase 6c-2 proof-of-storage tally (consensus). Epoch = height / STORAGE_PROOF_EPOCH_BLOCKS; at each
// boundary the PREVIOUS epoch's proofs are tallied. Honest holders earn STORAGE_PROOF_REWARD from the
// storage pool; a holder whose proof disagrees with the quorum loses STORAGE_PROOF_SCORE_PENALTY
// participation score (→ fewer blocks). Dev values; genesis-tunable later.
constexpr uint32_t STORAGE_PROOF_EPOCH_BLOCKS = 240;        // proof/tally cadence (~1h @15s)
constexpr int64_t  STORAGE_PROOF_REWARD = ONE_ZBC / 1000;  // per honest (piece,epoch) proof, from the pool
constexpr int64_t  STORAGE_PROOF_SCORE_PENALTY = 100000000; // participation-score decrement for a lying holder
constexpr uint32_t GATEWAY_HEARTBEAT_INTERVAL = 5760;        // ~24h at 15s blocks: expected beat cadence.
// A heartbeat answers "is this service still real?", which does not change minute to minute. Beating
// hourly cost a fee every hour per gateway for no extra information, and made a brief restart look
// like a liveness failure. Daily is enough to keep a dead entry from lingering.
// The reference block a heartbeat cites must be within this many blocks of the tip. It MUST
// exceed CONFIRMATION_DEPTH (3) so a heartbeat can cite a fully-confirmed, non-reorg-prone block.
constexpr uint32_t GATEWAY_HEARTBEAT_FRESHNESS_WINDOW = 20;  // > CONFIRMATION_DEPTH
static_assert(GATEWAY_HEARTBEAT_FRESHNESS_WINDOW > CONFIRMATION_DEPTH,
              "heartbeat freshness window must exceed confirmation depth");
constexpr uint32_t GATEWAY_PRUNE_GRACE = 11520;              // ~48h past the last beat before auto-prune.
// Two full missed days before removal: a reboot, a slow resync or a short outage must not cost a
// registry entry, because re-registering costs a stake lock and a round trip.
constexpr int32_t EVENT_TYPE_GATEWAY_PRUNED = 31;           // stale gateway auto-pruned: locked stake refunded to owner

// ---- Paid longevity ------------------------------------------------------------------------
// Rent is charged per period from the target's deposit, at the same per-byte rate the fee floor
// already uses for persistence — one source of truth, so "what it costs to keep a byte alive" is
// one number, not two that can drift apart.
constexpr uint32_t LONGEVITY_BILLING_PERIOD_BLOCKS = 5760;   // ~24h at 15s blocks
constexpr int64_t  LONGEVITY_MIN_DEPOSIT = 10000000;         // 0.1 ZBC — a floor so dust cannot pin a row
// 35 and 36 were already taken by EVENT_TYPE_CONSENSUS_PARAM_CHANGED and EVENT_TYPE_BRIDGE_BURN when
// the longevity events were added, so two different meanings shared one number in the same ledger
// column and no reader could tell them apart. Moved to free numbers rather than left to be decoded by
// guessing which subsystem wrote the row. Safe to renumber: no FundLongevity transaction has ever
// been submitted on either chain, so no ledger row carries the old values. NOTE the column is shared
// with model::EventType (0-16, and 100 for app payouts) — new values belong here, above 36, below 100.
constexpr int32_t EVENT_TYPE_LONGEVITY_FUNDED = 37;          // sponsor paid a deposit to keep a tx alive
constexpr int32_t EVENT_TYPE_LONGEVITY_RENT   = 38;          // rent drawn from a deposit into the pool
constexpr int32_t EVENT_TYPE_LONGEVITY_PAYOUT = 39;          // pool paid out to a node that kept the data
constexpr int32_t EVENT_TYPE_LONGEVITY_REFUND = 40;          // cancelled sponsorship: remainder returned to the sponsor

}  // namespace constants

// ---- Fee exemption for BRIDGE DEPOSIT attestations ----
//
// A bridge keeper attests from the node's OWN key (00000000 + node_public_key) — which is an
// ordinary ZBC account address, 4-byte type ‖ 32-byte key, and can hold a balance like any other.
//
// It used to hold none "by design", which forced this path to be fee-exempt. That is reversed:
// genesis seeds every registered node's account with an operating balance and the owner tops it up,
// so an attestation pays its own way. An UNFUNDED node simply stops attesting — which is why
// TransactionExecutor logs that case explicitly rather than letting it look like a network fault.
//
// It is NOT exempt by transaction type, unlike those two. AttestEvent also carries the generic
// gateway-oracle traffic, and its event_id is a free-form string up to 4 KB; exempting the whole
// type would let a single registry member write unlimited 4 KB rows into oracle_attestation at zero
// cost. So the exemption is scoped to the one thing that must work without funds: an event_id
// bearing the reserved BRIDGE_DEPOSIT_PREFIX, within BRIDGE_DEPOSIT_EVENT_ID_MAX bytes. Every other
// attestation still pays.
//
// This inspects the body rather than trusting the sender, and it is only half the gate: the
// authoritative "is the sender really a registered node?" check runs in
// TransactionExecutor::CanApplyUnconfirmed, which has the registry. A non-node offering a fee-0
// deposit attestation is bounced there, so this is not a free-transaction hole.
// Both bridge planes ride free: a DEPOSIT attestation (inbound, mints) and a WITHDRAWAL attestation
// (outbound, burns + publishes the foreign signature). Both are one vote per registered node,
// anchored to a fact nobody can invent — a foreign-chain deposit, or the user's own on-chain
// trigger transfer — so neither is a channel for free arbitrary traffic.
inline bool IsBridgeAttestation(TransactionType t, const std::vector<uint8_t>& body) {
    if (t != TransactionType::AttestEvent) return false;
    if (body.size() < 4) return false;
    uint32_t len = 0;
    for (int i = 0; i < 4; ++i)
        len |= static_cast<uint32_t>(static_cast<uint8_t>(body[i])) << (8 * i);
    if (len == 0 || len > constants::BRIDGE_DEPOSIT_EVENT_ID_MAX) return false;
    if (4 + static_cast<size_t>(len) > body.size()) return false;
    const char* const kPrefixes[] = {constants::BRIDGE_DEPOSIT_PREFIX,
                                     constants::BRIDGE_WITHDRAWAL_PREFIX};
    for (const char* p : kPrefixes) {
        const size_t plen = std::strlen(p);
        if (len >= plen && std::memcmp(body.data() + 4, p, plen) == 0) return true;
    }
    return false;
}

// Every transaction a NODE signs and submits for itself. No longer implies a fee exemption (owner
// decision 2026-08-09: the node funds its own account and pays like everybody else) — it identifies
// the traffic whose sender is the node account, so an unfunded node can be reported clearly.
inline bool IsNodeSignedTx(TransactionType t, const std::vector<uint8_t>& body) {
    return IsNodeSignedType(t) || IsBridgeAttestation(t, body);
}

}  // namespace zoobc

#endif  // ZOOBC_COMMON_CONSTANTS_H
