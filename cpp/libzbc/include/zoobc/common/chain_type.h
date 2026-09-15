// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_COMMON_CHAIN_TYPE_H
#define ZOOBC_COMMON_CHAIN_TYPE_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace zoobc {

/**
 * Chain Type Identifier
 *
 * Unique integer identifier for each chain type.
 */
enum class ChainTypeID : int32_t {
    MainChain = 0,
    SpineChain = 1
};

/**
 * Chain Type Interface
 *
 * Abstract base class defining the interface for different blockchain types.
 * Each chain type (MainChain, SpineChain) has different parameters for:
 * - Smithing timing (block creation intervals)
 * - Genesis block configuration
 * - Feature availability (transactions, snapshots)
 *
 * This abstraction allows the same codebase to support multiple chain types
 * with different consensus parameters.
 */
class ChainType {
public:
    virtual ~ChainType() = default;

    // ==================== Chain Identity ====================

    /**
     * Get the chain type identifier
     */
    virtual ChainTypeID GetTypeInt() const = 0;

    /**
     * Get the table prefix for database queries
     * e.g., "main" for main_block, "spine" for spine_block
     */
    virtual std::string GetTablePrefix() const = 0;

    /**
     * Get human-readable chain name
     */
    virtual std::string GetName() const = 0;

    // ==================== Smithing Parameters ====================

    /**
     * Get the smithing period in seconds
     * Time between block creation attempts
     */
    virtual int64_t GetSmithingPeriod() const = 0;

    /**
     * Get the blocksmith time gap in seconds
     * Time allocated per blocksmith slot
     */
    virtual int64_t GetBlocksmithTimeGap() const = 0;

    /**
     * Get the block creation time in seconds
     * Maximum time to create and broadcast a block
     */
    virtual int64_t GetBlocksmithBlockCreationTime() const = 0;

    /**
     * Get network tolerance in seconds
     * Allowance for network delays
     */
    virtual int64_t GetBlocksmithNetworkTolerance() const = 0;

    // ==================== Genesis Block Configuration ====================

    /**
     * Get the genesis block ID
     */
    virtual int64_t GetGenesisBlockID() const = 0;

    /**
     * Get the genesis block seed (32 bytes)
     */
    virtual std::vector<uint8_t> GetGenesisBlockSeed() const = 0;

    /**
     * Get the genesis node public key (32 bytes)
     */
    virtual std::vector<uint8_t> GetGenesisNodePublicKey() const = 0;

    /**
     * Get the genesis block timestamp
     */
    virtual int64_t GetGenesisBlockTimestamp() const = 0;

    /**
     * Get the genesis block signature (64 bytes)
     */
    virtual std::vector<uint8_t> GetGenesisBlockSignature() const = 0;

    // ==================== Feature Flags ====================

    /**
     * Check if this chain supports transactions
     * MainChain: true, SpineChain: false
     */
    virtual bool HasTransactions() const = 0;

    /**
     * Check if this chain supports snapshots
     * MainChain: true, SpineChain: false
     */
    virtual bool HasSnapshots() const = 0;

    /**
     * Get the snapshot interval in blocks
     * 0 if snapshots not supported
     */
    virtual uint32_t GetSnapshotInterval() const = 0;

    // ==================== Utility Methods ====================

    /**
     * Get the block table name for this chain
     * e.g., "main_block" or "spine_block"
     */
    std::string GetBlockTableName() const {
        return GetTablePrefix() + "_block";
    }

    /**
     * Check if this is the main chain
     */
    bool IsMainChain() const {
        return GetTypeInt() == ChainTypeID::MainChain;
    }

    /**
     * Check if this is the spine chain
     */
    bool IsSpineChain() const {
        return GetTypeInt() == ChainTypeID::SpineChain;
    }
};

/**
 * MainChain Implementation
 *
 * The primary blockchain for transactions and accounts.
 * Values match Go implementation in common/constant/smith.go:
 * - MainChainSmithingPeriod = 15 seconds
 * - MainSmithingBlockCreationTime = 30 seconds
 * - MainSmithingNetworkTolerance = 15 seconds
 * - MainSmithingBlocksmithTimeGap = 10 seconds
 * - Supports transactions
 * - Supports snapshots (cadence configured via main_snapshot_interval; default 1440 blocks)
 */
class MainChain : public ChainType {
public:
    // Chain Identity
    ChainTypeID GetTypeInt() const override { return ChainTypeID::MainChain; }
    std::string GetTablePrefix() const override { return "main"; }
    std::string GetName() const override { return "Mainchain"; }

    // Smithing Parameters (matching Go: common/constant/smith.go)
    int64_t GetSmithingPeriod() const override { return 15; }            // MainChainSmithingPeriod
    int64_t GetBlocksmithTimeGap() const override { return 10; }         // MainSmithingBlocksmithTimeGap
    int64_t GetBlocksmithBlockCreationTime() const override { return 30; } // MainSmithingBlockCreationTime
    int64_t GetBlocksmithNetworkTolerance() const override { return 15; }  // MainSmithingNetworkTolerance

    // Genesis Block Configuration
    int64_t GetGenesisBlockID() const override;
    std::vector<uint8_t> GetGenesisBlockSeed() const override;
    std::vector<uint8_t> GetGenesisNodePublicKey() const override;
    int64_t GetGenesisBlockTimestamp() const override;
    std::vector<uint8_t> GetGenesisBlockSignature() const override;

    // Feature Flags
    bool HasTransactions() const override { return true; }
    bool HasSnapshots() const override { return true; }
    // Default fallback cadence (1440 main blocks ≈ 6h at 15s/block). The running
    // node uses the configured `main_snapshot_interval` from the main genesis
    // config (see ConsensusParameters); this is only the hardcoded default.
    uint32_t GetSnapshotInterval() const override { return 1440; }
};

/**
 * SpineChain Implementation
 *
 * The spine blockchain for cross-shard coordination.
 * Values match Go implementation in common/constant/smith.go:
 * - SpineChainSmithingPeriod = 24 * OneHour = 86400 seconds (24 hours)
 * - SpineSmithingBlockCreationTime = 300 seconds
 * - SpineSmithingNetworkTolerance = 150 seconds
 * - SpineSmithingBlocksmithTimeGap = 100 seconds
 * - No transactions (metadata only)
 * - No snapshots
 */
class SpineChain : public ChainType {
public:
    // Chain Identity
    ChainTypeID GetTypeInt() const override { return ChainTypeID::SpineChain; }
    std::string GetTablePrefix() const override { return "spine"; }
    std::string GetName() const override { return "Spinechain"; }

    // Smithing Parameters (matching Go: common/constant/smith.go)
    int64_t GetSmithingPeriod() const override { return 86400; }           // SpineChainSmithingPeriod = 24 * OneHour
    int64_t GetBlocksmithTimeGap() const override { return 100; }          // SpineSmithingBlocksmithTimeGap
    int64_t GetBlocksmithBlockCreationTime() const override { return 300; } // SpineSmithingBlockCreationTime
    int64_t GetBlocksmithNetworkTolerance() const override { return 150; }  // SpineSmithingNetworkTolerance

    // Genesis Block Configuration
    int64_t GetGenesisBlockID() const override;
    std::vector<uint8_t> GetGenesisBlockSeed() const override;
    std::vector<uint8_t> GetGenesisNodePublicKey() const override;
    int64_t GetGenesisBlockTimestamp() const override;
    std::vector<uint8_t> GetGenesisBlockSignature() const override;

    // Feature Flags
    bool HasTransactions() const override { return false; }
    bool HasSnapshots() const override { return false; }
    uint32_t GetSnapshotInterval() const override { return 0; }
};

/**
 * ConfigurableSpineChain Implementation
 *
 * A SpineChain variant that uses configurable parameters from ConsensusParameters.
 * This allows spine chain timing to be configured via genesis config for testing
 * (e.g., 10-minute periods) vs production (24-hour periods).
 *
 * Usage:
 *   auto spine = std::make_shared<ConfigurableSpineChain>(consensus_params);
 */
class ConfigurableSpineChain : public ChainType {
public:
    // Constructor that takes spine parameters directly
    ConfigurableSpineChain(
        int64_t smithing_period = 86400,
        int64_t blocksmith_time_gap = 100,
        int64_t block_creation_time = 300,
        int64_t network_tolerance = 150,
        uint32_t snapshot_interval = 0
    ) : smithing_period_(smithing_period),
        blocksmith_time_gap_(blocksmith_time_gap),
        block_creation_time_(block_creation_time),
        network_tolerance_(network_tolerance),
        snapshot_interval_(snapshot_interval) {}

    // Chain Identity
    ChainTypeID GetTypeInt() const override { return ChainTypeID::SpineChain; }
    std::string GetTablePrefix() const override { return "spine"; }
    std::string GetName() const override { return "Spinechain (Configurable)"; }

    // Smithing Parameters - use configured values
    int64_t GetSmithingPeriod() const override { return smithing_period_; }
    int64_t GetBlocksmithTimeGap() const override { return blocksmith_time_gap_; }
    int64_t GetBlocksmithBlockCreationTime() const override { return block_creation_time_; }
    int64_t GetBlocksmithNetworkTolerance() const override { return network_tolerance_; }

    // Genesis Block Configuration (same as SpineChain)
    int64_t GetGenesisBlockID() const override;
    std::vector<uint8_t> GetGenesisBlockSeed() const override;
    std::vector<uint8_t> GetGenesisNodePublicKey() const override;
    int64_t GetGenesisBlockTimestamp() const override;
    std::vector<uint8_t> GetGenesisBlockSignature() const override;

    // Feature Flags
    bool HasTransactions() const override { return false; }
    bool HasSnapshots() const override { return snapshot_interval_ > 0; }
    uint32_t GetSnapshotInterval() const override { return snapshot_interval_; }

    // Update parameters (e.g., after loading from database)
    void SetSmithingPeriod(int64_t period) { smithing_period_ = period; }
    void SetBlocksmithTimeGap(int64_t gap) { blocksmith_time_gap_ = gap; }
    void SetBlockCreationTime(int64_t time) { block_creation_time_ = time; }
    void SetNetworkTolerance(int64_t tolerance) { network_tolerance_ = tolerance; }
    void SetSnapshotInterval(uint32_t interval) { snapshot_interval_ = interval; }

private:
    int64_t smithing_period_;
    int64_t blocksmith_time_gap_;
    int64_t block_creation_time_;
    int64_t network_tolerance_;
    uint32_t snapshot_interval_;
};

/**
 * Chain Type Factory
 *
 * Creates chain type instances by ID.
 */
class ChainTypeFactory {
public:
    /**
     * Create a chain type instance by ID
     * @param id The chain type identifier
     * @return Shared pointer to the chain type, or nullptr if unknown
     */
    static std::shared_ptr<ChainType> Create(ChainTypeID id);

    /**
     * Get the MainChain singleton instance
     */
    static std::shared_ptr<MainChain> GetMainChain();

    /**
     * Get the SpineChain singleton instance (default parameters)
     */
    static std::shared_ptr<SpineChain> GetSpineChain();

    /**
     * Create a ConfigurableSpineChain with custom parameters
     * @param smithing_period Period between spine blocks (default: 86400 = 24h)
     * @param blocksmith_time_gap Gap between blocksmith windows
     * @param block_creation_time Time for block creation
     * @param network_tolerance Network propagation tolerance
     * @param snapshot_interval Snapshot interval (0 = disabled)
     */
    static std::shared_ptr<ConfigurableSpineChain> CreateConfigurableSpineChain(
        int64_t smithing_period = 86400,
        int64_t blocksmith_time_gap = 100,
        int64_t block_creation_time = 300,
        int64_t network_tolerance = 150,
        uint32_t snapshot_interval = 0
    );
};

}  // namespace zoobc

#endif  // ZOOBC_COMMON_CHAIN_TYPE_H
