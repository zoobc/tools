// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/common/chain_type.h"
#include <mutex>

namespace zoobc {

// ==================== MainChain Genesis Configuration ====================

// Genesis block ID for MainChain (derived from genesis block hash)
int64_t MainChain::GetGenesisBlockID() const {
    // This value should match the GO implementation
    // Typically computed from the first 8 bytes of the genesis block hash
    return -1505131482682099276LL;  // Example value from GO
}

std::vector<uint8_t> MainChain::GetGenesisBlockSeed() const {
    // 32-byte seed for genesis block
    // This is typically a well-known constant or derived from network parameters
    return std::vector<uint8_t>(32, 0);  // Zeros for genesis
}

std::vector<uint8_t> MainChain::GetGenesisNodePublicKey() const {
    // 32-byte public key of the genesis node
    // This is the "bootstrap" node that creates the genesis block
    // In production, this would be a real public key
    return std::vector<uint8_t>(32, 0);  // Placeholder
}

int64_t MainChain::GetGenesisBlockTimestamp() const {
    // Unix timestamp of genesis block creation
    // July 24, 2019 00:00:00 UTC (ZooBC mainnet genesis)
    return 1563926400;
}

std::vector<uint8_t> MainChain::GetGenesisBlockSignature() const {
    // 64-byte signature of genesis block
    // In production, this would be a real Ed25519 signature
    return std::vector<uint8_t>(64, 0);  // Placeholder
}

// ==================== SpineChain Genesis Configuration ====================

// Genesis block ID for SpineChain
int64_t SpineChain::GetGenesisBlockID() const {
    // Different from MainChain to distinguish the chains
    return -7632829255395231288LL;  // Example value from GO
}

std::vector<uint8_t> SpineChain::GetGenesisBlockSeed() const {
    // 32-byte seed for spine genesis block
    return std::vector<uint8_t>(32, 0);  // Zeros for genesis
}

std::vector<uint8_t> SpineChain::GetGenesisNodePublicKey() const {
    // Same bootstrap node as MainChain (typically)
    return std::vector<uint8_t>(32, 0);  // Placeholder
}

int64_t SpineChain::GetGenesisBlockTimestamp() const {
    // Same timestamp as MainChain (chains start together)
    return 1563926400;
}

std::vector<uint8_t> SpineChain::GetGenesisBlockSignature() const {
    // 64-byte signature of spine genesis block
    return std::vector<uint8_t>(64, 0);  // Placeholder
}

// ==================== ConfigurableSpineChain Genesis Configuration ====================

// ConfigurableSpineChain uses the same genesis as SpineChain
int64_t ConfigurableSpineChain::GetGenesisBlockID() const {
    return -7632829255395231288LL;  // Same as SpineChain
}

std::vector<uint8_t> ConfigurableSpineChain::GetGenesisBlockSeed() const {
    return std::vector<uint8_t>(32, 0);  // Zeros for genesis
}

std::vector<uint8_t> ConfigurableSpineChain::GetGenesisNodePublicKey() const {
    return std::vector<uint8_t>(32, 0);  // Placeholder
}

int64_t ConfigurableSpineChain::GetGenesisBlockTimestamp() const {
    return 1563926400;  // Same as SpineChain
}

std::vector<uint8_t> ConfigurableSpineChain::GetGenesisBlockSignature() const {
    return std::vector<uint8_t>(64, 0);  // Placeholder
}

// ==================== Chain Type Factory ====================

namespace {
    // Singleton instances with thread-safe initialization
    std::once_flag main_chain_once;
    std::once_flag spine_chain_once;
    std::shared_ptr<MainChain> main_chain_instance;
    std::shared_ptr<SpineChain> spine_chain_instance;
}

std::shared_ptr<ChainType> ChainTypeFactory::Create(ChainTypeID id) {
    switch (id) {
        case ChainTypeID::MainChain:
            return GetMainChain();
        case ChainTypeID::SpineChain:
            return GetSpineChain();
        default:
            return nullptr;
    }
}

std::shared_ptr<MainChain> ChainTypeFactory::GetMainChain() {
    std::call_once(main_chain_once, []() {
        main_chain_instance = std::make_shared<MainChain>();
    });
    return main_chain_instance;
}

std::shared_ptr<SpineChain> ChainTypeFactory::GetSpineChain() {
    std::call_once(spine_chain_once, []() {
        spine_chain_instance = std::make_shared<SpineChain>();
    });
    return spine_chain_instance;
}

std::shared_ptr<ConfigurableSpineChain> ChainTypeFactory::CreateConfigurableSpineChain(
    int64_t smithing_period,
    int64_t blocksmith_time_gap,
    int64_t block_creation_time,
    int64_t network_tolerance,
    uint32_t snapshot_interval
) {
    return std::make_shared<ConfigurableSpineChain>(
        smithing_period,
        blocksmith_time_gap,
        block_creation_time,
        network_tolerance,
        snapshot_interval
    );
}

}  // namespace zoobc
