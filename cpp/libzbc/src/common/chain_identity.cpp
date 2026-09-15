// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/common/chain_identity.h"

#include <atomic>
#include <mutex>

namespace zoobc {
namespace chain {

namespace {
std::mutex& Mutex() {
    static std::mutex m;
    return m;
}
std::vector<uint8_t>& Storage() {
    static std::vector<uint8_t> hash;
    return hash;
}
std::atomic<bool>& SetFlag() {
    static std::atomic<bool> flag{false};
    return flag;
}
}  // namespace

bool Identity::SetGenesisHash(const std::vector<uint8_t>& genesis_hash) {
    if (genesis_hash.size() != 32) return false;
    std::lock_guard<std::mutex> lock(Mutex());
    if (SetFlag().load()) {
        return Storage() == genesis_hash;
    }
    Storage() = genesis_hash;
    SetFlag().store(true);
    return true;
}

const std::vector<uint8_t>& Identity::GenesisHash() {
    static const std::vector<uint8_t> empty;
    if (!SetFlag().load()) return empty;
    return Storage();
}

bool Identity::IsSet() {
    return SetFlag().load();
}

std::vector<uint8_t> Identity::TestGenesis() {
    return std::vector<uint8_t>(32, 0x5a);
}

void Identity::ResetForTests() {
    std::lock_guard<std::mutex> lock(Mutex());
    Storage().clear();
    SetFlag().store(false);
}

}  // namespace chain
}  // namespace zoobc
