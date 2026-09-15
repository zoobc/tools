// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_COMMON_CHAIN_IDENTITY_H
#define ZOOBC_COMMON_CHAIN_IDENTITY_H

#include <cstdint>
#include <vector>

namespace zoobc {
namespace chain {

// The one thing that separates one ZooBC chain from another is the hash of its genesis block:
// there is no network-id byte anywhere, and nodes compare this hash before they agree to peer.
//
// Since signing v2 (2026-09-08) that hash is also part of what every transaction signer commits
// to: the signing digest is SHA3-256("ZBC-TX" ‖ genesis_hash ‖ unsigned_tx_bytes), so a signature
// verifies on exactly one chain. Before that, a transaction signed for testnet was valid bytes on
// mainnet, devnet and every future parallel chain for the same key.
//
// This is process-wide state, set once at start-up as soon as block 0 is readable and never
// changed afterwards. It is deliberately NOT defaulted: a node that has not learned its genesis
// hash must refuse to verify or produce signatures rather than silently fall back to the
// unbound v1 digest, which would reopen the cross-chain replay this exists to close.
class Identity {
public:
    // Record the genesis block hash (32 bytes). Later calls with the same value are no-ops; a
    // different value is refused (returns false) — the chain a process serves does not change.
    static bool SetGenesisHash(const std::vector<uint8_t>& genesis_hash);

    // The recorded hash, or an empty vector when SetGenesisHash has not run.
    static const std::vector<uint8_t>& GenesisHash();

    static bool IsSet();

    // A fixed 32-byte value for unit tests that exercise signing without a real chain. Tests set
    // it explicitly in main(); production code never calls this.
    static std::vector<uint8_t> TestGenesis();

    // Test-only: forget the recorded hash so a test can exercise the "identity unknown" refusal
    // or verify that a signature made for one genesis fails under another.
    static void ResetForTests();
};

}  // namespace chain
}  // namespace zoobc

#endif  // ZOOBC_COMMON_CHAIN_IDENTITY_H
