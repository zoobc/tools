// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_CRYPTO_SOLANA_TRANSACTION_H
#define ZOOBC_CRYPTO_SOLANA_TRANSACTION_H
#include <cstdint>
#include <string>
#include <vector>

namespace zoobc {
namespace crypto {

// Result of parsing + verifying a (Phantom-signed) Solana System-transfer transaction.
struct SolanaTransfer {
    bool ok = false;
    std::vector<uint8_t> from;   // 32-byte ed25519 pubkey (fee payer / source)
    std::vector<uint8_t> to;     // 32-byte ed25519 pubkey (destination)
    uint64_t lamports = 0;
    std::string error;
};

// Parse a serialized legacy Solana transaction, require exactly one System-Program transfer,
// and verify signature[0] (ed25519, over the message bytes) against account_keys[0] (the fee
// payer). Robust against malformed input (all reads bounds-checked). Mirror of the proven
// reference (gw-work bridge/.../soltx.cjs); analog of the native-ETH path.
SolanaTransfer ParseAndVerifySolanaTransfer(const std::vector<uint8_t>& raw);

}  // namespace crypto
}  // namespace zoobc
#endif
