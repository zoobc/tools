// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#pragma once

// One place that turns an address STRING into the 36-byte on-chain account address.
//
// The chain has 17 account types. Until now the CLI tools knew four of them — ZooBC, Ethereum,
// Bitcoin and a raw hex key — because tools/tx_common.h grew its own parser and never caught up
// with the chain. So zbc-send could not pay a Solana or Polkadot account at all, even though the
// node verifies signatures for both.
//
// Worse than "cannot": is_btc_address() there returns true for ANY string starting with 1 or 3.
// Solana keys and Polkadot SS58 addresses are base58 too and routinely start with those, so they
// were accepted as BITCOIN — the chain would then hold a type-5/6 account the owner's Solana key
// can never spend from. Silently stranded funds.
//
// This mirrors decodeRecipient() in the wallet, which is the format authority: users already hold
// addresses it produced. The rule throughout is DISAMBIGUATE BY CHECKSUM, NEVER BY GUESSING —
//
//     1…/3…   base58check, 25 bytes, version 0x00 → P2PKH (5), 0x05 → P2SH (6)
//     SS58     35 bytes with a valid blake2b checksum          → Polkadot (12)
//     base58   exactly 32 bytes, no checksum                   → Solana   (11)
//
// which is why those three cannot be confused: a Solana key beginning with '1' fails Bitcoin's
// checksum and falls through to the 32-byte decode.

#include <cstdint>
#include <string>
#include <vector>

#include "zoobc/common/result.h"

namespace zoobc {
namespace crypto {

/// Which chain an ambiguous string should be read as. Auto is right almost always: the formats
/// carry their own checksums. It exists for the one case checksums cannot settle — an 0x… address
/// is valid on every EVM chain — and so an operator can force a reading rather than argue with a
/// heuristic.
enum class AddressChain {
    Auto = 0, ZooBC, Bitcoin, Ethereum, Solana, Polkadot, Cardano, Ripple, Tron, Tezos, DataSet
};

/// Parse a chain name ("solana", "sol", "dot", "eth"…). Returns Auto for an empty/unknown name.
AddressChain ParseAddressChain(const std::string& name);

/// Human name for an account type byte, for error messages and confirmations.
std::string AccountTypeName(int32_t account_type);

struct DecodedAddress {
    std::vector<uint8_t> address;   ///< 36 bytes: 4-byte LE type prefix + payload
    int32_t account_type = 0;
    std::string chain;              ///< "solana", "bitcoin-p2wpkh", … for display
};

/// Decode any address the chain can hold. `hint` forces an interpretation; Auto detects.
/// Fails rather than guesses: an address that matches no format, or whose checksum is wrong, is an
/// error — never a coin-flip between two chains.
Result<DecodedAddress> DecodeAddress(const std::string& address, AddressChain hint = AddressChain::Auto);

}  // namespace crypto
}  // namespace zoobc
