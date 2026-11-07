// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_TRANSACTION_ETH_SIGNATURE_CANONICAL_H
#define ZOOBC_TRANSACTION_ETH_SIGNATURE_CANONICAL_H
// Rule eth_signature_canonical_v (0.6.1). A signature made by an Ethereum- or Tron-typed key (account type 4 or 15, both
// verified by crypto::Signature::VerifyEthSignature) is r(32) ‖ s(32) ‖ v(1) with v exactly 27 or 28, the form the
// wallet, the tools and the RPC adapter produce. The verifier takes v 0-3 and 27-30 (and with the full 64-byte key in the
// address it does not use the recovery id at all), so one signer's one signature had up to eight byte strings. Every site
// that verifies a signature by such a key asks this first: the transaction envelope, a multisig participant's signature
// (carried in a MultiSignature body and counted at completion), an escrow co-signature, an account-group consent
// (kind 0, each kind 1 participant, kind 2) and a fee-vote reveal's voter signature, plus the fork weigher's owner check
// on a branch's registry transactions. A pure function of the bytes and the height, so admission and block validation
// give one answer. A foreign carrier (a raw Ethereum transaction in `message`) follows its own chain's rules
// (foreign_carrier_bound) and is not asked.
#include <cstdint>
#include <vector>

#include "zoobc/consensus/rule_activation.h"
#include "zoobc/util/transaction_util.h"

namespace zoobc {
namespace transaction {

constexpr const char* kEthRecoveryIdRefused = "Ethereum signature recovery id must be 27 or 28";

// Whether the verifier checks `signer`'s signatures as Ethereum ones: type 4 (Ethereum) or 15 (Tron). A 32-byte address
// is a bare ZBC key or a Cardano account to the verifier, never Ethereum, whatever its first four bytes read as.
inline bool SignsLikeEthereum(const std::vector<uint8_t>& signer) {
    if (signer.size() == 32) return false;
    const int32_t t = util::TransactionUtil::ExtractAccountType(signer);
    return t == util::TransactionUtil::ACCOUNT_TYPE_ETH || t == util::TransactionUtil::ACCOUNT_TYPE_TRON;
}

// False only when the rule is active at `height`, `signer` signs like Ethereum and `signature` is not 65 bytes ending in
// 27 or 28. Any other signer, or the rule off, is true: the 0.6.0 answer is the verifier's alone.
inline bool CanonicalForeignRecoveryId(const std::vector<uint8_t>& signer, const std::vector<uint8_t>& signature,
                                       uint32_t height) {
    if (!SignsLikeEthereum(signer)) return true;
    if (!consensus::RuleClock::Active("eth_signature_canonical_v", height)) return true;
    return signature.size() == util::TransactionUtil::ETH_SIGNATURE_LENGTH &&
           (signature[64] == 27 || signature[64] == 28);
}

}  // namespace transaction
}  // namespace zoobc

#endif  // ZOOBC_TRANSACTION_ETH_SIGNATURE_CANONICAL_H
