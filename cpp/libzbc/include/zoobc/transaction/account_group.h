// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#pragma once
// Account groups (transaction types 55-58) — docs/ACCOUNT_GROUPS.md, owner decisions 2026-09-23.
//
// A group is ONE account reachable at several addresses. The pooled balance and everything the group
// owns live on a keyless group address; every member address resolves to it (AccountState::
// BalanceHolder), so a payment to any member lands in the pool and a transaction signed by a member
// acts as the group. One member, the controller, manages the group.
//
// This header holds the wire codec (bodies and consent proofs) and the consent digests. They are
// stateless, so admission and execution apply exactly the same rules.
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "zoobc/common/result.h"
#include "zoobc/common/types.h"

namespace zoobc {
namespace transaction {
namespace group {

constexpr uint8_t kBodyVersion = 1;

// How a signing address consents. Kind 0: one signature by the address's own key, whatever its curve
// (Signature::VerifySignature dispatches on the address type). Kind 1: a multisig address consents
// the way it signs anything: a threshold of its participants, with the participant list, threshold and
// nonce that hash to the address (MultisignatureService::GenerateMultisigAddress). Kind 2: an
// Ethereum address's personal_sign (EIP-191) of the digest, because MetaMask signs no bare hash.
struct ConsentProof {
    uint8_t kind = 0;
    std::vector<uint8_t> signature;                                   // kind 0 and kind 2
    uint32_t minimum_signatures = 0;                                  // kind 1
    int64_t multisig_nonce = 0;                                       // kind 1
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> participants;  // kind 1: (address, signature or empty)
};

struct LinkBody {            // LinkAccount (55)
    uint8_t version = kBodyVersion;
    std::vector<uint8_t> member;
    uint32_t valid_until_height = 0;
    uint32_t link_seq = 0;
    ConsentProof proof;
};
struct UnlinkBody {          // UnlinkAccount (56)
    uint8_t version = kBodyVersion;
    std::vector<uint8_t> member;
};
struct PermissionsBody {     // SetMemberPermissions (57)
    uint8_t version = kBodyVersion;
    std::vector<uint8_t> member;
    uint8_t flags = 0;             // constants::ACCOUNT_GROUP_PERM_SPEND
    int64_t spend_limit = 0;       // atomic ZBC per period; 0 = no limit
    uint32_t period_blocks = 0;    // required (>= 1) when spend_limit > 0, else 0
};
struct ControlBody {         // TransferGroupControl (58)
    uint8_t version = kBodyVersion;
    std::vector<uint8_t> new_controller;
    uint32_t valid_until_height = 0;
    uint32_t link_seq = 0;
    ConsentProof proof;
};

std::vector<uint8_t> EncodeProof(const ConsentProof& p);
std::vector<uint8_t> EncodeLinkBody(const LinkBody& b);
std::vector<uint8_t> EncodeUnlinkBody(const UnlinkBody& b);
std::vector<uint8_t> EncodePermissionsBody(const PermissionsBody& b);
std::vector<uint8_t> EncodeControlBody(const ControlBody& b);

// Parsers refuse a wrong version, truncation and trailing bytes.
Result<LinkBody> ParseLinkBody(const std::vector<uint8_t>& bytes);
Result<UnlinkBody> ParseUnlinkBody(const std::vector<uint8_t>& bytes);
Result<PermissionsBody> ParsePermissionsBody(const std::vector<uint8_t>& bytes);
Result<ControlBody> ParseControlBody(const std::vector<uint8_t>& bytes);

// What the joining address signs:
//   SHA3-256("ZBC-GROUP-LINK" ‖ genesis_hash(32) ‖ len(u8) ‖ controller ‖ len(u8) ‖ member ‖
//            valid_until_height(u32 LE) ‖ link_seq(u32 LE))
// Both addresses in their typed form (a legacy 32-byte ZBC key is promoted to 00000000 ‖ key).
// Fails when the chain identity is unknown: an unbound digest would be valid on every chain.
Result<std::vector<uint8_t>> LinkConsentDigest(const std::vector<uint8_t>& controller,
                                               const std::vector<uint8_t>& member,
                                               uint32_t valid_until_height, uint32_t link_seq);
// What the new controller signs: the same shape under the tag "ZBC-GROUP-CONTROL", with the current
// controller first and the new controller second.
Result<std::vector<uint8_t>> ControlConsentDigest(const std::vector<uint8_t>& current_controller,
                                                  const std::vector<uint8_t>& new_controller,
                                                  uint32_t valid_until_height, uint32_t link_seq);

// Verify `proof` as `signer`'s consent to `digest`. Kind 1 recomputes the multisig address from the
// listed participants, threshold and nonce and requires it to be `signer`, then counts distinct
// participants whose signature verifies.
Result<void> VerifyConsent(const std::vector<uint8_t>& digest, const ConsentProof& proof,
                           const std::vector<uint8_t>& signer);

// Address types that can never sign, so can never consent: Empty (2), Estonia eID (3, no verifier),
// P2WSH (8, a script hash) and the ZBS_ dataset address (10).
bool IsNonSigningType(const std::vector<uint8_t>& address);

// The four group-management types. A member's transaction of any OTHER type acts as the group.
bool IsGroupManagementType(TransactionType t);
// Types only the controller may send on the group's behalf (SetTransactPolicy and SetSplitPolicy
// change the group account; the management types manage it). UnlinkAccount is also allowed to a
// member removing itself.
bool IsControllerOnlyType(TransactionType t);

// Weight of a group record for rent: ACCOUNT_GROUP_RECORD_BASE_BYTES + controller length + per member
// (address length + ACCOUNT_GROUP_MEMBER_ENTRY_BYTES).
uint64_t RecordWeight(const std::vector<uint8_t>& controller,
                      const std::vector<std::vector<uint8_t>>& member_addresses);

}  // namespace group
}  // namespace transaction
}  // namespace zoobc
