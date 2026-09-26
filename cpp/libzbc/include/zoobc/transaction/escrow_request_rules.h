// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#pragma once
// Multi-party escrow and the receiver-issued escrow request (rule `escrow_request`,
// docs/escrow-message-spec.md, docs/FEE_RULES.md §3).
//
// Two ways an escrow comes about:
//   1. sender-issued: the payer creates an escrowed SendZBC/TransferToken; the approver settles it.
//   2. receiver-issued: the payee publishes an EscrowRequest (type 260) naming the payer, the amount,
//      the approver and the commission. The payer finds it (GET /api/v1/escrow_requests?address=)
//      and funds it with an escrowed SendZBC whose escrow envelope carries multi_party = 1 and
//      escrow_request_id = the request's id. From then on it is an ordinary escrow.
//
// A multi-party envelope may also carry a CO-SIGNATURE by the recipient. The co-signer signs the
// transaction's unsigned bytes with its own co-signature field EMPTY (CoSignerSigningDigest): a
// signature cannot be part of the bytes it signs. The sender signs last, over the bytes that
// include the co-signature, so the sender's signature still covers everything.
//
// Below the rule's height none of this is checked (the multi-party fields were carried and ignored),
// which is how history is replayed.
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "zoobc/common/result.h"
#include "zoobc/model/transaction.h"

namespace zoobc {
namespace database { class Database; }
namespace transaction {
class AccountState;

// The digest a co-signer signs: the chain-bound signing digest of the unsigned transaction bytes
// with escrow.co_signer_signature cleared.
Result<std::vector<uint8_t>> CoSignerSigningDigest(const model::Transaction& tx);

// Stateless shape of a multi-party escrow envelope (from `escrow_request`): it must carry a
// co-signature or a request link (or both); a co-signature must verify against the recipient; a
// request link is only valid on SendZBC. No-op (Ok) for a transaction without multi_party.
Result<void> ValidateMultiPartyEscrow(const model::Transaction& tx);

// The latest version of an escrow request, if it exists.
std::optional<model::EscrowRequest> LoadEscrowRequest(const std::shared_ptr<database::Database>& db,
                                                      int64_t request_id);

// Empty when `tx` may fund the request it links to at `block_height`; otherwise why not. The
// request must exist, be Pending and not expired, and the escrow must match its terms: the payer
// is the proposed sender, the recipient is the requester, and the amount, the approver, the
// commission, the deadline (escrow timeout) and the instruction are exactly the ones requested
// (owner decision 2026-09-23). Same answer at admission and at execution.
// `accounts` (optional): with account groups a member's transaction runs as its group, so the
// payer is also accepted when it is the same account as the proposed sender
// (AccountState::SameAccount, docs/ACCOUNT_GROUPS.md: authority named on a member address).
std::string EscrowRequestFundingProblem(const std::shared_ptr<database::Database>& db,
                                        const model::Transaction& tx, uint32_t block_height,
                                        const AccountState* accounts = nullptr);

// Record that the request was funded by `escrow_tx_id` at `block_height` (a new version, status
// Approved). Versioned like every other state table, so a rollback reverts it.
Result<void> MarkEscrowRequestFunded(const std::shared_ptr<database::Database>& db,
                                     const model::EscrowRequest& request, int64_t escrow_tx_id,
                                     uint32_t block_height);

// DeclineEscrowRequest (type 516, rule `escrow_request`, owner decisions 2026-09-23): THE decline.
// Whichever side did not create the escrow may refuse it, with a reason:
//   - target Request (0): the payer an EscrowRequest names declines the request (the receiver created it);
//   - target Escrow  (1): the recipient of a pending sender-issued escrow (an escrowed SendZBC or
//     TransferToken) refuses it (the sender created it). The held amount and the commission go back to
//     the sender, as on expiry; the escrow's status becomes Declined (4) with the reason.
// Body: target_id(8 LE) | reason_len(u16 LE) | reason bytes [| target(1)]
// The trailing target byte is absent for a request (so every request decline keeps the exact bytes it
// had) and present, equal to 1, for an escrow. A present 0 or any other value is refused: one meaning,
// one encoding.
enum class DeclineTarget : uint8_t { Request = 0, Escrow = 1 };
struct DeclineEscrowRequestBody {
    int64_t request_id = 0;      // the id of the target: the EscrowRequest's id, or the escrowed transaction's id
    std::string reason;          // UTF-8, at most constants::ESCROW_REQUEST_DECLINE_REASON_MAX bytes, no NUL
    DeclineTarget target = DeclineTarget::Request;
};
std::vector<uint8_t> EncodeDeclineEscrowRequestBody(const DeclineEscrowRequestBody& b);
// Refuses truncation, trailing bytes other than the escrow target byte, a reason over the cap and a NUL
// byte in it.
Result<DeclineEscrowRequestBody> ParseDeclineEscrowRequestBody(const std::vector<uint8_t>& bytes);

// Empty when `tx` (a DeclineEscrowRequest) may decline its request at `block_height`; otherwise why
// not. The request must exist, be Pending and not expired, and the sender must be the payer it names:
// the same address in canonical form, or — with account groups — the same account
// (AccountState::SameAccount: a member acting as its group declines for the group, and a group's
// member may decline a request naming the group or another of its members). Same answer at admission
// and at execution; the executor turns a non-empty answer into a paid no-op.
std::string EscrowRequestDeclineProblem(const std::shared_ptr<database::Database>& db,
                                        const model::Transaction& tx, uint32_t block_height,
                                        const AccountState* accounts = nullptr);

// Empty when `tx` (a DeclineEscrowRequest with target Escrow) may refuse the escrow it names at
// `block_height`; otherwise why not. The escrow must exist and still be Pending (not approved, rejected,
// expired or already declined), it must hold a SendZBC or a TransferToken (the escrowable types), and
// the sender must be the escrow's recipient: the same address in canonical form, or — with account
// groups — the same account (AccountState::SameAccount). A recipient that is the same account as the
// escrow's sender did not receive it from anyone and may not decline it (it would be the creator
// cancelling unilaterally). Same answer at admission and at execution.
std::string EscrowDeclineProblem(const std::shared_ptr<database::Database>& db,
                                 const model::Transaction& tx, uint32_t block_height,
                                 const AccountState* accounts = nullptr);

// Record the decline (a new version, status Declined, the reason stored). Rolled back with its block;
// carried in snapshots by the generic StateTables section.
Result<void> MarkEscrowRequestDeclined(const std::shared_ptr<database::Database>& db,
                                       const model::EscrowRequest& request, const std::string& reason,
                                       uint32_t block_height);

// Is `signer` the escrow's approver? From `escrow_request` the two are compared in canonical form (a
// legacy 32-byte ZBC key equals the typed 36-byte address of the same key); below it byte for byte,
// as history was judged. Used by admission and by ExecuteApprovalEscrow alike.
bool IsEscrowApprover(const std::vector<uint8_t>& signer, const std::vector<uint8_t>& approver,
                      uint32_t block_height);

// What the API reports for a request (read-time only, no consensus effect). A stored Pending
// request that can no longer be funded — the next block (tip + 1) is past its expiry height, the
// same test the executor applies — is reported as Expired, so a wallet never has to compute it.
// Every other status is reported as stored.
model::EscrowRequestStatus ReportedEscrowRequestStatus(model::EscrowRequestStatus stored, int64_t expiry,
                                                       uint32_t tip_height);
const char* EscrowRequestStatusName(model::EscrowRequestStatus status);   // pending/approved/rejected/expired/declined

}  // namespace transaction
}  // namespace zoobc
