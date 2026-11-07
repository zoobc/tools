// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#pragma once
// Consensus rules that switch on at a block height, so the software can be upgraded without
// restarting the chain.
//
// The problem this solves. A new transaction type or a changed validation rule splits a network
// the moment a block exercises it while some nodes still run the old binary: one side accepts the
// block, the other rejects it. Until now the answer was to relaunch the chain, which is fine on a
// disposable testnet and impossible on mainnet. It also has a quieter failure: a STRICTER rule
// applied to history makes a re-syncing node reject a block that was legal when it was mined. The
// live testnet already contains one — a token whose name is `<img src=x onerror=alert(1)>`, issued
// before the name rule existed.
//
// Both problems have the same fix: every rule is scoped to a block height. A rule is off below its
// activation height and on from it, and the decision is made against the height of the BLOCK BEING
// VALIDATED, never the node's current tip. Old blocks are therefore judged by the rules that were
// in force when they were made, and every node switches behaviour at the same block whatever day
// it was upgraded. Announce the height with the release; operators upgrade by then or fork off,
// which is the intended and visible consequence.
//
// Where a height comes from, in order:
//   1. `rule.<name>` in consensus_parameters, written from the genesis config. A chain launched
//      fresh sets its own, which is what stops a relaunched testnet inheriting a height in the far
//      future and never activating anything.
//   2. the compiled default below, which the release engineer sets to a height comfortably ahead
//      of every live chain at the time of the release.
//
// Activation heights are deliberately NOT governable by SetConsensusParam. A 2/3 vote that can
// move a rule boundary is a 2/3 vote that can rewrite history's meaning.
//
// Rules are INTERVALS (protocol review 2026-10-21, item 16 F1): Active = on <= h < off. The off
// height is kRuleNeverOff unless a later release retires the rule (default_off in the table) or the
// genesis lists `rule_off.<name>`. A rule found wrong after it activated is switched off from a
// future height, chosen like an on-height (ahead of the fleet), without touching the blocks mined
// under it: a re-syncing node keeps judging those with the rule on, and the fix the rule needed
// ships in the same release. Removing the gate from the binary instead re-judges history and
// breaks replay, which is why 0.5.6's eleven-rule stall could only be answered on the producer
// side. The emergency path is written in docs/ROLLING-UPGRADE.md §6.
//
// A STATEFUL rule warms up (item 16 F6): one that counts misses, attendance or presence started at
// its height with empty tables, and the 0.5.6 rules each invented a warm-up of their own. Now the
// table carries default_warm_up (blocks), and the mechanism holds the split: state ACCUMULATES from
// on - warm_up (RuleClock::Accumulating) and the CONSEQUENCES bite from on (RuleClock::Active). A
// rule that writes state asks Accumulating at its state sites and Active at its consequence sites;
// the liveness counter is the worked example (block_service::ApplyLiveness). A fresh chain (on = 0)
// has nothing to warm; the value is for the first rolling upgrade that adds a stateful rule.
#include "zoobc/common/result.h"
#include <cstdint>
#include <cstdlib>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "zoobc/common/types.h"

namespace zoobc {
namespace consensus {

// "I do not know which block this is for" — admission and tooling. Reads as "the newest rules",
// which is right for judging something that has not been mined yet and wrong for replay, so block
// validation must always pass a real height.
constexpr uint32_t kHeightUnknown = 0xFFFFFFFFu;
// A rule's off-height when nothing retires it: no block ever reaches it. Same bits as
// kHeightUnknown by coincidence of "no such height"; the two are never compared.
constexpr uint32_t kRuleNeverOff = 0xFFFFFFFFu;

// Set per release: ahead of every live chain when the binary ships, so operators have time to
// upgrade. v0.5.5 ships with the relaunched chains near height 22,000 (testnet) and 20,000 (devnet)
// at 15-second blocks; 30,000 is about a day and a half of warning (owner decision 2026-09-30:
// the six 0.5.2 rules waited at 60,000 while testers kept reporting what they fix).
constexpr uint32_t kDefaultActivationHeight = 30000;
// v0.5.6: cut 2026-10-19 with testnet at ~121,300 and devnet at ~123,900 (16.3-second blocks measured);
// 142,000 (set at the cut, 2026-10-19 22:50 UTC, with testnet at 125,282 and devnet at 128,599): about
// 3.1 days (testnet, ≈ 2026-10-23 02:30 UTC) and 2.5 days (devnet, ≈ 2026-10-22 11:30 UTC) of warning
// for a build on 2026-10-20 and a roll by 2026-10-21. One line to move.
constexpr uint32_t kActivationHeight_0_5_6 = 142000;
// v0.5.7: first rule added 2026-10-21 with testnet at 131,000 and devnet at 134,500 (16.3-second blocks,
// ≈ 5,300 a day). 175,000 is ≈ 2026-10-29 (testnet) / 2026-10-28 (devnet): a week of warning for a cut
// on 2026-10-26 and a roll the day after. One line to move at the cut.
constexpr uint32_t kActivationHeight_0_5_7 = 175000;
// v0.5.8: both chains restart from zero on a genesis that lists every rule at height 0, so the
// compiled default for 0.5.8 rules is 0: on from genesis on any chain built from this release.
constexpr uint32_t kActivationHeight_0_5_8 = 0;
// 0.6.0 relaunch: both chains restart from a genesis that lists every rule at 0, so the rules 0.5.9 added for the
// live 0.5.8 devnet (at 12,000 there) are on from genesis too; a chain built later from this release gets 0.
constexpr uint32_t kActivationHeight_0_6_0 = 0;
// v0.6.1 (the 2026-11-02 audit's Phase 2: owner decisions Q1, Q5, Q6, Q7): PROVISIONAL. The owner sets the value at
// the cut, ahead of both live chains (the 0.5.6/0.5.7 pattern above: a week of warning for a build and a roll); a
// chain built from this release lists every rule at 0 in its genesis. One line to move at the cut.
constexpr uint32_t kActivationHeight_0_6_1 = 1000000;
// v0.6.2 (bounty report 2026-11-06, the token LiquidPayment fee mint): the first bundle rolled onto chains that
// already run (both relaunched on 0.6.1 with every rule at 0). Its rules are readiness-gated bundle 602: on the live
// chains the compiled height is never consulted (rule readiness_registry_schedule: the earliest unrevoked
// registration of the 0.6.2 release plus ACTIVATION_FLOOR_BLOCKS decides), and a chain built later from this
// release lists them at 0 in its genesis. The value only has to be above 0, so the live genesis files, which cannot
// change, may leave the rule out (relaunch_genesis_rules_test --live, tools/check-rule-names.py LIVE_CONFIGS).
constexpr uint32_t kActivationHeight_0_6_2 = 1000000;
// The per-chain override map of 0.5.6 (two genesis hashes, two heights) died with the old chains at
// the 0.5.8 relaunch: every rule is at height 0 in both relaunch genesis files, and a chain built
// later from this release gets the compiled default of its rules.

struct RuleActivation {
    const char* name;
    uint32_t default_height;
    const char* what;
    uint32_t default_off = kRuleNeverOff;   // 16 F1: the release that retires the rule sets this (a height ahead of the fleet)
    // dzoobc-de on ae36f1ab: not every rule can be switched off. A rule that wrote state (a column, a
    // table, a new meaning for stored rows) has no off-road: past the off-height every node would read
    // rows written under the rule with the old semantics (a rotated key resolving again, an owed payout
    // never paid, a frozen row read as expelled). Only a JUDGEMENT rule, whose off-road is the pre-rule
    // code over the same state, is retirable; the builder refuses rule_off on any other (CF9).
    bool retirable = false;
    // 16 F6: blocks of accumulation before the on-height for a stateful rule (0 = none). The
    // release that adds a stateful rule sets it; a fresh chain starts every rule at 0 anyway.
    uint32_t default_warm_up = 0;
    // 16 F2-2: the bundle the rule ships in (major*10000 + minor*100 + patch: 0.5.9 = 509). 0 = the
    // relaunch set, never gated by readiness (ROLLING-UPGRADE.md §7.2). A later bundle activates at
    // the first qualifying height at or after its scheduled one (16 F2-3), not at the height itself.
    uint32_t bundle = 0;
};

// 16 F2-1 / 16 F2-2: the bundle id of a release string, "0.5.9" -> 509, "0.6.0" -> 600; 0 if malformed.
constexpr uint32_t ParseBundleId(const char* v) {
    uint32_t parts[3] = {0, 0, 0}; int n = 0; bool digit = false;
    if (*v == 'v' || *v == 'V') ++v;   // the registry's tags carry a leading v ("v0.5.9")
    for (; *v; ++v) {
        if (*v >= '0' && *v <= '9') { if (n > 2) return 0; parts[n] = parts[n] * 10 + static_cast<uint32_t>(*v - '0'); digit = true; }
        else if (*v == '.') { if (!digit || n == 2) return 0; ++n; digit = false; }
        else break;   // a suffix ("-rc1") ends the numeric part
    }
    if (n != 2 || !digit || parts[1] > 99 || parts[2] > 99) return 0;
    return parts[0] * 10000 + parts[1] * 100 + parts[2];
}
#ifndef ZOOBC_VERSION
#define ZOOBC_VERSION "0.0.0"
#endif
// The bundle id this binary signals in block.version (ROLLING-UPGRADE.md §7.1): the newest rule
// bundle it carries, which is its own release (the VERSION file, exported by CMake as ZOOBC_VERSION).
// The genesis block keeps version 1.
constexpr uint32_t kBundleId = ParseBundleId(ZOOBC_VERSION);
// 0.6.1: its rules form readiness-gated bundle 601 for a rolling upgrade. Each explicit genesis zero
// exempts that rule from gating, so a fresh relaunch starts it at block 0 without signals.
static_assert(kBundleId > 0, "VERSION must be major.minor.patch");

inline const std::vector<RuleActivation>& ActivationTable() {
    static const std::vector<RuleActivation> kTable = {
        {"split_policy", kDefaultActivationHeight,
         "SetSplitPolicy (transaction type 54) is accepted, and an account's policy forwards its incoming credits"},
        {"taproot_recipients", kDefaultActivationHeight,
         "a Taproot (bc1p, account type 9) address may receive ZBC — the node has verified Taproot spends since v0.4.0", kRuleNeverOff, true},
        {"storage_acl", kDefaultActivationHeight,
         "StoreFile may carry an access mode and an allow list, and the content endpoint enforces them"},
        {"token_name_shape", kDefaultActivationHeight,
         "IssueToken refuses a name containing markup, control or bidi characters", kRuleNeverOff, true},
        // Forum #360: the scramble key hashed one byte of the node id, so an operator who ground
        // the first byte of a key chose where its nodes landed in the relay order.
        {"topology_full_id", kDefaultActivationHeight,
         "the topology scramble key hashes the whole node id and the period height, not one byte of the id"},
        // Forum #345: the trigger oracle resolved on 3 of the top 5 producers' owner accounts. The
        // bridge and governance resolvers already need ceil(2/3) of the full registry, node keys.
        {"oracle_full_registry_quorum", kDefaultActivationHeight,
         "a generic oracle event resolves on ceil(2/3) of the full active registry voting with node keys, not 3 of the top 5 producers"},
        // Forum #270 + owner decision 2026-09-23: every type returns (fee paid - fee charged), an
        // escrowed transaction at creation; the fee pays for processing only, and survival
        // (token persistence, escrow rent) is an explicit amount with its own ledger event.
        {"uniform_fee_refund", kDefaultActivationHeight,
         "every transaction refunds its overpay (escrowed ones at creation) and rent is paid as an explicit amount, never out of the fee"},
        // Owner decision 2026-09-23: both kinds of escrow must work — sender-issued, and
        // receiver-issued (the payee's EscrowRequest, funded by the payer). Before this rule the
        // multi-party fields of an escrow were carried and never checked: a request link changed
        // nothing and a co-signature was never verified (the only verifier, EscrowValidate, had no
        // caller, and it hashed the co-signature into the bytes the co-signature signs).
        {"escrow_request", kDefaultActivationHeight,
         "a multi-party escrow's co-signature is verified over the bytes without it, an escrow linked to an EscrowRequest must match the request exactly (payer, payee, amount, approver, commission, deadline, instruction) and marks it funded, the payer may decline a request and the recipient may decline a pending sender-issued escrow (DeclineEscrowRequest, type 516; the escrow's amount and commission return to its sender), and escrow parties (request terms, approver) compare in canonical address form"},
        // Owner decisions 2026-09-23 (docs/ACCOUNT_GROUPS.md): one account, many addresses.
        {"account_groups", kDefaultActivationHeight,
         "LinkAccount, UnlinkAccount, SetMemberPermissions and TransferGroupControl (types 55-58) are accepted; a member address resolves to its group's account"},
        // Found 2026-09-23: the lottery and the blocksmith fallback wrote the winner's balance row by
        // hand and reset its nonce, rent clock and transact policy to 0 on every reward.
        {"balance_credit_full_row", kDefaultActivationHeight,
         "a block reward is credited through the ordinary balance path, keeping the winner's nonce, rent clock and transact policy"},
        // Found 2026-09-23 (offline multisig tool): a type-5 re-carrying an executed inner
        // transaction's public bytes, with or without signatures, reset it to Pending and paid it
        // again, until the multisig account was empty.
        {"multisig_no_replay", kDefaultActivationHeight,
         "a multisig inner transaction that has executed is final: a type-5 naming it is refused at admission and, if mined, is a no-op that keeps only the outer fee floor"},
        // DESIGN-2026-09-23-unified-survival.md finding 4: the first FundLongevity on a target read
        // the target's size and height from the node's own zbc_transaction table, and "the target
        // is present" was checked at admission only, so a node still holding a target the others
        // had pruned recorded different numbers. The body now states them and every node checks
        // them the same way (docs/FEE_RULES.md, "FundLongevity: stated target").
        {"longevity_stated_target", kDefaultActivationHeight,
         "FundLongevity carries the target's block height and billable bytes (28-byte body); a first funding whose target is not younger than one snapshot interval, or whose stated values do not match the target, is a fee-floor no-op"},
        // Same study, finding 6: an expired token's remaining backing went to the issuer even when
        // other accounts held its units, whose units then became worthless.
        {"token_expiry_to_holders", kDefaultActivationHeight,
         "an expired token's remaining backing is paid to the accounts holding its units, pro rata (units held in orders, swap offers, escrows, schedules, liquid payments and apps count for their owners), not to the issuer"},
        // Owner decisions 2026-09-23 (DESIGN-2026-09-23-unified-survival.md §5; docs/FEE_RULES.md
        // "Survival in the transaction"): every transaction may carry its own survival deposit, the
        // owner of a transaction may close its longevity record, and every rent balance that ends
        // early pays what is left to the longevity node pool, never back to a funder or owner.
        {"survival_field", kDefaultActivationHeight,
         "transaction version 2 carries a survival amount (u64 after the fee) that opens or tops up the transaction's own longevity record; CloseLongevity (type 309) is a payer's vote to close a record: only payers whose money is not yet used up vote, the record closes in the block of the last missing vote and its remaining deposit goes to the longevity node pool (a top-up withdraws that payer's vote; FP11); CancelLongevity is retired (top-ups cannot be taken back); escrow rent and token survival payments, a deleted or pruned dataset's ZBS_ remainder and an exhausted stored file's remainder go to the longevity node pool; a deleted DFS file pays each payer back its unused part (FP12)"},
        // Wallet prompt 12, gap 3: a stored file's deposit could only be chosen once, at StoreFile.
        {"stored_file_topup", kDefaultActivationHeight,
         "FundStoredFile (transaction type 296) adds to an active stored file's rent deposit; anyone may fund, nothing added can be taken back"},
        // Tester report 2026-09-24: CreateMarket never checked that its tokens exist.
        {"market_known_tokens", kDefaultActivationHeight,
         "CreateMarket whose base or quote token does not exist (0 = ZBC) is a fee-only no-op: no market, no creation cost"},
        // Same report: two reassigns by the recipient in one block failed the block.
        {"reassign_schedule_moved", kDefaultActivationHeight,
         "ReassignSchedule whose sender is no longer the schedule's recipient (an earlier reassign in the block moved it) is a fee-only no-op instead of failing the block"},
        // Found 2026-09-24 (wallet V1.74 live test): mint backing, burn redemption and the fee-in-token
        // unit count were computed in double / long double. floor(backing/supply*amount) is not
        // floor(amount*backing/supply): burning the whole supply of a token backed by 1.23456789 ZBC
        // paid back 1 atom less than the backing and left it stranded, and long double is 80-bit on
        // x86-64 but 128-bit on ARM64, so the fee-in-token count could differ between architectures.
        {"token_exact_backing", kDefaultActivationHeight,
         "MintToken's added backing is ceil(amount*backing/supply), BurnToken's redemption floor(amount*backing/supply) and a fee-in-token's unit count ceil(fee*supply/backing), all in exact integer arithmetic (no floating point)"},
        // Same test: a pre-locked schedule whose end_time cut it short ended with locked ZBC that
        // nobody was ever paid and nobody could cancel.
        {"schedule_end_refund", kDefaultActivationHeight,
         "a pre-locked schedule that ends with funds still locked (end_time reached, or a failed last credit) returns them to its owner"},
        // Overnight devnet test 2026-09-25: LiquidPaymentStop split a stream with a double ceil, and
        // 0.11 * 1e8 is 11000000.000000002 in binary, so 66 s of a 600 s stream paid 11000001.
        {"liquid_exact_vesting", kDefaultActivationHeight,
         "LiquidPaymentStop pays the recipient ceil(amount * elapsed / duration) in exact integer arithmetic (no floating point)"},
        // Same test: SetupAccountDataset with property '' was stored and listed.
        {"dataset_property_nonempty", kDefaultActivationHeight,
         "SetupAccountDataset refuses an empty property name", kRuleNeverOff, true},
        // Same test: a transaction dated 2033 was admitted and mined (h147). The block check refused only
        // expired transactions, so one dated far ahead stayed replayable past the snapshot window.
        {"tx_timestamp_bound", kDefaultActivationHeight,
         "a block may not carry a transaction dated more than TRANSACTION_FUTURE_TOLERANCE (3600 s) after the block", kRuleNeverOff, true},
        // Same test: a decimals-2 token burned 25016210 units for a fee, leaving the sender 983790 units
        // no transfer can move ("finer than the token's decimals allow").
        {"fee_in_token_step", kDefaultActivationHeight,
         "the token units burned for a fee paid in the token are rounded up to the token's smallest step (10^(8-decimals))"},
        // Owner decision 2026-09-26: an account-group member's refused spend is an overspend. Before this
        // rule a producer that mined one got a VALID block in which it was a fee-free no-op recorded on
        // the group (fee_refund 22 + fee_not_collected 47), unlike an ordinary account's overspend, which
        // makes the block invalid. Builder and validator use the same EvaluateGroupGate.
        {"group_spend_invalid_block", kDefaultActivationHeight,
         "a transaction (or a multisig inner transaction) by an account-group member that the controller has not permitted, or that exceeds the member's spending limit, makes the block invalid, like an ordinary account's overspend; nothing is written (below the height it is a fee-free no-op with a 22 + 47 pair)"},
        // Owner rule 2026-09-26 (executors never hard-error on state; testnet block 6421): a mined
        // FeeVoteCommitment from an account without a registered node failed its block. Admission has
        // refused it since the overnight fix of 2026-09-25; the executor now agrees without erroring.
        {"fee_vote_noop", kDefaultActivationHeight,
         "a FeeVoteCommitment or FeeVoteReveal whose sender is not a registered node is a paid no-op (the fee charged, its overpay refunded, no vote stored), and one whose sender cannot cover the fee is a no-op that charges nothing (22 + 47), instead of failing the block; block validation leaves the registered-node check to the executor"},
        // Forum #365 (2026-09-26): a pre-locked schedule whose fire credit failed re-armed and completed
        // with the tranche still locked; schedule_end_refund returns it at the end, but a row that ended
        // with funds still locked (its end refund failed) had no way back: CancelSchedule refuses a
        // schedule that is not pending. Storage faults now fail the block, so such a row should never
        // be written again; this is the way back for one that exists.
        {"schedule_reclaim_locked", kDefaultActivationHeight,
         "CancelSchedule from the owner or the recipient of a pre-locked schedule that is no longer pending but still holds funds returns them to the owner (its status is unchanged); before the rule it is a fee-only no-op"},
        // TestNet 2026-09-26, blocks 549-655: five DFSDeleteFile for one path were each admitted (the
        // file existed) and selected into one candidate; the first deleted the file, the second failed
        // the block (DFSService::DeleteFile: NotFound), and every priority blocksmith re-selected them
        // for 107 empty, coinbase-less blocks until they expired. A create over an existing path also
        // rebound the file's ZBS_ deposit to the new hash and stranded the old deposit for ever.
        {"dfs_moved_state", kDefaultActivationHeight,
         "a DFSDeleteFile or DFSUpdateFile whose file no longer exists, or a DFSCreateFile whose path already holds an active file of the sender (the earlier transaction may be in the same block), is a fee-only no-op instead of failing the block"},
        // DevNet 2026-09-26 block 900 and 2026-09-27 block 3767: a transfer to a recipient whose 4-byte
        // account-type prefix names no account type passed admission and failed in AddBalance, which
        // failed every candidate carrying it. SendZBC refuses it at admission from 0.5.2 whatever the
        // height (its executor credits the recipient, so no such block ever applied); the other
        // recipient-bearing types stored the bytes without crediting them and were mineable, hence the gate.
        {"recipient_address_shape", kDefaultActivationHeight,
         "a transaction that names a recipient names one AccountState can hold (a known account type of the right length); TransferToken, LiquidPayment, ScheduledTransfer, CreateTrigger, SetupAccountDataset, RemoveAccountDataset and node registration are refused otherwise, as SendZBC already is", kRuleNeverOff, true},
        // The `dfs:` property namespace of the dataset store holds DFS file rows (DFSService::PathToProperty).
        // A SetupAccountDataset under that prefix made a "file" without content that DFSDeleteFile then acted
        // on (DevNet 2026-09-26, dfs:/pocdrain.txt).
        {"dfs_namespace_reserved", kDefaultActivationHeight,
         "SetupAccountDataset refuses a property beginning `dfs:`; rows there are DFS files, written by DFS transactions only", kRuleNeverOff, true},
        // Executor sweep after the 2026-09-26 stalls (owner rule: an executor never fails a block on
        // an answer about chain state; every such answer is a paid no-op). Each of these passed
        // admission against committed state and failed the block at execution.
        {"state_answer_noop", kDefaultActivationHeight,
         "fee-only no-ops instead of failed blocks: a fee-in-token TransferToken of a token with no ZBC backing; a CreateSwapOffer whose give or want amount is finer than that token's step; a solo CreateApp whose largest payout exceeds the apps pool's cap for one bet; a CancelSchedule by an address that is no longer the schedule's recipient (a ReassignSchedule moved it); a RegisterRelease, ReleaseAuthorityPropose or RevokeRelease by an address that is no longer the release authority, and a ReleaseAuthorityAccept with no pending authority or by an address that is not it; a NodeRegistration of a node key that is already registered; an escrowed TransferToken whose sender no longer holds the tokens; a token LiquidPayment naming an unknown token; a multisig wrapper repeating a signature already stored in the block; an ApprovalEscrow approving to a recipient AccountState cannot credit (the escrow stays pending and expires as usual); a LiquidPaymentStop whose recipient cannot be credited pays the whole remainder back to the sender; and a transaction whose sender cannot cover even its fee (Empty, IssueToken, MintToken, SubmitStorageProof, FundLongevity, EscrowRequest, TransferDataset, AcceptDataset, SetDatasetPolicy, DeleteDataset) writes nothing instead of failing the block"},
        // Forum #371 (2026-09-27) led here: a SetupAccountDataset over an existing active row bound the
        // row to the NEW transaction's hash, so the deposit funded on the old ZBS_ address was stranded
        // (nobody's to spend, never billed, never swept), and the row's object id was cleared.
        {"dataset_update_keeps_deposit", kDefaultActivationHeight,
         "a SetupAccountDataset over an active row of the same setter, recipient and property keeps the row's object, deposit binding (creating_tx_hash) and rent clock instead of binding it to the new transaction's hash"},
        // Forum #370: a pull-at-fire schedule a limited member created kept firing from the pool after
        // the controller lowered the limit, made the member receive-only or unlinked it; FireDueSchedules
        // never consulted the member row (the creating member was not even recorded on the schedule).
        {"schedule_fire_member_gate", kDefaultActivationHeight,
         "a pull-at-fire schedule created by a group member records the member; each fire is judged by the member's row of that moment (unlinked, receive-only or over the limit = the fire is skipped and counts toward auto-cancel) and counts against its spending window"},
        // Owner decisions 2026-10-19 (forum #424 #445 #455 #458 #462 #390): consecutive-miss counter,
        // expulsion of a never-produced node at the 4th miss, suspension of an established node at the
        // 4th miss (expelled after 17,280 silent blocks), floor of 3 active nodes, no consecutive
        // producer. The selection set, the skipped-blocksmith enumeration and the coinbase lottery
        // all run over the same selectable set.
        {"liveness_miss_rule", kActivationHeight_0_5_6,
         "the liveness and score road: a node drawn before the producer and skipped gains a miss, present or absent, and is missing until its next own block; at liveness_miss_limit (4) consecutive misses it is suspended (out of the draw, missing); while missing it loses score_loss_per_unit_bps of the maximum score per unit of max(n, score_unit_floor_blocks) blocks, prorated per block; a node whose score reaches zero is expelled, never below 3 active nodes (owner decisions 2026-10-19; LV1, LV2, LV5)"},
        // Forum #445 #458: the skip penalty was charged to every node drawn before the producer, present
        // nodes included, and a returning peer settled every skipped round in one block.
        // Forum #420 #424 #434 #435 #446 #450 #456 #457: the window estimate pulled the clock into the
        // past per skipped slot; after a stall no round validated again.
        // Owner decision 2026-10-19 (forum #417 #412 #416 #418 #422 #393 #397): registry guards.
        // Owner decision 2026-10-19 (forum #421 #424): a queued node must prove it is online for the
        // whole wait, pays for the proof out of its stake, and the queue is ordered by stake × time.
        // Forum #398 (owner decision 2026-10-19): the market creation cost becomes a deposit; no free fills.
        {"market_deposit_refund", kActivationHeight_0_5_6,
         "the 50 ZBC market creation cost is a deposit returned to the creator at the 100th fill (retired under market_rent)"},
        {"market_min_notional", kActivationHeight_0_5_6,
         "an order whose quote amount rounds to zero is refused", kRuleNeverOff, true},
        {"queue_attendance", kActivationHeight_0_5_6,
         "QueueAttendance (type 59) is accepted from queued nodes, its minimum fee from the stake; admission needs attendance in the newest evaluated 5,760-block window; the misses tolerated over the wait are one admission cycle's worth of windows (node_admission_max_delay / (window x block time), never under 2: 90 on mainnet and testnet), the next one drops the node (10 % of the lock to the longevity pool); queue order = stake × blocks waited"},
        {"poown_required", kActivationHeight_0_5_6,
         "RegisterNode and UpdateNode carry a verified proof of ownership (node key signs owner address, recent block hash and height)", kRuleNeverOff, true},
        {"relay_owner_gates", kActivationHeight_0_5_6,
         "RegisterRelay binds only to an active gateway the sender owns, and never to another owner's node key", kRuleNeverOff, true},
        {"oracle_registered_only", kActivationHeight_0_5_6,
         "AttestEvent rows are written only by the registry's attester accounts; anyone else pays the fee and writes nothing", kRuleNeverOff, true},
        {"smith_window_anchor", kActivationHeight_0_5_6,
         "blocksmith rounds anchor on the previous block's timestamp; skipped slots no longer shift the window"},
        // Forum #427 #428 #430 #432 #452 #391: a gap above 3600 s was a hard rejection.
        {"halt_recovery_param", kActivationHeight_0_5_6,
         "the recovery limit is the consensus parameter max_recovery_interval_seconds (consensus::RecoveryLimitSeconds, default 3600): a block whose gap to its parent exceeds it is a resume block, accepted when its producer is the expected smith of the round the gap implies; the resume draw and the P2P stale-tip threshold (twice the limit) read the same value (3 F4); the miss stall threshold is the separate constant LIVENESS_STALL_ROUNDS (3 F2)"},
        // Forum #413 (2026-10-13, retested 2026-10-21 on wallet V1.87): the wallet's `inv:` invoice rows are
        // JSON the payer's wallet computes with; the node stored one with a negative unit price and total.
        // The `inv:` namespace joins `tokenicon:` and `dfs:` as a reserved one (DESIGN-untrusted-chain-data:
        // what the protocol defines, it constrains to a shape). The check is a SAX walk, no tree, no schema:
        // a JSON object, and no negative number anywhere in it. Every other property stays opaque bytes.
        {"topology_window_fix", kActivationHeight_0_5_8,
         "the receipt datum is sampled over every datum of the lookback block (the last one was never sampled), a node's receiver window skips itself without shortening (P receivers, as the pivot assumes), and when gcd(P, N) > 1 the window starts are mixed with the scramble's seed so nodes of one residue class no longer share a window (6 F7)"},
        {"small_n_measurement", kActivationHeight_0_5_8,
         "the receipt score's pivot is half of what a producer can show (min(|S| - 1, P)) with the half-cap as the divisor, so scores mean something below seven nodes; with no score anywhere the coinbase lottery and the longevity payout split evenly among the ticket holders instead of paying the producer or keeping the pool; the storage tally's verdict is honoured, no reward and no penalty below the quorum or on a tie (6 F1 / 19 F2)"},
        {"receipt_count_active", kActivationHeight_0_5_8,
         "the receipt cap and the |R| factor of the receipt score use the ACTIVE registry size at the previous block (the validator's cap too, as of the block instead of the tip); the draw set is used only for the draw (1 F7)"},
        {"payout_instant", kActivationHeight_0_5_8,
         "every payout (the coinbase lottery, the longevity payout, the storage reward, the producer's taker fee) reads who earns at one instant, as of the previous block (consensus::IncomeView: not missing, not suspended, mature): a node that goes missing by block h keeps its ticket and its share for h and loses both from h + 1; before, the lottery ran before ApplyLiveness and the payout after it (1 F9; LV3, LV4)"},
        {"longevity_continuous", kActivationHeight_0_5_8,
         "the longevity pool pays through the coinbase lottery: every block above 1 adds pool_balance / (blocks left in the billing period) to its distributable amount, so the per-block ticket set decides a per-block slice and the pool is empty at each period boundary; the one-block-per-period payout retires (7 F3, D7)"},
        {"draw_count_previous_gap", kActivationHeight_0_5_8,
         "the coinbase lottery's draw count comes from the PREVIOUS block's gap (prev.timestamp - prev_prev.timestamp), the one the producer did not choose, instead of the block's own gap; the per-second rate, the per-block cap, the active-count cap and the fee smoothing are unchanged, and emission stays per second (2 F7 / 7 F7)"},
        {"late_stamp_priced", kActivationHeight_0_5_8,
         "a block's fork-choice weight is never better than the round its timestamp falls in: k = max(the smith's last drawn round, the selector's round of the stamp), so a round-1 smith that stamps in round 2's territory (later than its target + half a gap) weighs D / 2 like a round-2 block; before, a stamp up to 22 s late was free and a cartel slowed the chain by 22 s per block it produced (2 F2)"},
        {"apps_seed_after_bet", kActivationHeight_0_5_8,
         "a solo bet is never resolved by a block whose producer's owner account is the bettor (it waits for the next block), and a multiplayer app's opening turn is drawn from the seed of the block AFTER the join, not the join block's, so the including producer cannot act on dice it sees first; per-move dice are the sub-row 10 F3 (b) (10 F3)"},
        {"receipt_datum_prefix", kActivationHeight_0_5_8,
         "the receipt datum sampler seeds its generator with its own prefix (RECEIPT_DATUM_SEED_PREFIX, 'zbc-receipt-datum') instead of the blocksmith draw's 'zbc-blocksmith', so the two consensus samples of one block seed are separated by the tag and not only by the generator (10 F5)"},
        {"attendance_any_sign", kActivationHeight_0_5_8,
         "a queued node's attendance window counts as attended on ANY on-chain sign of its key (the attendance transaction, a published receipt it signed, an attestation it sent), and the misses it may accumulate over its wait are the windows that fit in one admission cycle (node_admission_max_delay / (window x block time), never under QUEUE_ATTENDANCE_MISSES_ALLOWED) instead of two, so a producing cartel that includes no attendance cannot empty the queue in three windows (8 F3)"},
        {"attendance_fee_floor", kActivationHeight_0_5_8,
         "a queued node's attendance fee never takes its stake below the registration minimum: the debit stops at the floor (the attendance still counts) and the node is not dropped for fees alone; before, the published minimum was false on long queues and the drop was silent (8 F5)"},
        {"admission_small_registry_cap", kActivationHeight_0_5_8,
         "while the active registry is below the genesis min_registry_size, the admission delay's ceiling is ADMISSION_SMALL_REGISTRY_MAX_DELAY_SECONDS (7 days) instead of node_admission_max_delay, so the chain is not slowest to grow when it is smallest (8 F5 / 19 F4)"},
        {"admission_timer_reanchor", kActivationHeight_0_5_8,
         "when a block arrives more than one admission delay after the scheduled admission (a stall, a lead), the next admission is scheduled from the block's timestamp, not from the missed one, so the timer does not catch up with one admission per block while the queue lasts (8 F7)"},
        {"claim_two_step", kActivationHeight_0_5_8,
         "a ClaimNodeRegistration signed by the node key alone only ANNOUNCES: the claim executes NODE_CLAIM_DELAY_BLOCKS (one admission cycle, 40,320 blocks) later, and during the wait the registered owner may remove the node normally (the lock to the owner, the claim void); a claim sent by the owner account executes at once, and a second claim on a node with one pending is refused; before, a hot node key moved the lock in one transaction (9 F3)"},
        {"floor_spares_recent", kActivationHeight_0_5_8,
         "when the liveness floor must keep some expulsion candidates, it expels the least recently seen first (then the lower score, then the lower id) and spares the most recent signs of life, instead of sparing the highest key ids (9 F6)"},
        {"storage_tally_no_penalty", kActivationHeight_0_5_8,
         "the storage-proof tally charges no participation score: a submitter the majority outvotes only loses the epoch's reward, because nobody can verify a proof and a majority of submitters was an unverifiable vote that expelled working nodes (9 F2 (c)); the verdict is still recorded in the audit ledger, and the score penalty returns with a verifiable challenge-response proof (13/14 design)"},
        {"spine_content_validated", kActivationHeight_0_5_8,
         "a spine block is accepted at storage only when its key changes equal this node's own registry delta over (previous reference, reference], every manifest for this chain equals the manifest this node holds at that reference height (none held: not checked; a foreign chain's manifest: refused); a block whose reference is above this node's main tip is stored on its own threshold and checked when the main chain reaches the reference (a1, SP1); keyed on the block's reference height; the drawn producer is the sub-row (13 F1 validator)"},
        {"spine_producer_by_reference", kActivationHeight_0_5_8,
         "a spine block's seed is the seed of the main block at the previous spine block's reference height, and its blocksmith must be the producer that seed draws for a round at or before the round its timestamp falls in over the signer set of the previous spine block; before, the producer carried the main tip's seed at production time, which no validator could check, so the proposer was never verified (13 F1 validator d)"},
        {"spine_reference_commit", kActivationHeight_0_5_8,
         "a spine block's payload hash commits the referenced main block's height, hash and cumulative difficulty (appended to the hashed bytes, not to the payload length), so the checkpoint names a block and not a height; the block carries those bytes (a1), every co-signer and validator checks them against its own chain, a co-signer that lacks the referenced block abstains and a validator that lacks it checks when its main chain gets there (13 F2)"},
        {"spine_min_spacing", kActivationHeight_0_5_8,
         "a spine block's timestamp is at least spine_smithing_period minus spine_blocksmith_network_tolerance after the previous spine block's; before, validation required only a later timestamp, so a spine branch could be minted as fast as its producer liked and win the fork choice by count (13 F5; the producer draw is 13 F1 d)", kRuleNeverOff, true},
        {"checkpoint_finality", kActivationHeight_0_5_8,
         "the main chain refuses any reorganisation below the finalized height, the reference height of the newest spine block checked against this node's own main chain (co-signed at the threshold and, under spine_reference_commit, bound to this chain's block there; a block stored ahead of the main chain is no floor until checked, a1); finalized_height is published beside confirmed_height and the bridge keeper acts only on finalized transactions; before, the only finality offered was 45 s and a checkpointed block could still be reorganised within the rollback bound (12 F1)"},
        {"escrow_horizon_pure", kActivationHeight_0_5_8,
         "the escrow release at the prune horizon is keyed on PruneHorizon(h), a pure function of the block height and the genesis snapshot parameters (the previous snapshot height below the newest multiple of main_snapshot_interval at or above main_snapshot_min_height), and releases an escrow by its OWN block height; before, it read this node's manifest table and the local presence of the transaction row, a consensus balance movement keyed on node-local values (14 F1); the local table still drives local pruning only"},
        {"escrow_timeout_cap", kActivationHeight_0_5_8,
         "an escrow's timeout may not exceed the prune horizon reachable from its block (ReleaseHeight x the block time) unless the transaction's header survival deposit keeps it alive until the timeout (the deposit the longevity sweep would need); before, a longer timeout was silently cut at the horizon while rent was charged for the declared duration (14 F4); the status API quotes the cap", kRuleNeverOff, true},
        {"queue_state_reset", kActivationHeight_0_5_8,
         "a node key that registers again after a drop or an expulsion starts its new stint with a fresh queue_state row (misses 0, wait from the new registration); before, queue misses were kept for life and a node dropped once was dropped again at its first miss (9 F4)"},
        {"resume_by_queue", kActivationHeight_0_5_8,
         "a block whose gap to the previous one exceeds max_recovery_interval_seconds is drawn over the selectable set plus the ATTENDED admission queue (an attendance in the current or last window), so any such queued node the draw names produces the resume block and is admitted by it; the halt needs nobody suspended first (4 F2 / 1 F2 (c,d))"},
        {"liveness_attestation", kActivationHeight_0_5_8,
         "a REGISTERED node may send QueueAttendance (type 59) as a ping: fee-free, one per node per 120-block window, block hash at most 120 blocks old, and valid only from a node suspended before the block, its reference block not older than the suspension; dated at its reference block, it returns the node to the draw on probation (its misses kept, so the next miss suspends it again) and never ends its missing stretch, which only its own block does (4 F1 / 6 F2 / 9 F2; LV6)"},
        {"floor_on_draw_set", kActivationHeight_0_5_8,
         "the floor keeps a node in the registry, not in the draw: an expulsion candidate the floor holds is suspended (it leaves the draw and counts as missing; a ping or a block of its own brings it back) instead of staying active and drawn for ever at the floor (4 F3 / 19 F1)"},
        {"miss_by_rounds", kActivationHeight_0_5_8,
         "misses advance on the rounds elapsed before a block's producer, one per node per block; a block more than LIVENESS_STALL_ROUNDS (10) rounds after the previous one is a resume after a stall and charges no miss and no skip penalty; a node registered at genesis or below this rule's height is established, so never-produced takes the suspension road, not the expulsion (1 F2 (b) + 3 F2 + 1 F3)"},
        {"validator_no_fallback", kActivationHeight_0_5_8,
         "a block's smith is validated against the draw set at the previous block and nothing else: no tip-registry fallback when that set has fewer than five nodes or when the at-height query fails, so the previous producer's and a suspended node's blocks are refused at every N (1 F4 / 19 F1)"},
        {"one_round_formula", kActivationHeight_0_5_8,
         "the score calculator takes the round a block falls in from the selector (the validator's centred formula) instead of its own 1 + (gap-1)/gap copy, so the draw a block is validated against and the draw its skips and misses are computed from are the same (1 F6 / 2 F4)"},
        {"difficulty_draw_set", kActivationHeight_0_5_8,
         "the fork-choice weight of a block is D / k with k the block's position over the DRAW set at the previous block (the selectable nodes), the set the smith was drawn from; before, k ran over the registry at that height, an unrelated RNG stream whenever a node was suspended (1 F1 / 11 F6 (a))"},
        {"attendance_tail", kActivationHeight_0_5_8,
         "a queue attendance window is evaluated QUEUE_ATTENDANCE_MAX_AGE_BLOCKS + 1 blocks after it closes, and admission looks at the same evaluated window, so a late but valid attendance counts for both (8 F4)"},
        {"snapshot_funded_transactions", kActivationHeight_0_5_8,
         "a snapshot carries a FundedTransactions section: every transaction below the recent window whose longevity record, newest as of the snapshot height, still holds a deposit (always present under the rule, empty when there is none), and a joiner refuses a snapshot without it; before, a fast-synced node held only the recent window, so a paid-for transaction older than that was on no new node and the longevity slice paid holders of nothing (14 F2)"},
        {"expiry_previous_stamp", kActivationHeight_0_5_8,
         "the escrow sweep, the liquid payment completion, the order expiry and the schedule firing of block h run on the timestamp of block h-1, never on h's own: a producer could stamp its block up to two hours ahead and expire every escrow and order whose timeout fell in that window at its choice, turning an approval or a fill in the mempool into a paid no-op (14 F5); one block of lag, ledger rows keep the block's own timestamp"},
        {"governance_window", kActivationHeight_0_5_8,
         "two thirds of the registry has a time dimension: a release vote counts for 30 days of blocks and its denominator is the larger of the counted registry nodes now and at the oldest counted vote, the ceiling of the two rents an account is pruned for is 10 ZBC per period, and a bridge deposit that would raise a wrapper's mints of the last day above 10% of its supply (never below one whole unit) needs every counted registry node; before, votes never expired so quorum came by attrition, 100 ZBC of account rent per period was a legal vote and the mint had no cap (15 F4, D13; the price votes have their own once-per-cycle count since FP3)"},
        {"release_registry_veto", kActivationHeight_0_5_8,
         "the registry can take the release authority back: a two-thirds supermajority of the non-suspended registry (AttestEvent rows under ZBCREL1, tallied by ProcessReleaseGovernance) vetoes a registered release at any time (marked revoked, as RevokeRelease does) and replaces the release authority once the proposal has stood for a week; a version string registers once, a second RegisterRelease for it is a paid no-op; and the generic oracle resolver leaves governance and release events to their own resolvers (it resolved a parameter vote first and the parameter never applied) (15 F2 a/d, 20 F3, D12)"},
        {"duty_fee_free", kActivationHeight_0_5_8,
         "consensus duties cost nothing: SubmitStorageProof, AttestEvent, SetConsensusParam, FeeVoteCommitment and FeeVoteReveal declare a fee of exactly zero (as the liveness attestation does), bounded by the duty lane (one pending per node and duty object, one per node per block) and by admission requiring a registry attester account; the storage reward per honest proof is the active files' rent per epoch over the proofs expected per epoch, never a constant; before, a node paid 0.025 ZBC from a float no income refilled for every duty and a holder proved at 25x the reward (18 F1, D14)"},
        {"permanent_state_priced", kActivationHeight_0_5_8,
         "permanent state is priced: a taker never fills against its own resting order (a self-trade counts toward nothing), an order's quote notional is at least ORDER_MIN_NOTIONAL_UNITS (0.025 units of the quote token), and the persistence rent in the fee floor is multiplied by the registry size at the block, since every node keeps the bytes; before, a market's refund came at 100 fills of one atomic unit against oneself, and 64 KB kept by every node for two snapshots cost 0.0003 ZBC (18 F3)"},
        {"market_rent", kActivationHeight_0_5_8,
         "a market pays rent instead of holding a refundable deposit: the creation cost pre-funds twelve billing periods (market_creation_cost / 12 per period, to the longevity pool), every PlaceOrder and CancelOrder on the market feeds it 20% of its own fee paid by the sender on top of the fee up to twenty-four periods, a market that cannot pay a period or whose base or quote token is gone is pruned with its resting orders refunded first and the rest of the deposit to the pool, the pair free to open again, and the 100-fill deposit refund is retired (18 F3, unified-survival decision 6)"},
        {"apps_payout_cap", kActivationHeight_0_5_8,
         "a block pays solo house-app wins only up to a cap per token, the apps pool's inflow of the last day (the solo stakes bet in the window); a bet is drawn once, what the cap cannot pay is owed on the row and paid from later blocks' caps in id order, nothing re-drawn and nothing forfeited; before, every won solo bet paid up to 5% of the pool to whoever ground the seed, block after block (18 F6). Alone this rule gives EVERY block the whole window's inflow again, nothing subtracted for what earlier blocks paid, so a win above it waits one block; apps_payout_cap_net makes the window's total the cap"},
        {"quorum_floor", kActivationHeight_0_5_8,
         "quorums have a floor: the spine signature threshold is a ceiling of active x percent (four signers at 66% need three), and a bridge deposit or withdrawal, a parameter vote, a release veto or hand-off and a generic oracle fact are not resolved while the active registry is below the genesis min_registry_size in registry nodes or in distinct owner accounts (two registry nodes of one operator are one voice; the builder refuses a mainnet genesis under seven); before, two of three registry nodes minted, resolved and moved prices, and four signers needed two (19 F3, 19 F1, 20 F2)"},
        {"node_key_rotation", kActivationHeight_0_5_8,
         "the owner's UpdateNodeRegistration may carry a new node public key after the proof (signed by the new key): the node keeps its id, registration height, stake and status; the change takes effect SEAT_CHANGE_DELAY_BLOCKS (120) after the block that includes it (CF6, consensus/seat_change.h: one change pending per registered node, void at its due block when the node has left the registry or another registered node holds the key), the versioned row names the new key from that block on, and the old key stops resolving past it (a pending claim announced on it is void at its due block); before, a new node key meant remove + register, a new queue wait and the registration height lost, and a stolen node key held the node's duties until then (20 F4)"},
        {"weight_by_draw_share", kActivationHeight_0_5_8,
         "a block's fork-choice increment is D x |S| / (k x |A|): S the draw set it was weighed over (the selectable nodes at the previous block), A the full active registry there; a branch that suspended the other side of a partition is light in proportion (3/11 per block against 8/11) instead of running at full weight once each side has suspended the other, and an honest majority that rightly suspended a dead minority pays the minority's fraction; the foreign-branch recomputation scales the same way (1 F11, D21: scale; the alternative, lifting suspensions on reorganisation, re-admits nodes without a receipt)"},
        {"fork_tie_by_hash", kActivationHeight_0_5_8,
         "fork choice breaks an equal cumulative difficulty by the lower tip block hash, on every node the same way: the resolver switches to an equal-weight branch whose tip hash is lower without asking peers (its weight was recomputed before any pop) and keeps its own when ours is lower, and the periodic investigation pulls an equal-weight peer whose tip hash is lower; before, equal weights were never switched outside bootstrap and two branches of first-turn blocks stayed split until a late turn broke the tie (11 F6 (b))", kRuleNeverOff, true},
        {"equivocation_miss", kActivationHeight_0_5_8,
         "EquivocationReport (type 60) is accepted: two different signed header byte strings by one producer key over one previous block hash of this chain, within EQUIVOCATION_EVIDENCE_MAX_AGE_BLOCKS (720) of the including block, sent fee-free by a registered node; the producer is charged one miss at the charging block with the ordinary consequence at the limit, once per (producer, height), and the fork weigher's replay charges the same; before, a producer who signed two blocks for one height split the fleet by arrival for free (the P2P path rejects the second block and bans the liar since 1a073024, node-local) (11 F6 (c) T2)"},
        {"equivocation_resume_exempt", kActivationHeight_0_5_8,
         "an EquivocationReport whose two headers straddle the recovery limit from their parent (exactly one has timestamp - parent timestamp > max_recovery_interval_seconds) is refused and charges nothing: past the limit a producer may sign a fresh block over a parent it signed over before (the resume of a halted chain; its earlier block could never be selected once the limit passed), and the chain needs that producer then; two headers inside the limit, or two past it, still convict; the validator, the executor, the fork weigher's replay and the wire check read the same function (consensus/equivocation_resume.h) (gate-D2c, dzoobc-de on fb66d6cc)"},
        {"seed_vrf", kActivationHeight_0_5_8,
         "the block seed is the ECVRF output (crypto/vrf.h, ECVRF-EDWARDS25519-SHA512-TAI/ZooBC-subgroup) over SHA3(previous seed) and the header carries the 80-byte proof, which the validator requires and verifies under the blocksmith key, refusing a seed that is not the proof's output; every proof for one (key, input) has the same output, so a producer has nothing to grind; before, the seed was an Ed25519 signature of that hash and every valid signature of the message was a valid seed, so a producer chose the seed and two producers could own the chain (10 F1, D2); the hash covers the proof, so a node without the field disagrees on hashes once the rule is on (the relaunch has every node on 0.5.8)"},
        {"apps_seed_prefix", kActivationHeight_0_5_8,
         "every apps draw (a solo bet's resolution, a multiplayer app's opening turn, a move's dice) is LE64(SHA3-256(APPS_SEED_PREFIX 'zbc-apps' || block seed || LE64(app id) || LE64(tx id))), the tx id 0 for a game-level draw and the move's own for its dice: one tag per consumer of the seed and the tx id its own field, so no apps stream equals another consumer's or another game's (10 F1-5; before it the apps hashed seed || LE64(app id ^ tx id) with no tag)"},
        {"apps_turn_plus_two", kActivationHeight_0_5_8,
         "a multiplayer app's opening turn is drawn by the resolver of the block TWO after the join (resolve_height = join + 2), not the next one: the producer of the join block who is drawn for the next block knows that block's seed while assembling the join (its alpha is SHA3 of the join block's seed and the key is its own), while the seed two blocks on needs the next block's seed first, so nobody knows it at join time and the only play left is to abstain at join + 2, which is priced (10 F3 (d); solo bets already resolve at inclusion + 2)"},
        {"activation_readiness_gate", kActivationHeight_0_5_8,
         "readiness signalling (ROLLING-UPGRADE.md §7): block.version carries the producer's bundle id and a block's version may not fall below the newest bundle active at its height (16 F2-2); a rule bundle with bundle > 0 activates at the first height at or after max(its scheduled height, its registry floor) where at least two thirds of the counted registry nodes (registered, not suspended) signalled it inside the last max(720, 5 x the counted registry nodes) blocks (16 F2-3, 16 F2-4; CF10)"},
        {"registry_as_of_prev", kActivationHeight_0_5_8,
         "a block-apply site reads the registry as of the previous block, never the tip (the score's network size, the published-receipt cap, the storage-proof placement universe; the liveness pass maps receipts over the rows as of the block itself), and a failed as-of read fails the block instead of falling back to the tip (the score update, the blocksmith check): every input as of a height, so a node replaying later computes what the fleet computed (17 F1 View-3a); the producer's owner address for the fee, the rent and the coinbase and the coinbase's ticket-holder count read the rows in force at the block, not the latest (17 F1 View-3b)"},
        {"branch_registry_replay", kActivationHeight_0_5_8,
         "the foreign-branch replay weighs a branch over its OWN registry: a scratch seeded with the active rows at the common block and advanced with the branch's node removals, key rotations and the replayed liveness expulsions, so those no longer make a branch 'unweighable here'; a node registration (its admission is not a transaction), a queued node at the common block and the resume draw are still not mirrored and keep the branch unweighable, never a lie (17 F1 View: branch replay, the 11 F6 (f) follow-up)"},
        {"tx_expiry_field", kActivationHeight_0_5_8,
         "transaction version 3 carries an expiry window (u32 seconds after survival, signed like every field): a block may carry the transaction within that many seconds of its timestamp, 0 = the hour, at most TRANSACTION_EXPIRY_CAP (a day); the pool's wall-clock window and the producer's selection honour it and the snapshot's replay floor spans the cap. Before the rule every transaction expired an hour after its timestamp, too short for a stall and the only replay guard (12 F3)"},
        {"dataset_owner_only_write", kActivationHeight_0_6_0,
         "a SetupAccountDataset or RemoveAccountDataset whose (sender, recipient, property) row is bound to a dataset object another account owns (it was transferred away) is refused at admission and is a paid no-op if mined; before, the former owner kept rewriting or removing its entry in an object it no longer owned and the new owner paid the rent for those bytes. The owner's own write and a new row (its own object) are unchanged; the object's manage policy (type 43) is stored but still not applied (devnet test 2026-10-30, A2). From 0.6.0 the object's own transactions too: a TransferDataset, SetDatasetPolicy or DeleteDataset from an account that does not own the object is refused at admission (the executor always made it a paid no-op; smoke test 2026-10-31)"},
        {"genesis_rent_clock", kActivationHeight_0_6_0,
         "every account pays rent, the treasury too (owner, devnet test run 2026-10-30, A1): in the block at this height every latest account row with rent_due_height 0, a balance above 0 and no rent exemption (system pools, the apps pool, ZBS_ addresses) is put on the rent clock the way a first credit puts it, due one cycle later, once; before, a genesis row was written off the clock and only a credit or a first send armed it, so a genesis account that never moved was never billed (a chain with this rule at 0 gets its genesis rows armed by the builder)"},
        {"apps_payout_cap_net", kActivationHeight_0_6_0,
         "the solo payout cap counts what the window already paid: a block's cap in a token is the solo stakes bet in the last APPS_PAYOUT_INFLOW_WINDOW_BLOCKS minus the solo wins paid in that window (a bet's paid_payout while its last payment is in the window), so the window pays out at most what players bet in it and the treasury's seed is never paid out faster than players pay in; an empty cap holds back only its own token's owed wins; before, every block's cap was the whole window's inflow again and a win above it waited one block (devnet test 2026-10-30, A3: 3.96 ZBC paid against 2.00 staked)"},
        {"token_name_not_address", kActivationHeight_0_6_0,
         "IssueToken refuses a name that the node's own address parser reads as an account address of any kind (crypto::DecodeAddress: ZBC_ or ZBS_ text with or without separators, any other native form the node accepts, a bare 64-hex key) or the raw typed account in 72 hex digits; before, a name made of an address with its separators removed (60 bytes) or four of them (64 bytes) was mined and a wallet that parses names could read it as an address (owner decision 11 of 2026-10-30, devnet test D21)"},
        {"typed_accounts_only", kActivationHeight_0_6_0,
         "an account is always typed (its 4-byte type, then its key): a transaction whose sender or recipient is a bare 32-byte key is refused at admission, in block validation, on the P2P wire and by the signing bytes ('accounts are typed: a bare 32-byte key is not an account on this chain'), and no lookup aliases a bare key to the typed ZBC account; a bare 32-byte key is a NODE key only (node_public_key fields and columns), and a node signs its duties as its typed node-key account 00000000 || node key; before, a bare key was typed as ZBC when signed and aliased on every lookup, so one account had two forms (ADDRESS-TYPES item 4, owner 2026-10-30; 0.6.0)"},
        // Audit 2026-11-02 F14, owner decision Q7 (2026-11-02): nothing stopped a producer from publishing one receipt
        // again in every block of the window for a score (the selector did not skip what it had published either:
        // review 2026-11-03; it does now, ungated, since skipping is never invalid).
        {"receipt_once", kActivationHeight_0_6_1,
         "a published receipt (identified by its recipient signature) is accepted in one block only: a block carrying it twice, or carrying one an earlier block of the lookback window already carried, is refused (DuplicateReceiptInBlock, ReceiptAlreadyPublished)", kRuleNeverOff, true, 0, 601},
        {"readiness_decision_state", kActivationHeight_0_6_1,
         "when block h*-1 is applied and the readiness tally for a gated bundle passes, the node writes the row readiness_bundle_decision(bundle_id, effective_height = h*, height = h*-1, latest) in versioned chain state (this rule judged at h*, the height the decision concerns, so the bundle that carries it writes its own row; rolled back with the block; a rollback that keeps block h*-1 keeps the decision); a restart or a snapshot joiner reads the latest row per bundle (valid only when effective_height = height + 1 and at most tip + 1) before anything else, and the snapshot carries the table only when this rule is active; a restart reads every stored row before judging this rule (a row exists only because the rule was active at its height), then a chain state without a row for a bundle has not activated it, so nothing is rescanned under this rule (below it, the bundle carrying this rule on a chain that rolled onto it included, a cold scan whose window this node no longer holds refuses to start and names the remedy, resync from a snapshot, instead of computing another h*); before readiness_registry_schedule a registered release ABOVE this binary's bundle is watched (its tally is reported) but never decided by this binary: it halts production only on a stored decision", kRuleNeverOff, true, 0, 601},
        // Owner decision 2026-11-05 (2): a 0.6.1 node cannot know the height a later bundle is compiled for, so the
        // registry floor IS the schedule, and every binary, old or new, computes the one h* and halts there.
        {"readiness_registry_schedule", kActivationHeight_0_6_1,
         "a readiness-gated bundle's schedule is its registry floor alone (the earliest unrevoked registration of its release plus ACTIVATION_FLOOR_BLOCKS; the binary's compiled height is not consulted), so a node running an older binary computes the same activation height h* from the registry and the headers and stops producing exactly there; a registered release above this binary's bundle is decided from the node's own tally and its readiness_bundle_decision row written, exactly as a newer binary does (a stored decision row is still honoured first); the signal window a tally reads is at most SIGNAL_WINDOW_MAX_BLOCKS = 1,440 blocks, the blocks every node holds (a snapshot carries them below its height, a pruned node keeps them), so a joiner, a pruned node and a full node count the same headers", kRuleNeverOff, true, 0, 601},
        // Audit 2026-11-02 F06, owner decision Q1 (2026-11-02, "C"): the spine's bar was max(two thirds, five), so a
        // list of three or four seats could never checkpoint and a list of five needed all five.
        {"spine_threshold_capped", kActivationHeight_0_6_1,
         "a spine block never needs more signatures than its signer list minus one: 2 of 3, 3 of 4, 4 of 5; six spine signers and more unchanged (judged at the previous spine block's reference height, like quorum_floor)", kRuleNeverOff, true, 0, 601},
        // Audit 2026-11-02 F10, owner decision Q5 (2026-11-02, "A"): a co-signer's promise to a proposal lapsed with its
        // collection window, so two proposals at one height could both reach a quorum and nodes kept different finals.
        {"cosign_promise_binds", kActivationHeight_0_6_1,
         "a co-signer's promise to a spine proposal binds until the height is settled: a different proposal at that height is signed only with enough signed refusals of the promised one (by signers who signed nothing there) that it can no longer reach its bar; a refusal by a signer of the stored proposal is a provable lie; a signer that refused a proposal never signs it", kRuleNeverOff, true, 0, 601},
        // Owner decision Q1 (2026-11-02), survival mode: below survival_min_producers distinct producers in the last
        // 120 blocks the chain freezes governance and the bridge category and pauses expulsions until N produce again.
        {"survival_mode", kActivationHeight_0_6_1,
         "survival mode: when fewer than survival_min_producers distinct producers made the last 120 blocks (0 = off) the chain keeps producing but refuses governance and bridge transactions (SetConsensusParam, FeeVoteCommitment, FeeVoteReveal, RegisterRelease, ReleaseAuthorityPropose, ReleaseAuthorityAccept, RevokeRelease and AttestEvent) and pauses expulsions, until N distinct producers show in the window again; the flag at a height depends on the parent's flag and the producers of the 120 blocks before it, and is stored beside the block (it writes survival_state: not retirable, CF9)", kRuleNeverOff, false, 0, 601},
        // Owner decision Q6 (2026-11-02), audit F12: the byte ceiling bounds the block, not only its transaction bodies.
        {"block_size_serialized", kActivationHeight_0_6_1,
         "max_block_size_bytes bounds the block's serialized size (the header bytes the hash covers with the 64-byte signature, every signed transaction's bytes, a fixed 1,288 bytes per published receipt = its 232 signed bytes + a 1,056-byte proof allowance whatever proof bytes the copy carries, so every copy of a block measures the same: util/block_size.h), not only the transaction bodies and receipts the payload length counts; a block over it is refused (BlockTooLarge), the producer budgets the same size and the relay refuses one before validation", kRuleNeverOff, true, 0, 601},
        {"escrow_commission_nonnegative", kActivationHeight_0_6_1,
         "an escrow commission is nonnegative, amount + fee + commission + rent is checked for int64 overflow at admission, mempool reservation, execution and refunds, and SendZBC refuses an amount above total supply", kRuleNeverOff, true, 0, 601},
        {"foreign_carrier_bound", kActivationHeight_0_6_1,
         "an Ethereum carrier is EIP-155 on this chain's EVM id and one minimally encoded RLP value whose re-encoding equals the message (no trailing bytes, no leading zeros, yParity 0 or 1, no access list), and its nonce is the sender account's nonce (the mempool admits only the exactly-next free nonce: the first nonce at or above the account's that no pooled or staged carrier of the signer already carries, so a carrier whose nonce is already queued is refused (\"carrier nonce N, account nonce ...\"), and a carrier queued behind a predecessor that expired or was dropped waits until a carrier with the missing nonce arrives or it expires itself; of several pooled copies of one carrier id block assembly takes the oldest; a carrier whose nonce is not the account nonce makes the block that carries it invalid (ForeignCarrierNonce; the mempool and block assembly refuse it first); a successful carrier increments the signer's nonce); a Bitcoin carrier re-serializes to the message (minimal CompactSize, witness marker only with a witness, no scriptSig on a P2WPKH input) and its single input spends (this chain's genesis block hash as the 32 txid bytes in ZooBC's byte order, index 0xFFFFFFFF); a Solana carrier carries exactly one signature and its signed recent_blockhash is the hash of a main chain block that is an ancestor of the including block and at most 720 blocks below it (SNAPSHOT_BLOCK_REFERENCE_REACH, the blocks every node holds: the carrier expires with that window); every foreign carrier is usable once by its native transaction id: a spent or duplicated id, or an unbound or expired Solana/Bitcoin carrier, makes the block that carries it invalid (ForeignCarrierReplayed; the mempool, the staging pool and block assembly refuse it first, so only a blocksmith that wants its block refused builds one); it carries no escrow or expiry, pays at least the minimum fee (an Ethereum carrier exactly the fee its signed gas fields name), and is only a SendZBC (or Solana TransferToken)", kRuleNeverOff, true, 0, 601},
        {"eth_signature_canonical_v", kActivationHeight_0_6_1,
         "every ZooBC-signed signature by an Ethereum- or Tron-typed key (the transaction envelope, a multisig participant's signature, an escrow co-signature, an account-group consent proof of kind 0, 1 or 2, a fee-vote reveal's voter signature) uses exactly recovery id 27 or 28, the form produced by the wallet, tools and RPC adapter; a 0/1 or 29/30 copy is refused at admission and makes a block that carries it invalid, a stored multisig signature in another form does not count toward completion, and the fork weigher does not take a branch's registry transaction signed so as its owner's; a foreign carrier keeps its own chain's form (foreign_carrier_bound)", kRuleNeverOff, true, 0, 601},
        // Review 2026-11-05 (account types): the transaction bytes carry one form per account type, the parser's
        // GetAccountPublicKeyLength, but AccountState also stored the full-key forms below. Nothing can be sent from one.
        {"canonical_account_forms", kActivationHeight_0_6_1,
         "an Ethereum or Tron account is its type and the 20 Keccak bytes, a Bitcoin legacy, P2PKH or P2WPKH account its type and the 20 HASH160 bytes; the full-key form of those types (the type and the 64-byte key; the type and the 33- or 65-byte key) is refused wherever a transaction names an account (its sender, recipient or escrow approver, and in its body a payee, beneficiary, member, controller, seat, escrow party, counterparty, new owner, authority, allow-list entry or split recipient), at admission and in a block, because no transaction can ever be sent from it (the transaction bytes carry the 20-byte form only); a state-channel app (CreateApp channel 1), which ends only by SettleApp, seats only a kind whose move voucher is a 64-byte signature (ZooBC, Solana, Polkadot, Taproot), as creator, invited opponent or joiner, because any other kind could never sign a move (every other app ends by on-chain moves, ResignApp, ClaimAppTimeout or the unstarted-app close, which every signing kind sends); a TransferDataset new owner and a release-authority proposal (ReleaseAuthorityPropose, or a ZBCREL1 authority event) name a kind that signs; a multisig's kind-1 consent is compared in the typed form the chain stores (00000000 || hash); and an account-group consent of kind 2 by a Tron-typed address is a TronLink signature, over keccak256(\"\\x19TRON Signed Message:\\n32\" || digest), as an Ethereum-typed one is a MetaMask personal_sign", kRuleNeverOff, true, 0, 601},
        {"bridge_burn_supply_first", kActivationHeight_0_6_1,
         "a bridge withdrawal checks token supply before debiting custody, so a supply underflow cannot destroy units while the withdrawal stays open", kRuleNeverOff, true, 0, 601},
        {"bridge_withdrawal_credit", kActivationHeight_0_6_1,
         "a bridge withdrawal starts only from a versioned request row bridge_withdrawal_request (keyed by the TransferToken's hash) that ExecuteTransferToken writes when a transfer with a ZBW1| memo is CREDITED to a custody account (a paid no-op writes nothing); the resolver burns from the row's custody only when the attested token, amount and destination equal the row's (a mismatch or a missing row is a refusal, never a block fault) and writes the oracle result after the burn; keepers attest the row (never a transaction row) and sign the foreign release (id = keccak(trigger ‖ LE32(result height)), published as withdrawal_id) only after that result exists; a deposit's result row is written only after its mint succeeded, so a refused mint leaves the deposit pending; a TransferToken with a ZBW1| memo is a withdrawal, and it is refused at admission and makes a block invalid unless its token is a bridge coin (bridge_coin, from genesis) whose release exists, which in this release is only the Ethereum native coin (chain ethereum, asset native: ZETH in the shipped genesis files; ERC-20, BSC, Bitcoin, Solana and every other chain are closed: withdrawals of <coin> are not open), it carries no escrow, it is sent to that coin's custody account (transaction::bridge_rules::CustodyAccount: 00000000 || SHA3-256(\"ZBC-BRIDGE-CUSTODY\" || LE64(token id)), which no key signs for), and its destination suits the chain (crypto::BridgeDestinationProblem: printable, no space or '|'; Ethereum 0x and 40 hex digits whose mixed case is a valid EIP-55 checksum); and a custody account receives nothing else: a transaction naming one as sender, recipient or escrow approver, or carrying its key in its body, is refused the same way, and a deposit minted to one waits; before, a withdrawal of a coin with no release, or with a typo, was burned with nothing paid out, and anything else sent to custody stayed there for good", kRuleNeverOff, true, 0, 601},
        {"admission_checks_in_block", kActivationHeight_0_6_1,
         "TransferToken and CreateApp refuse non-signing recipients/opponents in block validation, a GatewayHeartbeat whose gateway-key signature is bad is a paid no-op, and an AttestEvent whose event id starts with the parameter-vote prefix ZBCGOV1: (written only by SetConsensusParam, after its name and value checks) is refused at admission and makes a block that carries it invalid", kRuleNeverOff, true, 0, 601},
        {"receipt_reference_in_window", kActivationHeight_0_6_1,
         "a published receipt's reference block is inside the preceding 720 blocks and must be held and match its hash; an unheld reference is invalid on pruned and full-history nodes alike", kRuleNeverOff, true, 0, 601},
        {"failed_credit_to_pool", kActivationHeight_0_6_1,
         "a deterministic credit refusal sends the amount to the longevity pool instead of destroying it: token backing, fired triggers, pruned gateway stake and schedule remainders", kRuleNeverOff, true, 0, 601},
        {"one_node_per_owner", kActivationHeight_0_6_1,
         "one owner holds at most one non-deleted node: a second registration is a paid no-op, updates target the body key with an owner/group check, and same-height owner reads tiebreak by id", kRuleNeverOff, true, 0, 601},
        {"dataset_rent_object_clock", kActivationHeight_0_6_1,
         "one dataset object has one rollback-safe rent clock on dataset_object; billing updates active rows' clock column only, preserving added_by, first-write ownership and record versions", kRuleNeverOff, false, 0, 601},
        {"spine_bar_follows_registry", kActivationHeight_0_6_1,
         "spine signers deleted from the main registry as of the reference height stop counting toward signature bars and promise refusals without waiting for a later spine key change", kRuleNeverOff, true, 0, 601},
        {"claim_notifies_owner", kActivationHeight_0_6_1,
         "a non-owner ClaimNodeRegistration names the registered owner as recipient and carries a non-empty notice, so the claim appears in the owner's account history", kRuleNeverOff, true, 0, 601},
        {"spine_late_vote", kActivationHeight_0_6_1,
         "at least spine_late_vote_after_seconds after it is due a spine block is late: it is valid with the spine signatures of more than half of the spine signers (no spine_min_signatures floor), carries the main registry's deletions since the previous reference (so the spine signers it needs are the ones still registered) and no additions (they wait for the next spine block that is not late), and carries no non-signing statements (A14, owner decision 2026-11-04; removals on late blocks: review 2026-11-04)", kRuleNeverOff, false, 0, 601},
        {"spine_equivocation_report", kActivationHeight_0_6_1,
         "SpineEquivocationReport (type 62) is accepted: one registered node's spine signature on a spine block candidate's signed header bytes and its non-signing statement on the same candidate, sent fee-free by a registered node; the voter is charged one miss once per (node, spine height); signing two different candidates is not reportable (a node freed by non-signing statements may sign a new one) (owner decision 2026-11-04, A7)", kRuleNeverOff, false, 0, 601},
        {"fee_collected_explicit", kActivationHeight_0_6_1,
         "the fee settlement believes the executor, not the sender's balance: every debit of the declared fee (chargeFee, the no-op charge, the direct debits) says so, and the fee is 'not collected' only when nothing was debited; before, a type that credited the sender inside the same transaction (CancelOrder, BurnToken, a stopped stream, a returned stake) was read as fee-less and the fee it took reached nobody (review 2026-11-04)", kRuleNeverOff, true, 0, 601},
        {"liquid_chain_clock", kActivationHeight_0_6_1,
         "a liquid payment starts, and a LiquidPaymentStop splits the stream, at the block's timestamp, never at the transaction's own timestamp (which the stopping party chooses inside the admission window); a stop the chain clock places before the stream's start is a paid no-op (review 2026-11-04)", kRuleNeverOff, true, 0, 601},
        // 0.6.2, bundle 602 (bounty report 2026-11-06: measured on a private four-node 0.6.1 chain, three
        // transactions created 10.11 ZBC; confirmed in the code the same day).
        {"liquid_payment_noop_paid", kActivationHeight_0_6_2,
         "a token LiquidPayment whose sender holds fewer units than it streams is a paid no-op like a TransferToken that cannot be funded: an unbacked token's sender keeps paying the ZBC fee it was charged (the overpay comes back as event 22), a backed token settles the floor through its backing; and a fee an executor hands back is never a collected fee (ReturnFee clears dispatch_fee_collected_), so the settlement can never refund the overpay of a fee that already went back whole; before, that no-op returned the whole ZBC fee while the settlement still believed it collected, refunded fee - floor on top and the pool paid the producer the floor: the declared fee was created from nothing, once per transaction; admission refuses the over-spend at submit (not a rule: the mempool mirrors TransferToken's check)", kRuleNeverOff, true, 0, 602},
        {"cancel_schedule_kind", kActivationHeight_0_6_2,
         "a CancelSchedule that names a trigger (kind 0: a CreateTrigger's row, which shares the table with scheduled transfers and vestings) is a paid no-op, as a CancelTrigger that names a schedule already is, and admission refuses it with the way out (CancelTrigger); before, it marked the trigger cancelled and returned nothing, because a trigger's money is in `amount` and the cancel read `locked_remaining`, which a trigger never sets: the locked amount was destroyed, and anyone the trigger named as its recipient could do it (review 2026-11-07, stream A)", kRuleNeverOff, true, 0, 602},
        {"storage_proof_first_wins", kActivationHeight_0_6_2,
         "a second SubmitStorageProof for the same piece, epoch and prover writes nothing (a no-op; admission refuses it); before, it replaced the first row with its own proof bytes and its own block height, and the rollback of the second block alone, which deletes storage_proof rows above the target height, deleted the first proof too, so a node that rolled back and one that never saw the second block tallied the epoch differently (review 2026-11-07, stream C)", kRuleNeverOff, true, 0, 602},
        {"claim_lock_fee_collected", kActivationHeight_0_6_2,
         "the owner's own claim of a QUEUED node whose lock is at most the fee (the net road: the lock pays the fee, the owner's balance the rest) tells the settlement the fee was collected, and checks before the node is deleted that the owner can pay the rest (an unpaid no-op otherwise), exactly as RemoveNodeRegistration does (j77); before, a lock of exactly the fee moved nothing on the balance, the settlement booked the fee as not collected and the lock reached nobody, and an owner that could not pay the rest failed the block after the node was already deleted (review 2026-11-07, stream A)", kRuleNeverOff, true, 0, 602},
        // Security review 2026-11-07 (BUGS/REVIEW-2026-11-07-SECURITY.md), the consensus fixes: bundle 602 as well.
        {"multisig_inner_validated", kActivationHeight_0_6_2,
         "the inner transaction a completed MultiSignature carries is judged by its own type's rules before it runs (ValidateTransactionSkipSignature and TxTypeActive at the block's height, as a transaction sent directly is judged at block validation): one that fails stays Pending and nothing runs (the wrapper's own fee is paid); and the executor verifies itself what only admission used to check: the proof of ownership of the node key in NodeRegistration, NodeRegistrationUpdate (the new key's) and ClaimNodeRegistration, and a split policy's shares (at most 100 % in all, no duplicate, never the account itself, none zero), a paid no-op otherwise; a split credit never sends out more than arrived nor more than the account holds; before, block validation checked only the wrapper's structure and the inner fee, so a blocksmith's own block could set a split policy of 6,553.5 % (every credit then paid out 65.5 times itself and the account went below zero) or announce a claim on any node with no proof at all (its whole stake paid to the claimer seven days later)", kRuleNeverOff, true, 0, 602},
        {"balance_never_negative", kActivationHeight_0_6_2,
         "a debit never leaves an account balance, ZBC or token, below zero: one that would is an invalid block, which every node computes alike (a credit is always written, to a row an earlier release left negative too); before, AddBalance checked only for overflow, so a path that paid out more than it held left a negative row that rent later pruned, and the difference was created from nothing (security review 2026-11-07, D1)", kRuleNeverOff, true, 0, 602},
        {"settle_app_paid_noop", kActivationHeight_0_6_2,
         "a SettleApp that changes nothing (a malformed body, an unknown or non-channel app, a settled app, a sender not seated, a voucher chain that fails or is not longer than the recorded claim) is a paid no-op, and the length test runs before the voucher replay; admission mirrors the state checks (not a rule); before, every such no-op was free and admission checked no state, so reusable accounts filled blocks at no cost and each free copy of a stored voucher chain made every node replay it (security review 2026-11-07, D3)", kRuleNeverOff, true, 0, 602},
        {"spine_key_per_node", kActivationHeight_0_6_2,
         "a registered node has ONE spine signing key: a key rotation (NodeRegistrationUpdate) removes the previous key from the spine signer list as it adds the new one, spine signatures are counted per node (a second key of one node never counts), a key change's node id is committed by the spine payload hash, and at activation the list is cleaned of every key a rotation superseded; before, a rotation only added the new key, so each rotation gave one node one more counted spine signature (on testnet one node met the spine bar alone after about 42 daily rotations) and honest rotations left dead keys that raised the bar for good (security review 2026-11-07, B2)", kRuleNeverOff, false, 0, 602},
        {"receipt_fields_canonical", kActivationHeight_0_6_2,
         "every published receipt is judged as an unlinked receipt (its recipient is one of the blocksmith's priority peers, the recipients of one block's set are distinct, and the proof fields rmr_linked / intermediate_hashes / rmr_linked_index are ignored and stored empty), and a main chain block's reference_block_height is stored as 0: these fields sit outside both the block hash and the payload hash, so a relay could set them per recipient; before, a linked receipt skipped the recipient check (a blocksmith signed a full set with throwaway keys for the maximum score climb) and honest nodes stored different bytes for one block, which gave them different snapshot hashes, which spine co-signing and the archive tally need equal (security review 2026-11-07, C2/C3/C5)", kRuleNeverOff, false, 0, 602},
        {"solana_carrier_asset", kActivationHeight_0_6_2,
         "a transaction carried by a Phantom-signed Solana transfer binds its asset: the carrier is accepted as a ZSOL TransferToken only, never as a SendZBC of the same number of units; before, the same signed message was valid as either, so whoever wrapped it first chose which asset moved (security review 2026-11-07, E3)", kRuleNeverOff, true, 0, 602},
        {"invoice_namespace_shape", kActivationHeight_0_5_7,
         "SetupAccountDataset under a property beginning `inv:` must carry a JSON object with no negative number in it", kRuleNeverOff, true},
        // A fresh chain needs a few blocks to align before it carries user value. 0 = no floor.
        {"min_user_tx_height", 0,
         "no user transaction is accepted below this height"},
    };
    return kTable;
}

// 16 F6, the stateful rules of this table and their warm-up roads, reconciled (all at default_warm_up
// 0: every live chain starts them at genesis; the first upgrade that adds a stateful rule sets one):
//   - liveness_miss_rule / miss_by_rounds / floor_on_draw_set: misses, signs of life and the score
//     road's unit clock in node_liveness and score_unit_clock; the counter runs under Accumulating and
//     suspends, lifts and expels under Active (ApplyLiveness, LivenessView::Apply);
//   - queue_attendance / attendance_tail / attendance_any_sign: windows are evaluated from the first
//     window that closes after the on-height (no earlier state exists to accumulate);
//   - governance_window / release_registry_veto: votes and commitments are transactions stored
//     whatever the rule says; the resolver's window starts at the on-height.
// The compiled default of a rule, straight from the table: what a chain built from the generator
// inherits when its genesis names no height. Tests that assert where a rule is REGISTERED read this,
// not RuleClock::HeightOf, which is the height in force for this process (overrides and test mode).
inline uint32_t TableDefaultHeight(const std::string& name) {
    for (const auto& r : ActivationTable())
        if (name == r.name) return r.default_height;
    return 0;
}

// Overrides read once from consensus_parameters at startup. Kept here rather than passed around so
// a rule check stays a cheap call from deep inside validation.
//
// Test mode (protocol review 2026-10-21, item 16 F3). Every rule is off in a test unless the test
// switches it on, so 221 green tests said nothing about the eleven 0.5.6 rules that stalled both
// chains. The environment variable ZOOBC_TEST_RULES=all puts every rule at height 1 for a process,
// below any explicit SetOverride (a test that pins pre-rule behaviour keeps doing so by setting the
// rule's height itself). tests/CMakeLists.txt registers every test twice, once plain and once with
// the variable set, so the suite runs with the rules on and off in one ctest. The daemon calls
// DisableTestModes() first thing: a node's heights come from genesis and the table, never from an
// environment variable.
class RuleClock {
public:
    enum class TestMode { None, AllRules };

    static void SetOverride(const std::string& name, uint32_t height) {
        std::lock_guard<std::mutex> lock(Mutex());
        Overrides()[name] = height;
    }
    static void ClearOverrides() {
        std::lock_guard<std::mutex> lock(Mutex());
        Overrides().clear(); GateOverrides().clear();   // 16 F2-3
        OffOverrides().clear();
        WarmUpOverrides().clear();
    }
    // 16 F6: the warm-up of a stateful rule (blocks before the on-height during which its state
    // accumulates without consequences); a test pins one directly.
    static void SetWarmUpOverride(const std::string& name, uint32_t blocks) {
        std::lock_guard<std::mutex> lock(Mutex());
        WarmUpOverrides()[name] = blocks;
    }
    static uint32_t WarmUpOf(const std::string& name) {
        {
            std::lock_guard<std::mutex> lock(Mutex());
            auto it = WarmUpOverrides().find(name);
            if (it != WarmUpOverrides().end()) return it->second;
        }
        for (const auto& r : ActivationTable())
            if (name == r.name) return r.default_warm_up;
        return 0;
    }
    // Is the rule's STATE being accumulated for the block at `block_height`? True from
    // on - warm_up (floored at 0) to the off-height; Active is the consequence predicate.
    static bool Accumulating(const std::string& name, uint32_t block_height) {
        if (block_height == kHeightUnknown) return Active(name, block_height);
        const uint32_t on = HeightOf(name), warm = WarmUpOf(name);
        const uint32_t start = on > warm ? on - warm : 0;
        return block_height >= start && block_height < OffHeightOf(name);
    }
    // 16 F1: the height this rule switches OFF for this chain (rule_off.<name> from the genesis, read
    // at startup; a test pins one directly). kRuleNeverOff when nothing retires it.
    static void SetOffOverride(const std::string& name, uint32_t height) {
        std::lock_guard<std::mutex> lock(Mutex());
        OffOverrides()[name] = height;
    }
    static uint32_t OffHeightOf(const std::string& name) {
        {
            std::lock_guard<std::mutex> lock(Mutex());
            auto it = OffOverrides().find(name);
            if (it != OffOverrides().end()) return it->second;
        }
        for (const auto& r : ActivationTable())
            if (name == r.name) return r.default_off;
        return kRuleNeverOff;   // an unknown rule is never retired (and reads as on: see HeightOf)
    }
    // The daemon: ignore ZOOBC_TEST_RULES whatever the environment says.
    static void DisableTestModes() {
        std::lock_guard<std::mutex> lock(Mutex());
        TestModeState().enabled = false;
        TestModeState().loaded = true;
        TestModeState().mode = TestMode::None;
    }
    // Re-read ZOOBC_TEST_RULES (tests that set the variable after the first rule check).
    static void ReloadTestMode() {
        std::lock_guard<std::mutex> lock(Mutex());
        TestModeState().loaded = false;
    }
    static TestMode CurrentTestMode() {
        std::lock_guard<std::mutex> lock(Mutex());
        return LoadedTestMode();
    }
    // The height this rule switches on for this chain.
    static uint32_t HeightOf(const std::string& name) {
        {
            std::lock_guard<std::mutex> lock(Mutex());
            // 16 F2-3: the readiness gate's effective height (or kRuleOff while the bundle is pending)
            // sits above every other source: it only ever moves a bundle > 0 from its scheduled height
            // to the first qualifying one, and never touches the relaunch set (bundle 0).
            auto g = GateOverrides().find(name);
            if (g != GateOverrides().end()) return g->second;
        }
        return ScheduledHeightOf(name);
    }
    // True when this chain explicitly supplied rule.<name> (including the fresh-chain zero), rather than
    // inheriting the compiled table or a test-mode default.
    static bool HasHeightOverride(const std::string& name) {
        std::lock_guard<std::mutex> lock(Mutex());
        return Overrides().count(name) != 0;
    }
    // The height a rule is scheduled for, every source but the readiness gate (16 F2-3).
    static uint32_t ScheduledHeightOf(const std::string& name) {
        {
            std::lock_guard<std::mutex> lock(Mutex());
            auto it = Overrides().find(name);
            if (it != Overrides().end()) return it->second;
            if (LoadedTestMode() == TestMode::AllRules && !TestModeState().except.count(name)) return 1;
        }
        for (const auto& r : ActivationTable())
            if (name == r.name) return r.default_height;
        return 0;   // an unknown rule is on: a typo must not silently disable a check
    }
    static void SetGateOverride(const std::string& name, uint32_t height) {
        std::lock_guard<std::mutex> lock(Mutex());
        GateOverrides()[name] = height;
    }
    static void ClearGateOverride(const std::string& name) { std::lock_guard<std::mutex> lock(Mutex()); GateOverrides().erase(name); }
    // Is the rule in force for the block at `block_height`? kHeightUnknown means "newest rules".
    // A test pins a rule OFF with SetOverride(name, kRuleOff); that holds at an unknown height too
    // (before, an unknown height answered "active" whatever the override, so a fee predicate reached
    // from the mempool with no height could not be pinned off: 7 F2 / 18 F2).
    static constexpr uint32_t kRuleOff = 0xFFFFFFFEu;
    // 16 F1: a rule is an interval, on <= h < off. An unknown height reads the rules at the horizon:
    // a retired rule (any off-height) is off there.
    static bool Active(const std::string& name, uint32_t block_height) {
        const uint32_t off = OffHeightOf(name);
        if (block_height == kHeightUnknown) return HeightOf(name) < kRuleOff && off == kRuleNeverOff;
        return block_height >= HeightOf(name) && block_height < off;
    }

private:
    // `except`: rule names from ZOOBC_TEST_RULES_EXCEPT (comma-separated) that keep their compiled
    // default under all-rules mode. A diagnostic for finding which rule a fixture-bound test trips on.
    struct TestModeStateT { bool enabled = true; bool loaded = false; TestMode mode = TestMode::None; std::set<std::string> except; };
    static TestModeStateT& TestModeState() {
        static TestModeStateT st;
        return st;
    }
    // Caller holds Mutex().
    static TestMode LoadedTestMode() {
        auto& st = TestModeState();
        if (!st.enabled) return TestMode::None;
        if (!st.loaded) {
            const char* v = std::getenv("ZOOBC_TEST_RULES");
            st.mode = (v && std::string(v) == "all") ? TestMode::AllRules : TestMode::None;
            st.except.clear();
            if (const char* ex = std::getenv("ZOOBC_TEST_RULES_EXCEPT")) {
                std::string cur;
                for (const char* c = ex; ; ++c) {
                    if (*c == ',' || *c == '\0') { if (!cur.empty()) st.except.insert(cur); cur.clear(); if (!*c) break; }
                    else cur.push_back(*c);
                }
            }
            st.loaded = true;
        }
        return st.mode;
    }
    static std::map<std::string, uint32_t>& GateOverrides() {
        static std::map<std::string, uint32_t> m;
        return m;
    }
    static std::map<std::string, uint32_t>& Overrides() {
        static std::map<std::string, uint32_t> m;
        return m;
    }
    static std::map<std::string, uint32_t>& OffOverrides() {
        static std::map<std::string, uint32_t> m;
        return m;
    }
    static std::map<std::string, uint32_t>& WarmUpOverrides() {
        static std::map<std::string, uint32_t> m;
        return m;
    }
    static std::mutex& Mutex() {
        static std::mutex m;
        return m;
    }
};

// Transaction types that did not exist when the chain launched. A type absent from this list has
// always been valid and is never gated.
inline const char* RuleForTxType(TransactionType type) {
    switch (type) {
        case TransactionType::SetSplitPolicy: return "split_policy";
        case TransactionType::DeclineEscrowRequest: return "escrow_request";
        case TransactionType::LinkAccount:
        case TransactionType::UnlinkAccount:
        case TransactionType::SetMemberPermissions:
        case TransactionType::TransferGroupControl: return "account_groups";
        case TransactionType::CloseLongevity: return "survival_field";
        case TransactionType::FundStoredFile: return "stored_file_topup";
        case TransactionType::EquivocationReport: return "equivocation_miss";
        case TransactionType::SpineEquivocationReport: return "spine_equivocation_report";
        default: return nullptr;
    }
}

// Transaction types withdrawn by a rule: accepted below the rule's height, refused from it (the mirror
// of RuleForTxType). A type absent from this list is never retired.
inline const char* RuleRetiringTxType(TransactionType type) {
    switch (type) {
        // Owner decision 2026-09-23: top-ups cannot be taken back, and a record's leftover goes to the
        // node pool, never back to a funder. CloseLongevity (309, the owner) replaces it.
        case TransactionType::CancelLongevity: return "survival_field";
        default: return nullptr;
    }
}

inline bool TxTypeRetired(TransactionType type, uint32_t block_height) {
    const char* rule = RuleRetiringTxType(type);
    if (!rule) return false;
    return RuleClock::Active(rule, block_height);
}

// False when this type is not yet accepted at this height. The authoritative check lives in the
// executor, so a block carrying a too-early transaction fails on every node that has the rule.
// 16 F2-2: the newest bundle (by id) with a rule active at `height`; 0 when only the relaunch set is.
inline uint32_t NewestActiveBundle(uint32_t height, const std::vector<RuleActivation>& table = ActivationTable()) {
    uint32_t newest = 0;
    for (const auto& r : table)
        if (r.bundle > newest && RuleClock::Active(r.name, height)) newest = r.bundle;
    return newest;
}
// 16 F2-2: the signal check the validator runs under rule activation_readiness_gate: a block's version
// is its producer's bundle id and may not fall below the newest bundle the chain already runs at that
// height (the signal is monotone along the chain). Version 0 was always refused; that stays outside.
inline Result<void> CheckSignal(uint32_t version, uint32_t height, const std::vector<RuleActivation>& table = ActivationTable()) {
    if (!RuleClock::Active("activation_readiness_gate", height)) return Result<void>();
    const uint32_t newest = NewestActiveBundle(height, table);
    if (version < newest)
        return Error{ErrorCode::ValidationError, "Block version " + std::to_string(version) + " is below the active bundle " + std::to_string(newest) + " (activation_readiness_gate)"};
    return Result<void>();
}

inline bool TxTypeActive(TransactionType type, uint32_t block_height) {
    const char* rule = RuleForTxType(type);
    if (!rule) return true;
    return RuleClock::Active(rule, block_height);
}

}  // namespace consensus
}  // namespace zoobc
