// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_MODEL_TRANSACTION_H
#define ZOOBC_MODEL_TRANSACTION_H

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <variant>
#include <vector>
#include "zoobc/common/types.h"

namespace zoobc {
namespace model {

// Forward declarations
struct Escrow;

// Escrow status enum (matches Go model.EscrowStatus)
enum class EscrowStatus : int32_t {
    Pending  = 0,
    Approved = 1,
    Rejected = 2,
    Expired  = 3
};

// Escrow approval enum (matches Go model.EscrowApproval)
// Used in ApprovalEscrowTransaction body to indicate the approval decision
enum class EscrowApproval : int32_t {
    Approve = 0,
    Reject  = 1,
    Expire  = 2  // Used internally for automatic expiration
};

// Escrow structure (matches Go model.Escrow)
struct Escrow {
    int64_t id;
    std::vector<uint8_t> sender_address;
    std::vector<uint8_t> recipient_address;
    std::vector<uint8_t> approver_address;
    int64_t amount;
    int64_t commission;
    int64_t timeout;                    // ABSOLUTE Unix timestamp (seconds); escrow expires when timeout < block_timestamp
    EscrowStatus status;
    uint32_t block_height;
    bool latest;
    std::string instruction;
    // Multi-party escrow support (ZooBC extension)
    bool multi_party;                              // True if both sender and recipient must sign
    std::vector<uint8_t> co_signer_signature;      // Recipient's signature (for multi-party)
    int64_t escrow_request_id;                     // Reference to EscrowRequest (if from request)
    int64_t token_id;                              // 0 = ZBC escrow; else the escrowed token (amount in token units; commission/fee stay ZBC)

    Escrow()
        : id(0),
          amount(0),
          commission(0),
          timeout(0),
          status(EscrowStatus::Pending),
          block_height(0),
          latest(false),
          multi_party(false),
          escrow_request_id(0),
          token_id(0) {}
};

// ProofOfOwnership structure (matches Go model.ProofOfOwnership)
struct ProofOfOwnership {
    std::vector<uint8_t> message_bytes;
    std::vector<uint8_t> signature;

    ProofOfOwnership() = default;
};

// Transaction structure matching Go implementation
// Reference: originals/zoobc-core-develop/common/model/transaction.pb.go
struct Transaction {
    uint32_t version;                                 // Changed from int32_t to uint32_t
    int64_t id;                                       // Transaction ID
    int64_t block_id;                                 // NEW: Block ID this transaction belongs to
    uint32_t height;                                  // Renamed from block_height to match Go
    std::vector<uint8_t> sender_account_address;      // Raw public key (32 bytes)
    std::vector<uint8_t> recipient_account_address;   // Raw public key (32 bytes) or empty
    TransactionType transaction_type;                  // Enum type - values match Go's uint32 TransactionType
    int64_t fee;
    int64_t timestamp;
    std::vector<uint8_t> transaction_hash;            // 32 bytes
    uint32_t transaction_body_length;
    std::vector<uint8_t> transaction_body_bytes;
    uint32_t transaction_index;                       // Changed from int64_t to uint32_t
    bool multisig_child;                              // NEW: Is this a multisig child transaction
    std::vector<uint8_t> signature;                   // 64 bytes
    std::optional<Escrow> escrow;                     // NEW: Optional escrow data
    std::vector<uint8_t> message;                     // Optional transaction message

    Transaction()
        : version(1),
          id(0),
          block_id(0),
          height(0),
          transaction_type(TransactionType::Empty),
          fee(0),
          timestamp(0),
          transaction_body_length(0),
          transaction_index(0),
          multisig_child(false) {}
};

// Send ZBC transaction body
struct SendZBCTransactionBody {
    int64_t amount;

    SendZBCTransactionBody() : amount(0) {}
};

// ===== Exchange: atomic swap-offer primitive (docs/EXCHANGE_DESIGN.md) =====
// CreateSwapOffer body: maker offers `give_amount` of token `give_token_id` in exchange for
// `want_amount` of `want_token_id`. The give side is HELD on creation. token_id 0 = ZBC.
struct CreateSwapOfferTransactionBody {
    int64_t give_token_id;
    int64_t give_amount;
    int64_t want_token_id;
    int64_t want_amount;
    std::vector<uint8_t> counterparty_address;  // empty = open to anyone; else only this taker may accept
    int64_t expiry;                             // absolute unix seconds; 0 = good-till-cancelled
    CreateSwapOfferTransactionBody()
        : give_token_id(0), give_amount(0), want_token_id(0), want_amount(0), expiry(0) {}
};
// AcceptSwapOffer / CancelSwapOffer bodies: reference an open offer by id.
struct AcceptSwapOfferTransactionBody { int64_t offer_id; AcceptSwapOfferTransactionBody() : offer_id(0) {} };
struct CancelSwapOfferTransactionBody { int64_t offer_id; CancelSwapOfferTransactionBody() : offer_id(0) {} };

// Swap-offer record (versioned table swap_offer, keyed (id, block_height)).
enum class SwapOfferStatus : int32_t { Open = 0, Filled = 1, Cancelled = 2, Expired = 3 };
struct SwapOffer {
    int64_t id;                                 // = creating tx id
    std::vector<uint8_t> maker_address;
    int64_t give_token_id;
    int64_t give_amount;
    int64_t want_token_id;
    int64_t want_amount;
    std::vector<uint8_t> counterparty_address;  // empty = open
    int64_t expiry;
    SwapOfferStatus status;
    uint32_t block_height;
    bool latest;
    SwapOffer()
        : id(0), give_token_id(0), give_amount(0), want_token_id(0), want_amount(0),
          expiry(0), status(SwapOfferStatus::Open), block_height(0), latest(false) {}
};

// ===== Exchange: order-book CLOB (docs/EXCHANGE_DESIGN.md) =====
// Price is quote-atomic units per 1 base-atomic unit, scaled by PRICE_SCALE (1e8): the quote needed for
// `amount` base = amount * price / PRICE_SCALE (computed in int128 to avoid overflow). token_id 0 = ZBC.
enum class OrderSide   : int32_t { Buy = 0, Sell = 1 };
enum class OrderStatus : int32_t { Open = 0, Filled = 1, Cancelled = 2, Expired = 3 };
enum class MarketStatus: int32_t { Active = 0, Pruned = 1 };

struct CreateMarketTransactionBody {  // base/quote tokens + a rent deposit (pay-to-persist)
    int64_t base_token_id; int64_t quote_token_id; int64_t deposit;
    CreateMarketTransactionBody() : base_token_id(0), quote_token_id(0), deposit(0) {}
};
struct PlaceOrderTransactionBody {
    int64_t market_id; int32_t side; int64_t price; int64_t amount; uint8_t flags; int64_t expiry;
    PlaceOrderTransactionBody() : market_id(0), side(0), price(0), amount(0), flags(0), expiry(0) {}
};
struct CancelOrderTransactionBody { int64_t order_id; CancelOrderTransactionBody() : order_id(0) {} };

struct Market {  // versioned table 'market', keyed (id, block_height)
    int64_t id; int64_t base_token_id; int64_t quote_token_id;
    std::vector<uint8_t> creator_address; int64_t deposit;
    MarketStatus status; uint32_t block_height; bool latest;
    Market() : id(0), base_token_id(0), quote_token_id(0), deposit(0),
               status(MarketStatus::Active), block_height(0), latest(false) {}
};
struct Order {   // versioned table 'order_book', keyed (id, block_height)
    int64_t id; int64_t market_id; std::vector<uint8_t> maker_address;
    OrderSide side; int64_t price; int64_t amount; int64_t remaining;
    OrderStatus status; uint32_t block_height; bool latest;
    int64_t expiry;   // absolute unix seconds; 0 = good-till-cancelled. Swept at block apply.
    Order() : id(0), market_id(0), side(OrderSide::Buy), price(0), amount(0), remaining(0),
              status(OrderStatus::Open), block_height(0), latest(false), expiry(0) {}
};
struct Trade {   // append-only table 'trade' (for ticker/chart); keyed (taker_order_id, maker_order_id)
    int64_t market_id; int64_t taker_order_id; int64_t maker_order_id;
    int64_t price; int64_t amount; int64_t taker_fee; int64_t timestamp; uint32_t block_height;
    Trade() : market_id(0), taker_order_id(0), maker_order_id(0),
              price(0), amount(0), taker_fee(0), timestamp(0), block_height(0) {}
};

// ===== On-chain apps (docs/APPS_DESIGN.md) =====
enum class AppStatus : int32_t { Open = 0, Active = 1, Finished = 2, Cancelled = 3 };

struct CreateAppTransactionBody {
    int32_t app_type;          // registry id (1=ttt, 16=dice, ... )
    int64_t stake_token_id;     // 0 = ZBC
    int64_t stake_amount;
    int32_t seats;              // 1 = solo-vs-house, 2 = PvP, 3+ = party
    std::vector<uint8_t> params;             // app-specific setup (e.g. dice over/under, battleship commit)
    std::vector<uint8_t> opponent_address;   // optional: challenge a specific address (empty = open)
    uint8_t channel;            // 0 = on-chain per-move (default); 1 = state channel (off-chain play, one on-chain SettleApp). Valid only when seats==2.
    CreateAppTransactionBody() : app_type(0), stake_token_id(0), stake_amount(0), seats(2), channel(0) {}
};
// SettleApp (39): settle a channel app on-chain. Carries the ordered signed moves; the chain replays
// them from the app's initial state through the existing rules, verifies each signature + turn, and
// pays the winner. Body = app_id(8) | final_seq(4) | move_count(4) | [seat(1) move_len(2) move sig(64)]*.
struct SettleAppMoveEntry { uint8_t seat; std::vector<uint8_t> move_bytes; std::vector<uint8_t> signature; };
struct SettleAppTransactionBody {
    int64_t app_id;
    uint32_t final_seq;
    std::vector<SettleAppMoveEntry> moves;
    SettleAppTransactionBody() : app_id(0), final_seq(0) {}
};
struct JoinAppTransactionBody        { int64_t app_id; JoinAppTransactionBody() : app_id(0) {} };
struct AppMoveTransactionBody        { int64_t app_id; std::vector<uint8_t> move_bytes; AppMoveTransactionBody() : app_id(0) {} };
struct ResignAppTransactionBody      { int64_t app_id; ResignAppTransactionBody() : app_id(0) {} };
struct ClaimAppTimeoutTransactionBody{ int64_t app_id; ClaimAppTimeoutTransactionBody() : app_id(0) {} };

struct App {   // versioned table 'app', keyed (id, block_height)
    int64_t id; int32_t app_type; AppStatus status; int32_t seats;
    std::vector<uint8_t> creator_address;
    std::vector<uint8_t> players;            // concatenated 36-byte seated player addresses (incl creator)
    std::vector<uint8_t> opponent_address;   // challenge target (empty = open)
    int64_t stake_token_id; int64_t stake_amount; int64_t pot;
    std::vector<uint8_t> state_blob;         // serialized engine/board state
    int32_t turn;                            // index into players whose turn it is
    uint32_t created_height; uint32_t last_move_height; uint32_t deadline_height; uint32_t resolve_height;
    std::vector<uint8_t> winner_address;     // set when finished (empty = draw/none)
    uint32_t persist_height;                 // pay-to-survive horizon
    uint8_t channel;                         // 0 = on-chain per-move; 1 = state channel (off-chain play, on-chain SettleApp)
    uint32_t block_height; bool latest;
    App() : id(0), app_type(0), status(AppStatus::Open), seats(2),
             stake_token_id(0), stake_amount(0), pot(0), turn(0),
             created_height(0), last_move_height(0), deadline_height(0), resolve_height(0),
             persist_height(0), channel(0), block_height(0), latest(false) {}
};

// A state-channel settlement claim (Track B), versioned table 'app_settlement' keyed (app_id,
// block_height). A SettleApp tx replays a signed voucher chain and records the result here rather than
// settling instantly; during the challenge window a strictly-higher-seq valid chain OVERRIDES this
// claim (highest-seq-wins), so a truncated chain can always be rebutted by the fuller one. At window
// close the recorded claim is settled: outcome 1/2 pays the winner / refunds a draw; outcome 0
// (ongoing) forfeits the pot to the player NOT on the clock (the on-clock seat failed to produce a
// higher state). See ExecuteSettleApp + the window-close resolver.
struct AppSettlement {
    int64_t app_id;
    std::vector<uint8_t> claimant_address;   // who submitted the current best claim
    uint32_t final_seq;                      // number of moves in the claimed chain (the "height" that must be beaten)
    int32_t outcome;                         // 0 = ongoing, 1 = decisive win, 2 = draw
    int32_t winner_seat;                     // winning seat for outcome 1; -1 otherwise
    int32_t turn;                            // seat on the clock in the claimed state (the forfeiter if outcome 0)
    std::vector<uint8_t> state_blob;         // replayed terminal/ongoing board (audit)
    uint32_t challenge_deadline_height;      // window close; settles once height passes it
    int32_t resolved;                        // 0 = open, 1 = already settled (idempotent guard)
    uint32_t block_height; bool latest;
    AppSettlement() : app_id(0), final_seq(0), outcome(0), winner_seat(-1), turn(-1),
                       challenge_deadline_height(0), resolved(0), block_height(0), latest(false) {}
};

// Node registration transaction body (matches Go model.NodeRegistrationTransactionBody)
struct NodeRegistrationTransactionBody {
    std::vector<uint8_t> node_public_key;   // 32 bytes - node's Ed25519 public key
    std::vector<uint8_t> account_address;   // Raw account address bytes
    int64_t locked_balance;                 // Funds to be locked to register the node
    std::vector<uint8_t> proof_of_ownership; // Raw POOWN bytes (for parsing)
    std::optional<ProofOfOwnership> poown;  // Parsed proof of ownership (message + signature)

    NodeRegistrationTransactionBody() : locked_balance(0) {}
};

// Coinbase transaction body
struct CoinbaseTransactionBody {
    int64_t amount;

    CoinbaseTransactionBody() : amount(0) {}
};

// Update node registration transaction body (type 258)
// Used to update node details (can only increase locked balance)
// Matches Go model.UpdateNodeRegistrationTransactionBody
struct UpdateNodeRegistrationTransactionBody {
    std::vector<uint8_t> node_public_key;   // 32 bytes - node's Ed25519 public key
    int64_t locked_balance;                 // New locked balance (must be >= current)
    std::vector<uint8_t> proof_of_ownership; // Raw POOWN bytes (for parsing)
    std::optional<ProofOfOwnership> poown;  // Parsed proof of ownership (message + signature)

    UpdateNodeRegistrationTransactionBody() : locked_balance(0) {}
};

// Remove node registration transaction body (type 514)
// Used to deactivate a node and reclaim locked balance
struct RemoveNodeRegistrationTransactionBody {
    std::vector<uint8_t> node_public_key;  // 32 bytes - node to remove

    RemoveNodeRegistrationTransactionBody() = default;
};

// Claim node registration transaction body (type 770)
// Used to claim node rewards when original owner is unreachable
// Matches Go model.ClaimNodeRegistrationTransactionBody
struct ClaimNodeRegistrationTransactionBody {
    std::vector<uint8_t> node_public_key;   // 32 bytes - node to claim
    std::vector<uint8_t> proof_of_ownership; // Raw POOWN bytes (for parsing)
    std::optional<ProofOfOwnership> poown;  // Parsed proof of ownership (message + signature)

    ClaimNodeRegistrationTransactionBody() = default;
};

// Approval escrow transaction body (type 4)
// Used to approve, reject, or expire an escrow transaction
// Matches Go model.ApprovalEscrowTransactionBody
// Reference: originals/zoobc-core-develop/common/transaction/approvalEscrowTransaction.go
struct ApprovalEscrowTransactionBody {
    EscrowApproval approval;    // Approve (0), Reject (1), or Expire (2)
    // Since 2026-09-08 the body names the escrowed transaction by its FULL 32-byte hash, not the
    // 8-byte id. A signer that only sees an id cannot check what it is approving; with the hash,
    // a hardware wallet hands the original escrow transaction bytes to the device, hashes them,
    // and compares 256 bits — an 8-byte id could be matched by a 2^64 search on a fake escrow.
    std::vector<uint8_t> transaction_hash;   // 32 bytes: SHA3-256 of the escrowed tx (signed bytes)
    int64_t transaction_id;     // Derived: first 8 bytes of transaction_hash as int64 LE (escrow key)

    ApprovalEscrowTransactionBody()
        : approval(EscrowApproval::Approve), transaction_id(0) {}
};

// Escrow request status enum (ZooBC extension)
// Used to track the lifecycle of recipient-initiated escrow requests
enum class EscrowRequestStatus : int32_t {
    Pending  = 0,   // Awaiting sender approval
    Approved = 1,   // Sender approved and created escrow transaction
    Rejected = 2,   // Sender rejected the request
    Expired  = 3    // Request expired without sender action
};

// Escrow request record - stored in database
// Used for recipient-initiated escrow workflow
struct EscrowRequest {
    int64_t id;                                  // Request ID (transaction ID of the request tx)
    std::vector<uint8_t> requester_address;      // Recipient who initiated the request
    std::vector<uint8_t> proposed_sender;        // Proposed sender of the escrow
    int64_t proposed_amount;                     // Proposed transfer amount
    std::vector<uint8_t> approver_address;       // Third-party approver for the escrow
    int64_t commission;                          // Approver commission
    int64_t timeout;                             // Escrow timeout: ABSOLUTE Unix timestamp (seconds)
    std::string instruction;                     // Instructions for the transaction
    int64_t expiry;                              // Request expiry block height
    EscrowRequestStatus status;                  // Current status of the request
    int64_t escrow_transaction_id;               // ID of created escrow tx (if approved)
    uint32_t block_height;                       // Block height when record was created
    bool latest;                                 // Version flag for database

    EscrowRequest()
        : id(0),
          proposed_amount(0),
          commission(0),
          timeout(0),
          expiry(0),
          status(EscrowRequestStatus::Pending),
          escrow_transaction_id(0),
          block_height(0),
          latest(true) {}
};

// Escrow request transaction body (type 260)
// Used by recipient to propose an escrow transaction to a sender
// The sender must approve this request by creating the actual escrow transaction
struct EscrowRequestTransactionBody {
    std::vector<uint8_t> proposed_sender;    // Address of proposed sender
    int64_t proposed_amount;                 // Proposed transfer amount
    std::vector<uint8_t> approver_address;   // Third-party approver
    int64_t commission;                      // Approver commission (atomic units)
    int64_t timeout;                         // Escrow timeout (block height gap)
    std::string instruction;                 // Instructions for the approver
    int64_t expiry;                          // Request expiry (block height gap from creation)

    EscrowRequestTransactionBody()
        : proposed_amount(0),
          commission(0),
          timeout(0),
          expiry(0) {}
};

// Receipt structure (matches Go model.Receipt from receipt.pb.go)
struct Receipt {
    std::vector<uint8_t> sender_public_key;     // 32 bytes
    std::vector<uint8_t> recipient_public_key;  // 32 bytes
    uint32_t datum_type;                        // Changed to uint32_t to match Go
    std::vector<uint8_t> datum_hash;            // 32 bytes
    uint32_t reference_block_height;
    std::vector<uint8_t> reference_block_hash;  // 32 bytes
    std::vector<uint8_t> rmr;                   // Receipt merkle root (RMR)
    std::vector<uint8_t> recipient_signature;   // 64 bytes

    Receipt() : datum_type(0), reference_block_height(0) {}
};

// Published receipt (receipt included in block)
// Matches Go model.PublishedReceipt from publishedReceipt.pb.go
struct PublishedReceipt {
    Receipt receipt;
    std::vector<uint8_t> intermediate_hashes;   // Intermediate hashes for merkle proof
    uint32_t block_height;
    uint32_t published_index;
    std::vector<uint8_t> rmr_linked;            // Linked RMR
    uint32_t rmr_linked_index;                  // Index of linked RMR

    PublishedReceipt() : block_height(0), published_index(0), rmr_linked_index(0) {}
};

// Batch receipt - a receipt with RMR batch information
// Matches Go model.BatchReceipt from batchReceipt.pb.go
// This is a single receipt with Merkle batch metadata, ready to publish.
// Different from ReceiptBatch (in receipt_batch.h) which is a collection of receipts.
struct BatchReceipt {
    Receipt receipt;                            // Embedded receipt
    std::vector<uint8_t> rmr_batch;             // RMR for the batch this receipt belongs to (32 bytes)
    uint32_t rmr_batch_index;                   // Index of this receipt in the batch Merkle tree

    BatchReceipt() : rmr_batch_index(0) {}
};

// ============================================================================
// MultiSignature Transaction Models
// Reference: originals/zoobc-core-develop/common/model/multiSignature.pb.go
// ============================================================================

// Pending transaction status (matches Go model.PendingTransactionStatus)
enum class PendingTransactionStatus : int32_t {
    Pending  = 0,   // PendingTransactionPending - awaiting signatures
    Executed = 1    // PendingTransactionExecuted - all signatures received, tx executed
};

// Pending transaction - unsigned transaction awaiting multisig signatures
// Reference: originals/zoobc-core-develop/common/model/multiSignature.pb.go
struct PendingTransaction {
    std::vector<uint8_t> sender_address;     // Multisig address
    std::vector<uint8_t> transaction_hash;   // SHA3_256 hash of unsigned tx bytes
    std::vector<uint8_t> transaction_bytes;  // Raw unsigned transaction bytes
    PendingTransactionStatus status;
    uint32_t block_height;
    bool latest;

    PendingTransaction()
        : status(PendingTransactionStatus::Pending),
          block_height(0),
          latest(true) {}
};

// Pending signature - individual signature for a pending multisig transaction
// Reference: originals/zoobc-core-develop/common/model/multiSignature.pb.go
struct PendingSignature {
    std::vector<uint8_t> transaction_hash;   // Hash of tx being signed
    std::vector<uint8_t> account_address;    // Signer's account address
    std::vector<uint8_t> signature;          // 64-byte signature
    uint32_t block_height;
    bool latest;

    PendingSignature()
        : block_height(0),
          latest(true) {}
};

// Multi-signature info - configuration for a multisig account
// Reference: originals/zoobc-core-develop/common/model/multiSignature.pb.go
struct MultiSignatureInfo {
    std::vector<uint8_t> multisig_address;   // Generated multisig address
    uint32_t minimum_signatures;              // Required signatures
    int64_t nonce;                            // Used for unique address generation
    std::vector<std::vector<uint8_t>> addresses;  // Participant account addresses
    uint32_t block_height;
    bool latest;

    MultiSignatureInfo()
        : minimum_signatures(0),
          nonce(0),
          block_height(0),
          latest(true) {}
};

// Multi-signature participant - individual member of a multisig account
// Reference: originals/zoobc-core-develop/common/model/multiSignature.pb.go
struct MultiSignatureParticipant {
    std::vector<uint8_t> multisig_address;
    std::vector<uint8_t> account_address;
    uint32_t account_address_index;
    uint32_t block_height;
    bool latest;

    MultiSignatureParticipant()
        : account_address_index(0),
          block_height(0),
          latest(true) {}
};

// Signature info - collection of signatures for a transaction
// Reference: originals/zoobc-core-develop/common/model/multiSignature.pb.go
struct SignatureInfo {
    std::vector<uint8_t> transaction_hash;
    // Map from hex-encoded address to signature
    std::map<std::string, std::vector<uint8_t>> signatures;

    SignatureInfo() = default;
};

// Multi-signature transaction body (type 5)
// Reference: originals/zoobc-core-develop/common/model/multiSignature.pb.go
// This transaction type allows for:
// 1. Posting multisig info (account configuration)
// 2. Posting unsigned transaction bytes
// 3. Posting signatures
// Any combination can be submitted, and the multisig tx is executed when complete.
struct MultiSignatureTransactionBody {
    std::optional<MultiSignatureInfo> multi_signature_info;
    std::vector<uint8_t> unsigned_transaction_bytes;  // Inner transaction (unsigned)
    std::optional<SignatureInfo> signature_info;

    MultiSignatureTransactionBody() = default;
};

// ============================================================================
// Liquid Payment Transaction Models
// Reference: originals/zoobc-core-develop/common/model/liquidPayment.pb.go
// ============================================================================

// Liquid payment status (matches Go model.LiquidPaymentStatus)
enum class LiquidPaymentStatus : int32_t {
    Pending   = 0,   // LiquidPaymentPending - payment is active, can be stopped
    Completed = 1    // LiquidPaymentCompleted - payment has been completed/stopped
};

// Liquid payment record - tracks a time-vested payment
// Reference: originals/zoobc-core-develop/common/model/liquidPayment.pb.go
struct LiquidPayment {
    int64_t id;                              // Transaction ID of the original LiquidPayment tx
    std::vector<uint8_t> sender_address;     // Address that created the payment
    std::vector<uint8_t> recipient_address;  // Address that will receive the payment
    int64_t amount;                          // Total amount to be paid
    int64_t applied_time;                    // Timestamp when payment was created (block timestamp)
    uint64_t complete_minutes;               // Time period over which payment vests (in minutes)
    LiquidPaymentStatus status;              // Current status of the payment
    uint32_t block_height;                   // Block height when record was created/updated
    bool latest;                             // Flag for versioned table queries
    int64_t token_id;                        // 0 = ZBC; else the token being streamed (NEW)

    LiquidPayment()
        : id(0),
          amount(0),
          applied_time(0),
          complete_minutes(0),
          status(LiquidPaymentStatus::Pending),
          block_height(0),
          latest(true),
          token_id(0) {}
};

// Liquid payment transaction body (type 6)
// Creates a new time-vested payment to a recipient
// Reference: originals/zoobc-core-develop/common/transaction/liquidPayment.go
struct LiquidPaymentTransactionBody {
    int64_t amount;              // Amount to pay (ZBC atomic units, or token atomic units if token_id != 0)
    uint64_t complete_minutes;   // Time period over which payment fully vests
    int64_t token_id;            // 0 = ZBC; else the colored-coin token streamed (NEW, optional in body)

    LiquidPaymentTransactionBody()
        : amount(0), complete_minutes(0), token_id(0) {}
};

// Liquid payment stop transaction body (type 262)
// Stops/completes a pending liquid payment, distributing funds pro-rata
// Reference: originals/zoobc-core-develop/common/transaction/liquidPaymentStop.go
struct LiquidPaymentStopTransactionBody {
    int64_t transaction_id;   // ID of the LiquidPayment transaction to stop

    LiquidPaymentStopTransactionBody()
        : transaction_id(0) {}
};

// ============================================================================
// Account Dataset Transaction Models
// Reference: originals/zoobc-core-develop/common/model/accountDataset.pb.go
//            originals/zoobc-core-develop/common/transaction/setupAccountDataset.go
//            originals/zoobc-core-develop/common/transaction/removeAccountDataset.go
// ============================================================================

// Account dataset record - key-value metadata for accounts
// Reference: originals/zoobc-core-develop/common/model/accountDataset.pb.go
struct AccountDataset {
    std::vector<uint8_t> setter_account_address;     // Address that set the property
    std::vector<uint8_t> recipient_account_address;  // Address the property is set on
    std::string property;                            // Property name/key
    std::string value;                               // Property value
    bool is_active;                                  // Whether the property is active
    bool latest;                                     // Flag for versioned table queries
    uint32_t height;                                 // Block height when record was created/updated

    // DataSet survival financing: the dataset's creating tx hash (32 bytes) → its fundable
    // ZBS_ Reed-Solomon address (type-10 account = 10,0,0,0 + this hash). Storage rent is
    // drawn from THAT address's own balance each period; last_billing_height is the clock.
    std::vector<uint8_t> creating_tx_hash;
    uint32_t last_billing_height;

    // Object model (unified): every entry belongs to a dataset OBJECT identified by object_id
    // (= the object-creating tx hash → its ZBS_ address). added_by is the account that set THIS
    // entry (gated by the object's policy). Owner + policy live in DatasetObject, keyed by object_id.
    // Backward-compatible: a legacy single-property dataset is its own object (object_id =
    // creating_tx_hash, added_by = setter).
    std::vector<uint8_t> object_id;
    std::vector<uint8_t> added_by;

    AccountDataset()
        : is_active(false),
          latest(true),
          height(0),
          last_billing_height(0) {}
};

// A dataset OBJECT: owner + management policy, keyed by object_id (= creating tx hash → ZBS_ addr).
// Its entries are AccountDataset rows sharing object_id; its longevity deposit is the ZBS_ balance.
struct DatasetObject {
    std::vector<uint8_t> object_id;       // 32-byte creating tx hash (→ ZBS_ address)
    std::vector<uint8_t> owner_account;   // current owner (transferable, two-step)
    std::vector<uint8_t> pending_owner;   // proposed owner awaiting AcceptDataset (empty if none)
    int32_t manage_mode;                  // 0 owner_only, 1 whitelist, 2 blacklist, 3 open
    uint32_t height;
    bool latest;
    DatasetObject() : manage_mode(0), height(0), latest(true) {}
};

// Setup account dataset transaction body (type 3)
// Creates or updates a key-value property on an account
// Reference: originals/zoobc-core-develop/common/transaction/setupAccountDataset.go
struct SetupAccountDatasetTransactionBody {
    std::string property;   // Property name/key (max length defined by constant)
    std::string value;      // Property value (max length defined by constant)

    SetupAccountDatasetTransactionBody() = default;
};

// Remove account dataset transaction body (type 259)
// Deactivates a key-value property on an account
// Reference: originals/zoobc-core-develop/common/transaction/removeAccountDataset.go
struct RemoveAccountDatasetTransactionBody {
    std::string property;   // Property name/key to remove
    std::string value;      // Property value (for verification)

    RemoveAccountDatasetTransactionBody() = default;
};

// ============================================================================
// DFS (Distributed File System) Transaction Models
// Provides file system abstraction on top of AccountDataset storage
// ============================================================================

// DFS create file transaction body (type 8)
// Creates a new file in the distributed file system
struct DFSCreateFileTransactionBody {
    std::string path;                      // Absolute file path (e.g., "/home/user/file.txt")
    std::vector<uint8_t> content;          // File content (max 10 MB)

    DFSCreateFileTransactionBody() = default;
};

// DFS update file transaction body (type 264)
// Updates an existing file in the distributed file system
struct DFSUpdateFileTransactionBody {
    std::string path;                      // Absolute file path to update
    std::vector<uint8_t> content;          // New file content

    DFSUpdateFileTransactionBody() = default;
};

// DFS delete file transaction body (type 520)
// Deletes a file from the distributed file system
struct DFSDeleteFileTransactionBody {
    std::string path;                      // Absolute file path to delete

    DFSDeleteFileTransactionBody() = default;
};

// ============================================================================
// Fee Vote Transaction Models
// Reference: originals/zoobc-core-develop/common/model/feeVote.pb.go
//            originals/zoobc-core-develop/common/transaction/feeVoteCommit.go
//            originals/zoobc-core-develop/common/transaction/feeVoteReveal.go
// ============================================================================

// Fee vote info - the actual vote data that gets hashed for commitment
// Reference: originals/zoobc-core-develop/common/model/feeVote.pb.go
struct FeeVoteInfo {
    std::vector<uint8_t> recent_block_hash;   // 32 bytes - reference block hash
    uint32_t recent_block_height;              // Block height of reference block
    int64_t fee_vote;                          // Proposed fee multiplier

    FeeVoteInfo()
        : recent_block_height(0),
          fee_vote(0) {}
};

// Fee vote commitment transaction body (type 7)
// Used to submit a hashed vote during the commit phase
// Reference: originals/zoobc-core-develop/common/transaction/feeVoteCommit.go
struct FeeVoteCommitTransactionBody {
    std::vector<uint8_t> vote_hash;   // 32 bytes - SHA3_256 hash of FeeVoteInfo bytes

    FeeVoteCommitTransactionBody() = default;
};

// Fee vote reveal transaction body (type 263)
// Used to reveal the actual vote during the reveal phase
// Reference: originals/zoobc-core-develop/common/transaction/feeVoteReveal.go
struct FeeVoteRevealTransactionBody {
    FeeVoteInfo fee_vote_info;                 // The actual vote info
    std::vector<uint8_t> voter_signature;      // Signature on the fee vote info bytes

    FeeVoteRevealTransactionBody() = default;
};

// Fee vote commitment vote record - stored in database
// Reference: originals/zoobc-core-develop/common/query/feeVoteCommitmentVoteQuery.go
struct FeeVoteCommitmentVote {
    std::vector<uint8_t> vote_hash;           // 32 bytes - hashed vote
    std::vector<uint8_t> voter_address;       // Voter's account address
    uint32_t block_height;                     // Block height when committed

    FeeVoteCommitmentVote()
        : block_height(0) {}
};

// Fee vote reveal vote record - stored in database
// Reference: originals/zoobc-core-develop/common/query/feeVoteRevealVoteQuery.go
struct FeeVoteRevealVote {
    FeeVoteInfo vote_info;                     // The revealed vote info
    std::vector<uint8_t> voter_signature;      // Signature on the vote info
    std::vector<uint8_t> voter_address;        // Voter's account address
    uint32_t block_height;                     // Block height when revealed

    FeeVoteRevealVote()
        : block_height(0) {}
};

// Fee scale record - stores the calculated fee multiplier per voting period
// Reference: originals/zoobc-core-develop/common/query/feeScaleQuery.go
struct FeeScale {
    int64_t fee_scale;        // Fee multiplier value
    uint32_t block_height;    // Block height when this fee scale was set
    bool latest;              // Flag for versioned table queries

    FeeScale()
        : fee_scale(1),
          block_height(0),
          latest(true) {}
};

// Fee vote phase enumeration (matches Go model.FeeVotePhase)
enum class FeeVotePhase : int32_t {
    Commit = 0,    // FeeVotePhaseCommmit - commit vote hash phase
    Reveal = 1     // FeeVotePhaseReveal - reveal actual vote phase
};

}  // namespace model
}  // namespace zoobc

#endif  // ZOOBC_MODEL_TRANSACTION_H
