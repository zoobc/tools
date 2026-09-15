// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_COMMON_TYPES_H
#define ZOOBC_COMMON_TYPES_H

#include <cstdint>
#include <string>
#include <vector>

namespace zoobc {

// Note: ChainTypeID is defined in chain_type.h
// Use ChainTypeID::MainChain and ChainTypeID::SpineChain

// Transaction types (IDs match Go implementation in model/transaction.pb.go)
// Pattern: Base transaction types use sequential IDs (0-7)
// Node registration variants use: 2 + (subtype * 256) pattern
// Account dataset variants use: 3 + (subtype * 256) pattern
// Liquid payment variants use: 6 + (subtype * 256) pattern
// Fee vote variants use: 7 + (subtype * 256) pattern
enum class TransactionType : uint32_t {
    Empty                     = 0,      // EmptyTransaction
    SendZBC                   = 1,      // SendZBCTransaction
    NodeRegistration          = 2,      // NodeRegistrationTransaction - Register new node
    SetupAccountDataset       = 3,      // SetupAccountDatasetTransaction
    ApprovalEscrow            = 4,      // ApprovalEscrowTransaction
    MultiSignature            = 5,      // MultiSignatureTransaction
    LiquidPayment             = 6,      // LiquidPaymentTransaction
    FeeVoteCommitment         = 7,      // FeeVoteCommitmentVoteTransaction
    AddPrepaidStorage         = 9,      // AddPrepaidStorageTransaction - fund dataset storage rent
    // ----- Native tokens / colored coins (Epsilon) -----
    IssueToken                = 10,     // IssueTokenTransaction  - create a token, lock backing
    TransferToken             = 11,     // TransferTokenTransaction
    MintToken                 = 12,     // MintTokenTransaction    - add backing, mint to self (if mintable)
    BurnToken                 = 13,     // BurnTokenTransaction    - burn/redeem (reclaim backing if redeemable)
    FinanceToken              = 14,     // FinanceTokenTransaction - top up survival financing
    // ----- Event triggers Phase B (on-chain, deterministic) — EVENT_TRIGGERS.md -----
    CreateTrigger             = 15,     // CreateTriggerTransaction - schedule a SendZBC at a future block height
    CancelTrigger             = 16,     // CancelTriggerTransaction - cancel a pending trigger, refund the owner
    AttestEvent               = 17,     // AttestEventTransaction (Phase C oracle) - an authorized node attests an external (event_id,value)
    // ----- Exchange: atomic swap-offer primitive (docs/EXCHANGE_DESIGN.md) -----
    CreateSwapOffer           = 18,     // maker offers give_amount of give_token for want_amount of want_token (give held)
    AcceptSwapOffer           = 19,     // taker fills an open offer: atomic swap give<->want + fees
    CancelSwapOffer           = 20,     // maker cancels an open offer, refund the held give_amount
    // ----- Exchange: order-book CLOB (docs/EXCHANGE_DESIGN.md) -----
    CreateMarket              = 21,     // open a permissionless (base,quote) market, paying a rent deposit
    PlaceOrder                = 22,     // place a limit/market buy/sell order; matches the resting book, rests the remainder
    CancelOrder               = 23,     // cancel a resting order, refund the held remainder
    // ----- On-chain apps (docs/APPS_DESIGN.md) -----
    CreateApp                = 24,     // open an app: type + stake (token,amount) + seats + params + [opponent]
    JoinApp                  = 25,     // join an open app seat, locking an equal stake
    AppMove                  = 26,     // one move (app_id + move_bytes); rules enforced on-chain
    ResignApp                = 27,     // forfeit; your stake share goes to the opponent(s)
    ClaimAppTimeout          = 28,     // claim the win if an opponent abandoned past the per-move deadline
    ScheduledTransfer         = 29,     // recurring/vested transfer (scheduler)
    CancelSchedule            = 30,     // revoke (sender) or decline (recipient) a schedule
    ReassignSchedule          = 31,     // recipient redirects future fires
    // ----- On-chain release governance (docs/ …onchain-release-and-gateway-registry.md) -----
    RegisterRelease           = 32,     // publish a signed binary release (version + manifest hash), by the release authority
    ReleaseAuthorityPropose   = 33,     // current authority proposes a hand-off to a pending address
    ReleaseAuthorityAccept    = 34,     // pending address accepts, becoming the new release authority
    RevokeRelease             = 35,     // authority revokes a previously-published release (e.g. bad build)
    // ----- On-chain gateway registry (Track B) -----
    RegisterGateway           = 36,     // register a gateway: gateway_key + domain + url, locking a stake
    GatewayHeartbeat          = 37,     // liveness proof: an unforgeable, tip-fresh reference-block-hash beat
    UnregisterGateway         = 38,     // owner withdraws its gateway, refunding the locked stake
    // ----- App state channels (2-player only): off-chain signed moves, one on-chain settlement -----
    SettleApp                = 39,     // settle a channel app on-chain: replay the ordered signed moves through the rules, pay the winner

    StoreFile                 = 40,     // anchor a decentralized-storage file: manifest (root + piece ids) + a rent deposit; content lives off-chain (sharded)
    SubmitStorageProof        = 41,     // a holder attests possession of a challenged piece this epoch: H(piece_bytes ‖ chain-nonce); tallied for rent reward / slash
    TransferDataset           = 42,     // propose transfer of a dataset object's ownership (two-step; pending until AcceptDataset)
    SetDatasetPolicy          = 43,     // set a dataset object's manage policy (owner-only/whitelist/blacklist/open) + acl edits
    AcceptDataset             = 44,     // proposed owner accepts a pending TransferDataset — becomes owner + billing fallback
    DeleteDataset             = 45,     // owner deletes a whole dataset object: deactivate all entries + refund remaining ZBS_ deposit
    RegisterArchival          = 46,     // announce a registered node as archival (serves history + the read API): node_key + domain + url
    UnregisterArchival        = 47,     // withdraw an archival announcement (owner only)
    RegisterRelay             = 48,     // announce a relay a gateway runs (voice/video/data passthrough): relay_key + gateway_key + domain + url
    UnregisterRelay           = 49,     // withdraw a relay announcement (owner only)
    SetTransactPolicy         = 50,     // set the sender's per-account umbrella opt-out bitmask (bidirectional refusal)
    SetConsensusParam         = 51,     // a registry node votes to change an ECONOMIC consensus parameter; applied at a 2/3 registry supermajority (docs: param_governance.h)
    // ---- Paid longevity: keep a transaction's payload retrievable past the prune horizon --------
    // Nodes prune transactions below snapshot N-1. That is correct behaviour and stays — the answer
    // for data someone wants kept is to PAY for it, not to switch pruning off. FundLongevity
    // attaches a deposit to a target transaction id; rent is drawn from that deposit each period and
    // the transaction (and its block header) is excluded from pruning while the deposit lasts.
    // Anyone may sponsor anything; the sponsor may cancel, forfeiting the remainder (owner's rule).
    FundLongevity             = 52,     // body: target_tx_id(8 LE) | amount(8 LE)
    CancelLongevity           = 53,     // body: target_tx_id(8 LE) — sponsor only; refunds the remainder less the period being consumed (owner rule 2026-08-31)
    NodeRegistrationUpdate    = 258,    // UpdateNodeRegistrationTransaction [2,1,0,0]
    RemoveAccountDataset      = 259,    // RemoveAccountDatasetTransaction [3,1,0,0]
    LiquidPaymentStop         = 262,    // LiquidPaymentStopTransaction [6,1,0,0]
    FeeVoteReveal             = 263,    // FeeVoteRevealVoteTransaction [7,1,0,0]
    EscrowRequest             = 260,    // EscrowRequestTransaction [4,1,0,0] - Recipient-initiated escrow
    RemoveNodeRegistration    = 514,    // RemoveNodeRegistrationTransaction [2,2,0,0]
    ClaimNodeRegistration     = 770,    // ClaimNodeRegistrationTransaction [2,3,0,0]

    // DFS (Distributed File System) transaction types
    // Pattern: 8 + (subtype * 256)
    DFSCreateFile             = 8,      // DFSCreateFileTransaction - Create a new file
    DFSUpdateFile             = 264,    // DFSUpdateFileTransaction [8,1,0,0] - Update existing file
    DFSDeleteFile             = 520     // DFSDeleteFileTransaction [8,2,0,0] - Delete a file

    // NOTE: Coinbase rewards are NOT transaction types (matching Go implementation)
    // Coinbase is calculated per block and stored in block.total_coinbase field
};

// Node-signed, FEE-EXEMPT transaction types. A node votes/attests from its own key
// (00000000 + node_public_key), and that account holds no balance — the owner's funds live in the
// wallet and never touch the node. So these types pay no fee and must skip the balance gate.
//
// Skipping the balance gate is safe ONLY because the authoritative "is the sender really a
// registered node?" check runs in TransactionExecutor::CanApplyUnconfirmed, which has the registry.
// A non-node is rejected there, so this cannot become a free-transaction flood.
// Node-signed transaction types: the node submits these itself, from its OWN account
// (00000000 ‖ node_public_key — a perfectly ordinary ZBC address), not from the owner's wallet.
//
// These used to be FEE-EXEMPT, on the assumption that the node's account holds no balance. Owner
// decision 2026-08-09 reverses that: the node's account is funded (genesis seeds it, and the owner
// can top it up like any address), and a node pays for the block space it consumes exactly like
// everybody else. The exemption was a free-transaction channel — worse, the declared fee was still
// minted into the reward pool — and "a node is trusted" is not a reason to let it write unpriced
// rows into everyone's permanent storage.
//
// The predicate is kept because these types ARE still special in one way: their sender is the node
// account rather than a wallet, so an unfunded node stops attesting rather than failing loudly in
// someone's UI. Callers use it to log that clearly.
inline bool IsNodeSignedType(TransactionType t) {
    return t == TransactionType::SubmitStorageProof || t == TransactionType::SetConsensusParam;
}

// Umbrella categories for the per-account transact policy (SetTransactPolicy). FIXED SET — baked in
// before mainnet (can't change once live). Each account carries a 9-bit opt-out mask; a transaction is
// REFUSED if the sender OR the recipient has opted out of its category (bidirectional: opting out of a
// category removes both sending AND receiving it). Bit index = the enum value.
enum class TxCategory : uint8_t {
    Payments = 0,       // SendZBC, liquid/scheduled/trigger transfers
    Apps = 1,          // create/join/move/resign/timeout/settle
    Tokens = 2,         // issue/transfer/mint/burn/finance colored coins
    Exchange = 3,       // swap offers + order-book markets
    DataStorage = 4,    // datasets, prepaid storage, files (DFS/StoreFile), storage proofs
    EscrowMultisig = 5, // escrow approval/request, multisignature
    NodeInfra = 6,      // node registration + gateway/archival/relay registry
    Bridge = 7,         // cross-chain attestation / mint
    Governance = 8,     // fee votes + signed-release governance
    None = 255,         // uncategorized / always-allowed (Empty, SetTransactPolicy itself, admin)
};
constexpr int kTxCategoryCount = 9;   // Payments..Governance

// Map a transaction type to its umbrella. Uncategorized/admin types default to None (never refusable),
// so a policy can never accidentally block a critical or unknown tx. Has a default → no -Werror=switch.
inline TxCategory TransactionCategoryOf(TransactionType t) {
    switch (t) {
        case TransactionType::SendZBC: case TransactionType::LiquidPayment:
        case TransactionType::LiquidPaymentStop: case TransactionType::CreateTrigger:
        case TransactionType::CancelTrigger: case TransactionType::ScheduledTransfer:
        case TransactionType::CancelSchedule: case TransactionType::ReassignSchedule:
            return TxCategory::Payments;
        case TransactionType::CreateApp: case TransactionType::JoinApp:
        case TransactionType::AppMove: case TransactionType::ResignApp:
        case TransactionType::ClaimAppTimeout: case TransactionType::SettleApp:
            return TxCategory::Apps;
        case TransactionType::IssueToken: case TransactionType::TransferToken:
        case TransactionType::MintToken: case TransactionType::BurnToken:
        case TransactionType::FinanceToken:
            return TxCategory::Tokens;
        case TransactionType::CreateSwapOffer: case TransactionType::AcceptSwapOffer:
        case TransactionType::CancelSwapOffer: case TransactionType::CreateMarket:
        case TransactionType::PlaceOrder: case TransactionType::CancelOrder:
            return TxCategory::Exchange;
        case TransactionType::SetupAccountDataset: case TransactionType::RemoveAccountDataset:
        case TransactionType::AddPrepaidStorage: case TransactionType::StoreFile:
        case TransactionType::SubmitStorageProof: case TransactionType::TransferDataset:
        case TransactionType::SetDatasetPolicy: case TransactionType::AcceptDataset:
        case TransactionType::DeleteDataset: case TransactionType::DFSCreateFile:
        case TransactionType::DFSUpdateFile: case TransactionType::DFSDeleteFile:
            return TxCategory::DataStorage;
        case TransactionType::ApprovalEscrow: case TransactionType::EscrowRequest:
        case TransactionType::MultiSignature:
            return TxCategory::EscrowMultisig;
        case TransactionType::NodeRegistration: case TransactionType::NodeRegistrationUpdate:
        case TransactionType::RemoveNodeRegistration: case TransactionType::ClaimNodeRegistration:
        case TransactionType::RegisterGateway: case TransactionType::GatewayHeartbeat:
        case TransactionType::UnregisterGateway: case TransactionType::RegisterArchival:
        case TransactionType::UnregisterArchival: case TransactionType::RegisterRelay:
        case TransactionType::UnregisterRelay:
            return TxCategory::NodeInfra;
        case TransactionType::AttestEvent:
            return TxCategory::Bridge;
        case TransactionType::FeeVoteCommitment: case TransactionType::FeeVoteReveal:
        case TransactionType::RegisterRelease: case TransactionType::ReleaseAuthorityPropose:
        case TransactionType::ReleaseAuthorityAccept: case TransactionType::RevokeRelease:
        case TransactionType::SetConsensusParam:
            return TxCategory::Governance;
        default:
            return TxCategory::None;  // Empty, SetTransactPolicy, and any uncategorized/admin tx
    }
}

// Account types (matching Go model.AccountType in accountType.pb.go)
enum class AccountType : int32_t {
    ZbcAccount        = 0,  // ZbcAccountType - Native ZooBC account
    // NOTE: BTCAccount (1) is legacy/ambiguous (20-byte payload without script type).
    // New BTC script types use distinct IDs so the original Bitcoin address can be
    // reconstructed exactly (bridge correctness).
    BTCAccount        = 1,  // BTCAccountType - Legacy/ambiguous BTC hash payload (20 bytes)
    EmptyAccount      = 2,  // EmptyAccountType - Placeholder/uninitialized
    EstoniaEidAccount = 3,  // EstoniaEidAccountType - Estonian eID
    ETHAccount        = 4,  // ETHAccountType - Ethereum-style address

    // Bitcoin script subtypes (ZooBC extension; fixed payload sizes for tx parsing)
    BTCP2PKHAccount   = 5,  // 20-byte payload (hash160(pubkey)), Base58 "1..."
    BTCP2SHAccount    = 6,  // 20-byte payload (hash160(script)), Base58 "3..."
    BTCP2WPKHAccount  = 7,  // 20-byte payload (witness v0 program), Bech32 "bc1q..."
    BTCP2WSHAccount   = 8,  // 32-byte payload (witness v0 program), Bech32 "bc1q..."
    BTCP2TRAccount    = 9,  // 32-byte payload (witness v1 program), Bech32m "bc1p..."

    // ZooBC object addresses (ROADMAP §C): an on-chain DataSet gets a fundable,
    // Reed-Solomon "ZBS_" address derived from its creating tx hash (32-byte payload).
    // It can hold a ZBC balance (receive SendZBC) but never signs — funds are consumed
    // by storage-financing/return, not by a recipient signature.
    DataSetAccount    = 10, // 32-byte payload (creating tx hash), human prefix "ZBS"

    // Multichain mirror accounts (docs/MULTICHAIN_ACCOUNTS.md): a foreign-chain address held
    // verbatim as a distinct ZooBC account, so a bridge deposit credits the depositor's SAME
    // source address. Solana = 32-byte ed25519 pubkey (same scheme as ZBC), base58 display.
    SolanaAccount     = 11, // 32-byte payload (ed25519 pubkey), native Solana base58 address

    // Polkadot / Substrate: the 32-byte AccountId (SS58-encoded for display). Receives transfers now;
    // SPEND needs an sr25519 (Schnorrkel) verifier — vendored separately. Default Polkadot keys are
    // sr25519, but ed25519-keyed accounts share this AccountId space too.
    PolkadotAccount   = 12  // 32-byte payload (AccountId), SS58 address (prefix 0 = Polkadot)
};

// Node registration status (matches Go model.NodeRegistrationState in nodeRegistration.pb.go)
// IMPORTANT: Values must match Go exactly for cross-node compatibility
enum class NodeRegistrationStatus : uint32_t {
    Registered = 0,   // NodeRegistered - node is registered and active, can participate in consensus
    Queued     = 1,   // NodeQueued - node is in admission queue, pending registration
    Deleted    = 2    // NodeDeleted - node has been removed or claimed
};

// Receipt datum types (matches Go constant/receipt.go)
// CRITICAL: Values must match Go exactly for cross-node compatibility
// Go: ReceiptDatumTypeBlock = 1, ReceiptDatumTypeTransaction = 2
enum class ReceiptDatumType : uint32_t {
    BlockData        = 1,   // ReceiptDatumTypeBlock - receipt for block data
    TransactionData  = 2    // ReceiptDatumTypeTransaction - receipt for transaction data
};

// Common type aliases
using Hash      = std::vector<uint8_t>;  // 32 bytes
using Signature = std::vector<uint8_t>;  // 64 bytes
using PublicKey = std::vector<uint8_t>;  // 32 bytes
using Address   = std::vector<uint8_t>;  // Variable length

// Convert enum to string (ChainTypeID is in chain_type.h)

inline const char* TransactionTypeToString(TransactionType type) {
    switch (type) {
        case TransactionType::Empty:
            return "EmptyTransaction";
        case TransactionType::SendZBC:
            return "SendZBCTransaction";
        case TransactionType::NodeRegistration:
            return "NodeRegistrationTransaction";
        case TransactionType::SetupAccountDataset:
            return "SetupAccountDatasetTransaction";
        case TransactionType::ApprovalEscrow:
            return "ApprovalEscrowTransaction";
        case TransactionType::MultiSignature:
            return "MultiSignatureTransaction";
        case TransactionType::LiquidPayment:
            return "LiquidPaymentTransaction";
        case TransactionType::FeeVoteCommitment:
            return "FeeVoteCommitmentVoteTransaction";
        case TransactionType::NodeRegistrationUpdate:
            return "UpdateNodeRegistrationTransaction";
        case TransactionType::RemoveAccountDataset:
            return "RemoveAccountDatasetTransaction";
        case TransactionType::LiquidPaymentStop:
            return "LiquidPaymentStopTransaction";
        case TransactionType::FeeVoteReveal:
            return "FeeVoteRevealVoteTransaction";
        case TransactionType::EscrowRequest:
            return "EscrowRequestTransaction";
        case TransactionType::RemoveNodeRegistration:
            return "RemoveNodeRegistrationTransaction";
        case TransactionType::ClaimNodeRegistration:
            return "ClaimNodeRegistrationTransaction";
        case TransactionType::DFSCreateFile:
            return "DFSCreateFileTransaction";
        case TransactionType::DFSUpdateFile:
            return "DFSUpdateFileTransaction";
        case TransactionType::DFSDeleteFile:
            return "DFSDeleteFileTransaction";
        case TransactionType::RegisterRelease:
            return "RegisterReleaseTransaction";
        case TransactionType::ReleaseAuthorityPropose:
            return "ReleaseAuthorityProposeTransaction";
        case TransactionType::ReleaseAuthorityAccept:
            return "ReleaseAuthorityAcceptTransaction";
        case TransactionType::RevokeRelease:
            return "RevokeReleaseTransaction";
        case TransactionType::RegisterGateway:
            return "RegisterGatewayTransaction";
        case TransactionType::GatewayHeartbeat:
            return "GatewayHeartbeatTransaction";
        case TransactionType::UnregisterGateway:
            return "UnregisterGatewayTransaction";
        default:
            return "Unknown";
    }
}

}  // namespace zoobc

#endif  // ZOOBC_COMMON_TYPES_H
