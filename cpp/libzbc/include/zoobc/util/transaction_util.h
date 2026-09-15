// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_UTIL_TRANSACTION_UTIL_H
#include <cctype>
#define ZOOBC_UTIL_TRANSACTION_UTIL_H

#include <cstdint>
#include <vector>
#include <string>
#include <unordered_set>
#include "zoobc/model/transaction.h"
#include "zoobc/common/types.h"
#include "zoobc/common/result.h"

namespace zoobc {
namespace util {

// Transaction serialization utilities matching Go implementation exactly
// Reference: originals/zoobc-core-develop/common/transaction/transactionGeneral.go
class TransactionUtil {
public:
    // ========================================================================
    // Constants matching Go implementation (common/constant/fieldsSize.go)
    // ========================================================================
    static constexpr uint32_t TRANSACTION_TYPE_SIZE = 4;
    static constexpr uint32_t TRANSACTION_VERSION_SIZE = 1;  // Go uses only 1 byte!
    static constexpr uint32_t TIMESTAMP_SIZE = 8;
    static constexpr uint32_t ACCOUNT_TYPE_SIZE = 4;         // AccountAddressTypeLength
    static constexpr uint32_t PUBLIC_KEY_SIZE = 32;          // NodePublicKey / ZBC pubkey
    static constexpr uint32_t FEE_SIZE = 8;
    static constexpr uint32_t BODY_LENGTH_SIZE = 4;
    static constexpr uint32_t SIGNATURE_SIZE = 64;           // NodeSignature / ZBCSignatureLength
    static constexpr uint32_t MESSAGE_LENGTH_SIZE = 4;
    static constexpr uint32_t BALANCE_SIZE = 8;              // Balance field size
    static constexpr uint32_t BLOCK_HASH_SIZE = 32;          // BlockHash
    static constexpr uint32_t HEIGHT_SIZE = 4;               // Height
    static constexpr uint32_t NODE_PUBLIC_KEY_SIZE = 32;     // NodePublicKey constant

    // Account types matching Go model.AccountType
    static constexpr int32_t ACCOUNT_TYPE_ZBC = 0;
    static constexpr int32_t ACCOUNT_TYPE_BTC = 1;
    static constexpr int32_t ACCOUNT_TYPE_EMPTY = 2;
    static constexpr int32_t ACCOUNT_TYPE_ESTONIA_EID = 3;
    static constexpr int32_t ACCOUNT_TYPE_ETH = 4;
    // ZooBC extension: Bitcoin script subtypes (preserves original address format)
    static constexpr int32_t ACCOUNT_TYPE_BTC_P2PKH = 5;
    static constexpr int32_t ACCOUNT_TYPE_BTC_P2SH = 6;
    static constexpr int32_t ACCOUNT_TYPE_BTC_P2WPKH = 7;
    static constexpr int32_t ACCOUNT_TYPE_BTC_P2WSH = 8;
    static constexpr int32_t ACCOUNT_TYPE_BTC_P2TR = 9;
    static constexpr int32_t ACCOUNT_TYPE_DATASET = 10;  // fundable DataSet object address (ZBS_)
    static constexpr int32_t ACCOUNT_TYPE_SOLANA = 11;   // mirrored Solana addr (32-byte ed25519, base58)
    static constexpr int32_t ACCOUNT_TYPE_POLKADOT = 12; // mirrored Polkadot AccountId (32-byte, SS58)
    // Mirrored crypto-coin account types. Each verifies with the chain's signature primitive by
    // reusing the matching ZooBC verifier (see Signature::GetAccountType):
    static constexpr int32_t ACCOUNT_TYPE_CARDANO = 13;  // ZADA — REAL Cardano enterprise address: blake2b-224(pubkey), key carried in the signature
    static constexpr uint32_t CARDANO_KEYHASH_SIZE = 28; // blake2b-224 of the ed25519 key, as on Cardano
    static constexpr int32_t ACCOUNT_TYPE_RIPPLE  = 14;  // ZXRP — secp256k1 + HASH160 addr (verifies like BTC)
    static constexpr int32_t ACCOUNT_TYPE_TRON     = 15; // ZTRX — secp256k1 + Keccak addr (verifies like ETH)
    static constexpr int32_t ACCOUNT_TYPE_TEZOS    = 16; // ZXTZ — ed25519 tz1 (verifies as ed25519)

    // Signature lengths for different account types (Go: common/constant/signature.go)
    static constexpr uint32_t ZBC_SIGNATURE_LENGTH = 64;      // Ed25519
    static constexpr uint32_t BTC_SIGNATURE_LENGTH = 32;      // ECDSA compact
    static constexpr uint32_t ETH_SIGNATURE_LENGTH = 65;      // ECDSA + recovery byte

    // Address sizes for different account types (without type prefix)
    static constexpr uint32_t ETH_ADDRESS_SIZE = 20;          // ETH address (last 20 bytes of Keccak256(pubkey))
    static constexpr uint32_t BTC_ADDRESS20_SIZE = 20;        // BTC 20-byte payload (hash160 / witness program)
    static constexpr uint32_t BTC_ADDRESS32_SIZE = 32;        // BTC 32-byte witness program (P2WSH/P2TR)

    // Full account address size for ZBC type: type (4) + pubkey (32) = 36 bytes
    static constexpr uint32_t ZBC_ACCOUNT_ADDRESS_SIZE = ACCOUNT_TYPE_SIZE + PUBLIC_KEY_SIZE;
    // Full account address size for ETH type: type (4) + address (20) = 24 bytes
    static constexpr uint32_t ETH_ACCOUNT_ADDRESS_SIZE = ACCOUNT_TYPE_SIZE + ETH_ADDRESS_SIZE;
    // Full account address size for BTC 20-byte payload: type (4) + payload (20) = 24 bytes
    static constexpr uint32_t BTC20_ACCOUNT_ADDRESS_SIZE = ACCOUNT_TYPE_SIZE + BTC_ADDRESS20_SIZE;
    // Full account address size for BTC 32-byte payload: type (4) + payload (32) = 36 bytes
    static constexpr uint32_t BTC32_ACCOUNT_ADDRESS_SIZE = ACCOUNT_TYPE_SIZE + BTC_ADDRESS32_SIZE;

    // ProofOfOwnership message size for ZBC: account_addr (36) + block_hash (32) + height (4) = 72
    static constexpr uint32_t ZBC_POOWN_MESSAGE_SIZE = ZBC_ACCOUNT_ADDRESS_SIZE + BLOCK_HASH_SIZE + HEIGHT_SIZE;

    // ProofOfOwnership total size for ZBC: message (72) + signature (64) = 136
    static constexpr uint32_t ZBC_POOWN_SIZE = ZBC_POOWN_MESSAGE_SIZE + SIGNATURE_SIZE;

    // Get transaction bytes for signing or storage
    // signed=false: returns bytes for signature verification (no signature included)
    // signed=true: returns complete transaction bytes (with signature)
    // This matches Go's GetTransactionBytes(transaction, sign bool)
    static Result<std::vector<uint8_t>> GetTransactionBytes(
        const model::Transaction& tx, bool include_signature);

    // Parse transaction bytes into Transaction struct
    // This matches Go's ParseTransactionBytes(transactionBytes, sign bool)
    static Result<model::Transaction> ParseTransactionBytes(
        const std::vector<uint8_t>& tx_bytes, bool has_signature);

    // Calculate transaction hash (SHA3-256 of complete transaction bytes with signature)
    static Result<std::vector<uint8_t>> CalculateTransactionHash(
        const model::Transaction& tx);

    // Calculate transaction ID from hash (first 8 bytes as int64)
    static int64_t GetTransactionID(const std::vector<uint8_t>& tx_hash);

    // ========================================================================
    // Signing digest (signing v2, 2026-09-08)
    // ========================================================================
    // What a transaction signer signs, and what the node verifies against, is NOT the bare
    // SHA3-256 of the unsigned bytes any more. It is
    //
    //     SHA3-256( "ZBC-TX" ‖ genesis_block_hash(32) ‖ unsigned_transaction_bytes )
    //
    // The genesis hash binds the signature to one chain: the same bytes signed for testnet no
    // longer verify on mainnet, devnet, or a parallel chain. The fixed tag separates transaction
    // signatures from every other thing a ZooBC key signs raw (proof-of-ownership, fee-vote
    // reveals, off-chain "prove you hold this key" messages), so no raw-signed blob can double as
    // a transaction digest. The wire format, the JSON API and the transaction hash (SHA3-256 of
    // unsigned bytes ‖ signature) are unchanged; nothing extra is stored on chain.
    //
    // Every signer moves together: node verifier, multisig participants, escrow co-signers, the
    // node's own node-signed types, the CLI tools, the web wallet, the signer extension, the
    // bridge keepers. Foreign carrier paths (a raw MetaMask / Phantom / Bitcoin transaction in
    // `message`) verify their native payload and are outside this rule.
    static constexpr const char* TX_SIGNING_TAG = "ZBC-TX";   // 6 bytes, no terminator

    // Digest over an explicit genesis hash (tools, tests, anything that signs for a chain it is
    // not itself running). `genesis_hash` must be 32 bytes.
    static Result<std::vector<uint8_t>> SigningDigest(
        const std::vector<uint8_t>& unsigned_tx_bytes,
        const std::vector<uint8_t>& genesis_hash);

    // Digest over the process-wide chain identity (chain::Identity). Fails — never falls back to
    // the unbound v1 digest — when the identity has not been recorded.
    static Result<std::vector<uint8_t>> SigningDigest(
        const std::vector<uint8_t>& unsigned_tx_bytes);

    // Serialize the transaction unsigned and return its signing digest (process-wide identity).
    static Result<std::vector<uint8_t>> SigningDigestOf(const model::Transaction& tx);

    // Build account address bytes with type prefix
    // Returns: [4 bytes account_type (little-endian)] + [32 bytes public_key]
    static std::vector<uint8_t> BuildAccountAddress(
        int32_t account_type, const std::vector<uint8_t>& public_key);

    // Build empty account address (for missing recipient)
    // Returns: [4 bytes ACCOUNT_TYPE_EMPTY (little-endian)]
    static std::vector<uint8_t> BuildEmptyAccountAddress();

    // Extract public key from account address (skip first 4 bytes of type)
    static std::vector<uint8_t> ExtractPublicKey(
        const std::vector<uint8_t>& account_address);

    // Extract account type from account address (first 4 bytes)
    static int32_t ExtractAccountType(
        const std::vector<uint8_t>& account_address);

    // Check if account address is empty type
    static bool IsEmptyAccountAddress(
        const std::vector<uint8_t>& account_address);

    // Reserve the bridge wrapped/stable-token namespace. A token symbol that is 4-5 chars
    // long and starts OR ends with 'Z' (case-insensitive) — ZBTC, ZUSD, ZETH, BTCZ, ZUSDT,
    // etc. — is protocol-reserved and may NOT be issued via a normal IssueToken transaction.
    // This blocks look-alike squatting (registering BTCZ to impersonate the official ZBTC).
    // Official wrapped/stable tokens are created by the bridge mint path, not user IssueToken.
    static bool IsReservedTokenSymbol(const std::string& symbol) {
        const size_t n = symbol.size();
        if (n < 4 || n > 5) return false;
        auto up = [](char c) { return static_cast<char>(std::toupper(static_cast<unsigned char>(c))); };
        return up(symbol.front()) == 'Z' || up(symbol.back()) == 'Z';
    }

    // Token symbol must be uppercase ASCII A-Z / 0-9, length 2-10. Forbidding lowercase +
    // non-ASCII kills homoglyph impersonation (e.g. a Cyrillic 'С' in "USDС") that an
    // exact-match blocklist alone can't catch.
    static bool HasValidTokenSymbolCharset(const std::string& symbol);

    // Well-known fiat / stablecoin / major-coin ticker that a normal IssueToken must NOT mint,
    // so a community token can't impersonate the real thing (a token literally named USDC/BTC).
    // Compiled default (v1); an on-chain registry editable by a foundation-authorized
    // UpdateReservedSymbols governance tx is v2 (see docs/MULTICHAIN_BRIDGE.md).
    static bool IsBlockedTokenSymbol(const std::string& symbol);

    // The well-known-ticker blocklist (single source of truth; surfaced via /blockchain/reserved-symbols).
    static const std::unordered_set<std::string>& BlockedTokenSymbols();

    // ========================================================================
    // Transaction Body Serialization (matching Go implementations)
    // Reference: originals/zoobc-core-develop/common/transaction/*.go
    // ========================================================================

    // SendZBC body: just Amount (8 bytes)
    // Go: common/transaction/sendZBC.go - GetBodyBytes/ParseBodyBytes
    static std::vector<uint8_t> GetSendZBCBodyBytes(int64_t amount);
    static Result<int64_t> ParseSendZBCBodyBytes(const std::vector<uint8_t>& body_bytes);

    // NodeRegistration body: NodePublicKey + AccountAddress + LockedBalance + POOWN
    // Go: common/transaction/nodeRegistration.go - GetBodyBytes/ParseBodyBytes
    static std::vector<uint8_t> GetNodeRegistrationBodyBytes(
        const std::vector<uint8_t>& node_public_key,
        const std::vector<uint8_t>& account_address,  // Full address with type prefix
        int64_t locked_balance,
        const std::vector<uint8_t>& proof_of_ownership);
    static Result<model::NodeRegistrationTransactionBody> ParseNodeRegistrationBodyBytes(
        const std::vector<uint8_t>& body_bytes);

    // UpdateNodeRegistration body: NodePublicKey + LockedBalance + POOWN
    // Go: common/transaction/nodeRegistrationUpdate.go - GetBodyBytes/ParseBodyBytes
    static std::vector<uint8_t> GetUpdateNodeRegistrationBodyBytes(
        const std::vector<uint8_t>& node_public_key,
        int64_t locked_balance,
        const std::vector<uint8_t>& proof_of_ownership);
    static Result<model::UpdateNodeRegistrationTransactionBody> ParseUpdateNodeRegistrationBodyBytes(
        const std::vector<uint8_t>& body_bytes);

    // ClaimNodeRegistration body: NodePublicKey + POOWN
    // Go: common/transaction/nodeRegistrationClaim.go - GetBodyBytes/ParseBodyBytes
    static std::vector<uint8_t> GetClaimNodeRegistrationBodyBytes(
        const std::vector<uint8_t>& node_public_key,
        const std::vector<uint8_t>& proof_of_ownership);
    static Result<model::ClaimNodeRegistrationTransactionBody> ParseClaimNodeRegistrationBodyBytes(
        const std::vector<uint8_t>& body_bytes);

    // RemoveNodeRegistration body: just NodePublicKey (32 bytes)
    // Go: common/transaction/removeNodeRegistration.go - GetBodyBytes/ParseBodyBytes
    static std::vector<uint8_t> GetRemoveNodeRegistrationBodyBytes(
        const std::vector<uint8_t>& node_public_key);
    static Result<model::RemoveNodeRegistrationTransactionBody> ParseRemoveNodeRegistrationBodyBytes(
        const std::vector<uint8_t>& body_bytes);

    // ApprovalEscrow body: Approval (4 bytes) + escrowed TransactionHash (32 bytes) = 36 bytes.
    // Was Approval + TransactionID (8 bytes) = 12 bytes (Go's EscrowApprovalBytesLength) until
    // 2026-09-08; see model::ApprovalEscrowTransactionBody for why the full hash is carried.
    static constexpr uint32_t APPROVAL_ESCROW_BODY_SIZE = 4 + 32;
    static std::vector<uint8_t> GetApprovalEscrowBodyBytes(
        model::EscrowApproval approval,
        const std::vector<uint8_t>& escrowed_transaction_hash);
    static Result<model::ApprovalEscrowTransactionBody> ParseApprovalEscrowBodyBytes(
        const std::vector<uint8_t>& body_bytes);

    // ========================================================================
    // Escrow Request Body Serialization (ZooBC extension)
    // Recipient-initiated escrow proposal
    // ========================================================================

    // EscrowRequest body:
    //   ProposedSender (36 bytes, account address)
    //   ProposedAmount (8 bytes)
    //   ApproverAddress (36 bytes, account address)
    //   Commission (8 bytes)
    //   Timeout (8 bytes)
    //   InstructionLength (4 bytes)
    //   Instruction (variable)
    //   Expiry (8 bytes)
    static std::vector<uint8_t> GetEscrowRequestBodyBytes(
        const model::EscrowRequestTransactionBody& body);
    static Result<model::EscrowRequestTransactionBody> ParseEscrowRequestBodyBytes(
        const std::vector<uint8_t>& body_bytes);

    // ========================================================================
    // Liquid Payment Body Serialization
    // Reference: originals/zoobc-core-develop/common/transaction/liquidPayment.go
    //            originals/zoobc-core-develop/common/transaction/liquidPaymentStop.go
    // ========================================================================

    // LiquidPayment body: Amount (8 bytes) + CompleteMinutes (8 bytes) = 16 bytes
    // Go: common/transaction/liquidPayment.go - GetBodyBytes/ParseBodyBytes
    // Go constant: Balance (8) + LiquidPaymentCompleteMinutesLength (8)
    static constexpr uint32_t LIQUID_PAYMENT_COMPLETE_MINUTES_SIZE = 8;

    static std::vector<uint8_t> GetLiquidPaymentBodyBytes(
        int64_t amount,
        uint64_t complete_minutes,
        int64_t token_id = 0);
    static Result<model::LiquidPaymentTransactionBody> ParseLiquidPaymentBodyBytes(
        const std::vector<uint8_t>& body_bytes);

    // LiquidPaymentStop body: TransactionID (8 bytes)
    // Go: common/transaction/liquidPaymentStop.go - GetBodyBytes/ParseBodyBytes
    // Go constant: TransactionID (8 bytes)
    static std::vector<uint8_t> GetLiquidPaymentStopBodyBytes(
        int64_t transaction_id);
    static Result<model::LiquidPaymentStopTransactionBody> ParseLiquidPaymentStopBodyBytes(
        const std::vector<uint8_t>& body_bytes);

    // ========================================================================
    // Escrow serialization for transactions
    // Reference: originals/zoobc-core-develop/common/transaction/transactionGeneral.go
    // ========================================================================

    // Serialize escrow data for transaction bytes
    // Structure: ApproverAddress (36) + Commission (8) + Timeout (8) + InstructionLen (4) + Instruction
    static std::vector<uint8_t> GetEscrowBytes(const model::Escrow& escrow);

    // Parse escrow data from transaction bytes
    // Returns escrow and updates offset to point after escrow data
    static Result<model::Escrow> ParseEscrowBytes(
        const std::vector<uint8_t>& bytes, size_t& offset);

    // Check if transaction has escrow (approver address is set)
    static bool HasEscrow(const model::Transaction& tx);

    // ========================================================================
    // ProofOfOwnership utilities
    // Reference: originals/zoobc-core-develop/common/util/proofOfOwnership.go
    // ========================================================================

    // Get size of proof of ownership based on account type
    // For ZBC: message (72) + signature (64) = 136 bytes
    static uint32_t GetProofOfOwnershipSize(int32_t account_type, bool with_signature);

    // Get proof of ownership message size based on account type
    // For ZBC: account_addr (36) + block_hash (32) + height (4) = 72 bytes
    static uint32_t GetProofOfOwnershipMessageSize(int32_t account_type);

    // Get public key length for account type (32 for ZBC)
    static uint32_t GetAccountPublicKeyLength(int32_t account_type);

    // Get signature length for account type
    // ZBC: 64 bytes (Ed25519), BTC: 32 bytes (ECDSA), ETH: 65 bytes (ECDSA + recovery)
    static uint32_t GetSignatureLength(int32_t account_type);

    // ========================================================================
    // SetupAccountDataset body: PropertyLen(4) + Property + ValueLen(4) + Value
    //   + SetterAccountAddress(36) + RecipientAccountAddress(36)
    // Go: common/transaction/setupAccountDataset.go - GetBodyBytes/ParseBodyBytes
    // ========================================================================
    static std::vector<uint8_t> GetSetupAccountDatasetBodyBytes(
        const std::string& property,
        const std::string& value,
        const std::vector<uint8_t>& setter_address,     // Full 36-byte address with type prefix
        const std::vector<uint8_t>& recipient_address);  // Full 36-byte address with type prefix
    static Result<model::SetupAccountDatasetTransactionBody> ParseSetupAccountDatasetBodyBytes(
        const std::vector<uint8_t>& body_bytes);

    // RemoveAccountDataset body: same format as SetupAccountDataset
    // Go: common/transaction/removeAccountDataset.go - GetBodyBytes/ParseBodyBytes
    static std::vector<uint8_t> GetRemoveAccountDatasetBodyBytes(
        const std::string& property,
        const std::string& value,
        const std::vector<uint8_t>& setter_address,
        const std::vector<uint8_t>& recipient_address);
    static Result<model::RemoveAccountDatasetTransactionBody> ParseRemoveAccountDatasetBodyBytes(
        const std::vector<uint8_t>& body_bytes);

    // FeeVoteCommitment body: VoteHash (32 bytes)
    // Go: common/transaction/feeVoteCommit.go - GetBodyBytes/ParseBodyBytes
    static std::vector<uint8_t> GetFeeVoteCommitBodyBytes(
        const std::vector<uint8_t>& vote_hash);
    static Result<model::FeeVoteCommitTransactionBody> ParseFeeVoteCommitBodyBytes(
        const std::vector<uint8_t>& body_bytes);

    // FeeVoteReveal body: FeeVoteInfo (44 bytes) + VoterSignature (64 bytes) = 108 bytes
    // FeeVoteInfo = RecentBlockHash(32) + RecentBlockHeight(4) + FeeVote(8) = 44
    // Go: common/transaction/feeVoteReveal.go - GetBodyBytes/ParseBodyBytes
    // The 44 FeeVoteInfo bytes = RecentBlockHash(32) ‖ RecentBlockHeight(4 LE) ‖ FeeVote(8 LE): the
    // message the voter signs (voter_signature = Ed25519 by the sender over exactly these bytes, Go
    // feeVoteReveal.go GetFeeVoteInfoBytes) and the prefix of the reveal body. One serializer for
    // signer (tools), body builder and verifier (validator), so they cannot drift.
    static std::vector<uint8_t> GetFeeVoteInfoBytes(const model::FeeVoteInfo& vote_info);
    static std::vector<uint8_t> GetFeeVoteRevealBodyBytes(
        const model::FeeVoteInfo& vote_info,
        const std::vector<uint8_t>& voter_signature);
    static Result<model::FeeVoteRevealTransactionBody> ParseFeeVoteRevealBodyBytes(
        const std::vector<uint8_t>& body_bytes);

    // ========================================================================
    // Byte conversion helpers (little-endian, matching Go binary.LittleEndian)
    // ========================================================================

    // Helper to write uint32 in little-endian
    static void WriteUint32LE(std::vector<uint8_t>& buffer, uint32_t value);

    // Helper to write uint64 in little-endian
    static void WriteUint64LE(std::vector<uint8_t>& buffer, uint64_t value);

    // Helper to write int32 in little-endian
    static void WriteInt32LE(std::vector<uint8_t>& buffer, int32_t value);

    // Helper to write int64 in little-endian
    static void WriteInt64LE(std::vector<uint8_t>& buffer, int64_t value);

    // Helper to read uint32 from little-endian bytes
    static uint32_t ReadUint32LE(const uint8_t* data);

    // Helper to read uint64 from little-endian bytes
    static uint64_t ReadUint64LE(const uint8_t* data);

    // Helper to read int32 from little-endian bytes
    static int32_t ReadInt32LE(const uint8_t* data);

    // Helper to read int64 from little-endian bytes
    static int64_t ReadInt64LE(const uint8_t* data);
};

}  // namespace util
}  // namespace zoobc

#endif  // ZOOBC_UTIL_TRANSACTION_UTIL_H
