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
    // Transaction versions. Version 1 is the original layout. Version 2 (rule `survival_field`) adds
    // one field: survival, u64 LE, written immediately after the fee and covered by the signature
    // like every other field. Nothing else differs. Version 1 stays valid at every height.
    static constexpr uint32_t TX_VERSION_LEGACY = 1;
    static constexpr uint32_t TX_VERSION_SURVIVAL = 2;
    // Version 3 (rule `tx_expiry_field`, 12 F3) adds one more field after survival: expiry, u32 LE
    // seconds (0 = the default hour, at most TRANSACTION_EXPIRY_CAP). Versions 1 and 2 stay valid.
    static constexpr uint32_t TX_VERSION_EXPIRY = 3;
    static constexpr uint32_t SURVIVAL_SIZE = 8;
    static constexpr uint32_t EXPIRY_SIZE = 4;
    // The seconds after tx.timestamp within which a block may carry the transaction: the stated
    // expiry for a version-3 transaction (capped), the hour for every other.
    static int64_t ExpiryWindow(const model::Transaction& tx);
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
    static constexpr uint32_t ETH_SIGNATURE_LENGTH = 65;      // ECDSA + recovery byte
    static constexpr uint32_t ESTONIA_EID_SIGNATURE_LENGTH = 96;   // Go's EstoniaEidSignatureLength (no verifier here)

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
    // With has_signature, the signature must end the bytes: anything after it is an error (E2, review 2026-11-07).
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

    // Forum #399: the sender of a PENDING transaction may ask a node to drop it. It proves it is
    // the sender by signing SHA3-256("ZBC-CANCEL" ‖ genesis_hash ‖ transaction_hash) with the key
    // of the transaction's sender account. Chain-bound like every other signature.
    static constexpr const char* CANCEL_SIGNING_TAG = "ZBC-CANCEL";
    static Result<std::vector<uint8_t>> CancelPendingDigest(const std::vector<uint8_t>& transaction_hash,
                                                           const std::vector<uint8_t>& genesis_hash);
    static Result<std::vector<uint8_t>> CancelPendingDigest(const std::vector<uint8_t>& transaction_hash);

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
    // Owner decision 4 (2026-10-30): a 32-byte address is a bare legacy ZBC key UNLESS its first four bytes are the
    // Cardano type (13): a Cardano account is 4-byte type + 28-byte blake2b-224 key hash, also 32 bytes. Every site that
    // used to judge "32 bytes = bare key" asks this instead, so a Cardano account is never re-typed as ZBC.
    static bool IsBareLegacyKey(const std::vector<uint8_t>& a) {
        return a.size() == 32 && !(a[0] == 13 && a[1] == 0 && a[2] == 0 && a[3] == 0);
    }
    // Rule typed_accounts_only (0.6.0): a bare 32-byte key is a NODE key, never an account. The one refusal text, and
    // whether the rule is in force for the newest block (a static helper has no block height; every chain built from
    // 0.6.0 has the rule at 0).
    static constexpr const char* kBareAccountRefused = "accounts are typed: a bare 32-byte key is not an account on this chain";
    static bool BareAccountsRefused();
    // The node key of a node's typed node-key account (00000000 || 32-byte node key), the account a node signs its
    // duties with; empty for any other account.
    static std::vector<uint8_t> NodeKeyOfAccount(const std::vector<uint8_t>& a) {
        if (a.size() == 36 && a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0) return std::vector<uint8_t>(a.begin() + 4, a.end());
        return {};
    }
    // ONE LIST (owner decisions 1, 2, 3, 7, 8 of 2026-10-30): the account types that can sign a transaction. Everything
    // the node verifies is here, P2SH (6) included (the BIP49 single-key form). Not here, so never a recipient of value,
    // an escrow approver, a node owner or a group member: Empty (2), Estonia eID (3, no verifier), BTC P2WSH (8, a
    // script hash), DataSet (10, a ZBS_ deposit address; ZBC may still finance it, see IsUnspendableRecipientType).
    // CreateSwapOffer's counterparty (0.6.0, ADDRESS-TYPES item 5): the body is give_token(8) give_amount(8)
    // want_token(8) want_amount(8) expiry(8), then nothing (an open offer) or u32 LE length + that many bytes of a
    // typed account (its 4-byte type first, so any kind fits: a 24-byte Ethereum address, a 32-byte Cardano one).
    // Before, the counterparty was a fixed 36 bytes at offset 40 and a shorter address silently made the offer open.
    // Returns false when the body has another shape; `counterparty` is empty for an open offer.
    static bool ParseSwapCounterparty(const std::vector<uint8_t>& body, std::vector<uint8_t>& counterparty) {
        counterparty.clear();
        if (body.size() == 40) return true;
        if (body.size() < 44) return false;
        const uint32_t n = static_cast<uint32_t>(body[40]) | (static_cast<uint32_t>(body[41]) << 8) |
                           (static_cast<uint32_t>(body[42]) << 16) | (static_cast<uint32_t>(body[43]) << 24);
        if (n < 4 || body.size() != 44 + static_cast<size_t>(n)) return false;
        counterparty.assign(body.begin() + 44, body.end());
        return true;
    }

    // Rule canonical_account_forms (0.6.1): the full-key form of an Ethereum or Tron account (type + 64-byte key) or of
    // a Bitcoin legacy, P2PKH or P2WPKH account (type + 33- or 65-byte key). AccountState stores it, but the
    // transaction bytes carry only the 20-byte form of these types (GetAccountPublicKeyLength), so no transaction can
    // ever be sent from it: money or a duty given to it is stranded. FullKeyFormRefused is the one check, asked
    // wherever a transaction names an account, with the block's height.
    static bool IsFullKeyAccountForm(const std::vector<uint8_t>& a) {
        if (a.size() < ACCOUNT_TYPE_SIZE) return false;
        const int32_t t = ReadInt32LE(a.data());
        const size_t n = a.size() - ACCOUNT_TYPE_SIZE;
        if (t == ACCOUNT_TYPE_ETH || t == ACCOUNT_TYPE_TRON) return n == 64;
        if (t == ACCOUNT_TYPE_BTC || t == ACCOUNT_TYPE_BTC_P2PKH || t == ACCOUNT_TYPE_BTC_P2WPKH) return n == 33 || n == 65;
        return false;
    }
    static bool FullKeyFormRefused(const std::vector<uint8_t>& a, uint32_t at_height);
    static constexpr const char* kFullKeyFormRefused =
        "a full-key account form (an Ethereum or Tron key, a Bitcoin key) is not an account: no transaction can be sent "
        "from it; name the 20-byte address (rule canonical_account_forms)";

    static bool IsSigningAccountType(int32_t t) {
        switch (t) {
            case ACCOUNT_TYPE_ZBC: case ACCOUNT_TYPE_BTC: case ACCOUNT_TYPE_ETH: case ACCOUNT_TYPE_BTC_P2PKH:
            case ACCOUNT_TYPE_BTC_P2SH: case ACCOUNT_TYPE_BTC_P2WPKH: case ACCOUNT_TYPE_BTC_P2TR:
            case ACCOUNT_TYPE_SOLANA: case ACCOUNT_TYPE_POLKADOT: case ACCOUNT_TYPE_CARDANO:
            case ACCOUNT_TYPE_RIPPLE: case ACCOUNT_TYPE_TRON: case ACCOUNT_TYPE_TEZOS:
                return true;
            default:
                return false;
        }
    }
    // The address form of the same question. A bare legacy key is a ZBC key (signs); anything shorter than a type is
    // nothing; otherwise the type decides.
    static bool IsNonSigningAccountAddress(const std::vector<uint8_t>& a) {
        if (IsBareLegacyKey(a)) return BareAccountsRefused();   // typed_accounts_only: a bare key is not an account
        if (a.size() < ACCOUNT_TYPE_SIZE) return true;
        return !IsSigningAccountType(ReadInt32LE(a.data()));
    }
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

    // Token NAME shape (consensus rule; admission and execution both refuse). The name is a label a
    // human reads in a list, so it is held to what a label needs and nothing a renderer could take
    // for markup or a spoofer could hide in. A token named "<img src=x onerror=alert(1)>" was
    // issued on testnet on 2026-09-19 and ran in a wallet that rendered its list unescaped.
    // Escaping stays every consumer's job (Rule A of DESIGN-untrusted-chain-data); this removes
    // the shapes that have no legitimate use in a name:
    //   - 1..64 bytes of well-formed UTF-8 (no overlongs, no surrogates, nothing past U+10FFFF)
    //   - none of  < > " ' `  (the HTML/attribute metacharacters)
    //   - no control or format character: U+0000-001F, U+007F-009F, U+00AD, U+061C, U+180E,
    //     U+200B-200F (zero-widths, joiners), U+2028-202E (line/paragraph separators, bidi
    //     embeddings and overrides), U+2060-2064, U+2066-2069 (bidi isolates), U+FEFF,
    //     U+FFF9-FFFB, U+E0000-E007F (tags)
    //   - no space other than U+0020 (NBSP and the U+2000 block make look-alike names)
    //   - no leading or trailing space
    // Byte-level rules on a tiny decoder, on purpose: no normalisation, no Unicode tables, nothing
    // two implementations could disagree about. `why` receives the first rule violated.
    //
    // `refuse_address` (rule token_name_not_address, owner decision 11 of 2026-10-30, devnet test D21): a
    // name that the node's own address parser reads as an address of ANY account kind is refused too:
    // crypto::DecodeAddress (the decoder behind the API's address parameters and the tools: ZBC_/ZBS_ text
    // with any separators or none, any case; Ethereum 0x; every Bitcoin form; Solana; Polkadot; Cardano;
    // Ripple; Tron; Tezos; a bare 64-hex key) or the raw typed account in hex (72 hex digits, 0x optional,
    // the 36-byte form the API also takes). A wallet that parses a token name could otherwise read it as an
    // address. Callers pass RuleClock::Active("token_name_not_address", height).
    static bool HasValidTokenNameShape(const std::string& name, std::string* why = nullptr, bool refuse_address = false);
    static constexpr size_t kMaxTokenNameBytes = 64;

    /**
     * Registry domain charset: [A-Za-z0-9.-], length 1..256.
     * A registry domain is rendered as text and often as the label of a link, so it must not be
     * able to carry markup, quotes or whitespace.
     */
    static bool HasValidRegistryDomain(const std::string& domain);

    /**
     * Reserved dataset namespace `tokenicon:` — the value must already BE a picture: PNG or WebP
     * by magic bytes, declared dimensions inside 512x512, within the 4096-byte dataset cap.
     * On success sets out_media to "image/png" or "image/webp".
     *
     * A picture format has no instructions in it, so there is nothing to execute however a
     * consumer displays it. That is why the rule is "no SVG" and not "sanitised SVG". Magic bytes
     * and header fields only: no image decoder and no XML parser, because both are a classic source
     * of remote code execution and neither belongs inside consensus software. It is also why this
     * can BE a consensus rule — a handful of byte comparisons that every implementation agrees on,
     * where a parser plus a policy would eventually disagree, and disagreement is a fork.
     *
     * Used by the SetupAccountDataset validator (admission) and by the icon endpoint (serving), so
     * that what is storable and what is servable can never drift apart.
     */
    static bool TokenIconMediaType(const std::string& value, std::string& out_media);

    /**
     * Invoice shape for the reserved `inv:` dataset namespace (forum #413, rule invoice_namespace_shape).
     * An invoice is a JSON object a payer's wallet does arithmetic on. The node knows no schema and
     * wants none: it refuses what no invoice may carry — a value that is not a JSON object, and any
     * negative number anywhere in it. A SAX walk over the bytes, no tree, so the only consensus
     * surface is the JSON grammar itself. On refusal out_why says which of the three it was.
     */
    static bool InvoiceValueShape(const std::string& value, std::string& out_why);

    /**
     * Registry URL shape: must begin "https://" (or "http://" when allow_http, which a devnet
     * genesis may switch on), and must contain no control character, no whitespace and none of
     * " ' < > `.
     *
     * The point is that a consumer rendering this as a link is then safe BY CONSTRUCTION, rather
     * than having to invent a guard of its own. A javascript: URL is storable today and a client
     * that renders it as an href executes it. Pure byte comparisons, no parser, so every
     * implementation agrees — which is what makes it safe to run as a consensus rule.
     */
    static bool HasValidRegistryUrl(const std::string& url, bool allow_http);

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
        const std::vector<uint8_t>& proof_of_ownership,
        const std::vector<uint8_t>& new_node_public_key = {});   // rule node_key_rotation (20 F4)
    // EquivocationReport (type 60, 11 F6 (c) T2)
    static std::vector<uint8_t> GetEquivocationReportBodyBytes(const std::vector<uint8_t>& header1, const std::vector<uint8_t>& signature1,
                                                               const std::vector<uint8_t>& header2, const std::vector<uint8_t>& signature2);
    static Result<model::EquivocationReportTransactionBody> ParseEquivocationReportBodyBytes(const std::vector<uint8_t>& body_bytes);
    // SpineEquivocationReport (type 62, rule spine_equivocation_report)
    static std::vector<uint8_t> GetSpineEquivocationReportBodyBytes(const model::SpineEquivocationReportTransactionBody& body);
    static Result<model::SpineEquivocationReportTransactionBody> ParseSpineEquivocationReportBodyBytes(const std::vector<uint8_t>& body_bytes);
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

    // Get proof of ownership message size based on account type. The proof's signature is always the node key's
    // 64-byte ed25519 one, whatever the owner's type (TransactionValidator::ParseRawProofOfOwnership).
    // For ZBC: account_addr (36) + block_hash (32) + height (4) = 72 bytes
    static uint32_t GetProofOfOwnershipMessageSize(int32_t account_type);

    // Get public key length for account type (32 for ZBC)
    static uint32_t GetAccountPublicKeyLength(int32_t account_type);

    // The envelope signature of a sender of this type (the last field of a signed transaction), exactly as its
    // verifier (crypto::Signature::VerifySignature) takes it:
    //   64  ed25519 (ZBC, Solana), sr25519 (Polkadot), bare BIP-340 Schnorr (Taproot)
    //   65  secp256k1 r‖s‖v, the key recovered against the Keccak address (Ethereum, Tron)
    //   98  [32,0] ‖ 32-byte ed25519 key ‖ 64-byte signature, the address being a key hash (Cardano, Tezos)
    //   0   no one length: [2-byte LE key length][33- or 65-byte secp256k1 key][64-byte compact ECDSA], the
    //       address being a HASH160 (Bitcoin legacy, P2PKH, P2SH, P2WPKH, Ripple), so 99 or 131 bytes; also
    //       P2WSH, a script hash that cannot sign
    //   96  Estonia eID (Go's length; nothing verifies it, so it cannot send)
    // Empty, DataSet and unknown types, none of which can send, get 64.
    static uint32_t GetSignatureLength(int32_t account_type);

    // Whether ParseTransactionBytes takes every byte left as the signature of a sender of this type rather than
    // GetSignatureLength bytes: the carried-key types above (length 0), and Taproot, which always parsed so (its
    // verifier refuses anything but 64, so a longer one fails there instead of being cut).
    static bool SignatureRunsToEnd(int32_t account_type);

    // ========================================================================
    // SetupAccountDataset body: PropertyLen(4) + Property + ValueLen(4) + Value, exactly what the parser reads
    // (0.6.0: the setter and recipient accounts the Go layout appended, 72 bytes nobody read, are gone; the setter is
    // the sender and the recipient the envelope's).
    // ========================================================================
    static std::vector<uint8_t> GetSetupAccountDatasetBodyBytes(
        const std::string& property,
        const std::string& value);
    static Result<model::SetupAccountDatasetTransactionBody> ParseSetupAccountDatasetBodyBytes(
        const std::vector<uint8_t>& body_bytes);

    // RemoveAccountDataset body: same format as SetupAccountDataset
    // Go: common/transaction/removeAccountDataset.go - GetBodyBytes/ParseBodyBytes
    static std::vector<uint8_t> GetRemoveAccountDatasetBodyBytes(
        const std::string& property,
        const std::string& value);
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
