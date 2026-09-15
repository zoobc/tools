// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/util/transaction_util.h"
#include "zoobc/crypto/hash.h"
#include "zoobc/common/chain_identity.h"
#include <cstring>
#include <cctype>
#include <string>
#include <unordered_set>

namespace zoobc {
namespace util {

// Helper functions implementation
void TransactionUtil::WriteUint32LE(std::vector<uint8_t>& buffer, uint32_t value) {
    buffer.push_back(static_cast<uint8_t>(value & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

void TransactionUtil::WriteUint64LE(std::vector<uint8_t>& buffer, uint64_t value) {
    for (int i = 0; i < 8; i++) {
        buffer.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

void TransactionUtil::WriteInt32LE(std::vector<uint8_t>& buffer, int32_t value) {
    WriteUint32LE(buffer, static_cast<uint32_t>(value));
}

void TransactionUtil::WriteInt64LE(std::vector<uint8_t>& buffer, int64_t value) {
    WriteUint64LE(buffer, static_cast<uint64_t>(value));
}

uint32_t TransactionUtil::ReadUint32LE(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
}

uint64_t TransactionUtil::ReadUint64LE(const uint8_t* data) {
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result |= static_cast<uint64_t>(data[i]) << (i * 8);
    }
    return result;
}

int32_t TransactionUtil::ReadInt32LE(const uint8_t* data) {
    return static_cast<int32_t>(ReadUint32LE(data));
}

int64_t TransactionUtil::ReadInt64LE(const uint8_t* data) {
    return static_cast<int64_t>(ReadUint64LE(data));
}

std::vector<uint8_t> TransactionUtil::BuildAccountAddress(
    int32_t account_type, const std::vector<uint8_t>& public_key) {
    std::vector<uint8_t> address;
    address.reserve(ACCOUNT_TYPE_SIZE + public_key.size());

    // Write account type (4 bytes, little-endian)
    WriteInt32LE(address, account_type);

    // Write public key
    address.insert(address.end(), public_key.begin(), public_key.end());

    return address;
}

std::vector<uint8_t> TransactionUtil::BuildEmptyAccountAddress() {
    std::vector<uint8_t> address;
    // Write empty account type (4 bytes, little-endian)
    WriteInt32LE(address, ACCOUNT_TYPE_EMPTY);
    return address;
}

std::vector<uint8_t> TransactionUtil::ExtractPublicKey(
    const std::vector<uint8_t>& account_address) {
    if (account_address.size() <= ACCOUNT_TYPE_SIZE) {
        return {};
    }
    return std::vector<uint8_t>(
        account_address.begin() + ACCOUNT_TYPE_SIZE,
        account_address.end());
}

int32_t TransactionUtil::ExtractAccountType(
    const std::vector<uint8_t>& account_address) {
    if (account_address.size() < ACCOUNT_TYPE_SIZE) {
        return ACCOUNT_TYPE_EMPTY;
    }
    return ReadInt32LE(account_address.data());
}

bool TransactionUtil::IsEmptyAccountAddress(
    const std::vector<uint8_t>& account_address) {
    if (account_address.empty()) {
        return true;
    }
    if (account_address.size() < ACCOUNT_TYPE_SIZE) {
        return true;
    }
    return ExtractAccountType(account_address) == ACCOUNT_TYPE_EMPTY;
}

bool TransactionUtil::HasValidTokenSymbolCharset(const std::string& symbol) {
    const size_t n = symbol.size();
    if (n < 2 || n > 10) return false;
    for (char c : symbol) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        if (!ok) return false;
    }
    return true;
}

const std::unordered_set<std::string>& TransactionUtil::BlockedTokenSymbols() {
    // COMPILED DEFAULT (v1): identical on every node -> consensus-consistent; edit this list +
    // rebuild + relaunch to change it. v2 promotes it to an on-chain registry editable live by a
    // foundation-authorized UpdateReservedSymbols tx (see docs/MULTICHAIN_BRIDGE.md). Single source
    // of truth; also surfaced read-only via GET /blockchain/reserved-symbols so wallets validate
    // client-side without round-tripping a guaranteed error.
    static const std::unordered_set<std::string> kBlocked = {
        // fiat (ISO 4217)
        "USD","EUR","CNY","CNH","JPY","GBP","CHF","AUD","CAD","HKD","SGD","KRW","INR","BRL","RUB","ZAR","MXN",
        // stablecoins
        "USDT","USDC","DAI","BUSD","TUSD","USDP","GUSD","USDD","FRAX","PYUSD","FDUSD","USDE","USDS","LUSD",
        "EURC","EURT","EUROC","USTC",
        // major coins
        "BTC","ETH","BNB","SOL","XRP","ADA","DOGE","TRX","DOT","MATIC","POL","LTC","BCH","AVAX","SHIB","LINK",
        "XLM","ATOM","XMR","ETC","XTZ","FIL","HBAR","ICP","APT","NEAR","ARB","OP","UNI","AAVE","MKR","ALGO",
        "VET","GRT","TON","SUI","SEI","TIA","INJ","RUNE","KAS","LDO","CRV",
    };
    return kBlocked;
}

bool TransactionUtil::IsBlockedTokenSymbol(const std::string& symbol) {
    // Matched case-insensitively, though HasValidTokenSymbolCharset already forces uppercase ASCII.
    std::string up;
    up.reserve(symbol.size());
    for (char c : symbol) up.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    return BlockedTokenSymbols().count(up) > 0;
}

Result<std::vector<uint8_t>> TransactionUtil::GetTransactionBytes(
    const model::Transaction& tx, bool include_signature) {

    std::vector<uint8_t> buffer;

    // Reserve estimated space
    size_t estimated_size = TRANSACTION_TYPE_SIZE + TRANSACTION_VERSION_SIZE +
                            TIMESTAMP_SIZE + (ACCOUNT_TYPE_SIZE + PUBLIC_KEY_SIZE) * 2 +
                            FEE_SIZE + BODY_LENGTH_SIZE + tx.transaction_body_bytes.size() +
                            ACCOUNT_TYPE_SIZE + MESSAGE_LENGTH_SIZE;
    if (include_signature) {
        estimated_size += SIGNATURE_SIZE;
    }
    buffer.reserve(estimated_size);

    // 1. Transaction Type (4 bytes, little-endian)
    // Go: buffer.Write(util.ConvertUint32ToBytes(transaction.TransactionType))
    WriteUint32LE(buffer, static_cast<uint32_t>(tx.transaction_type));

    // 2. Version (1 byte only!)
    // Go: buffer.Write(util.ConvertUint32ToBytes(transaction.Version)[:constant.TransactionVersion])
    // Note: Go writes first byte of uint32
    buffer.push_back(static_cast<uint8_t>(tx.version & 0xFF));

    // 3. Timestamp (8 bytes, little-endian)
    // Go: buffer.Write(util.ConvertUint64ToBytes(uint64(transaction.Timestamp)))
    WriteUint64LE(buffer, static_cast<uint64_t>(tx.timestamp));

    // 4. Sender Account Address
    // Address formats:
    // - 32 bytes: legacy ZBC pubkey (add type prefix)
    // - 24+ bytes with type prefix: ETH (24), BTC (24 or 37), ZBC (36), etc.
    // Go: buffer.Write(transaction.SenderAccountAddress)
    if (tx.sender_account_address.size() == PUBLIC_KEY_SIZE) {
        // If just public key (32 bytes), add ZBC account type prefix
        WriteInt32LE(buffer, ACCOUNT_TYPE_ZBC);
        buffer.insert(buffer.end(),
                      tx.sender_account_address.begin(),
                      tx.sender_account_address.end());
    } else if (tx.sender_account_address.size() >= ACCOUNT_TYPE_SIZE + ETH_ADDRESS_SIZE) {
        // Already has type prefix (minimum 24 bytes = 4 type + 20 ETH address)
        buffer.insert(buffer.end(),
                      tx.sender_account_address.begin(),
                      tx.sender_account_address.end());
    } else if (!tx.sender_account_address.empty()) {
        return Error{ErrorCode::ValidationError,
                     "Invalid sender account address size"};
    }

    // 5. Recipient Account Address
    // Go handles this with EmptyAccountType if recipient is nil/empty
    if (tx.recipient_account_address.empty() ||
        IsEmptyAccountAddress(tx.recipient_account_address)) {
        // Write empty account type (4 bytes)
        WriteInt32LE(buffer, ACCOUNT_TYPE_EMPTY);
    } else if (tx.recipient_account_address.size() == PUBLIC_KEY_SIZE) {
        // If just public key (32 bytes), add ZBC account type prefix
        WriteInt32LE(buffer, ACCOUNT_TYPE_ZBC);
        buffer.insert(buffer.end(),
                      tx.recipient_account_address.begin(),
                      tx.recipient_account_address.end());
    } else if (tx.recipient_account_address.size() >= ACCOUNT_TYPE_SIZE + ETH_ADDRESS_SIZE) {
        // Already has type prefix (minimum 24 bytes = 4 type + 20 ETH address)
        buffer.insert(buffer.end(),
                      tx.recipient_account_address.begin(),
                      tx.recipient_account_address.end());
    } else {
        return Error{ErrorCode::ValidationError,
                     "Invalid recipient account address size"};
    }

    // 6. Fee (8 bytes, little-endian)
    // Go: buffer.Write(util.ConvertUint64ToBytes(uint64(transaction.Fee)))
    WriteUint64LE(buffer, static_cast<uint64_t>(tx.fee));

    // 7. Transaction Body Length (4 bytes, little-endian)
    // Go: buffer.Write(util.ConvertUint32ToBytes(transaction.TransactionBodyLength))
    uint32_t body_length = static_cast<uint32_t>(tx.transaction_body_bytes.size());
    WriteUint32LE(buffer, body_length);

    // 8. Transaction Body Bytes
    // Go: buffer.Write(transaction.TransactionBodyBytes)
    buffer.insert(buffer.end(),
                  tx.transaction_body_bytes.begin(),
                  tx.transaction_body_bytes.end());

    // 9. Escrow Part (if present, or empty account type if not)
    // Go code:
    //   if transaction.GetEscrow() != nil && transaction.GetEscrow().GetApproverAddress() != nil {
    //       buffer.Write(transaction.GetEscrow().GetApproverAddress())
    //       buffer.Write(util.ConvertUint64ToBytes(uint64(transaction.GetEscrow().GetCommission())))
    //       buffer.Write(util.ConvertUint64ToBytes(uint64(transaction.GetEscrow().GetTimeout())))
    //       buffer.Write(util.ConvertUint32ToBytes(uint32(len([]byte(transaction.GetEscrow().GetInstruction())))))
    //       buffer.Write([]byte(transaction.GetEscrow().GetInstruction()))
    //   } else {
    //       emptyAccAddr := BuildEmptyAccountAddress()
    //       buffer.Write(emptyAccAddr)
    //   }
    if (HasEscrow(tx)) {
        auto escrow_bytes = GetEscrowBytes(tx.escrow.value());
        buffer.insert(buffer.end(), escrow_bytes.begin(), escrow_bytes.end());
    } else {
        // Write empty account type for approver (no escrow)
        WriteInt32LE(buffer, ACCOUNT_TYPE_EMPTY);
    }

    // 10. Message (4 bytes length + message bytes)
    // Go: msgLength := len(transaction.GetMessage())
    //     buffer.Write(util.ConvertUint32ToBytes(uint32(msgLength)))
    //     if msgLength > 0 { buffer.Write(transaction.GetMessage()) }
    uint32_t message_length = static_cast<uint32_t>(tx.message.size());
    WriteUint32LE(buffer, message_length);
    if (message_length > 0) {
        buffer.insert(buffer.end(), tx.message.begin(), tx.message.end());
    }

    // 11. Signature (if requested)
    // Go: if signed { buffer.Write(transaction.Signature) }
    if (include_signature) {
        if (tx.signature.empty()) {
            return Error{ErrorCode::ValidationError,
                         "Signature required but not present"};
        }
        buffer.insert(buffer.end(), tx.signature.begin(), tx.signature.end());
    }

    return buffer;
}

Result<model::Transaction> TransactionUtil::ParseTransactionBytes(
    const std::vector<uint8_t>& tx_bytes, bool has_signature) {

    model::Transaction tx;
    size_t offset = 0;

    // Minimum size check
    size_t min_size = TRANSACTION_TYPE_SIZE + TRANSACTION_VERSION_SIZE +
                      TIMESTAMP_SIZE + ACCOUNT_TYPE_SIZE + FEE_SIZE + BODY_LENGTH_SIZE;
    if (tx_bytes.size() < min_size) {
        return Error{ErrorCode::ValidationError, "Transaction bytes too short"};
    }

    // 1. Transaction Type (4 bytes)
    tx.transaction_type = static_cast<TransactionType>(
        ReadUint32LE(tx_bytes.data() + offset));
    offset += TRANSACTION_TYPE_SIZE;

    // 2. Version (1 byte)
    tx.version = tx_bytes[offset];
    offset += TRANSACTION_VERSION_SIZE;

    // 3. Timestamp (8 bytes)
    tx.timestamp = ReadInt64LE(tx_bytes.data() + offset);
    offset += TIMESTAMP_SIZE;

    // 4. Sender Account Address (type prefix + public key)
    // Go stores full address with type prefix, we must do the same for hash compatibility
    if (offset + ACCOUNT_TYPE_SIZE > tx_bytes.size()) {
        return Error{ErrorCode::ValidationError, "Unexpected end of bytes (sender type)"};
    }
    int32_t sender_type = ReadInt32LE(tx_bytes.data() + offset);

    if (sender_type != ACCOUNT_TYPE_EMPTY) {
        // Get public key length based on account type
        uint32_t sender_pubkey_len = GetAccountPublicKeyLength(sender_type);
        uint32_t sender_addr_size = ACCOUNT_TYPE_SIZE + sender_pubkey_len;

        if (offset + sender_addr_size > tx_bytes.size()) {
            return Error{ErrorCode::ValidationError, "Unexpected end of bytes (sender address)"};
        }
        // Store FULL address including type prefix (matches Go implementation)
        tx.sender_account_address.assign(
            tx_bytes.begin() + offset,
            tx_bytes.begin() + offset + sender_addr_size);
        offset += sender_addr_size;
    } else {
        // Empty account type - just advance past the type marker
        offset += ACCOUNT_TYPE_SIZE;
    }

    // 5. Recipient Account Address (type prefix + public key)
    if (offset + ACCOUNT_TYPE_SIZE > tx_bytes.size()) {
        return Error{ErrorCode::ValidationError, "Unexpected end of bytes (recipient type)"};
    }
    int32_t recipient_type = ReadInt32LE(tx_bytes.data() + offset);

    if (recipient_type != ACCOUNT_TYPE_EMPTY) {
        // Get public key length based on account type
        uint32_t recipient_pubkey_len = GetAccountPublicKeyLength(recipient_type);
        uint32_t recipient_addr_size = ACCOUNT_TYPE_SIZE + recipient_pubkey_len;

        if (offset + recipient_addr_size > tx_bytes.size()) {
            return Error{ErrorCode::ValidationError, "Unexpected end of bytes (recipient address)"};
        }
        // Store FULL address including type prefix (matches Go implementation)
        tx.recipient_account_address.assign(
            tx_bytes.begin() + offset,
            tx_bytes.begin() + offset + recipient_addr_size);
        offset += recipient_addr_size;
    } else {
        // Empty account type - just advance past the type marker
        offset += ACCOUNT_TYPE_SIZE;
    }

    // 6. Fee (8 bytes)
    if (offset + FEE_SIZE > tx_bytes.size()) {
        return Error{ErrorCode::ValidationError, "Unexpected end of bytes (fee)"};
    }
    tx.fee = ReadInt64LE(tx_bytes.data() + offset);
    offset += FEE_SIZE;

    // 7. Body Length (4 bytes)
    if (offset + BODY_LENGTH_SIZE > tx_bytes.size()) {
        return Error{ErrorCode::ValidationError, "Unexpected end of bytes (body length)"};
    }
    tx.transaction_body_length = ReadUint32LE(tx_bytes.data() + offset);
    offset += BODY_LENGTH_SIZE;

    // 8. Body Bytes
    if (offset + tx.transaction_body_length > tx_bytes.size()) {
        return Error{ErrorCode::ValidationError, "Unexpected end of bytes (body)"};
    }
    tx.transaction_body_bytes.assign(
        tx_bytes.begin() + offset,
        tx_bytes.begin() + offset + tx.transaction_body_length);
    offset += tx.transaction_body_length;

    // 9. Escrow - parse if present
    // Check the approver account type first to see if escrow data exists
    auto escrow_result = ParseEscrowBytes(tx_bytes, offset);
    if (escrow_result.IsOk()) {
        // Escrow data was successfully parsed
        tx.escrow = escrow_result.Value();
    }
    // If escrow_result is NotFound, offset was already advanced past the empty account type
    // If it's another error, we ignore it and continue (malformed escrow data)

    // 10. Message
    if (offset + MESSAGE_LENGTH_SIZE > tx_bytes.size()) {
        return Error{ErrorCode::ValidationError, "Unexpected end of bytes (message length)"};
    }
    uint32_t message_length = ReadUint32LE(tx_bytes.data() + offset);
    offset += MESSAGE_LENGTH_SIZE;

    if (message_length > 0) {
        if (offset + message_length > tx_bytes.size()) {
            return Error{ErrorCode::ValidationError, "Unexpected end of bytes (message)"};
        }
        tx.message.assign(
            tx_bytes.begin() + offset,
            tx_bytes.begin() + offset + message_length);
        offset += message_length;
    }

    // 11. Signature (if present)
    // Go: signatureLength := senderAccType.GetSignatureLength()
    // The signature length depends on the sender account type
    if (has_signature) {
        // Get sender account type from the stored address (first 4 bytes)
        int32_t sender_account_type = ACCOUNT_TYPE_ZBC;  // Default to ZBC
        if (tx.sender_account_address.size() >= ACCOUNT_TYPE_SIZE) {
            sender_account_type = ReadInt32LE(tx.sender_account_address.data());
        }
        // Bitcoin signatures are VARIABLE length: [2B pubkey_len][pubkey][ECDSA sig]
        // (e.g. 2+33+64 = 99 for a compressed key + compact sig). A fixed GetSignatureLength()
        // truncates them, mangling the round-trip (serialize at submit -> re-parse on mempool
        // admission), so BTC-signed txs were silently dropped before mining. The signature is the
        // final envelope field, so for BTC types it occupies all remaining bytes.
        bool is_btc_sender =
            sender_account_type == ACCOUNT_TYPE_BTC ||
            sender_account_type == ACCOUNT_TYPE_BTC_P2PKH ||
            sender_account_type == ACCOUNT_TYPE_BTC_P2SH ||
            sender_account_type == ACCOUNT_TYPE_BTC_P2WPKH ||
            sender_account_type == ACCOUNT_TYPE_BTC_P2WSH ||
            sender_account_type == ACCOUNT_TYPE_BTC_P2TR;
        uint32_t sig_length = is_btc_sender
            ? (offset <= tx_bytes.size() ? static_cast<uint32_t>(tx_bytes.size() - offset) : 0u)
            : GetSignatureLength(sender_account_type);

        if (offset + sig_length > tx_bytes.size()) {
            return Error{ErrorCode::ValidationError, "Unexpected end of bytes (signature)"};
        }
        tx.signature.assign(
            tx_bytes.begin() + offset,
            tx_bytes.begin() + offset + sig_length);
        offset += sig_length;
    }

    // Compute and attach TransactionHash and Transaction ID (Go-compatible behavior)
    // Go: transactionHash := sha3.Sum256(transactionBytes)
    //     txID, _ := u.GetTransactionID(transactionHash[:])
    auto hash_result = crypto::Hash::SHA3_256(tx_bytes);
    if (hash_result.IsErr()) {
        return Error{hash_result.GetError()};
    }
    tx.transaction_hash = hash_result.Value();
    tx.id = GetTransactionID(tx.transaction_hash);

    return tx;
}

Result<std::vector<uint8_t>> TransactionUtil::CalculateTransactionHash(
    const model::Transaction& tx) {

    // Get complete transaction bytes with signature
    auto bytes_result = GetTransactionBytes(tx, true);
    if (bytes_result.IsErr()) {
        return Error{bytes_result.GetError()};
    }

    // Hash with SHA3-256
    return crypto::Hash::SHA3_256(bytes_result.Value());
}

int64_t TransactionUtil::GetTransactionID(const std::vector<uint8_t>& tx_hash) {
    if (tx_hash.size() < 8) {
        return -1;
    }
    // First 8 bytes as little-endian int64
    return ReadInt64LE(tx_hash.data());
}

// ============================================================================
// Signing digest (signing v2) — see the header for the rule and the reasons
// ============================================================================

Result<std::vector<uint8_t>> TransactionUtil::SigningDigest(
    const std::vector<uint8_t>& unsigned_tx_bytes,
    const std::vector<uint8_t>& genesis_hash) {
    if (genesis_hash.size() != BLOCK_HASH_SIZE) {
        return Error{ErrorCode::InvalidArgument,
                     "Signing digest needs a 32-byte genesis hash, got " +
                         std::to_string(genesis_hash.size())};
    }
    const size_t tag_len = std::strlen(TX_SIGNING_TAG);
    std::vector<uint8_t> preimage;
    preimage.reserve(tag_len + genesis_hash.size() + unsigned_tx_bytes.size());
    preimage.insert(preimage.end(), TX_SIGNING_TAG, TX_SIGNING_TAG + tag_len);
    preimage.insert(preimage.end(), genesis_hash.begin(), genesis_hash.end());
    preimage.insert(preimage.end(), unsigned_tx_bytes.begin(), unsigned_tx_bytes.end());
    return crypto::Hash::SHA3_256(preimage);
}

Result<std::vector<uint8_t>> TransactionUtil::SigningDigest(
    const std::vector<uint8_t>& unsigned_tx_bytes) {
    if (!chain::Identity::IsSet()) {
        // Refusing is the point: an unbound fallback here would quietly accept a signature made
        // for another chain, which is exactly the replay this digest exists to prevent.
        return Error{ErrorCode::Internal,
                     "Chain identity not initialised: genesis hash unknown, cannot compute the "
                     "transaction signing digest"};
    }
    return SigningDigest(unsigned_tx_bytes, chain::Identity::GenesisHash());
}

Result<std::vector<uint8_t>> TransactionUtil::SigningDigestOf(const model::Transaction& tx) {
    auto unsigned_bytes = GetTransactionBytes(tx, false);
    if (unsigned_bytes.IsErr()) return Error{unsigned_bytes.GetError()};
    return SigningDigest(unsigned_bytes.Value());
}

// ============================================================================
// ProofOfOwnership utilities
// Reference: originals/zoobc-core-develop/common/util/proofOfOwnership.go
// ============================================================================

uint32_t TransactionUtil::GetAccountPublicKeyLength(int32_t account_type) {
    // Go: common/accounttype/*.go GetAccountPublicKeyLength()
    // Different account types may have different public key sizes
    switch (account_type) {
        case ACCOUNT_TYPE_ZBC:
            return PUBLIC_KEY_SIZE;  // 32 bytes (Ed25519)
        case ACCOUNT_TYPE_BTC:
        case ACCOUNT_TYPE_BTC_P2PKH:
        case ACCOUNT_TYPE_BTC_P2SH:
        case ACCOUNT_TYPE_BTC_P2WPKH:
            return BTC_ADDRESS20_SIZE;  // 20 bytes
        case ACCOUNT_TYPE_BTC_P2WSH:
        case ACCOUNT_TYPE_BTC_P2TR:
            return BTC_ADDRESS32_SIZE;  // 32 bytes
        case ACCOUNT_TYPE_ETH:
            return ETH_ADDRESS_SIZE;  // 20 bytes (ETH address)
        case ACCOUNT_TYPE_ESTONIA_EID:
            return PUBLIC_KEY_SIZE;  // 32 bytes
        case ACCOUNT_TYPE_SOLANA:
        case ACCOUNT_TYPE_POLKADOT:
            return PUBLIC_KEY_SIZE;  // 32 bytes (ed25519 pubkey / Polkadot AccountId)
        // Cardano is a REAL Cardano enterprise address: addr1… over [0x61 || blake2b-224(pubkey)].
        // The account carries the 28-byte hash, the key rides in the signature (like Tezos), so a
        // Cardano user's own address is their ZooBC account (owner decision, 2026-09-04).
        case ACCOUNT_TYPE_CARDANO:
            return CARDANO_KEYHASH_SIZE;  // 28 bytes
        // Tezos carries a 20-byte KEY HASH, not the key: a tz1 address is
        // base58check(0x06a19f || blake2b-160(pubkey)). It used to sit in the 32-byte case above,
        // which is the same defect that hit Ripple and Tron below: ParseTransactionBytes would
        // over-read 12 bytes past the address and take the fee and body-length fields with it, so
        // no tz1 transaction could be decoded at all. The key cannot be recovered from the address,
        // so the SIGNATURE carries it (see GetSignatureLength and VerifyTezosSignature).
        case ACCOUNT_TYPE_TEZOS:
            return BTC_ADDRESS20_SIZE;  // 20 bytes (blake2b-160 key hash)
        // Ripple and Tron carry a 20-BYTE address, like BTC and ETH respectively — not a 32-byte
        // key. They were missing here and fell to the 32-byte default, so ParseTransactionBytes
        // over-read 12 bytes and corrupted the rest of the envelope. That parser runs on the P2P
        // tx-relay path, so a wallet emitting one of these addresses could break propagation.
        // AccountState::ValidateAccountAddressBytes already expects 20 for both.
        case ACCOUNT_TYPE_RIPPLE:
            return BTC_ADDRESS20_SIZE;  // 20 bytes (HASH160 address, verifies like BTC)
        case ACCOUNT_TYPE_TRON:
            return ETH_ADDRESS_SIZE;    // 20 bytes (Keccak address, verifies like ETH)
        default:
            return PUBLIC_KEY_SIZE;  // Default to 32 bytes
    }
}

uint32_t TransactionUtil::GetSignatureLength(int32_t account_type) {
    // Go: common/accounttype/*.go GetSignatureLength()
    // Reference: common/constant/signature.go
    switch (account_type) {
        case ACCOUNT_TYPE_ZBC:
            return ZBC_SIGNATURE_LENGTH;  // 64 bytes (Ed25519)
        case ACCOUNT_TYPE_BTC:
        case ACCOUNT_TYPE_BTC_P2PKH:
        case ACCOUNT_TYPE_BTC_P2SH:
        case ACCOUNT_TYPE_BTC_P2WPKH:
        case ACCOUNT_TYPE_BTC_P2WSH:
        case ACCOUNT_TYPE_BTC_P2TR:
            return BTC_SIGNATURE_LENGTH;  // 32 bytes (ECDSA compact)
        case ACCOUNT_TYPE_ETH:
            return ETH_SIGNATURE_LENGTH;  // 65 bytes (ECDSA + recovery)
        case ACCOUNT_TYPE_ESTONIA_EID:
            return ZBC_SIGNATURE_LENGTH;  // 64 bytes (same as ZBC)
        case ACCOUNT_TYPE_POLKADOT:
            return ZBC_SIGNATURE_LENGTH;  // 64 bytes (sr25519 / ed25519 signature)
        // Tezos: [2-byte LE pubkey length = 32] + 32-byte ed25519 pubkey + 64-byte signature.
        // The address is a hash, so the key has to travel with the signature; this is the same
        // envelope Bitcoin and Ripple already use, with a fixed 32-byte key.
        case ACCOUNT_TYPE_TEZOS:
        case ACCOUNT_TYPE_CARDANO:
            return 2 + PUBLIC_KEY_SIZE + ZBC_SIGNATURE_LENGTH;  // 98 bytes: [32,0] + key + ed25519 sig
        default:
            return ZBC_SIGNATURE_LENGTH;  // Default to ZBC signature
    }
}

uint32_t TransactionUtil::GetProofOfOwnershipMessageSize(int32_t account_type) {
    // Go: accountAddressSize + constant.BlockHash + constant.Height
    // For ZBC: (4 + 32) + 32 + 4 = 72 bytes
    uint32_t account_address_size = ACCOUNT_TYPE_SIZE + GetAccountPublicKeyLength(account_type);
    return account_address_size + BLOCK_HASH_SIZE + HEIGHT_SIZE;
}

uint32_t TransactionUtil::GetProofOfOwnershipSize(int32_t account_type, bool with_signature) {
    // Go: message := accountAddressSize + constant.BlockHash + constant.Height
    //     if withSignature { return message + signatureLength }
    uint32_t message_size = GetProofOfOwnershipMessageSize(account_type);
    if (with_signature) {
        return message_size + GetSignatureLength(account_type);  // 72 + 64 = 136 for ZBC
    }
    return message_size;
}

// ============================================================================
// Transaction Body Serialization Functions
// Reference: originals/zoobc-core-develop/common/transaction/*.go
// ============================================================================

// SendZBC body: just Amount (8 bytes)
// Go: common/transaction/sendZBC.go - GetBodyBytes
std::vector<uint8_t> TransactionUtil::GetSendZBCBodyBytes(int64_t amount) {
    std::vector<uint8_t> buffer;
    buffer.reserve(BALANCE_SIZE);
    WriteUint64LE(buffer, static_cast<uint64_t>(amount));
    return buffer;
}

// Go: common/transaction/sendZBC.go - ParseBodyBytes
Result<int64_t> TransactionUtil::ParseSendZBCBodyBytes(const std::vector<uint8_t>& body_bytes) {
    if (body_bytes.size() < BALANCE_SIZE) {
        return Error{ErrorCode::ValidationError, "Invalid SendZBC body size: expected " +
            std::to_string(BALANCE_SIZE) + " bytes, got " + std::to_string(body_bytes.size())};
    }
    return static_cast<int64_t>(ReadUint64LE(body_bytes.data()));
}

// NodeRegistration body: NodePublicKey + AccountAddress + LockedBalance + POOWN
// Go: common/transaction/nodeRegistration.go - GetBodyBytes
std::vector<uint8_t> TransactionUtil::GetNodeRegistrationBodyBytes(
    const std::vector<uint8_t>& node_public_key,
    const std::vector<uint8_t>& account_address,
    int64_t locked_balance,
    const std::vector<uint8_t>& proof_of_ownership) {

    std::vector<uint8_t> buffer;
    buffer.reserve(node_public_key.size() + account_address.size() +
                   BALANCE_SIZE + proof_of_ownership.size());

    // 1. NodePublicKey (32 bytes)
    buffer.insert(buffer.end(), node_public_key.begin(), node_public_key.end());

    // 2. AccountAddress (full address with type prefix: 4 + 32 = 36 bytes for ZBC)
    buffer.insert(buffer.end(), account_address.begin(), account_address.end());

    // 3. LockedBalance (8 bytes)
    WriteUint64LE(buffer, static_cast<uint64_t>(locked_balance));

    // 4. ProofOfOwnership (message + signature)
    buffer.insert(buffer.end(), proof_of_ownership.begin(), proof_of_ownership.end());

    return buffer;
}

// Go: common/transaction/nodeRegistration.go - ParseBodyBytes
Result<model::NodeRegistrationTransactionBody> TransactionUtil::ParseNodeRegistrationBodyBytes(
    const std::vector<uint8_t>& body_bytes) {

    model::NodeRegistrationTransactionBody body;
    size_t offset = 0;

    // Minimum size check for header fields
    // NodePublicKey (32) + AccountType (4) is minimum before we know account address length
    if (body_bytes.size() < NODE_PUBLIC_KEY_SIZE + ACCOUNT_TYPE_SIZE) {
        return Error{ErrorCode::ValidationError, "NodeRegistration body too short"};
    }

    // 1. Parse NodePublicKey (32 bytes)
    body.node_public_key.assign(body_bytes.begin() + offset,
                                 body_bytes.begin() + offset + NODE_PUBLIC_KEY_SIZE);
    offset += NODE_PUBLIC_KEY_SIZE;

    // 2. Parse AccountAddress (type prefix + public key)
    // First read account type to determine public key length
    int32_t account_type = ReadInt32LE(body_bytes.data() + offset);
    uint32_t pubkey_length = GetAccountPublicKeyLength(account_type);
    uint32_t account_address_size = ACCOUNT_TYPE_SIZE + pubkey_length;

    if (offset + account_address_size + BALANCE_SIZE > body_bytes.size()) {
        return Error{ErrorCode::ValidationError,
            "NodeRegistration body too short for account address + balance"};
    }

    body.account_address.assign(body_bytes.begin() + offset,
                                 body_bytes.begin() + offset + account_address_size);
    offset += account_address_size;

    // 3. Parse LockedBalance (8 bytes)
    body.locked_balance = static_cast<int64_t>(ReadUint64LE(body_bytes.data() + offset));
    offset += BALANCE_SIZE;

    // 4. Parse ProofOfOwnership (remaining bytes)
    // POOWN structure: message_bytes (variable) + signature (64)
    // For ZBC: message = account_addr (36) + block_hash (32) + height (4) = 72 bytes
    // Total POOWN for ZBC = 72 + 64 = 136 bytes
    if (body_bytes.size() > offset) {
        body.proof_of_ownership.assign(body_bytes.begin() + offset, body_bytes.end());
    }

    return body;
}

// UpdateNodeRegistration body: NodePublicKey + LockedBalance + POOWN
// Go: common/transaction/nodeRegistrationUpdate.go - GetBodyBytes
std::vector<uint8_t> TransactionUtil::GetUpdateNodeRegistrationBodyBytes(
    const std::vector<uint8_t>& node_public_key,
    int64_t locked_balance,
    const std::vector<uint8_t>& proof_of_ownership) {

    std::vector<uint8_t> buffer;
    buffer.reserve(node_public_key.size() + BALANCE_SIZE + proof_of_ownership.size());

    // 1. NodePublicKey (32 bytes)
    buffer.insert(buffer.end(), node_public_key.begin(), node_public_key.end());

    // 2. LockedBalance (8 bytes)
    WriteUint64LE(buffer, static_cast<uint64_t>(locked_balance));

    // 3. ProofOfOwnership (message + signature)
    buffer.insert(buffer.end(), proof_of_ownership.begin(), proof_of_ownership.end());

    return buffer;
}

// Go: common/transaction/nodeRegistrationUpdate.go - ParseBodyBytes
Result<model::UpdateNodeRegistrationTransactionBody> TransactionUtil::ParseUpdateNodeRegistrationBodyBytes(
    const std::vector<uint8_t>& body_bytes) {

    model::UpdateNodeRegistrationTransactionBody body;
    size_t offset = 0;

    // Minimum size: NodePublicKey (32) + LockedBalance (8) = 40 bytes
    if (body_bytes.size() < NODE_PUBLIC_KEY_SIZE + BALANCE_SIZE) {
        return Error{ErrorCode::ValidationError, "UpdateNodeRegistration body too short"};
    }

    // 1. Parse NodePublicKey (32 bytes)
    body.node_public_key.assign(body_bytes.begin() + offset,
                                 body_bytes.begin() + offset + NODE_PUBLIC_KEY_SIZE);
    offset += NODE_PUBLIC_KEY_SIZE;

    // 2. Parse LockedBalance (8 bytes)
    body.locked_balance = static_cast<int64_t>(ReadUint64LE(body_bytes.data() + offset));
    offset += BALANCE_SIZE;

    // 3. Parse ProofOfOwnership (remaining bytes)
    // Need to determine account type from POOWN bytes to get correct size
    if (body_bytes.size() > offset) {
        body.proof_of_ownership.assign(body_bytes.begin() + offset, body_bytes.end());
    }

    return body;
}

// ClaimNodeRegistration body: NodePublicKey + POOWN
// Go: common/transaction/nodeRegistrationClaim.go - GetBodyBytes
std::vector<uint8_t> TransactionUtil::GetClaimNodeRegistrationBodyBytes(
    const std::vector<uint8_t>& node_public_key,
    const std::vector<uint8_t>& proof_of_ownership) {

    std::vector<uint8_t> buffer;
    buffer.reserve(node_public_key.size() + proof_of_ownership.size());

    // 1. NodePublicKey (32 bytes)
    buffer.insert(buffer.end(), node_public_key.begin(), node_public_key.end());

    // 2. ProofOfOwnership (message + signature)
    buffer.insert(buffer.end(), proof_of_ownership.begin(), proof_of_ownership.end());

    return buffer;
}

// Go: common/transaction/nodeRegistrationClaim.go - ParseBodyBytes
Result<model::ClaimNodeRegistrationTransactionBody> TransactionUtil::ParseClaimNodeRegistrationBodyBytes(
    const std::vector<uint8_t>& body_bytes) {

    model::ClaimNodeRegistrationTransactionBody body;
    size_t offset = 0;

    // Minimum size: NodePublicKey (32 bytes)
    if (body_bytes.size() < NODE_PUBLIC_KEY_SIZE) {
        return Error{ErrorCode::ValidationError, "ClaimNodeRegistration body too short"};
    }

    // 1. Parse NodePublicKey (32 bytes)
    body.node_public_key.assign(body_bytes.begin() + offset,
                                 body_bytes.begin() + offset + NODE_PUBLIC_KEY_SIZE);
    offset += NODE_PUBLIC_KEY_SIZE;

    // 2. Parse ProofOfOwnership (remaining bytes)
    if (body_bytes.size() > offset) {
        body.proof_of_ownership.assign(body_bytes.begin() + offset, body_bytes.end());
    }

    return body;
}

// RemoveNodeRegistration body: just NodePublicKey (32 bytes)
// Go: common/transaction/removeNodeRegistration.go - GetBodyBytes
std::vector<uint8_t> TransactionUtil::GetRemoveNodeRegistrationBodyBytes(
    const std::vector<uint8_t>& node_public_key) {

    // Just the node public key (32 bytes)
    return node_public_key;
}

// Go: common/transaction/removeNodeRegistration.go - ParseBodyBytes
Result<model::RemoveNodeRegistrationTransactionBody> TransactionUtil::ParseRemoveNodeRegistrationBodyBytes(
    const std::vector<uint8_t>& body_bytes) {

    // Body is just NodePublicKey (32 bytes)
    if (body_bytes.size() < NODE_PUBLIC_KEY_SIZE) {
        return Error{ErrorCode::ValidationError, "RemoveNodeRegistration body too short"};
    }

    model::RemoveNodeRegistrationTransactionBody body;
    body.node_public_key.assign(body_bytes.begin(), body_bytes.begin() + NODE_PUBLIC_KEY_SIZE);

    return body;
}

// ============================================================================
// ApprovalEscrow body: Approval (4 bytes) + TransactionID (8 bytes) = 12 bytes
// Go: common/transaction/approvalEscrowTransaction.go
// ============================================================================

std::vector<uint8_t> TransactionUtil::GetApprovalEscrowBodyBytes(
    model::EscrowApproval approval,
    const std::vector<uint8_t>& escrowed_transaction_hash) {

    std::vector<uint8_t> buffer;
    buffer.reserve(APPROVAL_ESCROW_BODY_SIZE);

    // approval (4 bytes LE): 0 = approve, 1 = reject, 2 = expire (internal)
    WriteUint32LE(buffer, static_cast<uint32_t>(approval));

    // escrowed transaction hash (32 bytes). A caller handing over the wrong length produces a
    // body the parser refuses, which is the right failure: never pad or truncate a hash.
    buffer.insert(buffer.end(), escrowed_transaction_hash.begin(), escrowed_transaction_hash.end());

    return buffer;
}

Result<model::ApprovalEscrowTransactionBody> TransactionUtil::ParseApprovalEscrowBodyBytes(
    const std::vector<uint8_t>& body_bytes) {

    // Exactly approval(4) + hash(32). The pre-2026-09-08 12-byte body (approval + 8-byte id) is
    // refused outright: on this chain there is no such transaction, and a lenient parser would let
    // an 8-byte id ride in with 24 bytes of padding and skip the hash comparison.
    if (body_bytes.size() != APPROVAL_ESCROW_BODY_SIZE) {
        return Error{ErrorCode::ValidationError,
                     "ApprovalEscrow body must be exactly 36 bytes (approval + escrowed tx hash), got " +
                         std::to_string(body_bytes.size())};
    }

    model::ApprovalEscrowTransactionBody body;

    uint32_t approval_int = ReadUint32LE(body_bytes.data());
    body.approval = static_cast<model::EscrowApproval>(approval_int);

    body.transaction_hash.assign(body_bytes.begin() + 4, body_bytes.begin() + 4 + BLOCK_HASH_SIZE);
    // The escrow row is keyed by the transaction id, which is the first 8 bytes of the hash.
    body.transaction_id = GetTransactionID(body.transaction_hash);

    return body;
}

// ============================================================================
// EscrowRequest body serialization (ZooBC extension)
// Recipient-initiated escrow proposal
// ============================================================================

std::vector<uint8_t> TransactionUtil::GetEscrowRequestBodyBytes(
    const model::EscrowRequestTransactionBody& body) {

    std::vector<uint8_t> buffer;

    // 1. ProposedSender address (36 bytes for ZBC)
    buffer.insert(buffer.end(), body.proposed_sender.begin(), body.proposed_sender.end());

    // 2. ProposedAmount (8 bytes)
    WriteUint64LE(buffer, static_cast<uint64_t>(body.proposed_amount));

    // 3. ApproverAddress (36 bytes for ZBC)
    buffer.insert(buffer.end(), body.approver_address.begin(), body.approver_address.end());

    // 4. Commission (8 bytes)
    WriteUint64LE(buffer, static_cast<uint64_t>(body.commission));

    // 5. Timeout (8 bytes)
    WriteUint64LE(buffer, static_cast<uint64_t>(body.timeout));

    // 6. InstructionLength (4 bytes) + Instruction (variable)
    std::vector<uint8_t> instruction_bytes(body.instruction.begin(), body.instruction.end());
    WriteUint32LE(buffer, static_cast<uint32_t>(instruction_bytes.size()));
    if (!instruction_bytes.empty()) {
        buffer.insert(buffer.end(), instruction_bytes.begin(), instruction_bytes.end());
    }

    // 7. Expiry (8 bytes)
    WriteUint64LE(buffer, static_cast<uint64_t>(body.expiry));

    return buffer;
}

Result<model::EscrowRequestTransactionBody> TransactionUtil::ParseEscrowRequestBodyBytes(
    const std::vector<uint8_t>& body_bytes) {

    model::EscrowRequestTransactionBody body;
    size_t offset = 0;

    // Minimum size check:
    // ProposedSender type (4) + ProposedAmount (8) + ApproverType (4) +
    // Commission (8) + Timeout (8) + InstructionLen (4) + Expiry (8) = 44 bytes minimum
    // (plus variable address sizes based on account type)
    if (body_bytes.size() < 44) {
        return Error{ErrorCode::ValidationError, "EscrowRequest body too short"};
    }

    // 1. Parse ProposedSender address
    if (offset + ACCOUNT_TYPE_SIZE > body_bytes.size()) {
        return Error{ErrorCode::ValidationError, "Unexpected end of bytes (proposed sender type)"};
    }
    int32_t sender_type = ReadInt32LE(body_bytes.data() + offset);
    uint32_t sender_pubkey_len = GetAccountPublicKeyLength(sender_type);
    uint32_t sender_addr_size = ACCOUNT_TYPE_SIZE + sender_pubkey_len;

    if (offset + sender_addr_size > body_bytes.size()) {
        return Error{ErrorCode::ValidationError, "Unexpected end of bytes (proposed sender)"};
    }
    body.proposed_sender.assign(
        body_bytes.begin() + offset,
        body_bytes.begin() + offset + sender_addr_size);
    offset += sender_addr_size;

    // 2. Parse ProposedAmount (8 bytes)
    if (offset + 8 > body_bytes.size()) {
        return Error{ErrorCode::ValidationError, "Unexpected end of bytes (proposed amount)"};
    }
    body.proposed_amount = ReadInt64LE(body_bytes.data() + offset);
    offset += 8;

    // 3. Parse ApproverAddress
    if (offset + ACCOUNT_TYPE_SIZE > body_bytes.size()) {
        return Error{ErrorCode::ValidationError, "Unexpected end of bytes (approver type)"};
    }
    int32_t approver_type = ReadInt32LE(body_bytes.data() + offset);
    uint32_t approver_pubkey_len = GetAccountPublicKeyLength(approver_type);
    uint32_t approver_addr_size = ACCOUNT_TYPE_SIZE + approver_pubkey_len;

    if (offset + approver_addr_size > body_bytes.size()) {
        return Error{ErrorCode::ValidationError, "Unexpected end of bytes (approver address)"};
    }
    body.approver_address.assign(
        body_bytes.begin() + offset,
        body_bytes.begin() + offset + approver_addr_size);
    offset += approver_addr_size;

    // 4. Parse Commission (8 bytes)
    if (offset + 8 > body_bytes.size()) {
        return Error{ErrorCode::ValidationError, "Unexpected end of bytes (commission)"};
    }
    body.commission = ReadInt64LE(body_bytes.data() + offset);
    offset += 8;

    // 5. Parse Timeout (8 bytes)
    if (offset + 8 > body_bytes.size()) {
        return Error{ErrorCode::ValidationError, "Unexpected end of bytes (timeout)"};
    }
    body.timeout = ReadInt64LE(body_bytes.data() + offset);
    offset += 8;

    // 6. Parse InstructionLength (4 bytes) + Instruction (variable)
    if (offset + 4 > body_bytes.size()) {
        return Error{ErrorCode::ValidationError, "Unexpected end of bytes (instruction length)"};
    }
    uint32_t instruction_length = ReadUint32LE(body_bytes.data() + offset);
    offset += 4;

    if (instruction_length > 0) {
        if (offset + instruction_length > body_bytes.size()) {
            return Error{ErrorCode::ValidationError, "Unexpected end of bytes (instruction)"};
        }
        body.instruction.assign(
            body_bytes.begin() + offset,
            body_bytes.begin() + offset + instruction_length);
        offset += instruction_length;
    }

    // 7. Parse Expiry (8 bytes)
    if (offset + 8 > body_bytes.size()) {
        return Error{ErrorCode::ValidationError, "Unexpected end of bytes (expiry)"};
    }
    body.expiry = ReadInt64LE(body_bytes.data() + offset);

    return body;
}

// ============================================================================
// Escrow serialization for transactions
// Reference: originals/zoobc-core-develop/common/transaction/transactionGeneral.go
// ============================================================================

std::vector<uint8_t> TransactionUtil::GetEscrowBytes(const model::Escrow& escrow) {
    std::vector<uint8_t> buffer;

    // Go: buffer.Write(transaction.GetEscrow().GetApproverAddress())
    // ApproverAddress includes account type prefix (4 bytes) + public key (32 bytes) = 36 bytes
    buffer.insert(buffer.end(), escrow.approver_address.begin(), escrow.approver_address.end());

    // Go: buffer.Write(util.ConvertUint64ToBytes(uint64(transaction.GetEscrow().GetCommission())))
    WriteUint64LE(buffer, static_cast<uint64_t>(escrow.commission));

    // Go: buffer.Write(util.ConvertUint64ToBytes(uint64(transaction.GetEscrow().GetTimeout())))
    WriteUint64LE(buffer, static_cast<uint64_t>(escrow.timeout));

    // Go: buffer.Write(util.ConvertUint32ToBytes(uint32(len([]byte(transaction.GetEscrow().GetInstruction())))))
    std::vector<uint8_t> instruction_bytes(escrow.instruction.begin(), escrow.instruction.end());
    WriteUint32LE(buffer, static_cast<uint32_t>(instruction_bytes.size()));

    // Go: buffer.Write([]byte(transaction.GetEscrow().GetInstruction()))
    if (!instruction_bytes.empty()) {
        buffer.insert(buffer.end(), instruction_bytes.begin(), instruction_bytes.end());
    }

    // ZooBC Extension: Multi-party escrow support
    // Format: MultiParty (1 byte) + [CoSignerSigLen (4) + CoSignerSig (64) + RequestId (8)]
    buffer.push_back(escrow.multi_party ? 1 : 0);
    if (escrow.multi_party) {
        // Co-signer signature length + signature
        WriteUint32LE(buffer, static_cast<uint32_t>(escrow.co_signer_signature.size()));
        if (!escrow.co_signer_signature.empty()) {
            buffer.insert(buffer.end(),
                escrow.co_signer_signature.begin(),
                escrow.co_signer_signature.end());
        }
        // Escrow request ID reference
        WriteInt64LE(buffer, escrow.escrow_request_id);
    }

    return buffer;
}

Result<model::Escrow> TransactionUtil::ParseEscrowBytes(
    const std::vector<uint8_t>& bytes, size_t& offset) {

    model::Escrow escrow;

    // Parse approver account type first
    if (offset + ACCOUNT_TYPE_SIZE > bytes.size()) {
        return Error{ErrorCode::ValidationError, "Unexpected end of bytes (escrow approver type)"};
    }

    int32_t approver_type = ReadInt32LE(bytes.data() + offset);

    if (approver_type == ACCOUNT_TYPE_EMPTY) {
        // No escrow - just skip the account type
        offset += ACCOUNT_TYPE_SIZE;
        return Error{ErrorCode::NotFound, "No escrow data"};
    }

    // Parse full approver address (type + pubkey)
    uint32_t pubkey_length = GetAccountPublicKeyLength(approver_type);
    uint32_t approver_address_size = ACCOUNT_TYPE_SIZE + pubkey_length;

    if (offset + approver_address_size + 8 + 8 + 4 > bytes.size()) {
        return Error{ErrorCode::ValidationError, "Escrow data too short"};
    }

    // Approver address
    escrow.approver_address.assign(
        bytes.begin() + offset,
        bytes.begin() + offset + approver_address_size);
    offset += approver_address_size;

    // Commission (8 bytes)
    escrow.commission = ReadInt64LE(bytes.data() + offset);
    offset += 8;

    // Timeout (8 bytes)
    escrow.timeout = ReadInt64LE(bytes.data() + offset);
    offset += 8;

    // Instruction length (4 bytes)
    uint32_t instruction_length = ReadUint32LE(bytes.data() + offset);
    offset += 4;

    // Instruction string
    if (instruction_length > 0) {
        if (offset + instruction_length > bytes.size()) {
            return Error{ErrorCode::ValidationError, "Escrow instruction too long"};
        }
        escrow.instruction.assign(
            bytes.begin() + offset,
            bytes.begin() + offset + instruction_length);
        offset += instruction_length;
    }

    // ZooBC Extension: Multi-party escrow support (optional, backwards compatible)
    // If there's more data after instruction, try to parse multi-party fields
    if (offset < bytes.size()) {
        escrow.multi_party = (bytes[offset] == 1);
        offset += 1;

        if (escrow.multi_party && offset < bytes.size()) {
            // Parse co-signer signature length and signature
            if (offset + 4 <= bytes.size()) {
                uint32_t co_sig_length = ReadUint32LE(bytes.data() + offset);
                offset += 4;

                if (co_sig_length > 0 && offset + co_sig_length <= bytes.size()) {
                    escrow.co_signer_signature.assign(
                        bytes.begin() + offset,
                        bytes.begin() + offset + co_sig_length);
                    offset += co_sig_length;
                }

                // Parse escrow request ID
                if (offset + 8 <= bytes.size()) {
                    escrow.escrow_request_id = ReadInt64LE(bytes.data() + offset);
                    offset += 8;
                }
            }
        }
    }

    return escrow;
}

bool TransactionUtil::HasEscrow(const model::Transaction& tx) {
    if (!tx.escrow.has_value()) {
        return false;
    }
    const auto& escrow = tx.escrow.value();
    return !escrow.approver_address.empty();
}

// ============================================================================
// LiquidPayment body: Amount (8 bytes) + CompleteMinutes (8 bytes) = 16 bytes
// Reference: originals/zoobc-core-develop/common/transaction/liquidPayment.go
// ============================================================================

std::vector<uint8_t> TransactionUtil::GetLiquidPaymentBodyBytes(
    int64_t amount,
    uint64_t complete_minutes,
    int64_t token_id) {

    std::vector<uint8_t> buffer;
    buffer.reserve(BALANCE_SIZE + LIQUID_PAYMENT_COMPLETE_MINUTES_SIZE + 8);  // 8 + 8 (+8 token_id)

    // Go: buffer.Write(util.ConvertUint64ToBytes(uint64(tx.Body.Amount)))
    WriteUint64LE(buffer, static_cast<uint64_t>(amount));

    // Go: buffer.Write(util.ConvertUint64ToBytes(tx.Body.CompleteMinutes))
    WriteUint64LE(buffer, complete_minutes);

    // ZooBC extension: token_id (0 = ZBC). Only appended when non-zero so a ZBC liquid payment keeps
    // the legacy 16-byte body (backward-compatible; the parser treats a missing token_id as 0).
    if (token_id != 0) {
        WriteUint64LE(buffer, static_cast<uint64_t>(token_id));
    }

    return buffer;
}

Result<model::LiquidPaymentTransactionBody> TransactionUtil::ParseLiquidPaymentBodyBytes(
    const std::vector<uint8_t>& body_bytes) {

    // Go: constant.Balance + constant.LiquidPaymentCompleteMinutesLength = 8 + 8 = 16
    const size_t expected_size = BALANCE_SIZE + LIQUID_PAYMENT_COMPLETE_MINUTES_SIZE;
    if (body_bytes.size() < expected_size) {
        return Error{ErrorCode::ValidationError,
            "LiquidPayment body too short: expected " + std::to_string(expected_size) +
            " bytes, got " + std::to_string(body_bytes.size())};
    }

    model::LiquidPaymentTransactionBody body;
    size_t offset = 0;

    // Go: amount := util.ConvertBytesToUint64(bufferBytes.Next(int(constant.Balance)))
    body.amount = static_cast<int64_t>(ReadUint64LE(body_bytes.data() + offset));
    offset += BALANCE_SIZE;

    // Go: completeMinutes := util.ConvertBytesToUint64(bufferBytes.Next(int(constant.LiquidPaymentCompleteMinutesLength)))
    body.complete_minutes = ReadUint64LE(body_bytes.data() + offset);
    offset += LIQUID_PAYMENT_COMPLETE_MINUTES_SIZE;

    // ZooBC extension: optional token_id (0 = ZBC) appended after the legacy 16-byte body.
    if (body_bytes.size() >= offset + 8) {
        body.token_id = static_cast<int64_t>(ReadUint64LE(body_bytes.data() + offset));
    }

    return body;
}

// ============================================================================
// LiquidPaymentStop body: TransactionID (8 bytes)
// Reference: originals/zoobc-core-develop/common/transaction/liquidPaymentStop.go
// ============================================================================

std::vector<uint8_t> TransactionUtil::GetLiquidPaymentStopBodyBytes(
    int64_t transaction_id) {

    std::vector<uint8_t> buffer;
    buffer.reserve(BALANCE_SIZE);  // 8 bytes (TransactionID uses Balance constant)

    // Go: buffer.Write(util.ConvertUint64ToBytes(uint64(tx.Body.TransactionID)))
    WriteUint64LE(buffer, static_cast<uint64_t>(transaction_id));

    return buffer;
}

Result<model::LiquidPaymentStopTransactionBody> TransactionUtil::ParseLiquidPaymentStopBodyBytes(
    const std::vector<uint8_t>& body_bytes) {

    // Go: constant.TransactionID = 8 bytes (same as Balance)
    if (body_bytes.size() < BALANCE_SIZE) {
        return Error{ErrorCode::ValidationError,
            "LiquidPaymentStop body too short: expected " + std::to_string(BALANCE_SIZE) +
            " bytes, got " + std::to_string(body_bytes.size())};
    }

    model::LiquidPaymentStopTransactionBody body;

    // Go: txID := util.ConvertBytesToUint64(bufferBytes.Next(int(constant.Balance)))
    body.transaction_id = static_cast<int64_t>(ReadUint64LE(body_bytes.data()));

    return body;
}

// ============================================================================
// SetupAccountDataset body serialization
// Go: common/transaction/setupAccountDataset.go
// Body format: PropertyLen(4) + Property + ValueLen(4) + Value
//   + SetterAccountAddress(36) + RecipientAccountAddress(36)
// ============================================================================

std::vector<uint8_t> TransactionUtil::GetSetupAccountDatasetBodyBytes(
    const std::string& property,
    const std::string& value,
    const std::vector<uint8_t>& setter_address,
    const std::vector<uint8_t>& recipient_address) {

    std::vector<uint8_t> buffer;

    // 1. PropertyLength (4 bytes) + Property (variable)
    std::vector<uint8_t> prop_bytes(property.begin(), property.end());
    WriteUint32LE(buffer, static_cast<uint32_t>(prop_bytes.size()));
    buffer.insert(buffer.end(), prop_bytes.begin(), prop_bytes.end());

    // 2. ValueLength (4 bytes) + Value (variable)
    std::vector<uint8_t> val_bytes(value.begin(), value.end());
    WriteUint32LE(buffer, static_cast<uint32_t>(val_bytes.size()));
    buffer.insert(buffer.end(), val_bytes.begin(), val_bytes.end());

    // 3. SetterAccountAddress (36 bytes: type(4) + pubkey(32))
    buffer.insert(buffer.end(), setter_address.begin(), setter_address.end());

    // 4. RecipientAccountAddress (36 bytes: type(4) + pubkey(32))
    buffer.insert(buffer.end(), recipient_address.begin(), recipient_address.end());

    return buffer;
}

Result<model::SetupAccountDatasetTransactionBody> TransactionUtil::ParseSetupAccountDatasetBodyBytes(
    const std::vector<uint8_t>& body_bytes) {

    if (body_bytes.size() < 8) {  // At minimum: PropLen(4) + ValLen(4)
        return Error{ErrorCode::ValidationError, "SetupAccountDataset body too short"};
    }

    model::SetupAccountDatasetTransactionBody body;
    size_t offset = 0;

    // 1. PropertyLength + Property
    uint32_t prop_len = ReadUint32LE(body_bytes.data() + offset);
    offset += 4;
    if (offset + prop_len > body_bytes.size()) {
        return Error{ErrorCode::ValidationError, "SetupAccountDataset body: property truncated"};
    }
    body.property = std::string(body_bytes.begin() + offset, body_bytes.begin() + offset + prop_len);
    offset += prop_len;

    // 2. ValueLength + Value
    if (offset + 4 > body_bytes.size()) {
        return Error{ErrorCode::ValidationError, "SetupAccountDataset body: missing value length"};
    }
    uint32_t val_len = ReadUint32LE(body_bytes.data() + offset);
    offset += 4;
    if (offset + val_len > body_bytes.size()) {
        return Error{ErrorCode::ValidationError, "SetupAccountDataset body: value truncated"};
    }
    body.value = std::string(body_bytes.begin() + offset, body_bytes.begin() + offset + val_len);

    return body;
}

// ============================================================================
// RemoveAccountDataset body serialization (same format as Setup)
// Go: common/transaction/removeAccountDataset.go
// ============================================================================

std::vector<uint8_t> TransactionUtil::GetRemoveAccountDatasetBodyBytes(
    const std::string& property,
    const std::string& value,
    const std::vector<uint8_t>& setter_address,
    const std::vector<uint8_t>& recipient_address) {

    // Same format as SetupAccountDataset
    return GetSetupAccountDatasetBodyBytes(property, value, setter_address, recipient_address);
}

Result<model::RemoveAccountDatasetTransactionBody> TransactionUtil::ParseRemoveAccountDatasetBodyBytes(
    const std::vector<uint8_t>& body_bytes) {

    auto setup_result = ParseSetupAccountDatasetBodyBytes(body_bytes);
    if (setup_result.IsErr()) {
        return Error{setup_result.GetError()};
    }
    auto setup_body = setup_result.Value();

    model::RemoveAccountDatasetTransactionBody body;
    body.property = setup_body.property;
    body.value = setup_body.value;
    return body;
}

// ============================================================================
// FeeVoteCommitment body serialization
// Go: common/transaction/feeVoteCommit.go
// Body format: VoteHash (32 bytes)
// ============================================================================

std::vector<uint8_t> TransactionUtil::GetFeeVoteCommitBodyBytes(
    const std::vector<uint8_t>& vote_hash) {

    std::vector<uint8_t> buffer;
    buffer.reserve(BLOCK_HASH_SIZE);  // 32 bytes

    // Go: buffer.Write(tx.Body.GetVoteHash())
    buffer.insert(buffer.end(), vote_hash.begin(), vote_hash.end());

    return buffer;
}

Result<model::FeeVoteCommitTransactionBody> TransactionUtil::ParseFeeVoteCommitBodyBytes(
    const std::vector<uint8_t>& body_bytes) {

    if (body_bytes.size() < BLOCK_HASH_SIZE) {
        return Error{ErrorCode::ValidationError,
            "FeeVoteCommit body too short: expected 32 bytes, got " + std::to_string(body_bytes.size())};
    }

    model::FeeVoteCommitTransactionBody body;
    body.vote_hash = std::vector<uint8_t>(body_bytes.begin(), body_bytes.begin() + BLOCK_HASH_SIZE);

    return body;
}

// ============================================================================
// FeeVoteReveal body serialization
// Go: common/transaction/feeVoteReveal.go
// Body format: FeeVoteInfo (44 bytes) + VoterSignature (64 bytes) = 108 bytes
// FeeVoteInfo = RecentBlockHash(32) + RecentBlockHeight(4) + FeeVote(8)
// ============================================================================

std::vector<uint8_t> TransactionUtil::GetFeeVoteInfoBytes(const model::FeeVoteInfo& vote_info) {
    std::vector<uint8_t> buffer;
    buffer.reserve(44);
    // 1. RecentBlockHash (32 bytes)
    buffer.insert(buffer.end(), vote_info.recent_block_hash.begin(), vote_info.recent_block_hash.end());
    // 2. RecentBlockHeight (4 bytes LE)
    WriteUint32LE(buffer, vote_info.recent_block_height);
    // 3. FeeVote (8 bytes LE)
    WriteInt64LE(buffer, vote_info.fee_vote);
    return buffer;
}

std::vector<uint8_t> TransactionUtil::GetFeeVoteRevealBodyBytes(
    const model::FeeVoteInfo& vote_info,
    const std::vector<uint8_t>& voter_signature) {

    // FeeVoteInfo (44 bytes) — exactly the bytes the voter_signature is over.
    std::vector<uint8_t> buffer = GetFeeVoteInfoBytes(vote_info);
    buffer.reserve(44 + 4 + voter_signature.size());

    // VoterSignature: LENGTH-PREFIXED (uint32 LE length, then the bytes) — matches Go
    // (feeVoteReveal.go GetBodyBytes writes ConvertUint32ToBytes(len(VoterSignature)) then
    // the sig) and the executor's ParseFeeVoteRevealBody. The old code wrote a bare 64-byte
    // signature with NO length prefix, so the executor (correct, length-prefixed) misread the
    // first 4 signature bytes as a huge sig_length -> "signature length exceeds body size" ->
    // the block wedged. Variable length also supports non-64-byte (e.g. secp256k1) signatures.
    WriteUint32LE(buffer, static_cast<uint32_t>(voter_signature.size()));
    buffer.insert(buffer.end(), voter_signature.begin(), voter_signature.end());

    return buffer;
}

Result<model::FeeVoteRevealTransactionBody> TransactionUtil::ParseFeeVoteRevealBodyBytes(
    const std::vector<uint8_t>& body_bytes) {

    // FeeVoteInfo (44) + sig_length (4) = 48 bytes minimum, then the variable signature.
    // (Matches Go ParseBodyBytes + the executor's ParseFeeVoteRevealBody: length-prefixed sig.)
    constexpr size_t MIN_BODY_SIZE = BLOCK_HASH_SIZE + HEIGHT_SIZE + 8 + 4;
    if (body_bytes.size() < MIN_BODY_SIZE) {
        return Error{ErrorCode::ValidationError,
            "FeeVoteReveal body too short: expected at least " + std::to_string(MIN_BODY_SIZE) +
            " bytes, got " + std::to_string(body_bytes.size())};
    }

    model::FeeVoteRevealTransactionBody body;
    size_t offset = 0;

    // FeeVoteInfo:
    // 1. RecentBlockHash (32 bytes)
    body.fee_vote_info.recent_block_hash = std::vector<uint8_t>(
        body_bytes.begin() + offset, body_bytes.begin() + offset + BLOCK_HASH_SIZE);
    offset += BLOCK_HASH_SIZE;

    // 2. RecentBlockHeight (4 bytes)
    body.fee_vote_info.recent_block_height = ReadUint32LE(body_bytes.data() + offset);
    offset += HEIGHT_SIZE;

    // 3. FeeVote (8 bytes)
    body.fee_vote_info.fee_vote = ReadInt64LE(body_bytes.data() + offset);
    offset += 8;

    // 4. VoterSignature: uint32 LE length prefix, then that many bytes.
    uint32_t sig_length = ReadUint32LE(body_bytes.data() + offset);
    offset += 4;
    if (offset + sig_length > body_bytes.size()) {
        return Error{ErrorCode::ValidationError,
            "FeeVoteReveal: signature length exceeds body size"};
    }
    body.voter_signature = std::vector<uint8_t>(
        body_bytes.begin() + offset, body_bytes.begin() + offset + sig_length);

    return body;
}

}  // namespace util
}  // namespace zoobc
