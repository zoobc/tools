// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#ifndef ZOOBC_TOOLS_TX_COMMON_H
#define ZOOBC_TOOLS_TX_COMMON_H

// Shared header-only library for ZooBC transaction CLI tools.
// Extracts all duplicated boilerplate from transfer.cpp, register-node.cpp, etc.

#include <stdexcept>
#include <utility>
#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <cctype>
#include <optional>
#include <functional>
#include <sodium.h>
#include "httplib.h"
#include "zoobc/crypto/signature.h"
#include "zoobc/crypto/address_decode.h"
#include "zoobc/crypto/hash.h"
#include "zoobc/crypto/message_encryption.h"
#include "zoobc/crypto/slip10.h"
#include "zoobc/crypto/ethereum_signature.h"
#include "zoobc/crypto/bitcoin_signature.h"
#include "zoobc/common/types.h"
#include "zoobc/util/transaction_util.h"
#include "nlohmann/json.hpp"

namespace txc {

using json = nlohmann::json;
using TransactionUtil = zoobc::util::TransactionUtil;
using Signature = zoobc::crypto::Signature;
namespace AccountAddressSize = zoobc::crypto::AccountAddressSize;

// ============================================================================
// Byte utilities
// ============================================================================

inline std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

inline std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    for (uint8_t b : bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}

// ============================================================================
// Exit codes (2026-09-15)
// ============================================================================
// Every tool used to exit 1 for every failure, so a caller running us as a child process had to
// parse the error text to learn whether the node was down, the arguments were wrong or the chain
// said no. These codes are the contract: stable numbers, one meaning each. The same code is also
// written into the JSON error as "exit_code" with a short "error_class" name.
namespace exit_code {
constexpr int OK = 0;
constexpr int INTERNAL = 1;              // anything not classified below (signing, hashing, bugs)
constexpr int USAGE = 2;                 // bad or missing arguments, bad address, bad option
constexpr int UNREACHABLE = 3;           // node not reachable, connection refused, DNS, TLS
constexpr int INSUFFICIENT_BALANCE = 4;  // node: sender cannot pay (fee, or account unknown)
constexpr int FEE_TOO_LOW = 5;           // node: declared fee below the enforced minimum
constexpr int REJECTED = 6;              // node: any other validation rejection (HTTP 4xx)
constexpr int NOT_FOUND = 7;             // node: unknown transaction / escrow / token
constexpr int TIMEOUT = 8;               // node did not answer within --timeout
constexpr int NODE_BUSY = 9;             // node: 503 emergency mode / backpressure / 5xx
constexpr int VERIFY_FAILED = 10;        // verify-message: signature does not verify
inline const char* name(int c) {
    switch (c) {
        case OK: return "ok";
        case USAGE: return "usage";
        case UNREACHABLE: return "node_unreachable";
        case INSUFFICIENT_BALANCE: return "insufficient_balance";
        case FEE_TOO_LOW: return "fee_too_low";
        case REJECTED: return "rejected";
        case NOT_FOUND: return "not_found";
        case TIMEOUT: return "timeout";
        case NODE_BUSY: return "node_busy";
        case VERIFY_FAILED: return "verify_failed";
        default: return "internal";
    }
}
}  // namespace exit_code

// The code the NEXT emitted JSON error carries (consumed by emit_error_json), and the code the
// last classified failure had (for callers that only see a bool). Kept as process-wide state so the
// sixty existing `emit_error(msg); return 1;` sites keep compiling while the classified sites use
// `return fail(emit_error, code, msg);`.
inline int& pending_exit_code() { static int c = 0; return c; }
inline int& last_exit_code() { static int c = exit_code::INTERNAL; return c; }
inline int fail(const std::function<void(const std::string&)>& emit, int code, const std::string& msg) {
    pending_exit_code() = code;
    last_exit_code() = code;
    emit(msg);
    return code;
}

// Classify a node rejection from its HTTP status and error text. The node's error strings are the
// only signal it gives; the substrings below are the ones TransactionValidator / the staging pool
// actually emit (checked 2026-09-15). Unknown text stays REJECTED, never a "softer" class.
inline int classify_node_error(int http_code, const std::string& text) {
    if (http_code == 0) return exit_code::UNREACHABLE;
    if (http_code == 503 || http_code >= 500) return exit_code::NODE_BUSY;
    std::string t = text;
    std::transform(t.begin(), t.end(), t.begin(), [](unsigned char c) { return std::tolower(c); });
    if (t.find("fee too low") != std::string::npos) return exit_code::FEE_TOO_LOW;
    if (t.find("insufficient balance") != std::string::npos ||
        t.find("insufficient spendable") != std::string::npos ||
        t.find("account does not exist") != std::string::npos) return exit_code::INSUFFICIENT_BALANCE;
    if (t.find("not found") != std::string::npos ||
        t.find("unknown token") != std::string::npos ||
        t.find("unknown or expired token") != std::string::npos ||
        t.find("unknown app") != std::string::npos) return exit_code::NOT_FOUND;
    return exit_code::REJECTED;
}

// Transport failures: the difference between "no answer in time" and "nobody there" is the
// difference between retrying later and fixing the URL, so they get separate codes.
inline int classify_transport_error(httplib::Error e) {
    switch (e) {
        case httplib::Error::ConnectionTimeout:
        case httplib::Error::Read:
        case httplib::Error::Write:
            return exit_code::TIMEOUT;
        default:
            return exit_code::UNREACHABLE;
    }
}

// --timeout / --timeout-seconds / ZBC_TIMEOUT: one bound for connect, read and write of every HTTP
// call the tool makes (a transaction command makes two: node/info, then the POST).
inline int& http_timeout_seconds() { static int t = 20; return t; }

// ============================================================================
// Message signing (sign-message / verify-message, 2026-09-15)
// ============================================================================
// The chain has no message-signing standard, so this defines one for the tools:
//     digest    = SHA3-256("ZBC-MSG" ‖ message_bytes)
//     signature = Ed25519.sign(seed, digest)                      (64 bytes)
// Domain-separated from every other signature the key makes: a transaction signs
// SHA3-256("ZBC-TX" ‖ genesis ‖ bytes) (v2) or SHA3-256(bytes) of a serialized transaction whose
// first four bytes are a small type number (v1); proof-of-ownership and multisig participants sign
// other shapes. A message can therefore never double as a transaction signature and vice versa.
// Hashing first also keeps the signed input a fixed 32 bytes for hardware devices that hash
// on-device (SPEC-hardware-wallet-signing §3.1 asks devices never to raw-sign caller-supplied
// 32-byte inputs; here the device computes the digest itself from tag + message).
inline const char* MESSAGE_SIGNING_TAG = "ZBC-MSG";
inline const char* MESSAGE_SIGNING_SCHEME = "ZBC-MSG-v1";
inline zoobc::Result<std::vector<uint8_t>> message_signing_digest(const std::vector<uint8_t>& message) {
    std::vector<uint8_t> buf(MESSAGE_SIGNING_TAG, MESSAGE_SIGNING_TAG + std::strlen(MESSAGE_SIGNING_TAG));
    buf.insert(buf.end(), message.begin(), message.end());
    return zoobc::crypto::Hash::SHA3_256(buf);
}

// ============================================================================
// Address parsing
// ============================================================================

inline bool is_formatted_address(const std::string& str) {
    std::string upper = str;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    return (upper.find("ZBC") == 0 || upper.find("ZNK") == 0);
}

// Decode a 32-byte REGISTRY key given either a Reed-Solomon address (ZNK_ node, ZBG_ gateway,
// ZBR_ relay — the form the wallet and the installer show) or plain 64-hex.
//
// A Reed-Solomon key address is 66 chars: a 3-letter prefix + '_' + 7 underscore-separated base32
// groups. Hex is 64 chars with no '_' at index 3, so the '_' at index 3 distinguishes them
// unambiguously. ANY prefix decodes to the same 32 raw bytes — the prefix is display-only, and the
// on-chain key is the raw key either way. (Mirrors public_key_to_hex in genesis-builder.cpp, where
// accepting only ZNK_ once made ZBG_/ZBR_ genesis entries silently fail to seed.)
inline zoobc::Result<std::vector<uint8_t>> decode_registry_key(const std::string& input) {
    if (input.length() == 66 && input[3] == '_') {
        auto dec = zoobc::crypto::ZoobcAddress::Decode(input);
        if (!dec.IsOk()) return zoobc::Error{dec.GetError()};
        if (dec.Value().size() != 32)
            return zoobc::Error{zoobc::ErrorCode::ValidationError, "decoded key is not 32 bytes"};
        return dec.Value();
    }
    std::string hex = input;
    if (hex.rfind("0x", 0) == 0 || hex.rfind("0X", 0) == 0) hex = hex.substr(2);
    if (hex.length() != 64)
        return zoobc::Error{zoobc::ErrorCode::ValidationError,
                            "key must be a 64-hex string or a ZNK_/ZBG_/ZBR_ address"};
    std::vector<uint8_t> out;
    out.reserve(32);
    for (size_t i = 0; i < 64; i += 2) {
        try { out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16))); }
        catch (...) { return zoobc::Error{zoobc::ErrorCode::ValidationError, "key is not valid hex"}; }
    }
    return out;
}

// A fundable DataSet object address (ROADMAP §C): "ZBS_..." Reed-Solomon, account type 10.
inline bool is_dataset_address(const std::string& str) {
    std::string upper = str;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    return upper.find("ZBS") == 0;
}

inline bool is_eth_address(const std::string& str) {
    if (str.size() >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        return str.size() == 42;
    }
    return false;
}

inline bool is_btc_address(const std::string& str) {
    if (str.empty()) return false;
    if (str[0] == '1' || str[0] == '3') return true;
    if (str.size() < 3) return false;
    std::string prefix;
    prefix.reserve(5);
    for (size_t i = 0; i < std::min<size_t>(5, str.size()); i++) {
        prefix.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(str[i]))));
    }
    return prefix.rfind("bc1", 0) == 0 || prefix.rfind("tb1", 0) == 0 || prefix.rfind("bcrt1", 0) == 0;
}

enum class KeyType { ZBC, ETH, BTC };
using RecipientType = KeyType;

struct AddressInfo {
    std::vector<uint8_t> address;  // Full address with type prefix
    RecipientType type;
    std::string display;           // Formatted display string
    std::string type_label;
};

inline std::string get_btc_recipient_label(const std::vector<uint8_t>& address_bytes) {
    if (address_bytes.size() < 4) return "BTC";
    uint32_t t = static_cast<uint32_t>(address_bytes[0]) |
                 (static_cast<uint32_t>(address_bytes[1]) << 8) |
                 (static_cast<uint32_t>(address_bytes[2]) << 16) |
                 (static_cast<uint32_t>(address_bytes[3]) << 24);
    switch (t) {
        case 5: return "BTC P2PKH";
        case 6: return "BTC P2SH";
        case 7: return "BTC P2WPKH";
        case 8: return "BTC P2WSH";
        case 9: return "BTC P2TR";
        case 1: return "BTC (legacy)";
        default: return "BTC";
    }
}

// Parse any address format: ZBC_, ZNK_, 0x (ETH), BTC (1/3/bc1), or 64-char hex
// The chain-wide decoder. Every account type the node supports, resolved by checksum rather than by
// guessing — see include/zoobc/crypto/address_decode.h.
//
// This function used to know four formats out of seventeen, so no CLI tool could pay a Solana,
// Polkadot, Cardano, Ripple, Tron or Tezos account even though the node verifies signatures for all
// of them. It was also unsafe in the other direction: the old is_btc_address() matched ANY string
// starting with 1 or 3, so a Polkadot address became a BITCOIN account nobody could spend from.
//
// `chain_hint` (from --chain) forces a reading. Nothing needs it today — the formats carry their own
// checksums — but an 0x… address is valid on every EVM chain, so the override exists for the day
// ZooBC distinguishes them, and so an operator can overrule a heuristic rather than argue with it.
inline zoobc::Result<AddressInfo> parse_address(const std::string& address_str,
                                                const std::string& chain_hint = "") {
    AddressInfo info;
    info.display = address_str;

    {
        auto dec = zoobc::crypto::DecodeAddress(address_str,
                                                zoobc::crypto::ParseAddressChain(chain_hint));
        if (dec.IsOk()) {
            const auto& d = dec.Value();
            info.address = d.address;
            info.type_label = zoobc::crypto::AccountTypeName(d.account_type);
            // RecipientType only distinguishes the three signing families the tools branch on.
            info.type = (d.account_type == zoobc::util::TransactionUtil::ACCOUNT_TYPE_ETH)
                            ? RecipientType::ETH
                            : ((d.account_type == zoobc::util::TransactionUtil::ACCOUNT_TYPE_BTC ||
                                (d.account_type >= zoobc::util::TransactionUtil::ACCOUNT_TYPE_BTC_P2PKH &&
                                 d.account_type <= zoobc::util::TransactionUtil::ACCOUNT_TYPE_BTC_P2TR))
                                   ? RecipientType::BTC
                                   : RecipientType::ZBC);
            return info;
        }
        // Fall through to the legacy branches below on failure, so nothing that used to work stops
        // working — the new decoder is strictly additive until it has been exercised in the field.
    }

    if (is_eth_address(address_str)) {
        auto result = Signature::ParseEthAddress(address_str);
        if (result.IsErr()) return zoobc::Error{result.GetError()};
        info.address = result.Value();
        info.type = RecipientType::ETH;
        info.type_label = "ETH (compact)";
        return info;
    }

    if (is_btc_address(address_str)) {
        auto result = Signature::ParseBtcAddress(address_str);
        if (result.IsErr()) return zoobc::Error{result.GetError()};
        info.address = result.Value();
        info.type = RecipientType::BTC;
        info.type_label = get_btc_recipient_label(info.address);
        return info;
    }

    if (is_formatted_address(address_str)) {
        auto result = zoobc::crypto::ZoobcAddress::Decode(address_str);
        if (result.IsErr()) return zoobc::Error{result.GetError()};
        std::vector<uint8_t> pubkey = result.Value();
        info.address.reserve(AccountAddressSize::ZBC_FULL);
        info.address.push_back(0x00); info.address.push_back(0x00);
        info.address.push_back(0x00); info.address.push_back(0x00);
        info.address.insert(info.address.end(), pubkey.begin(), pubkey.end());
        info.type = RecipientType::ZBC;
        info.display = address_str;
        info.type_label = "ZBC";
        return info;
    }

    if (is_dataset_address(address_str)) {
        // ZBS_ DataSet address: same Reed-Solomon scheme, but the 4-byte type prefix is
        // 10 (DataSetAccount), not 0 — so a SendZBC credits the dataset's funding balance.
        auto result = zoobc::crypto::ZoobcAddress::Decode(address_str);
        if (result.IsErr()) return zoobc::Error{result.GetError()};
        std::vector<uint8_t> payload = result.Value();  // 32-byte dataset (creating-tx-hash) id
        info.address.reserve(AccountAddressSize::ZBC_FULL);
        info.address.push_back(0x0A); info.address.push_back(0x00);  // type 10, little-endian
        info.address.push_back(0x00); info.address.push_back(0x00);
        info.address.insert(info.address.end(), payload.begin(), payload.end());
        info.type = RecipientType::ZBC;
        info.display = address_str;
        info.type_label = "DATASET";
        return info;
    }

    if (address_str.length() == 64) {
        std::vector<uint8_t> pubkey = hex_to_bytes(address_str);
        info.address.reserve(AccountAddressSize::ZBC_FULL);
        info.address.push_back(0x00); info.address.push_back(0x00);
        info.address.push_back(0x00); info.address.push_back(0x00);
        info.address.insert(info.address.end(), pubkey.begin(), pubkey.end());
        info.type = RecipientType::ZBC;
        info.display = zoobc::crypto::ZoobcAddress::Encode(pubkey, "ZBC");
        info.type_label = "ZBC";
        return info;
    }

    return zoobc::Error{zoobc::ErrorCode::ValidationError,
        "Invalid address format. Supported: ZBC_/ZNK_, 64-hex, 0x ETH, BTC (1/3/bc1)"};
}

// ============================================================================
// Key derivation
// ============================================================================

struct DerivedKeys {
    zoobc::crypto::KeyPair keypair;
    std::vector<uint8_t> sender_address;  // Full address with type prefix
    std::string formatted;                // Display string (ZBC_..., 0x..., etc.)
    std::string type_label;
    KeyType type;
};

inline zoobc::Result<DerivedKeys> derive_sender_keys(const std::string& privkey_hex, KeyType type = KeyType::ZBC) {
    if (privkey_hex.length() != 64) {
        return zoobc::Error{zoobc::ErrorCode::ValidationError, "Private key must be 64 hex characters (32 bytes)"};
    }

    DerivedKeys keys;
    keys.type = type;
    auto seed = hex_to_bytes(privkey_hex);

    if (type == KeyType::ZBC) {
        keys.keypair.public_key.resize(crypto_sign_ed25519_PUBLICKEYBYTES);
        keys.keypair.private_key.resize(crypto_sign_ed25519_SECRETKEYBYTES);
        if (crypto_sign_ed25519_seed_keypair(keys.keypair.public_key.data(),
                                              keys.keypair.private_key.data(),
                                              seed.data()) != 0) {
            return zoobc::Error{zoobc::ErrorCode::CryptoError, "Failed to derive ZBC keypair from seed"};
        }
        keys.formatted = zoobc::crypto::ZoobcAddress::Encode(keys.keypair.public_key, "ZBC");
        keys.type_label = "ZBC";
        keys.sender_address.resize(4 + 32);
        keys.sender_address[0] = 0x00; keys.sender_address[1] = 0x00;
        keys.sender_address[2] = 0x00; keys.sender_address[3] = 0x00;
        std::copy(keys.keypair.public_key.begin(), keys.keypair.public_key.end(), keys.sender_address.begin() + 4);

    } else if (type == KeyType::ETH) {
        zoobc::crypto::EthereumSignature eth_sig;
        auto pubkey_result = eth_sig.GetPublicKeyFromPrivateKey(seed);
        if (!pubkey_result.IsOk()) {
            return zoobc::Error{pubkey_result.GetError()};
        }
        keys.keypair.public_key = pubkey_result.Value();
        keys.keypair.private_key = seed;
        auto addr20 = zoobc::crypto::EthereumSignature::GetAddress20(keys.keypair.public_key);
        keys.formatted = zoobc::crypto::EthereumSignature::ToChecksumAddress(addr20);
        keys.type_label = "ETH";
        keys.sender_address.resize(4 + 64);
        keys.sender_address[0] = 0x04; keys.sender_address[1] = 0x00;
        keys.sender_address[2] = 0x00; keys.sender_address[3] = 0x00;
        std::copy(keys.keypair.public_key.begin(), keys.keypair.public_key.end(), keys.sender_address.begin() + 4);

    } else if (type == KeyType::BTC) {
        zoobc::crypto::BitcoinSignature btc_sig;
        auto pubkey_result = btc_sig.GetPublicKeyFromPrivateKey(seed);
        if (!pubkey_result.IsOk()) {
            return zoobc::Error{pubkey_result.GetError()};
        }
        keys.keypair.public_key = pubkey_result.Value();
        keys.keypair.private_key = seed;
        keys.formatted = btc_sig.GetAddressFromPublicKey("", keys.keypair.public_key);
        keys.type_label = "BTC";
        keys.sender_address.resize(4 + 33);
        keys.sender_address[0] = 0x05; keys.sender_address[1] = 0x00;
        keys.sender_address[2] = 0x00; keys.sender_address[3] = 0x00;
        std::copy(keys.keypair.public_key.begin(), keys.keypair.public_key.end(), keys.sender_address.begin() + 4);
    }

    return keys;
}

// Convenience: derive ZBC keypair only (for node tools)
inline zoobc::Result<zoobc::crypto::KeyPair> derive_zbc_keypair(const std::string& privkey_hex) {
    if (privkey_hex.length() != 64) {
        return zoobc::Error{zoobc::ErrorCode::ValidationError, "Private key must be 64 hex characters (32 bytes)"};
    }
    auto seed = hex_to_bytes(privkey_hex);
    zoobc::crypto::KeyPair kp;
    kp.public_key.resize(crypto_sign_ed25519_PUBLICKEYBYTES);
    kp.private_key.resize(crypto_sign_ed25519_SECRETKEYBYTES);
    if (crypto_sign_ed25519_seed_keypair(kp.public_key.data(), kp.private_key.data(), seed.data()) != 0) {
        return zoobc::Error{zoobc::ErrorCode::CryptoError, "Failed to derive keypair from seed"};
    }
    return kp;
}

// ============================================================================
// Transaction building
// ============================================================================

static constexpr int32_t ACCOUNT_TYPE_ZBC = 0;
static constexpr int32_t ACCOUNT_TYPE_EMPTY = 2;

// Build transaction bytes for signing (matches Go's GetTransactionBytes format exactly)
// sender_pubkey: 32-byte Ed25519 pubkey (type prefix added automatically for ZBC)
// recipient_address: Full address with type prefix, or empty for no recipient
inline std::vector<uint8_t> build_transaction_bytes(
    int32_t version,
    int64_t timestamp,
    const std::vector<uint8_t>& sender_pubkey,
    const std::vector<uint8_t>& recipient_address,
    uint32_t tx_type,
    int64_t fee,
    const std::vector<uint8_t>& body_bytes,
    const std::vector<uint8_t>& escrow_bytes,
    const std::vector<uint8_t>& message_bytes) {

    std::vector<uint8_t> tx_bytes;

    // 1. Transaction Type (4 bytes LE)
    TransactionUtil::WriteUint32LE(tx_bytes, tx_type);

    // 2. Version (1 byte)
    tx_bytes.push_back(static_cast<uint8_t>(version & 0xFF));

    // 3. Timestamp (8 bytes LE)
    TransactionUtil::WriteUint64LE(tx_bytes, static_cast<uint64_t>(timestamp));

    // 4. Sender Account Address (4 bytes type + 32 bytes pubkey)
    TransactionUtil::WriteInt32LE(tx_bytes, ACCOUNT_TYPE_ZBC);
    tx_bytes.insert(tx_bytes.end(), sender_pubkey.begin(), sender_pubkey.end());

    // 5. Recipient Account Address
    if (recipient_address.empty() ||
        std::all_of(recipient_address.begin(), recipient_address.end(), [](uint8_t b) { return b == 0; })) {
        TransactionUtil::WriteInt32LE(tx_bytes, ACCOUNT_TYPE_EMPTY);
    } else {
        // Recipient already includes type prefix - write directly
        tx_bytes.insert(tx_bytes.end(), recipient_address.begin(), recipient_address.end());
    }

    // 6. Fee (8 bytes LE)
    TransactionUtil::WriteUint64LE(tx_bytes, static_cast<uint64_t>(fee));

    // 7. Body length (4 bytes LE)
    TransactionUtil::WriteUint32LE(tx_bytes, static_cast<uint32_t>(body_bytes.size()));

    // 8. Body bytes
    tx_bytes.insert(tx_bytes.end(), body_bytes.begin(), body_bytes.end());

    // 9. Escrow
    if (!escrow_bytes.empty()) {
        tx_bytes.insert(tx_bytes.end(), escrow_bytes.begin(), escrow_bytes.end());
    } else {
        TransactionUtil::WriteInt32LE(tx_bytes, ACCOUNT_TYPE_EMPTY);
    }

    // 10. Message length (4 bytes) + message bytes
    TransactionUtil::WriteUint32LE(tx_bytes, static_cast<uint32_t>(message_bytes.size()));
    if (!message_bytes.empty()) {
        tx_bytes.insert(tx_bytes.end(), message_bytes.begin(), message_bytes.end());
    }

    return tx_bytes;
}

// Multi-key-type version: sender_address already has type prefix (for ETH/BTC)
inline std::vector<uint8_t> build_transaction_bytes_multikey(
    int32_t version,
    int64_t timestamp,
    const std::vector<uint8_t>& sender_address,   // Full address with type prefix
    const std::vector<uint8_t>& recipient_address,
    uint32_t tx_type,
    int64_t fee,
    const std::vector<uint8_t>& body_bytes,
    const std::vector<uint8_t>& escrow_bytes,
    const std::vector<uint8_t>& message_bytes) {

    std::vector<uint8_t> tx_bytes;
    TransactionUtil::WriteUint32LE(tx_bytes, tx_type);
    tx_bytes.push_back(static_cast<uint8_t>(version & 0xFF));
    TransactionUtil::WriteUint64LE(tx_bytes, static_cast<uint64_t>(timestamp));

    // Sender: write type prefix + key directly
    tx_bytes.insert(tx_bytes.end(), sender_address.begin(), sender_address.end());

    // Recipient
    if (recipient_address.empty() ||
        std::all_of(recipient_address.begin(), recipient_address.end(), [](uint8_t b) { return b == 0; })) {
        TransactionUtil::WriteInt32LE(tx_bytes, ACCOUNT_TYPE_EMPTY);
    } else {
        tx_bytes.insert(tx_bytes.end(), recipient_address.begin(), recipient_address.end());
    }

    TransactionUtil::WriteUint64LE(tx_bytes, static_cast<uint64_t>(fee));
    TransactionUtil::WriteUint32LE(tx_bytes, static_cast<uint32_t>(body_bytes.size()));
    tx_bytes.insert(tx_bytes.end(), body_bytes.begin(), body_bytes.end());

    if (!escrow_bytes.empty()) {
        tx_bytes.insert(tx_bytes.end(), escrow_bytes.begin(), escrow_bytes.end());
    } else {
        TransactionUtil::WriteInt32LE(tx_bytes, ACCOUNT_TYPE_EMPTY);
    }

    TransactionUtil::WriteUint32LE(tx_bytes, static_cast<uint32_t>(message_bytes.size()));
    if (!message_bytes.empty()) {
        tx_bytes.insert(tx_bytes.end(), message_bytes.begin(), message_bytes.end());
    }
    return tx_bytes;
}

// ============================================================================
// Signing context (signing v2, 2026-09-08)
// ============================================================================
// What a signer signs depends on the chain it signs for. Since node v0.4.0 the verified digest is
//     SHA3-256("ZBC-TX" ‖ genesis_block_hash ‖ unsigned transaction bytes)
// so a signature is valid on exactly one chain. Nodes still on signing v1 verify the bare
// SHA3-256 of the unsigned bytes and report no `signing_version` in /api/v1/node/info. The tools
// ask the node they are about to submit to and follow whatever it enforces, so one binary works
// against both during the transition. `--genesis <hex>` signs for a chain without asking it
// (offline signing, or a node that cannot be reached); `--genesis v1` forces the legacy digest.
struct SigningContext {
    int version = 0;                    // 0 = unresolved, 1 = legacy bare SHA3, 2 = chain-bound
    std::vector<uint8_t> genesis_hash;  // 32 bytes when version == 2
    std::string source;                 // where the rule came from, for --verbose
};

inline SigningContext& signing_context() {
    static SigningContext ctx;
    return ctx;
}


// The digest a transaction signer signs, under the resolved context. Refuses to guess: a tool
// that silently fell back to v1 would produce signatures the new chain rejects — or, worse, a
// signature that also verifies on a chain the user never meant.
inline zoobc::Result<std::vector<uint8_t>> signing_digest(const std::vector<uint8_t>& tx_bytes) {
    const auto& c = signing_context();
    if (c.version == 2) return TransactionUtil::SigningDigest(tx_bytes, c.genesis_hash);
    if (c.version == 1) return zoobc::crypto::Hash::SHA3_256(tx_bytes);
    return zoobc::Error{zoobc::ErrorCode::Internal,
                        "signing context not resolved: ensure_signing_context() must run first "
                        "(pass --api <node>, or --genesis <hex>)"};
}

// ============================================================================
// Signing (dispatches by key type)
// ============================================================================

struct SignResult {
    std::vector<uint8_t> signature;
    std::vector<uint8_t> tx_bytes_hash;   // the digest that was signed
};

inline zoobc::Result<SignResult> sign_transaction(
    const std::vector<uint8_t>& tx_bytes,
    const DerivedKeys& keys) {

    SignResult sr;

    // One digest for every key type: the node computes it once and hands the same 32 bytes to
    // whichever verifier the sender's account type selects. (The ETH branch used to Keccak the
    // bytes first and the BTC branch used to double-SHA256 them, on top of what the signers do
    // internally — neither matched what the node verifies, so those paths never worked.)
    auto digest = signing_digest(tx_bytes);
    if (!digest.IsOk()) return zoobc::Error{digest.GetError()};
    sr.tx_bytes_hash = digest.Value();

    if (keys.type == KeyType::ZBC) {
        auto sig_result = Signature::Sign(sr.tx_bytes_hash, keys.keypair.private_key);
        if (!sig_result.IsOk()) return zoobc::Error{sig_result.GetError()};
        sr.signature = sig_result.Value();

    } else if (keys.type == KeyType::ETH) {
        // EthereumSignature::Sign applies Keccak-256 to its input itself, as RecoverPublicKey does
        // on the node: sign the digest as-is.
        zoobc::crypto::EthereumSignature eth_sig;
        auto sig_result = eth_sig.Sign(keys.keypair.private_key, sr.tx_bytes_hash);
        if (!sig_result.IsOk()) return zoobc::Error{sig_result.GetError()};
        sr.signature = sig_result.Value();

    } else if (keys.type == KeyType::BTC) {
        // BitcoinSignature::Sign applies double-SHA256 itself, matching its Verify.
        zoobc::crypto::BitcoinSignature btc_sig;
        auto sig_result = btc_sig.Sign(keys.keypair.private_key, sr.tx_bytes_hash);
        if (!sig_result.IsOk()) return zoobc::Error{sig_result.GetError()};
        auto raw_sig = sig_result.Value();

        // BTC format: [2 bytes pubkey_len LE] + [pubkey] + [signature]
        uint16_t pubkey_len = static_cast<uint16_t>(keys.keypair.public_key.size());
        sr.signature.resize(2 + pubkey_len + raw_sig.size());
        sr.signature[0] = pubkey_len & 0xFF;
        sr.signature[1] = (pubkey_len >> 8) & 0xFF;
        std::copy(keys.keypair.public_key.begin(), keys.keypair.public_key.end(), sr.signature.begin() + 2);
        std::copy(raw_sig.begin(), raw_sig.end(), sr.signature.begin() + 2 + pubkey_len);
    }

    return sr;
}

// ZBC-only signing (simpler, for node tools)
inline zoobc::Result<SignResult> sign_transaction_zbc(
    const std::vector<uint8_t>& tx_bytes,
    const zoobc::crypto::KeyPair& owner_keypair) {

    SignResult sr;
    auto hash_result = signing_digest(tx_bytes);
    if (!hash_result.IsOk()) return zoobc::Error{hash_result.GetError()};
    sr.tx_bytes_hash = hash_result.Value();

    auto sig_result = Signature::Sign(sr.tx_bytes_hash, owner_keypair.private_key);
    if (!sig_result.IsOk()) return zoobc::Error{sig_result.GetError()};
    sr.signature = sig_result.Value();
    return sr;
}

// ============================================================================
// Transaction hash (SHA3-256 of tx_bytes + signature)
// ============================================================================

inline zoobc::Result<std::vector<uint8_t>> calculate_tx_hash(
    const std::vector<uint8_t>& tx_bytes,
    const std::vector<uint8_t>& signature) {

    std::vector<uint8_t> complete;
    complete.reserve(tx_bytes.size() + signature.size());
    complete.insert(complete.end(), tx_bytes.begin(), tx_bytes.end());
    complete.insert(complete.end(), signature.begin(), signature.end());
    return zoobc::crypto::Hash::SHA3_256(complete);
}

// ============================================================================
// ProofOfOwnership
// ============================================================================

struct BlockInfo {
    std::vector<uint8_t> hash;
    uint32_t height;
    bool valid;
};


// ============================================================================
// One HTTP client for every tool
// ============================================================================
// The scheme used to be stripped and thrown away: `https://host` became `host` while the port stayed
// 80 and the client stayed plaintext, so every tool silently dialled port 80 in the clear and a
// public gateway answered with a CDN error. Nothing could submit a transaction to an https endpoint.
//
// Parse it once, here, and let the caller stay ignorant of the transport.
struct ApiTarget {
    std::string host;
    int port = 80;
    bool tls = false;
    std::string path_prefix;   // e.g. "/faucet" when the API lives under a sub-path
};

inline ApiTarget parse_api_url(const std::string& api_url) {
    ApiTarget t;
    std::string rest = api_url;
    if (rest.rfind("https://", 0) == 0) { t.tls = true;  t.port = 443; rest = rest.substr(8); }
    else if (rest.rfind("http://", 0) == 0) { t.tls = false; t.port = 80;  rest = rest.substr(7); }

    // A path after the host is kept, so `--api https://host/faucet` still addresses the right API.
    if (auto slash = rest.find('/'); slash != std::string::npos) {
        t.path_prefix = rest.substr(slash);
        while (!t.path_prefix.empty() && t.path_prefix.back() == '/') t.path_prefix.pop_back();
        rest = rest.substr(0, slash);
    }
    // An explicit port wins over the scheme default. IPv6 literals are not supported here and never
    // were; a bracketed host would need its own branch.
    if (auto colon = rest.rfind(':'); colon != std::string::npos) {
        t.host = rest.substr(0, colon);
        try { t.port = std::stoi(rest.substr(colon + 1)); } catch (...) {}
    } else {
        t.host = rest;
    }
    return t;
}

// httplib's Client and SSLClient are unrelated types, so the two paths cannot be collapsed behind a
// reference without a virtual base. A tiny wrapper is less code than the alternative and keeps the
// header/timeout policy in exactly one place.
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
using ZbcHttpClient = httplib::SSLClient;
#endif

// Headers every request carries. httplib adds its own Content-Type when the body form is used, so
// passing one in the Headers map too produced a DUPLICATE Content-Type; and an empty Accept-Encoding
// is malformed. Both are the kind of thing a WAF in front of a gateway rejects out of hand.
inline httplib::Headers zbc_default_headers() {
    return httplib::Headers{{"User-Agent", "zbc-cli/1.0"}, {"Accept", "application/json"}};
}

template <typename Fn>
inline auto with_api_client(const ApiTarget& t, Fn&& fn) -> decltype(fn(std::declval<httplib::Client&>())) {
    // One bound for connect/read/write: --timeout (default 20 s). A transaction command makes two
    // calls, so its worst case is twice this.
    const int to = http_timeout_seconds() > 0 ? http_timeout_seconds() : 20;
    if (t.tls) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
        httplib::SSLClient c(t.host.c_str(), t.port);
        c.set_connection_timeout(to, 0);
        c.set_read_timeout(to, 0);
        c.set_write_timeout(to, 0);
        c.set_follow_location(true);
        c.set_default_headers(zbc_default_headers());
        return fn(c);
#else
        // Built without TLS: say so rather than dialling plaintext on 443 and reporting a confusing
        // connection error.
        throw std::runtime_error("this build has no TLS support; use an http:// api url");
#endif
    }
    httplib::Client c(t.host.c_str(), t.port);
    c.set_connection_timeout(to, 0);
    c.set_read_timeout(to, 0);
    c.set_write_timeout(to, 0);
    c.set_follow_location(true);
    c.set_default_headers(zbc_default_headers());
    return fn(c);
}

// Resolve the signing rule for this run: from --genesis / ZOOBC_GENESIS_HASH, else by asking the
// node at --api which rule it enforces and which chain it is. Idempotent; run before any digest.
inline bool ensure_signing_context(const std::string& api_url,
                                   const std::string& genesis_override,
                                   const std::function<void(const std::string&)>& emit_error) {
    auto& c = signing_context();
    if (c.version != 0) return true;

    std::string wanted = genesis_override;
    if (wanted.empty()) {
        const char* env = std::getenv("ZOOBC_GENESIS_HASH");
        if (env && *env) wanted = env;
    }
    if (wanted == "v1" || wanted == "legacy") {
        c.version = 1; c.source = "--genesis v1 (legacy, unbound)";
        return true;
    }
    if (!wanted.empty()) {
        auto bytes = hex_to_bytes(wanted);
        if (bytes.size() != 32) {
            emit_error("--genesis must be the 64-hex genesis block hash (or 'v1' for the legacy digest)");
            return false;
        }
        c.version = 2; c.genesis_hash = bytes; c.source = "--genesis";
        return true;
    }

    // Ask the node. It reports signing_version (absent on pre-v0.4.0 nodes) and genesis_hash.
    try {
        const ApiTarget t = parse_api_url(api_url);
        auto res = with_api_client(t, [&](auto& cl) {
            return cl.Get((t.path_prefix + "/api/v1/node/info").c_str());
        });
        if (!res) {
            const int code = classify_transport_error(res.error());
            fail(emit_error, code,
                 std::string(code == exit_code::TIMEOUT ? "timed out reading" : "cannot read") +
                 " /api/v1/node/info from " + api_url + " (" + httplib::to_string(res.error()) +
                 ") to learn which chain to sign for; pass --genesis <hex> to sign for a known chain");
            return false;
        }
        if (res->status != 200) {
            fail(emit_error, res->status >= 500 ? exit_code::NODE_BUSY : exit_code::UNREACHABLE,
                 "cannot read /api/v1/node/info from " + api_url + " (HTTP " + std::to_string(res->status) +
                 ") to learn which chain to sign for; pass --genesis <hex> to sign for a known chain");
            return false;
        }
        auto j = json::parse(res->body);
        const int sv = j.value("signing_version", 1);
        if (sv >= 2) {
            auto bytes = hex_to_bytes(j.value("genesis_hash", ""));
            if (bytes.size() != 32) {
                emit_error("node enforces chain-bound signing but reports no genesis hash; pass --genesis <hex>");
                return false;
            }
            c.version = 2; c.genesis_hash = bytes; c.source = api_url;
        } else {
            c.version = 1; c.source = api_url + " (signing v1, legacy)";
        }
        return true;
    } catch (const std::exception& e) {
        fail(emit_error, exit_code::UNREACHABLE,
             std::string("cannot resolve the chain's signing rule: ") + e.what() + "; pass --genesis <hex>");
        return false;
    }
}

inline BlockInfo fetch_latest_block(const std::string& api_url) {
    BlockInfo info;
    info.valid = false;
    info.height = 0;

    const ApiTarget t = parse_api_url(api_url);
    httplib::Result res = with_api_client(t, [&](auto& c) {
        return c.Get((t.path_prefix + "/api/v1/blocks/latest").c_str());
    });
    if (!res || res->status != 200) return info;

    try {
        auto response = json::parse(res->body);
        info.height = response.value("height", 0u);
        std::string hash_hex = response.value("block_hash", "");
        if (!hash_hex.empty()) {
            info.hash = hex_to_bytes(hash_hex);
            info.valid = true;
        }
    } catch (...) {}

    return info;
}

inline std::vector<uint8_t> build_poown_message(
    const std::vector<uint8_t>& account_address,
    const std::vector<uint8_t>& block_hash,
    uint32_t block_height) {

    std::vector<uint8_t> message;
    message.reserve(TransactionUtil::ZBC_POOWN_MESSAGE_SIZE);
    message.insert(message.end(), account_address.begin(), account_address.end());
    message.insert(message.end(), block_hash.begin(), block_hash.end());
    TransactionUtil::WriteUint32LE(message, block_height);
    return message;
}

// Build full ProofOfOwnership: fetch block, build message, sign
inline zoobc::Result<std::vector<uint8_t>> build_proof_of_ownership(
    const zoobc::crypto::KeyPair& owner_keypair,
    const std::string& api_url) {

    auto block_info = fetch_latest_block(api_url);
    if (!block_info.valid) {
        return zoobc::Error{zoobc::ErrorCode::NetworkError, "Failed to fetch latest block from " + api_url};
    }

    auto owner_account_address = TransactionUtil::BuildAccountAddress(
        TransactionUtil::ACCOUNT_TYPE_ZBC, owner_keypair.public_key);

    auto poown_msg = build_poown_message(owner_account_address, block_info.hash, block_info.height);

    auto sig_result = Signature::Sign(poown_msg, owner_keypair.private_key);
    if (!sig_result.IsOk()) {
        return zoobc::Error{sig_result.GetError()};
    }

    std::vector<uint8_t> proof;
    proof.reserve(TransactionUtil::ZBC_POOWN_SIZE);
    proof.insert(proof.end(), poown_msg.begin(), poown_msg.end());
    proof.insert(proof.end(), sig_result.Value().begin(), sig_result.Value().end());
    return proof;
}

// ============================================================================
// HTTP submission
// ============================================================================

struct SubmitResult {
    int http_code;
    std::string response_body;
    json response_json;
    bool ok;
    httplib::Error transport_error = httplib::Error::Success;  // set when http_code == 0
};

inline SubmitResult submit_transaction(const std::string& api_url, const std::string& json_payload) {
    SubmitResult sr;
    sr.ok = false;
    sr.http_code = 0;

    const ApiTarget t = parse_api_url(api_url);
    httplib::Result res;
    try {
        res = with_api_client(t, [&](auto& c) {
            // No Headers overload: httplib sets Content-Type from the last argument, and passing it
            // in a Headers map as well emitted the header TWICE.
            return c.Post((t.path_prefix + "/api/v1/transactions").c_str(), json_payload, "application/json");
        });
    } catch (const std::exception& e) {
        sr.response_body = e.what();
        sr.transport_error = httplib::Error::Connection;
        return sr;
    }

    if (!res) {
        sr.transport_error = res.error();
        sr.response_body = (classify_transport_error(res.error()) == exit_code::TIMEOUT ? "Timed out: " : "Connection failed: ") +
                           httplib::to_string(res.error());
        return sr;
    }

    sr.http_code = res->status;
    sr.response_body = res->body;
    sr.response_json = json::parse(sr.response_body, nullptr, false);
    sr.ok = (sr.http_code == 200 || sr.http_code == 202);
    return sr;
}

// ============================================================================
// Escrow handling
// ============================================================================

struct EscrowParams {
    std::string approver;
    int64_t commission = 0;
    int64_t timeout = 0;
    std::string instruction;
    bool active = false;
};

inline zoobc::Result<std::vector<uint8_t>> build_escrow_data(
    const EscrowParams& params, json& escrow_json) {

    auto approver_result = parse_address(params.approver);
    if (!approver_result.IsOk()) {
        return zoobc::Error{approver_result.GetError()};
    }

    zoobc::model::Escrow escrow_value;
    escrow_value.approver_address = approver_result.Value().address;
    escrow_value.commission = params.commission;
    escrow_value.timeout = params.timeout;
    escrow_value.instruction = params.instruction;
    escrow_value.multi_party = false;
    auto bytes = TransactionUtil::GetEscrowBytes(escrow_value);

    escrow_json = {
        {"approver_address", bytes_to_hex(escrow_value.approver_address)},
        {"commission", escrow_value.commission},
        {"timeout", escrow_value.timeout}
    };
    if (!escrow_value.instruction.empty()) {
        escrow_json["instruction"] = escrow_value.instruction;
    }

    return bytes;
}

// ============================================================================
// CLI parameter framework
// ============================================================================

struct ParamDef {
    std::string name;            // Display name for help
    std::string json_key;        // Key in JSON input
    std::string prompt;          // Prompt text for interactive mode
    std::string default_value;   // Default if empty
    bool required = true;
    std::function<bool(const std::string&)> validator;
};

struct ToolConfig {
    std::string name;            // Tool display name (e.g., "ZooBC Transfer Tool")
    std::string description;     // One-line description
    std::vector<ParamDef> params;
    uint32_t tx_type;
    bool has_recipient = false;
    bool needs_poown = false;
    bool supports_multi_key = false;
};

struct ParsedParams {
    std::vector<std::string> values;  // Positional param values (indexed by params order)
    bool json_output = true;
    KeyType sender_type = KeyType::ZBC;
    std::string message_text;
    bool encrypt_message = false;  // --encrypt: seal the message to the recipient's key
    EscrowParams escrow;
    std::string api_url = "http://localhost:8080";
    // --genesis: sign for this chain (64-hex genesis block hash) without asking the node, or "v1"
    // for the legacy unbound digest. Empty = ask --api which rule it enforces.
    std::string genesis_hex;
    int64_t fee = 5000000;   // 0.05 ZBC — above the node minimum (~0.025); 0.01 was rejected "fee too low"
    int64_t token_id = 0;  // --token: stream a colored-coin token instead of ZBC (liquid payment)
    // --chain: read the recipient as this chain. Detection is by checksum and needs no help, but an
    // 0x… address is valid on every EVM chain, so an explicit answer must always be possible.
    std::string chain;
    // --hex: a `message` parameter (sign-message / verify-message) is hex-encoded bytes, not text.
    bool hex_input = false;
};

// Check if stdin is a terminal (not piped)
inline bool is_stdin_terminal() {
#ifdef _WIN32
    return _isatty(_fileno(stdin));
#else
    return isatty(fileno(stdin));
#endif
}

inline void print_tool_usage(const ToolConfig& config, const char* program) {
    std::cout << config.name << std::endl;
    std::cout << std::string(config.name.length(), '=') << std::endl;
    std::cout << std::endl;
    std::cout << config.description << std::endl;
    std::cout << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << "  " << program << " [options]";
    for (const auto& p : config.params) {
        if (p.required)
            std::cout << " <" << p.json_key << ">";
        else
            std::cout << " [" << p.json_key << "]";
    }
    // [fee] is consumed FIRST from the extra positionals for every command, whether or not it has a
    // recipient. Printing it only for recipient commands told everyone else that the next argument
    // was the api_url — so following this tool's own help put a URL where the fee is parsed, and the
    // tool aborted on it. Always show both, in the order they are actually read.
    std::cout << " [fee] [api_url]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -v, --verbose         Verbose output (default is JSON)" << std::endl;
    std::cout << "  --json-input          Read parameters from JSON on stdin" << std::endl;
    std::cout << "  --chain <name>        Read the recipient as this chain: zbc, btc, eth, sol," << std::endl;
    std::cout << "                        dot, ada, xrp, trx, xtz. Detection is automatic; use this" << std::endl;
    std::cout << "                        only to force a reading." << std::endl;
    if (config.supports_multi_key) {
        std::cout << "  --eth                 Use Ethereum key (secp256k1)" << std::endl;
        std::cout << "  --btc                 Use Bitcoin key (secp256k1)" << std::endl;
    }
    std::cout << "  --message <text>      Optional transaction message" << std::endl;
    std::cout << "  --encrypt             Encrypt --message to the recipient (ZBC only)" << std::endl;
    std::cout << "  --genesis <hex|v1>    Sign for this chain (its genesis block hash) without asking" << std::endl;
    std::cout << "                        the node; 'v1' = legacy unbound digest. Default: ask --api." << std::endl;
    std::cout << "  --escrow-approver <addr>   Escrow approver address" << std::endl;
    std::cout << "  --escrow-commission <n>    Escrow commission (atomic units)" << std::endl;
    std::cout << "  --escrow-timeout <n>       Escrow timeout as a FUTURE Unix timestamp (seconds), e.g. now+3600" << std::endl;
    std::cout << "  --escrow-instruction <s>   Escrow instruction" << std::endl;
    std::cout << "  --fee <n>             Transaction fee (default: 5000000 = 0.05 ZBC)" << std::endl;
    std::cout << "  --api <url>           API endpoint (default: $ZBC_API, else http://localhost:8080)" << std::endl;
    std::cout << "  --timeout <s>         Bound for each HTTP call, seconds (default: $ZBC_TIMEOUT, else 20;" << std::endl;
    std::cout << "                        also --timeout-seconds). A command makes up to two calls." << std::endl;
    std::cout << "  --hex                 sign-message/verify-message: the message is hex bytes, not text" << std::endl;
    std::cout << std::endl;
    std::cout << "Environment:" << std::endl;
    std::cout << "  ZBC_KEY               Sender private key (64 hex). Used when the key argument is omitted" << std::endl;
    std::cout << "                        or given as '-' (positional), or absent/'-' in stdin JSON." << std::endl;
    std::cout << "  ZBC_API, ZBC_TIMEOUT  Defaults for --api and --timeout." << std::endl;
    std::cout << "  ZOOBC_GENESIS_HASH    Default for --genesis." << std::endl;
    std::cout << std::endl;
    std::cout << "Exit codes:" << std::endl;
    std::cout << "  0 ok  1 internal  2 usage  3 node unreachable  4 insufficient balance  5 fee too low" << std::endl;
    std::cout << "  6 rejected by node  7 not found  8 timeout  9 node busy (5xx)  10 signature invalid" << std::endl;
    std::cout << "  JSON errors carry the same code as \"exit_code\" and its name as \"error_class\"." << std::endl;
    std::cout << std::endl;
    std::cout << "Parameters:" << std::endl;
    for (const auto& p : config.params) {
        std::cout << "  " << std::left << std::setw(22) << p.json_key << p.name << std::endl;
    }
    std::cout << std::endl;
    std::cout << "Modes:" << std::endl;
    std::cout << "  CLI args:     " << program << " <args...>" << std::endl;
    std::cout << "  JSON stdin:   echo '{...}' | " << program << " --json-input" << std::endl;
    std::cout << "  Interactive:  " << program << "  (no args, terminal stdin)" << std::endl;
    std::cout << std::endl;
}

// Read a line from stdin with prompt
inline std::string read_prompted(const std::string& prompt, const std::string& default_val = "") {
    std::string input;
    std::cout << "  " << prompt;
    if (!default_val.empty()) std::cout << " [" << default_val << "]";
    std::cout << ": ";
    std::getline(std::cin, input);
    if (input.empty() && !default_val.empty()) input = default_val;
    return input;
}

// Parse params from CLI args, JSON stdin, or interactive prompts
inline int parse_params(const ToolConfig& config, int argc, char* argv[], ParsedParams& out,
                        const std::function<void(const std::string&)>& emit_error) {
    bool json_input = false;
    std::vector<std::string> positional;
    bool escrow_commission_set = false;
    bool escrow_timeout_set = false;
    bool api_set = false;

    // Parse CLI flags
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-v" || arg == "--verbose") {
            out.json_output = false;
        } else if (arg == "--json") {
            out.json_output = true;
        } else if (arg == "--chain" && i + 1 < argc) {
            out.chain = argv[++i];
        } else if (arg == "--json-input") {
            json_input = true;
        } else if (arg == "--eth" && config.supports_multi_key) {
            out.sender_type = KeyType::ETH;
        } else if (arg == "--btc" && config.supports_multi_key) {
            out.sender_type = KeyType::BTC;
        } else if (arg == "--encrypt") {
            out.encrypt_message = true;
        } else if (arg == "--hex") {
            out.hex_input = true;
        } else if (arg == "--message") {
            if (i + 1 >= argc) return fail(emit_error, exit_code::USAGE, "--message requires a value");
            out.message_text = argv[++i];
        } else if (arg == "--fee") {
            if (i + 1 >= argc) return fail(emit_error, exit_code::USAGE, "--fee requires a value");
            try { out.fee = std::stoll(argv[++i]); }
            catch (const std::exception&) { return fail(emit_error, exit_code::USAGE, "--fee must be a whole number of atomic units"); }
        } else if (arg == "--api") {
            if (i + 1 >= argc) return fail(emit_error, exit_code::USAGE, "--api requires a value");
            out.api_url = argv[++i];
            api_set = true;
        } else if (arg == "--timeout" || arg == "--timeout-seconds") {
            if (i + 1 >= argc) return fail(emit_error, exit_code::USAGE, arg + " requires a value (seconds)");
            try { http_timeout_seconds() = std::stoi(argv[++i]); }
            catch (const std::exception&) { return fail(emit_error, exit_code::USAGE, arg + " must be a whole number of seconds"); }
            if (http_timeout_seconds() <= 0) return fail(emit_error, exit_code::USAGE, arg + " must be > 0");
        } else if (arg == "--genesis") {
            if (i + 1 >= argc) return fail(emit_error, exit_code::USAGE, "--genesis requires a value");
            out.genesis_hex = argv[++i];
        } else if (arg == "--escrow-approver") {
            if (i + 1 >= argc) return fail(emit_error, exit_code::USAGE, "--escrow-approver requires a value");
            out.escrow.approver = argv[++i];
        } else if (arg == "--escrow-commission") {
            if (i + 1 >= argc) return fail(emit_error, exit_code::USAGE, "--escrow-commission requires a value");
            try { out.escrow.commission = std::stoll(argv[++i]); }
            catch (const std::exception&) { return fail(emit_error, exit_code::USAGE, "--escrow-commission must be a whole number of atomic units"); }
            escrow_commission_set = true;
        } else if (arg == "--escrow-timeout") {
            if (i + 1 >= argc) return fail(emit_error, exit_code::USAGE, "--escrow-timeout requires a value");
            try { out.escrow.timeout = std::stoll(argv[++i]); }
            catch (const std::exception&) { return fail(emit_error, exit_code::USAGE, "--escrow-timeout must be a Unix timestamp in seconds"); }
            escrow_timeout_set = true;
        } else if (arg == "--escrow-instruction") {
            if (i + 1 >= argc) return fail(emit_error, exit_code::USAGE, "--escrow-instruction requires a value");
            out.escrow.instruction = argv[++i];
        } else if (arg == "--token") {
            if (i + 1 >= argc) return fail(emit_error, exit_code::USAGE, "--token requires a value");
            try { out.token_id = std::stoll(argv[++i]); }
            catch (const std::exception&) { return fail(emit_error, exit_code::USAGE, "--token must be a decimal token id"); }
        } else if (arg == "--help" || arg == "-h") {
            print_tool_usage(config, argv[0]);
            return -1;  // Signal help printed, exit 0
        } else if (arg.size() > 1 && arg[0] == '-' && !std::isdigit((unsigned char)arg[1]) && arg[1] != '.') {
            // A leading '-' followed by a non-digit is an option; '-<digit>' is a negative number
            // (e.g. a hash-derived token_id / tx_id, which is a signed int64 and often negative).
            // A bare '-' is the "take the key from ZBC_KEY" placeholder and stays positional.
            return fail(emit_error, exit_code::USAGE, "Unknown option: " + arg);
        } else {
            positional.push_back(arg);
        }
    }

    // Environment defaults (flags win): ZBC_API for the endpoint, ZBC_TIMEOUT for the HTTP bound.
    if (!api_set) {
        if (const char* env_api = std::getenv("ZBC_API"); env_api && *env_api) out.api_url = env_api;
    }
    if (const char* env_to = std::getenv("ZBC_TIMEOUT"); env_to && *env_to && http_timeout_seconds() == 20) {
        try { int t = std::stoi(env_to); if (t > 0) http_timeout_seconds() = t; } catch (...) {}
    }
    // ZBC_KEY: the sender key without putting it in argv (visible in `ps`) or in a file. It applies
    // only to commands whose first parameter is the sender key, never to e.g. verify-message.
    const bool key_is_first = !config.params.empty() && config.params[0].json_key == "sender_privkey";
    const char* env_key_c = key_is_first ? std::getenv("ZBC_KEY") : nullptr;
    const std::string env_key = (env_key_c && *env_key_c) ? std::string(env_key_c) : std::string();
    auto is_key_placeholder = [](const std::string& s) { return s == "-" || s == "@env" || s == "env:ZBC_KEY"; };

    out.values.resize(config.params.size());

    if (json_input || (!is_stdin_terminal() && positional.empty())) {
        // JSON input mode: read JSON from stdin
        std::string json_str;
        std::string line;
        while (std::getline(std::cin, line)) {
            json_str += line;
        }
        if (json_str.empty()) return fail(emit_error, exit_code::USAGE, "No JSON input received on stdin");
        auto j = json::parse(json_str, nullptr, false);
        if (j.is_discarded()) return fail(emit_error, exit_code::USAGE, "Invalid JSON input");

        for (size_t i = 0; i < config.params.size(); i++) {
            const auto& p = config.params[i];
            if (j.contains(p.json_key)) {
                if (j[p.json_key].is_string())
                    out.values[i] = j[p.json_key].get<std::string>();
                else
                    out.values[i] = j[p.json_key].dump();
            } else if (!p.default_value.empty()) {
                out.values[i] = p.default_value;
            } else if (i == 0 && key_is_first && !env_key.empty()) {
                out.values[i] = env_key;  // sender_privkey omitted: ZBC_KEY supplies it
            } else if (p.required) {
                return fail(emit_error, exit_code::USAGE, "Missing required field: " + p.json_key);
            }
            if (i == 0 && key_is_first && is_key_placeholder(out.values[i])) {
                if (env_key.empty()) return fail(emit_error, exit_code::USAGE, "sender_privkey is '-' but ZBC_KEY is not set");
                out.values[i] = env_key;
            }
        }
        try {
            if (j.contains("fee")) {
                if (j["fee"].is_number()) out.fee = j["fee"].get<int64_t>();
                else out.fee = std::stoll(j["fee"].get<std::string>());
            }
            if (j.contains("timeout_seconds")) {
                int t = j["timeout_seconds"].is_number() ? j["timeout_seconds"].get<int>()
                                                          : std::stoi(j["timeout_seconds"].get<std::string>());
                if (t <= 0) return fail(emit_error, exit_code::USAGE, "timeout_seconds must be > 0");
                http_timeout_seconds() = t;
            }
        } catch (const std::exception&) {
            return fail(emit_error, exit_code::USAGE, "fee / timeout_seconds must be whole numbers");
        }
        if (j.contains("api_url")) out.api_url = j["api_url"].get<std::string>();
        if (j.contains("message")) out.message_text = j["message"].get<std::string>();
        if (j.contains("hex") && j["hex"].is_boolean()) out.hex_input = j["hex"].get<bool>();
        if (j.contains("verbose") && j["verbose"].get<bool>()) out.json_output = false;
        // Escrow from JSON
        if (j.contains("escrow")) {
            auto& ej = j["escrow"];
            if (ej.contains("approver")) out.escrow.approver = ej["approver"].get<std::string>();
            if (ej.contains("commission")) out.escrow.commission = ej["commission"].get<int64_t>();
            if (ej.contains("timeout")) out.escrow.timeout = ej["timeout"].get<int64_t>();
            if (ej.contains("instruction")) out.escrow.instruction = ej["instruction"].get<std::string>();
        }

    } else if (positional.empty() && is_stdin_terminal()) {
        // Interactive mode
        std::cout << config.name << std::endl;
        std::cout << std::string(config.name.length(), '=') << std::endl;
        std::cout << std::endl;

        for (size_t i = 0; i < config.params.size(); i++) {
            const auto& p = config.params[i];
            out.values[i] = read_prompted(p.prompt, p.default_value);
            if (out.values[i].empty() && p.required) {
                emit_error("Required parameter: " + p.name);
                return 1;
            }
        }

        std::string fee_str = read_prompted("Transaction fee (atomic units)", "5000000");
        if (!fee_str.empty()) out.fee = std::stoll(fee_str);
        out.api_url = read_prompted("API URL", "http://localhost:8080");
        out.message_text = read_prompted("Message (optional)", "");

        std::string escrow_choice = read_prompted("Use escrow? (y/N)", "N");
        if (escrow_choice == "y" || escrow_choice == "Y") {
            out.escrow.approver = read_prompted("Escrow approver address");
            std::string comm = read_prompted("Escrow commission", "0");
            out.escrow.commission = std::stoll(comm);
            escrow_commission_set = true;
            std::string timeout = read_prompted("Escrow timeout (future Unix timestamp, seconds)");
            out.escrow.timeout = std::stoll(timeout);
            escrow_timeout_set = true;
            out.escrow.instruction = read_prompted("Escrow instruction (optional)", "");
        }
        out.json_output = false;  // Interactive mode defaults to verbose

    } else {
        // CLI positional mode.
        //
        // ZBC_KEY: the key may be left out of argv entirely. When the env var is set and one fewer
        // positional than the command's required count was given, the key is taken from the env and
        // the positionals shift right by one. An explicit '-' (or '@env') in the key position always
        // means "from ZBC_KEY", regardless of how many positionals follow — use that form in scripts
        // that also pass the optional trailing [fee] [api_url].
        if (key_is_first) {
            size_t required = 0;
            for (const auto& p : config.params) if (p.required && p.default_value.empty()) required++;
            if (!positional.empty() && is_key_placeholder(positional[0])) {
                if (env_key.empty()) return fail(emit_error, exit_code::USAGE, "key argument is '-' but ZBC_KEY is not set");
                positional[0] = env_key;
            } else if (!env_key.empty() && positional.size() + 1 == required) {
                positional.insert(positional.begin(), env_key);
            }
        }
        for (size_t i = 0; i < config.params.size(); i++) {
            if (i < positional.size()) {
                out.values[i] = positional[i];
            } else if (!config.params[i].default_value.empty()) {
                out.values[i] = config.params[i].default_value;
            } else if (config.params[i].required) {
                return fail(emit_error, exit_code::USAGE, "Missing required argument: " + config.params[i].name +
                            (i == 0 && key_is_first ? " (pass it, or set ZBC_KEY)" : ""));
            }
        }

        // Extra positional args: fee, api_url (after tool-specific params)
        size_t extra_start = config.params.size();
        if (extra_start < positional.size()) {
            // An unguarded stoll here aborted the process with a bare
            // "terminate called after throwing an instance of 'std::invalid_argument'"
            // whenever this argument was not a number — which is what happens when someone passes
            // an api_url positionally, the very thing the usage line used to invite. A CLI must
            // explain a bad argument, not die on it.
            const std::string& fee_arg = positional[extra_start];
            try {
                size_t consumed = 0;
                out.fee = std::stoll(fee_arg, &consumed);
                if (consumed != fee_arg.size()) throw std::invalid_argument("trailing characters");
            } catch (const std::exception&) {
                return fail(emit_error, exit_code::USAGE,
                            "Fee must be a whole number of atomic units, got \"" + fee_arg +
                            "\". The API endpoint is passed with --api URL, not as a positional argument.");
            }
        }
        if (extra_start + 1 < positional.size()) {
            out.api_url = positional[extra_start + 1];
        }
    }

    // Validate escrow
    out.escrow.active = !out.escrow.approver.empty() || escrow_commission_set ||
                        escrow_timeout_set || !out.escrow.instruction.empty();
    if (out.escrow.active) {
        if (out.escrow.approver.empty()) return fail(emit_error, exit_code::USAGE, "Escrow requires --escrow-approver");
        if (out.escrow.timeout <= 0) return fail(emit_error, exit_code::USAGE, "Escrow requires --escrow-timeout > 0");
        if (out.escrow.commission < 0) return fail(emit_error, exit_code::USAGE, "Escrow commission cannot be negative");
    }

    return 0;
}

// ============================================================================
// Output helpers
// ============================================================================

inline void emit_error_json(const std::string& message) {
    const int code = pending_exit_code() ? pending_exit_code() : exit_code::INTERNAL;
    pending_exit_code() = 0;
    json result = {{"success", false}, {"error", message},
                   {"exit_code", code}, {"error_class", exit_code::name(code)}};
    std::cout << result.dump() << std::endl;
}

inline void emit_error_verbose(const std::string& message) {
    std::cerr << "Error: " << message << std::endl;
}

// Create an emit_error function based on json_output flag
inline std::function<void(const std::string&)> make_emitter(bool json_output) {
    if (json_output) return emit_error_json;
    return emit_error_verbose;
}

// ============================================================================
// Build JSON payload for submission
// ============================================================================

inline std::string build_json_payload(
    int32_t version,
    int64_t timestamp,
    const std::vector<uint8_t>& sender_pubkey,
    const std::vector<uint8_t>& recipient_pubkey,  // Just pubkey, no type prefix
    uint32_t tx_type,
    int64_t fee,
    const std::vector<uint8_t>& body_bytes,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& message_bytes,
    const json& escrow_json) {

    json tx_json = {
        {"version", version},
        {"timestamp", timestamp},
        {"sender_account_address", bytes_to_hex(sender_pubkey)},
        {"recipient_account_address", bytes_to_hex(recipient_pubkey)},
        {"transaction_type", tx_type},
        {"fee", fee},
        {"transaction_body_bytes", bytes_to_hex(body_bytes)},
        {"signature", bytes_to_hex(signature)}
    };
    // Carry the EXACT signed message bytes as hex (binary-safe). A plaintext
    // string field would corrupt encrypted (non-UTF-8) bytes and mismatch the
    // signature; message_hex preserves them verbatim.
    if (!message_bytes.empty()) {
        tx_json["message_hex"] = bytes_to_hex(message_bytes);
    }
    if (!escrow_json.empty() && !escrow_json.is_null()) {
        tx_json["escrow"] = escrow_json;
    }
    return tx_json.dump();
}

// ============================================================================
// Full transaction lifecycle helper
// ============================================================================

// Runs the complete tx lifecycle: build body -> build tx_bytes -> sign -> hash -> submit -> output
// Tool-specific code just needs to provide body_bytes and extra output fields.
inline int run_transaction(
    const ParsedParams& params,
    uint32_t tx_type,
    const std::vector<uint8_t>& sender_pubkey,       // 32-byte pubkey (ZBC)
    const std::vector<uint8_t>& recipient_address,    // Full address with type prefix, or empty
    const std::vector<uint8_t>& body_bytes,
    const zoobc::crypto::KeyPair& signing_keypair,    // Keypair for signing
    KeyType signing_type,                              // Key type for dispatch
    const json& extra_success_fields,                  // Extra fields to add to JSON success output
    const std::function<void(const std::string&)>& emit_error,
    const std::string& verbose_success_msg = "") {

    try {
        std::vector<uint8_t> message_bytes(params.message_text.begin(), params.message_text.end());

        // --encrypt: seal the message to the recipient so only they can read it.
        // Only meaningful for ZBC (Ed25519) recipients; the pubkey is the 32 bytes
        // following the 4-byte type prefix of the recipient address.
        if (params.encrypt_message && !message_bytes.empty()) {
            if (recipient_address.size() != 36) {
                return fail(emit_error, exit_code::USAGE, "--encrypt is only supported for ZBC recipients");
            }
            std::vector<uint8_t> recipient_pubkey(recipient_address.begin() + 4, recipient_address.end());
            auto enc = zoobc::crypto::MessageEncryption::Encrypt(message_bytes, recipient_pubkey);
            if (!enc.IsOk()) {
                emit_error("Message encryption failed: " + enc.GetError().ToString());
                return 1;
            }
            message_bytes = enc.Value();
        }
        std::vector<uint8_t> escrow_bytes;
        json escrow_json;

        if (params.escrow.active) {
            auto eb_result = build_escrow_data(params.escrow, escrow_json);
            if (!eb_result.IsOk()) {
                return fail(emit_error, exit_code::USAGE, "Invalid escrow approver: " + eb_result.GetError().ToString());
            }
            escrow_bytes = eb_result.Value();
        }

        int32_t version = 1;
        int64_t timestamp = static_cast<int64_t>(std::time(nullptr));

        // Build transaction bytes
        std::vector<uint8_t> tx_bytes;
        if (signing_type == KeyType::ZBC) {
            tx_bytes = build_transaction_bytes(
                version, timestamp, sender_pubkey, recipient_address,
                tx_type, params.fee, body_bytes, escrow_bytes, message_bytes);
        } else {
            // For ETH/BTC, sender_address needs type prefix (handled by build_transaction_bytes_multikey)
            DerivedKeys dk;
            dk.type = signing_type;
            dk.keypair = signing_keypair;
            // Need full sender address - reconstruct from keypair
            // Actually, for non-ZBC we'd use the multikey builder, but for simplicity
            // the transfer tool handles this specially
            tx_bytes = build_transaction_bytes(
                version, timestamp, sender_pubkey, recipient_address,
                tx_type, params.fee, body_bytes, escrow_bytes, message_bytes);
        }

        // Sign — for the chain the node at --api serves (or the one named by --genesis).
        if (!ensure_signing_context(params.api_url, params.genesis_hex, emit_error)) return last_exit_code();
        DerivedKeys dk;
        dk.type = signing_type;
        dk.keypair = signing_keypair;
        auto sign_result = sign_transaction(tx_bytes, dk);
        if (!sign_result.IsOk()) {
            emit_error("Failed to sign transaction: " + sign_result.GetError().ToString());
            return 1;
        }
        auto signature = sign_result.Value().signature;

        // Hash
        auto hash_result = calculate_tx_hash(tx_bytes, signature);
        if (!hash_result.IsOk()) {
            emit_error("Failed to calculate transaction hash: " + hash_result.GetError().ToString());
            return 1;
        }
        auto tx_hash = hash_result.Value();

        // For ZBC recipients, strip type prefix for backward compat in JSON payload
        std::vector<uint8_t> recipient_for_json;
        if (!recipient_address.empty() && recipient_address.size() >= 4) {
            // Check if ZBC type (0)
            uint32_t rtype = static_cast<uint32_t>(recipient_address[0]) |
                            (static_cast<uint32_t>(recipient_address[1]) << 8) |
                            (static_cast<uint32_t>(recipient_address[2]) << 16) |
                            (static_cast<uint32_t>(recipient_address[3]) << 24);
            if (rtype == 0) {
                recipient_for_json = std::vector<uint8_t>(recipient_address.begin() + 4, recipient_address.end());
            } else {
                recipient_for_json = recipient_address;
            }
        }

        auto json_payload = build_json_payload(
            version, timestamp, sender_pubkey, recipient_for_json,
            tx_type, params.fee, body_bytes, signature,
            message_bytes, escrow_json);

        // Submit
        auto submit_result = submit_transaction(params.api_url, json_payload);

        if (!submit_result.ok && submit_result.http_code == 0) {
            return fail(emit_error, classify_transport_error(submit_result.transport_error),
                        "Failed to submit transaction: " + submit_result.response_body);
        }

        if (submit_result.ok) {
            if (params.json_output) {
                json result = {
                    {"success", true},
                    {"transaction_hash", bytes_to_hex(tx_hash)},
                    {"api_response", submit_result.response_json}
                };
                if (!params.message_text.empty()) result["message"] = params.message_text;
                if (params.escrow.active) result["escrow"] = escrow_json;
                // Merge extra fields
                for (auto& [key, val] : extra_success_fields.items()) {
                    result[key] = val;
                }
                std::cout << result.dump(2) << std::endl;
            } else {
                if (!verbose_success_msg.empty()) {
                    std::cout << verbose_success_msg << std::endl;
                } else {
                    std::cout << "SUCCESS: Transaction submitted!" << std::endl;
                }
                std::cout << std::endl;
                std::cout << "Transaction Hash: " << bytes_to_hex(tx_hash) << std::endl;
            }
        } else {
            // The node said no. Its own error text is the only signal, so classify it into the
            // exit-code contract and hand both the code and the raw text back.
            std::string node_text = submit_result.response_body;
            if (submit_result.response_json.is_object() && submit_result.response_json.contains("error") &&
                submit_result.response_json["error"].is_string())
                node_text = submit_result.response_json["error"].get<std::string>();
            const int code = classify_node_error(submit_result.http_code, node_text);
            last_exit_code() = code;
            if (params.json_output) {
                json result = {
                    {"success", false},
                    {"http_code", submit_result.http_code},
                    {"error", node_text},
                    {"exit_code", code},
                    {"error_class", exit_code::name(code)},
                    {"api_response", submit_result.response_json}
                };
                std::cout << result.dump(2) << std::endl;
            } else {
                std::cerr << "FAILED: Transaction submission rejected (" << exit_code::name(code) << ")" << std::endl;
                std::cerr << "HTTP " << submit_result.http_code << ": " << submit_result.response_body << std::endl;
            }
            return code;
        }

    } catch (const std::exception& e) {
        emit_error(e.what());
        return 1;
    }

    return 0;
}

// ============================================================================
// Convenience: sodium init check
// ============================================================================

inline bool init_sodium(const std::function<void(const std::string&)>& emit_error) {
    if (sodium_init() < 0) {
        emit_error("Failed to initialize libsodium");
        return false;
    }
    return true;
}

}  // namespace txc

#endif  // ZOOBC_TOOLS_TX_COMMON_H
