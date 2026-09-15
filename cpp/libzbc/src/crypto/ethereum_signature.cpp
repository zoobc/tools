// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/crypto/ethereum_signature.h"
#include "zoobc/crypto/hash.h"
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace zoobc {
namespace crypto {

EthereumSignature::EthereumSignature() : ctx_(nullptr) {
    InitContext();
}

EthereumSignature::~EthereumSignature() {
    DestroyContext();
}

EthereumSignature::EthereumSignature(EthereumSignature&& other) noexcept
    : ctx_(other.ctx_) {
    other.ctx_ = nullptr;
}

EthereumSignature& EthereumSignature::operator=(EthereumSignature&& other) noexcept {
    if (this != &other) {
        DestroyContext();
        ctx_ = other.ctx_;
        other.ctx_ = nullptr;
    }
    return *this;
}

void EthereumSignature::InitContext() {
    ctx_ = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx_) {
        throw std::runtime_error("Failed to create secp256k1 context");
    }
}

void EthereumSignature::DestroyContext() {
    if (ctx_) {
        secp256k1_context_destroy(static_cast<secp256k1_context*>(ctx_));
        ctx_ = nullptr;
    }
}

bool EthereumSignature::IsValidPrivateKey(const std::vector<uint8_t>& private_key) const {
    if (private_key.size() != KeySize::SECP256K1_PRIVATE_KEY) {
        return false;
    }
    return secp256k1_ec_seckey_verify(
        static_cast<secp256k1_context*>(ctx_),
        private_key.data()) == 1;
}

Result<std::vector<uint8_t>> EthereumSignature::Keccak256(const std::vector<uint8_t>& data) {
    return Hash::Keccak256(data);
}

std::vector<uint8_t> EthereumSignature::GetAddress20(const std::vector<uint8_t>& public_key) {
    // Ethereum address = last 20 bytes of Keccak256(public_key)
    // Public key should be 64 bytes (uncompressed without 0x04 prefix)
    auto hash = Keccak256(public_key);
    if (hash.IsErr()) {
        return {};
    }

    // Take last 20 bytes
    auto& hash_bytes = hash.Value();
    if (hash_bytes.size() < 20) {
        return {};
    }

    return std::vector<uint8_t>(hash_bytes.end() - 20, hash_bytes.end());
}

Result<std::vector<uint8_t>> EthereumSignature::GetPrivateKeyFromSeed(
    const std::string& seed) {

    // Ethereum uses Keccak256 of seed as private key
    std::vector<uint8_t> seed_bytes(seed.begin(), seed.end());
    auto hash_result = Keccak256(seed_bytes);
    if (hash_result.IsErr()) {
        return Error{hash_result.GetError()};
    }

    // Verify it's a valid private key
    if (!IsValidPrivateKey(hash_result.Value())) {
        auto key = hash_result.Value();
        for (int i = 0; i < 100; ++i) {
            auto rehash = Keccak256(key);
            if (rehash.IsErr()) {
                return Error{rehash.GetError()};
            }
            key = rehash.Value();
            if (IsValidPrivateKey(key)) {
                return key;
            }
        }
        return Error{ErrorCode::CryptoError, "Failed to generate valid secp256k1 private key"};
    }

    return hash_result.Value();
}

Result<std::vector<uint8_t>> EthereumSignature::GetPublicKeyFromPrivateKey(
    const std::vector<uint8_t>& private_key) {

    if (!IsValidPrivateKey(private_key)) {
        return Error{ErrorCode::InvalidArgument, "Invalid secp256k1 private key"};
    }

    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_create(static_cast<secp256k1_context*>(ctx_),
                                    &pubkey, private_key.data()) != 1) {
        return Error{ErrorCode::CryptoError, "Failed to create public key"};
    }

    // Serialize as uncompressed (65 bytes with 0x04 prefix)
    std::vector<uint8_t> full_pubkey(65);
    size_t output_len = full_pubkey.size();

    if (secp256k1_ec_pubkey_serialize(static_cast<secp256k1_context*>(ctx_),
                                       full_pubkey.data(), &output_len,
                                       &pubkey, SECP256K1_EC_UNCOMPRESSED) != 1) {
        return Error{ErrorCode::CryptoError, "Failed to serialize public key"};
    }

    // Return 64 bytes (without 0x04 prefix) as Ethereum expects
    return std::vector<uint8_t>(full_pubkey.begin() + 1, full_pubkey.end());
}

Result<std::vector<uint8_t>> EthereumSignature::GetPublicKeyFromSeed(
    const std::string& seed) {

    auto private_key = GetPrivateKeyFromSeed(seed);
    if (private_key.IsErr()) {
        return Error{private_key.GetError()};
    }

    return GetPublicKeyFromPrivateKey(private_key.Value());
}

Result<std::vector<uint8_t>> EthereumSignature::Sign(
    const std::vector<uint8_t>& private_key,
    const std::vector<uint8_t>& payload) {

    if (!IsValidPrivateKey(private_key)) {
        return Error{ErrorCode::InvalidArgument, "Invalid secp256k1 private key"};
    }

    // Hash the payload with Keccak256
    auto hash_result = Keccak256(payload);
    if (hash_result.IsErr()) {
        return Error{hash_result.GetError()};
    }

    // Sign with recoverable signature
    secp256k1_ecdsa_recoverable_signature sig;
    if (secp256k1_ecdsa_sign_recoverable(static_cast<secp256k1_context*>(ctx_),
                                          &sig, hash_result.Value().data(),
                                          private_key.data(), nullptr, nullptr) != 1) {
        return Error{ErrorCode::CryptoError, "secp256k1 signing failed"};
    }

    // Serialize to r,s,v format (65 bytes)
    std::vector<uint8_t> signature(65);
    int recovery_id;

    if (secp256k1_ecdsa_recoverable_signature_serialize_compact(
            static_cast<secp256k1_context*>(ctx_),
            signature.data(), &recovery_id, &sig) != 1) {
        return Error{ErrorCode::CryptoError, "Failed to serialize signature"};
    }

    // v = recovery_id + 27 (Ethereum convention)
    signature[64] = static_cast<uint8_t>(recovery_id + 27);

    return signature;
}

Result<bool> EthereumSignature::Verify(
    const std::vector<uint8_t>& public_key,
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& signature) {

    if (signature.size() != 65) {
        return Error{ErrorCode::InvalidArgument, "Invalid Ethereum signature size"};
    }

    // Hash the payload
    auto hash_result = Keccak256(payload);
    if (hash_result.IsErr()) {
        return Error{hash_result.GetError()};
    }

    // Parse public key (add 0x04 prefix if needed)
    std::vector<uint8_t> full_pubkey;
    if (public_key.size() == 64) {
        full_pubkey.reserve(65);
        full_pubkey.push_back(0x04);
        full_pubkey.insert(full_pubkey.end(), public_key.begin(), public_key.end());
    } else if (public_key.size() == 65 && public_key[0] == 0x04) {
        full_pubkey = public_key;
    } else {
        return Error{ErrorCode::InvalidArgument, "Invalid public key format"};
    }

    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_parse(static_cast<secp256k1_context*>(ctx_),
                                   &pubkey, full_pubkey.data(),
                                   full_pubkey.size()) != 1) {
        return Error{ErrorCode::InvalidArgument, "Invalid public key"};
    }

    // Parse recoverable signature
    int recovery_id = signature[64];
    if (recovery_id >= 27) {
        recovery_id -= 27;  // Ethereum convention
    }

    secp256k1_ecdsa_recoverable_signature sig;
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(
            static_cast<secp256k1_context*>(ctx_),
            &sig, signature.data(), recovery_id) != 1) {
        return Error{ErrorCode::InvalidArgument, "Invalid signature format"};
    }

    // Convert to standard signature for verification
    secp256k1_ecdsa_signature std_sig;
    if (secp256k1_ecdsa_recoverable_signature_convert(
            static_cast<secp256k1_context*>(ctx_),
            &std_sig, &sig) != 1) {
        return Error{ErrorCode::CryptoError, "Failed to convert signature"};
    }

    // Verify
    int result = secp256k1_ecdsa_verify(
        static_cast<secp256k1_context*>(ctx_),
        &std_sig, hash_result.Value().data(), &pubkey);

    return result == 1;
}

Result<std::vector<uint8_t>> EthereumSignature::RecoverPublicKey(
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& signature) {

    if (signature.size() != 65) {
        return Error{ErrorCode::InvalidArgument, "Invalid Ethereum signature size"};
    }

    // Hash the payload
    auto hash_result = Keccak256(payload);
    if (hash_result.IsErr()) {
        return Error{hash_result.GetError()};
    }

    // Parse recovery ID
    int recovery_id = signature[64];
    if (recovery_id >= 27) {
        recovery_id -= 27;
    }

    // Parse signature
    secp256k1_ecdsa_recoverable_signature sig;
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(
            static_cast<secp256k1_context*>(ctx_),
            &sig, signature.data(), recovery_id) != 1) {
        return Error{ErrorCode::InvalidArgument, "Invalid signature format"};
    }

    // SECURITY: reject non-canonical (high-s) signatures. secp256k1_ecdsa_recover does NOT
    // enforce low-s, so an attacker can take a valid (r, s, v) and submit (r, n-s, v^1), which
    // recovers the SAME public key/address and still verifies — signature malleability. Because
    // the signature bytes are part of GetTransactionBytes → transaction_hash, malleating them
    // mutates the tx hash and bypasses mempool/ledger dedup → replay / double-credit. Convert to
    // a standard signature and reject if normalize reports the input was high-s.
    {
        secp256k1_ecdsa_signature std_sig;
        secp256k1_ecdsa_recoverable_signature_convert(
            static_cast<secp256k1_context*>(ctx_), &std_sig, &sig);
        secp256k1_ecdsa_signature normalized;
        if (secp256k1_ecdsa_signature_normalize(
                static_cast<secp256k1_context*>(ctx_), &normalized, &std_sig) == 1) {
            return Error{ErrorCode::InvalidArgument, "Non-canonical (high-s) signature rejected"};
        }
    }

    // Recover public key
    secp256k1_pubkey pubkey;
    if (secp256k1_ecdsa_recover(static_cast<secp256k1_context*>(ctx_),
                                 &pubkey, &sig,
                                 hash_result.Value().data()) != 1) {
        return Error{ErrorCode::CryptoError, "Failed to recover public key"};
    }

    // Serialize uncompressed (65 bytes)
    std::vector<uint8_t> output(65);
    size_t output_len = output.size();

    if (secp256k1_ec_pubkey_serialize(static_cast<secp256k1_context*>(ctx_),
                                       output.data(), &output_len,
                                       &pubkey, SECP256K1_EC_UNCOMPRESSED) != 1) {
        return Error{ErrorCode::CryptoError, "Failed to serialize public key"};
    }

    // Return 64 bytes (without 0x04 prefix)
    return std::vector<uint8_t>(output.begin() + 1, output.end());
}

std::string EthereumSignature::ToChecksumAddress(const std::vector<uint8_t>& address) {
    if (address.size() != 20) {
        return "";
    }

    // Convert address to hex (lowercase)
    std::ostringstream hex_ss;
    for (uint8_t byte : address) {
        hex_ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::string hex_addr = hex_ss.str();

    // Hash the hex address
    std::vector<uint8_t> addr_bytes(hex_addr.begin(), hex_addr.end());
    auto hash = Keccak256(addr_bytes);
    if (hash.IsErr()) {
        return "0x" + hex_addr;
    }

    // Apply EIP-55 checksum
    std::string result = "0x";
    for (size_t i = 0; i < hex_addr.size(); ++i) {
        char c = hex_addr[i];
        if (std::isalpha(static_cast<unsigned char>(c))) {
            // Get corresponding nibble from hash
            uint8_t hash_nibble = (hash.Value()[i / 2] >> (4 * (1 - (i % 2)))) & 0x0F;
            if (hash_nibble >= 8) {
                c = std::toupper(static_cast<unsigned char>(c));
            }
        }
        result += c;
    }

    return result;
}

bool EthereumSignature::VerifyChecksumAddress(const std::string& address) {
    if (address.size() != 42 || address.substr(0, 2) != "0x") {
        return false;
    }

    // Extract hex part
    std::string hex_part = address.substr(2);

    // Convert to lowercase for hashing
    std::string lower_hex;
    for (char c : hex_part) {
        lower_hex += std::tolower(static_cast<unsigned char>(c));
    }

    // Decode to bytes
    std::vector<uint8_t> addr_bytes(20);
    for (size_t i = 0; i < 20; ++i) {
        unsigned int byte;
        std::istringstream iss(lower_hex.substr(i * 2, 2));
        iss >> std::hex >> byte;
        addr_bytes[i] = static_cast<uint8_t>(byte);
    }

    // Generate checksum address and compare
    std::string checksum_addr = ToChecksumAddress(addr_bytes);
    return address == checksum_addr;
}

std::string EthereumSignature::GetAddressFromPublicKey(
    const std::string& /* prefix */,
    const std::vector<uint8_t>& public_key) {

    auto address20 = GetAddress20(public_key);
    if (address20.empty()) {
        return "";
    }

    return ToChecksumAddress(address20);
}

Result<std::vector<uint8_t>> EthereumSignature::GetPublicKeyFromAddress(
    const std::string& /* address */) {
    // Ethereum addresses are hashes - cannot recover public key
    return Error{ErrorCode::Unimplemented,
                 "Cannot recover public key from Ethereum address"};
}

std::vector<uint8_t> EthereumSignature::GetAccountAddress(
    const std::vector<uint8_t>& public_key) {

    auto address20 = GetAddress20(public_key);
    if (address20.empty()) {
        return {};
    }

    // Account address = prefix byte + 20-byte address
    std::vector<uint8_t> address;
    address.reserve(1 + address20.size());
    address.push_back(GetAddressPrefix());
    address.insert(address.end(), address20.begin(), address20.end());
    return address;
}

Result<std::vector<uint8_t>> EthereumSignature::PersonalSign(
    const std::vector<uint8_t>& private_key,
    const std::vector<uint8_t>& message) {

    // EIP-191 personal sign prefix
    std::string prefix = "\x19" "Ethereum Signed Message:\n";
    prefix += std::to_string(message.size());

    std::vector<uint8_t> prefixed_msg;
    prefixed_msg.reserve(prefix.size() + message.size());
    prefixed_msg.insert(prefixed_msg.end(), prefix.begin(), prefix.end());
    prefixed_msg.insert(prefixed_msg.end(), message.begin(), message.end());

    // Hash and sign
    auto hash = Keccak256(prefixed_msg);
    if (hash.IsErr()) {
        return Error{hash.GetError()};
    }

    // Sign the hash directly (already hashed)
    if (!IsValidPrivateKey(private_key)) {
        return Error{ErrorCode::InvalidArgument, "Invalid secp256k1 private key"};
    }

    secp256k1_ecdsa_recoverable_signature sig;
    if (secp256k1_ecdsa_sign_recoverable(static_cast<secp256k1_context*>(ctx_),
                                          &sig, hash.Value().data(),
                                          private_key.data(), nullptr, nullptr) != 1) {
        return Error{ErrorCode::CryptoError, "secp256k1 signing failed"};
    }

    std::vector<uint8_t> signature(65);
    int recovery_id;

    if (secp256k1_ecdsa_recoverable_signature_serialize_compact(
            static_cast<secp256k1_context*>(ctx_),
            signature.data(), &recovery_id, &sig) != 1) {
        return Error{ErrorCode::CryptoError, "Failed to serialize signature"};
    }

    signature[64] = static_cast<uint8_t>(recovery_id + 27);

    return signature;
}

// ==================== RLP Decoding Helpers ====================

namespace {

// RLP decode result
struct RlpItem {
    bool is_list;
    std::vector<uint8_t> data;
    std::vector<RlpItem> items;  // Only used if is_list
};

// Decode RLP item at position, return bytes consumed
Result<std::pair<RlpItem, size_t>> DecodeRlpItem(const std::vector<uint8_t>& data, size_t pos) {
    if (pos >= data.size()) {
        return Error{ErrorCode::InvalidArgument, "RLP: unexpected end of data"};
    }

    uint8_t prefix = data[pos];
    RlpItem item;

    if (prefix <= 0x7f) {
        // Single byte
        item.is_list = false;
        item.data = {prefix};
        return std::make_pair(item, size_t(1));
    } else if (prefix <= 0xb7) {
        // Short string (0-55 bytes)
        size_t len = prefix - 0x80;
        if (pos + 1 + len > data.size()) {
            return Error{ErrorCode::InvalidArgument, "RLP: string length exceeds data"};
        }
        item.is_list = false;
        item.data = std::vector<uint8_t>(data.begin() + pos + 1, data.begin() + pos + 1 + len);
        return std::make_pair(item, 1 + len);
    } else if (prefix <= 0xbf) {
        // Long string
        size_t len_bytes = prefix - 0xb7;
        if (pos + 1 + len_bytes > data.size()) {
            return Error{ErrorCode::InvalidArgument, "RLP: length bytes exceed data"};
        }
        size_t len = 0;
        for (size_t i = 0; i < len_bytes; ++i) {
            len = (len << 8) | data[pos + 1 + i];
        }
        if (pos + 1 + len_bytes + len > data.size()) {
            return Error{ErrorCode::InvalidArgument, "RLP: string length exceeds data"};
        }
        item.is_list = false;
        item.data = std::vector<uint8_t>(data.begin() + pos + 1 + len_bytes,
                                          data.begin() + pos + 1 + len_bytes + len);
        return std::make_pair(item, 1 + len_bytes + len);
    } else if (prefix <= 0xf7) {
        // Short list (0-55 bytes total)
        size_t list_len = prefix - 0xc0;
        if (pos + 1 + list_len > data.size()) {
            return Error{ErrorCode::InvalidArgument, "RLP: list length exceeds data"};
        }
        item.is_list = true;
        size_t offset = 0;
        while (offset < list_len) {
            auto result = DecodeRlpItem(data, pos + 1 + offset);
            if (result.IsErr()) {
                return Error{result.GetError()};
            }
            item.items.push_back(result.Value().first);
            offset += result.Value().second;
        }
        return std::make_pair(item, 1 + list_len);
    } else {
        // Long list
        size_t len_bytes = prefix - 0xf7;
        if (pos + 1 + len_bytes > data.size()) {
            return Error{ErrorCode::InvalidArgument, "RLP: list length bytes exceed data"};
        }
        size_t list_len = 0;
        for (size_t i = 0; i < len_bytes; ++i) {
            list_len = (list_len << 8) | data[pos + 1 + i];
        }
        if (pos + 1 + len_bytes + list_len > data.size()) {
            return Error{ErrorCode::InvalidArgument, "RLP: list length exceeds data"};
        }
        item.is_list = true;
        size_t offset = 0;
        while (offset < list_len) {
            auto result = DecodeRlpItem(data, pos + 1 + len_bytes + offset);
            if (result.IsErr()) {
                return Error{result.GetError()};
            }
            item.items.push_back(result.Value().first);
            offset += result.Value().second;
        }
        return std::make_pair(item, 1 + len_bytes + list_len);
    }
}

// Convert RLP bytes to uint64 (big-endian)
uint64_t RlpToUint64(const std::vector<uint8_t>& data) {
    uint64_t result = 0;
    for (uint8_t byte : data) {
        result = (result << 8) | byte;
    }
    return result;
}

// RLP encode a single value
std::vector<uint8_t> RlpEncode(const std::vector<uint8_t>& data) {
    if (data.size() == 1 && data[0] <= 0x7f) {
        // Single byte <= 0x7f is its own RLP encoding
        // Use explicit construction to avoid GCC array-bounds false positive
        return std::vector<uint8_t>{data[0]};
    } else if (data.size() <= 55) {
        std::vector<uint8_t> result;
        result.push_back(0x80 + static_cast<uint8_t>(data.size()));
        result.insert(result.end(), data.begin(), data.end());
        return result;
    } else {
        // Calculate length of length
        size_t len = data.size();
        std::vector<uint8_t> len_bytes;
        while (len > 0) {
            len_bytes.insert(len_bytes.begin(), len & 0xff);
            len >>= 8;
        }
        std::vector<uint8_t> result;
        result.push_back(0xb7 + static_cast<uint8_t>(len_bytes.size()));
        result.insert(result.end(), len_bytes.begin(), len_bytes.end());
        result.insert(result.end(), data.begin(), data.end());
        return result;
    }
}

// RLP encode a uint64
std::vector<uint8_t> RlpEncodeUint(uint64_t value) {
    if (value == 0) {
        return {};  // Empty string for zero
    }
    std::vector<uint8_t> bytes;
    while (value > 0) {
        bytes.insert(bytes.begin(), value & 0xff);
        value >>= 8;
    }
    return bytes;
}

// RLP encode a list
std::vector<uint8_t> RlpEncodeList(const std::vector<std::vector<uint8_t>>& items) {
    std::vector<uint8_t> payload;
    for (const auto& item : items) {
        auto encoded = RlpEncode(item);
        payload.insert(payload.end(), encoded.begin(), encoded.end());
    }

    if (payload.size() <= 55) {
        std::vector<uint8_t> result;
        result.push_back(0xc0 + static_cast<uint8_t>(payload.size()));
        result.insert(result.end(), payload.begin(), payload.end());
        return result;
    } else {
        size_t len = payload.size();
        std::vector<uint8_t> len_bytes;
        while (len > 0) {
            len_bytes.insert(len_bytes.begin(), len & 0xff);
            len >>= 8;
        }
        std::vector<uint8_t> result;
        result.push_back(0xf7 + static_cast<uint8_t>(len_bytes.size()));
        result.insert(result.end(), len_bytes.begin(), len_bytes.end());
        result.insert(result.end(), payload.begin(), payload.end());
        return result;
    }
}

// Wrap an already-encoded RLP payload (concatenation of encoded items) in a list header.
// Used to build EIP-2718 typed-tx signing payloads where one element (the access list) is
// a nested list pre-encoded as raw bytes (0xc0 for empty), which RlpEncodeList can't carry.
std::vector<uint8_t> RlpWrapList(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;
    if (payload.size() <= 55) {
        result.push_back(0xc0 + static_cast<uint8_t>(payload.size()));
    } else {
        size_t len = payload.size();
        std::vector<uint8_t> len_bytes;
        while (len > 0) { len_bytes.insert(len_bytes.begin(), len & 0xff); len >>= 8; }
        result.push_back(0xf7 + static_cast<uint8_t>(len_bytes.size()));
        result.insert(result.end(), len_bytes.begin(), len_bytes.end());
    }
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

}  // anonymous namespace

// Divide a big-endian wei amount by 1e10 (wei->atomic) at full precision, rejecting
// results above INT64_MAX. Long division in base 256: at each step the running
// remainder r < DIV, so cur = r*256 + byte < DIV*256, hence the output digit
// cur/DIV <= 255 fits a byte — so this stays in uint64 with NO __int128.
Result<int64_t> EthereumSignature::WeiToAtomicZbc(const std::vector<uint8_t>& wei_be) {
    const uint64_t DIV = 10000000000ULL;        // 1e10 wei per atomic (1 ZBC = 1e8 atomic = 1e18 wei)
    const uint64_t INT64_MAXU = 9223372036854775807ULL;
    uint64_t rem = 0, quotient = 0;
    bool overflow = false;
    for (uint8_t b : wei_be) {
        uint64_t cur = rem * 256ULL + b;        // rem < DIV (~2^34) -> cur < 2^42, safe
        uint64_t digit = cur / DIV;             // <= 255
        rem = cur % DIV;
        if (quotient > (INT64_MAXU - digit) / 256ULL) { overflow = true; break; }
        quotient = quotient * 256ULL + digit;
    }
    if (overflow || quotient > INT64_MAXU) {
        return Error{ErrorCode::ValidationError, "Ethereum transaction value too large (exceeds max ZBC amount)"};
    }
    return static_cast<int64_t>(quotient);
}

Result<EthereumSignature::ParsedTransaction> EthereumSignature::ParseSignedTransaction(
    const std::vector<uint8_t>& raw_tx) {

    // EIP-2718 typed transaction: a leading byte 0x01 (EIP-2930) or 0x02 (EIP-1559 —
    // MetaMask's default), followed by RLP(payload). A legacy tx starts with an RLP list
    // header (>= 0xc0), so a leading 0x01/0x02 unambiguously marks a typed envelope.
    if (!raw_tx.empty() && (raw_tx[0] == 0x01 || raw_tx[0] == 0x02)) {
        const uint8_t type_byte = raw_tx[0];
        std::vector<uint8_t> payload(raw_tx.begin() + 1, raw_tx.end());
        auto dec = DecodeRlpItem(payload, 0);
        if (dec.IsErr()) return Error{dec.GetError()};
        auto& root = dec.Value().first;
        ParsedTransaction tx;
        size_t v_idx, r_idx, s_idx;
        if (type_byte == 0x02) {
            // [chainId, nonce, maxPriorityFee, maxFee, gasLimit, to, value, data, accessList, yParity, r, s]
            if (!root.is_list || root.items.size() != 12)
                return Error{ErrorCode::InvalidArgument, "Invalid EIP-1559 transaction (expected 12 items)"};
            tx.tx_type = 2;
            tx.chain_id = RlpToUint64(root.items[0].data);
            tx.nonce = RlpToUint64(root.items[1].data);
            tx.max_priority_fee_per_gas = RlpToUint64(root.items[2].data);
            tx.gas_price = RlpToUint64(root.items[3].data);   // maxFeePerGas
            tx.gas_limit = RlpToUint64(root.items[4].data);
            tx.to = root.items[5].data;
            tx.value = RlpToUint64(root.items[6].data);
            tx.value_be = root.items[6].data;
            tx.data = root.items[7].data;
            if (!(root.items[8].is_list && root.items[8].items.empty()))
                return Error{ErrorCode::InvalidArgument, "EIP-1559 access list must be empty for a ZooBC transfer"};
            v_idx = 9; r_idx = 10; s_idx = 11;
        } else {
            // EIP-2930: [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, yParity, r, s]
            if (!root.is_list || root.items.size() != 11)
                return Error{ErrorCode::InvalidArgument, "Invalid EIP-2930 transaction (expected 11 items)"};
            tx.tx_type = 1;
            tx.chain_id = RlpToUint64(root.items[0].data);
            tx.nonce = RlpToUint64(root.items[1].data);
            tx.gas_price = RlpToUint64(root.items[2].data);
            tx.gas_limit = RlpToUint64(root.items[3].data);
            tx.to = root.items[4].data;
            tx.value = RlpToUint64(root.items[5].data);
            tx.value_be = root.items[5].data;
            tx.data = root.items[6].data;
            if (!(root.items[7].is_list && root.items[7].items.empty()))
                return Error{ErrorCode::InvalidArgument, "EIP-2930 access list must be empty for a ZooBC transfer"};
            v_idx = 8; r_idx = 9; s_idx = 10;
        }
        // Typed txs carry yParity (0/1) directly (no EIP-155 v encoding).
        uint64_t y = RlpToUint64(root.items[v_idx].data);
        std::vector<uint8_t> r = root.items[r_idx].data, s = root.items[s_idx].data;
        while (r.size() < 32) r.insert(r.begin(), 0);
        while (s.size() < 32) s.insert(s.begin(), 0);
        uint8_t recovery_id = static_cast<uint8_t>(y & 1);
        tx.signature.reserve(65);
        tx.signature.insert(tx.signature.end(), r.begin(), r.end());
        tx.signature.insert(tx.signature.end(), s.begin(), s.end());
        tx.signature.push_back(recovery_id + 27);
        return tx;
    }

    // ---- Legacy / EIP-155 (flat 9-item list) ----
    // Decode RLP
    auto decode_result = DecodeRlpItem(raw_tx, 0);
    if (decode_result.IsErr()) {
        return Error{decode_result.GetError()};
    }

    auto& root = decode_result.Value().first;
    if (!root.is_list || root.items.size() != 9) {
        return Error{ErrorCode::InvalidArgument,
            "Invalid transaction format: expected list of 9 items, got " +
            std::to_string(root.items.size())};
    }

    ParsedTransaction tx;
    tx.nonce = RlpToUint64(root.items[0].data);
    tx.gas_price = RlpToUint64(root.items[1].data);
    tx.gas_limit = RlpToUint64(root.items[2].data);
    tx.to = root.items[3].data;  // May be empty for contract creation
    tx.value = RlpToUint64(root.items[4].data);   // legacy 64-bit (caps ~18.4 ZBC)
    tx.value_be = root.items[4].data;             // full-precision big-endian wei
    tx.data = root.items[5].data;

    // Parse v, r, s
    uint64_t v = RlpToUint64(root.items[6].data);
    std::vector<uint8_t> r = root.items[7].data;
    std::vector<uint8_t> s = root.items[8].data;

    // Pad r and s to 32 bytes
    while (r.size() < 32) r.insert(r.begin(), 0);
    while (s.size() < 32) s.insert(s.begin(), 0);

    // Extract chain_id from v (EIP-155)
    // v = chain_id * 2 + 35 + recovery_id (EIP-155)
    // v = 27 + recovery_id (legacy)
    uint8_t recovery_id;
    if (v >= 35) {
        // EIP-155 transaction
        tx.chain_id = (v - 35) / 2;
        recovery_id = static_cast<uint8_t>((v - 35) % 2);
    } else if (v == 27 || v == 28) {
        // Legacy transaction
        tx.chain_id = 0;
        recovery_id = static_cast<uint8_t>(v - 27);
    } else {
        return Error{ErrorCode::InvalidArgument, "Invalid v value: " + std::to_string(v)};
    }

    // Build 65-byte signature (r, s, recovery_id + 27)
    tx.signature.reserve(65);
    tx.signature.insert(tx.signature.end(), r.begin(), r.end());
    tx.signature.insert(tx.signature.end(), s.begin(), s.end());
    tx.signature.push_back(recovery_id + 27);

    return tx;
}

Result<std::vector<uint8_t>> EthereumSignature::RecoverPublicKeyFromRawTx(
    const std::vector<uint8_t>& raw_tx) {

    // Parse the transaction
    auto parse_result = ParseSignedTransaction(raw_tx);
    if (parse_result.IsErr()) {
        return Error{parse_result.GetError()};
    }

    auto& tx = parse_result.Value();

    // Build the signing hash. The pre-image differs by tx type:
    //  - EIP-1559 (2): keccak(0x02 ‖ RLP([chainId,nonce,maxPrio,maxFee,gas,to,value,data,accessList]))
    //  - EIP-2930  (1): keccak(0x01 ‖ RLP([chainId,nonce,gasPrice,gas,to,value,data,accessList]))
    //  - EIP-155   : keccak(RLP([nonce,gasPrice,gas,to,value,data,chainId,0,0]))
    //  - legacy    : keccak(RLP([nonce,gasPrice,gas,to,value,data]))
    // (accessList is empty for a ZooBC transfer → the literal byte 0xc0, an empty RLP list.)
    Result<std::vector<uint8_t>> hash_result = Error{ErrorCode::CryptoError, "unset"};
    if (tx.tx_type == 1 || tx.tx_type == 2) {
        std::vector<uint8_t> payload;
        auto add = [&](const std::vector<uint8_t>& e) { payload.insert(payload.end(), e.begin(), e.end()); };
        // RlpEncodeUint returns the RAW minimal big-endian bytes; wrap each in RlpEncode
        // to get the RLP string item (matching how the legacy path's RlpEncodeList does it).
        auto addUint = [&](uint64_t v) { add(RlpEncode(RlpEncodeUint(v))); };
        addUint(tx.chain_id);
        addUint(tx.nonce);
        if (tx.tx_type == 2) { addUint(tx.max_priority_fee_per_gas); addUint(tx.gas_price); }
        else                 { addUint(tx.gas_price); }
        addUint(tx.gas_limit);
        add(RlpEncode(tx.to));
        add(RlpEncode(tx.value_be));
        add(RlpEncode(tx.data));
        payload.push_back(0xc0);  // empty access list (a nested empty RLP list)
        std::vector<uint8_t> signing;
        signing.push_back(static_cast<uint8_t>(tx.tx_type));
        auto wrapped = RlpWrapList(payload);
        signing.insert(signing.end(), wrapped.begin(), wrapped.end());
        hash_result = Keccak256(signing);
    } else {
        std::vector<std::vector<uint8_t>> items;
        items.push_back(RlpEncodeUint(tx.nonce));
        items.push_back(RlpEncodeUint(tx.gas_price));
        items.push_back(RlpEncodeUint(tx.gas_limit));
        items.push_back(tx.to);
        // Full-precision big-endian value (minimal RLP form), NOT the truncated uint64.
        items.push_back(tx.value_be);
        items.push_back(tx.data);
        if (tx.chain_id > 0) {  // EIP-155
            items.push_back(RlpEncodeUint(tx.chain_id));
            items.push_back({});
            items.push_back({});
        }
        hash_result = Keccak256(RlpEncodeList(items));
    }
    if (hash_result.IsErr()) {
        return Error{hash_result.GetError()};
    }

    // Create context for recovery
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!ctx) {
        return Error{ErrorCode::CryptoError, "Failed to create secp256k1 context"};
    }

    // Parse recovery ID
    int recovery_id = tx.signature[64];
    if (recovery_id >= 27) {
        recovery_id -= 27;
    }

    // Parse signature
    secp256k1_ecdsa_recoverable_signature sig;
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(
            ctx, &sig, tx.signature.data(), recovery_id) != 1) {
        secp256k1_context_destroy(ctx);
        return Error{ErrorCode::InvalidArgument, "Invalid signature format"};
    }

    // SECURITY: reject non-canonical (high-s) signatures before recovery — secp256k1_ecdsa_recover
    // does not enforce low-s, so (r, n-s, v^1) recovers the same sender and would enable bridge-tx
    // malleability/replay (the signature is part of the tx hash used for dedup). See RecoverPublicKey.
    {
        secp256k1_ecdsa_signature std_sig;
        secp256k1_ecdsa_recoverable_signature_convert(ctx, &std_sig, &sig);
        secp256k1_ecdsa_signature normalized;
        if (secp256k1_ecdsa_signature_normalize(ctx, &normalized, &std_sig) == 1) {
            secp256k1_context_destroy(ctx);
            return Error{ErrorCode::InvalidArgument, "Non-canonical (high-s) signature rejected"};
        }
    }

    // Recover public key
    secp256k1_pubkey pubkey;
    if (secp256k1_ecdsa_recover(ctx, &pubkey, &sig, hash_result.Value().data()) != 1) {
        secp256k1_context_destroy(ctx);
        return Error{ErrorCode::CryptoError, "Failed to recover public key"};
    }

    // Serialize uncompressed (65 bytes)
    std::vector<uint8_t> pubkey_bytes(65);
    size_t output_len = pubkey_bytes.size();

    if (secp256k1_ec_pubkey_serialize(ctx, pubkey_bytes.data(), &output_len,
                                       &pubkey, SECP256K1_EC_UNCOMPRESSED) != 1) {
        secp256k1_context_destroy(ctx);
        return Error{ErrorCode::CryptoError, "Failed to serialize public key"};
    }

    secp256k1_context_destroy(ctx);
    return std::vector<uint8_t>(pubkey_bytes.begin() + 1, pubkey_bytes.end());
}

Result<std::vector<uint8_t>> EthereumSignature::RecoverSender(const std::vector<uint8_t>& raw_tx) {
    auto key = RecoverPublicKeyFromRawTx(raw_tx);
    if (key.IsErr()) return Error{key.GetError()};
    auto h = Keccak256(key.Value());
    if (h.IsErr()) return Error{h.GetError()};
    return std::vector<uint8_t>(h.Value().begin() + 12, h.Value().end());
}

}  // namespace crypto
}  // namespace zoobc
