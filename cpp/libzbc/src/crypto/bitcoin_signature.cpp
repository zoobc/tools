// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/crypto/bitcoin_signature.h"
#include "zoobc/crypto/hash.h"
#include "zoobc/crypto/bitcoin_transaction.h"
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>
#include <algorithm>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cctype>

namespace zoobc {
namespace crypto {

namespace {

constexpr uint32_t BECH32M_CONST = 0x2BC830A3;
constexpr const char* BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

struct SegwitDecodedAddress {
    uint8_t witness_version;
    std::vector<uint8_t> program;
};

int Bech32CharToValue(char c) {
    const char* p = std::strchr(BECH32_CHARSET, c);
    if (!p) {
        return -1;
    }
    return static_cast<int>(p - BECH32_CHARSET);
}

uint32_t Bech32Polymod(const std::vector<uint8_t>& values) {
    uint32_t chk = 1;
    static const uint32_t GEN[5] = {
        0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3
    };
    for (uint8_t v : values) {
        uint32_t top = chk >> 25;
        chk = (chk & 0x1FFFFFF) << 5;
        chk ^= v;
        for (int i = 0; i < 5; i++) {
            if ((top >> i) & 1U) {
                chk ^= GEN[i];
            }
        }
    }
    return chk;
}

std::vector<uint8_t> Bech32HrpExpand(const std::string& hrp) {
    std::vector<uint8_t> ret;
    ret.reserve(hrp.size() * 2 + 1);
    for (unsigned char c : hrp) {
        ret.push_back(static_cast<uint8_t>(c >> 5));
    }
    ret.push_back(0);
    for (unsigned char c : hrp) {
        ret.push_back(static_cast<uint8_t>(c & 31));
    }
    return ret;
}

Result<std::vector<uint8_t>> ConvertBits(
    const std::vector<uint8_t>& in,
    int from_bits,
    int to_bits,
    bool pad) {
    int acc = 0;
    int bits = 0;
    const int maxv = (1 << to_bits) - 1;
    std::vector<uint8_t> out;
    out.reserve((in.size() * from_bits + to_bits - 1) / to_bits);

    for (uint8_t value : in) {
        if (value >> from_bits) {
            return Error{ErrorCode::InvalidArgument, "Invalid value for convertbits"};
        }
        acc = (acc << from_bits) | value;
        bits += from_bits;
        while (bits >= to_bits) {
            bits -= to_bits;
            out.push_back(static_cast<uint8_t>((acc >> bits) & maxv));
        }
    }

    if (pad) {
        if (bits) {
            out.push_back(static_cast<uint8_t>((acc << (to_bits - bits)) & maxv));
        }
    } else if (bits >= from_bits || ((acc << (to_bits - bits)) & maxv)) {
        return Error{ErrorCode::InvalidArgument, "Invalid padding in convertbits"};
    }

    return out;
}

Result<SegwitDecodedAddress> DecodeBech32SegwitAddress(const std::string& address) {
    bool has_lower = false;
    bool has_upper = false;
    for (unsigned char c : address) {
        if (std::isalpha(c)) {
            has_lower = has_lower || std::islower(c);
            has_upper = has_upper || std::isupper(c);
        }
    }
    if (has_lower && has_upper) {
        return Error{ErrorCode::InvalidArgument, "Invalid Bech32: mixed case"};
    }

    std::string addr;
    addr.reserve(address.size());
    for (unsigned char c : address) {
        addr.push_back(static_cast<char>(std::tolower(c)));
    }

    if (addr.size() < 14 || addr.size() > 90) {
        return Error{ErrorCode::InvalidArgument, "Invalid Bech32: length"};
    }

    size_t sep_pos = addr.rfind('1');
    if (sep_pos == std::string::npos || sep_pos < 1 || sep_pos + 7 > addr.size()) {
        return Error{ErrorCode::InvalidArgument, "Invalid Bech32: missing separator or checksum"};
    }

    std::string hrp = addr.substr(0, sep_pos);
    std::string data_part = addr.substr(sep_pos + 1);

    if (hrp != "bc" && hrp != "tb" && hrp != "bcrt") {
        return Error{ErrorCode::InvalidArgument, "Invalid Bech32 HRP"};
    }

    std::vector<uint8_t> data;
    data.reserve(data_part.size());
    for (char c : data_part) {
        int v = Bech32CharToValue(c);
        if (v < 0) {
            return Error{ErrorCode::InvalidArgument, "Invalid Bech32 character"};
        }
        data.push_back(static_cast<uint8_t>(v));
    }

    std::vector<uint8_t> values = Bech32HrpExpand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    uint32_t chk = Bech32Polymod(values);
    bool is_bech32 = (chk == 1);
    bool is_bech32m = (chk == BECH32M_CONST);
    if (!is_bech32 && !is_bech32m) {
        return Error{ErrorCode::InvalidArgument, "Invalid Bech32 checksum"};
    }

    if (data.size() < 7) {
        return Error{ErrorCode::InvalidArgument, "Invalid Bech32: data too short"};
    }

    std::vector<uint8_t> payload(data.begin(), data.end() - 6);
    if (payload.empty()) {
        return Error{ErrorCode::InvalidArgument, "Invalid Bech32: empty payload"};
    }

    uint8_t witness_version = payload[0];
    if (witness_version > 16) {
        return Error{ErrorCode::InvalidArgument, "Invalid SegWit witness version"};
    }

    // BIP350: v0 uses bech32, v1+ uses bech32m.
    if (witness_version == 0 && !is_bech32) {
        return Error{ErrorCode::InvalidArgument, "Invalid Bech32 encoding for v0 witness program"};
    }
    if (witness_version != 0 && !is_bech32m) {
        return Error{ErrorCode::InvalidArgument, "Invalid Bech32m encoding for v1+ witness program"};
    }

    std::vector<uint8_t> program_5(payload.begin() + 1, payload.end());
    auto program_result = ConvertBits(program_5, 5, 8, false);
    if (program_result.IsErr()) {
        return Error{program_result.GetError()};
    }
    std::vector<uint8_t> program = program_result.Value();

    if (program.size() < 2 || program.size() > 40) {
        return Error{ErrorCode::InvalidArgument, "Invalid SegWit program length"};
    }
    if (witness_version == 0 && program.size() != 20 && program.size() != 32) {
        return Error{ErrorCode::InvalidArgument, "Invalid v0 witness program length"};
    }

    return SegwitDecodedAddress{witness_version, std::move(program)};
}

Result<std::vector<uint8_t>> DecodeBech32SegwitProgram(const std::string& address) {
    auto decoded = DecodeBech32SegwitAddress(address);
    if (decoded.IsErr()) {
        return Error{decoded.GetError()};
    }
    return decoded.Value().program;
}

}  // namespace

// Public wrapper over the bech32/bech32m segwit decoder above, so the shared address decoder can
// reuse it instead of carrying a second copy.
Result<Bech32Segwit> Bech32SegwitDecode(const std::string& address) {
    auto d = DecodeBech32SegwitAddress(address);
    if (d.IsErr()) return Error{d.GetError()};
    Bech32Segwit out;
    out.witness_version = d.Value().witness_version;
    out.program = d.Value().program;
    return out;
}


// Base58 alphabet used by Bitcoin
static const char* BASE58_ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

BitcoinSignature::BitcoinSignature() : ctx_(nullptr) {
    InitContext();
}

BitcoinSignature::~BitcoinSignature() {
    DestroyContext();
}

BitcoinSignature::BitcoinSignature(BitcoinSignature&& other) noexcept
    : ctx_(other.ctx_) {
    other.ctx_ = nullptr;
}

BitcoinSignature& BitcoinSignature::operator=(BitcoinSignature&& other) noexcept {
    if (this != &other) {
        DestroyContext();
        ctx_ = other.ctx_;
        other.ctx_ = nullptr;
    }
    return *this;
}

void BitcoinSignature::InitContext() {
    ctx_ = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx_) {
        throw std::runtime_error("Failed to create secp256k1 context");
    }
}

void BitcoinSignature::DestroyContext() {
    if (ctx_) {
        secp256k1_context_destroy(static_cast<secp256k1_context*>(ctx_));
        ctx_ = nullptr;
    }
}

bool BitcoinSignature::IsValidPrivateKey(const std::vector<uint8_t>& private_key) const {
    if (private_key.size() != KeySize::SECP256K1_PRIVATE_KEY) {
        return false;
    }
    return secp256k1_ec_seckey_verify(
        static_cast<secp256k1_context*>(ctx_),
        private_key.data()) == 1;
}

Result<std::vector<uint8_t>> BitcoinSignature::GetPrivateKeyFromSeed(
    const std::string& seed) {

    // Bitcoin uses SHA256 of seed as private key
    std::vector<uint8_t> seed_bytes(seed.begin(), seed.end());
    auto hash_result = Hash::SHA256(seed_bytes);
    if (hash_result.IsErr()) {
        return Error{hash_result.GetError()};
    }

    // Verify it's a valid private key
    if (!IsValidPrivateKey(hash_result.Value())) {
        // If not valid, hash again until valid
        auto key = hash_result.Value();
        for (int i = 0; i < 100; ++i) {
            auto rehash = Hash::SHA256(key);
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

Result<std::vector<uint8_t>> BitcoinSignature::GetPublicKeyFromPrivateKey(
    const std::vector<uint8_t>& private_key) {

    if (!IsValidPrivateKey(private_key)) {
        return Error{ErrorCode::InvalidArgument, "Invalid secp256k1 private key"};
    }

    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_create(static_cast<secp256k1_context*>(ctx_),
                                    &pubkey, private_key.data()) != 1) {
        return Error{ErrorCode::CryptoError, "Failed to create public key"};
    }

    // Serialize as compressed (33 bytes)
    std::vector<uint8_t> public_key(KeySize::SECP256K1_PUBLIC_KEY_COMPRESSED);
    size_t output_len = public_key.size();

    if (secp256k1_ec_pubkey_serialize(static_cast<secp256k1_context*>(ctx_),
                                       public_key.data(), &output_len,
                                       &pubkey, SECP256K1_EC_COMPRESSED) != 1) {
        return Error{ErrorCode::CryptoError, "Failed to serialize public key"};
    }

    return public_key;
}

Result<std::vector<uint8_t>> BitcoinSignature::GetUncompressedPublicKey(
    const std::vector<uint8_t>& private_key) {

    if (!IsValidPrivateKey(private_key)) {
        return Error{ErrorCode::InvalidArgument, "Invalid secp256k1 private key"};
    }

    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_create(static_cast<secp256k1_context*>(ctx_),
                                    &pubkey, private_key.data()) != 1) {
        return Error{ErrorCode::CryptoError, "Failed to create public key"};
    }

    // Serialize as uncompressed (65 bytes)
    std::vector<uint8_t> public_key(KeySize::SECP256K1_PUBLIC_KEY_UNCOMPRESSED);
    size_t output_len = public_key.size();

    if (secp256k1_ec_pubkey_serialize(static_cast<secp256k1_context*>(ctx_),
                                       public_key.data(), &output_len,
                                       &pubkey, SECP256K1_EC_UNCOMPRESSED) != 1) {
        return Error{ErrorCode::CryptoError, "Failed to serialize public key"};
    }

    return public_key;
}

Result<std::vector<uint8_t>> BitcoinSignature::GetPublicKeyFromSeed(
    const std::string& seed) {

    auto private_key = GetPrivateKeyFromSeed(seed);
    if (private_key.IsErr()) {
        return Error{private_key.GetError()};
    }

    return GetPublicKeyFromPrivateKey(private_key.Value());
}

Result<std::vector<uint8_t>> BitcoinSignature::Sign(
    const std::vector<uint8_t>& private_key,
    const std::vector<uint8_t>& payload) {

    if (!IsValidPrivateKey(private_key)) {
        return Error{ErrorCode::InvalidArgument, "Invalid secp256k1 private key"};
    }

    // Hash the payload (Bitcoin signs the hash)
    auto hash_result = Hash::DoubleSHA256(payload);
    if (hash_result.IsErr()) {
        return Error{hash_result.GetError()};
    }

    secp256k1_ecdsa_signature sig;
    if (secp256k1_ecdsa_sign(static_cast<secp256k1_context*>(ctx_),
                              &sig, hash_result.Value().data(),
                              private_key.data(), nullptr, nullptr) != 1) {
        return Error{ErrorCode::CryptoError, "secp256k1 signing failed"};
    }

    // Serialize to compact format (64 bytes)
    std::vector<uint8_t> signature(KeySize::SECP256K1_SIGNATURE);
    if (secp256k1_ecdsa_signature_serialize_compact(
            static_cast<secp256k1_context*>(ctx_),
            signature.data(), &sig) != 1) {
        return Error{ErrorCode::CryptoError, "Failed to serialize signature"};
    }

    return signature;
}

Result<std::vector<uint8_t>> BitcoinSignature::SignDER(
    const std::vector<uint8_t>& private_key,
    const std::vector<uint8_t>& payload) {

    if (!IsValidPrivateKey(private_key)) {
        return Error{ErrorCode::InvalidArgument, "Invalid secp256k1 private key"};
    }

    auto hash_result = Hash::DoubleSHA256(payload);
    if (hash_result.IsErr()) {
        return Error{hash_result.GetError()};
    }

    secp256k1_ecdsa_signature sig;
    if (secp256k1_ecdsa_sign(static_cast<secp256k1_context*>(ctx_),
                              &sig, hash_result.Value().data(),
                              private_key.data(), nullptr, nullptr) != 1) {
        return Error{ErrorCode::CryptoError, "secp256k1 signing failed"};
    }

    // Serialize to DER format
    std::vector<uint8_t> signature(KeySize::SECP256K1_SIGNATURE_DER_MAX);
    size_t sig_len = signature.size();

    if (secp256k1_ecdsa_signature_serialize_der(
            static_cast<secp256k1_context*>(ctx_),
            signature.data(), &sig_len, &sig) != 1) {
        return Error{ErrorCode::CryptoError, "Failed to serialize DER signature"};
    }

    signature.resize(sig_len);
    return signature;
}

Result<bool> BitcoinSignature::Verify(
    const std::vector<uint8_t>& public_key,
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& signature) {

    if (signature.size() != KeySize::SECP256K1_SIGNATURE) {
        return Error{ErrorCode::InvalidArgument, "Invalid signature size"};
    }

    // Parse public key
    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_parse(static_cast<secp256k1_context*>(ctx_),
                                   &pubkey, public_key.data(),
                                   public_key.size()) != 1) {
        return Error{ErrorCode::InvalidArgument, "Invalid public key"};
    }

    // Hash the payload
    auto hash_result = Hash::DoubleSHA256(payload);
    if (hash_result.IsErr()) {
        return Error{hash_result.GetError()};
    }

    // Parse signature from compact format
    secp256k1_ecdsa_signature sig;
    if (secp256k1_ecdsa_signature_parse_compact(
            static_cast<secp256k1_context*>(ctx_),
            &sig, signature.data()) != 1) {
        return Error{ErrorCode::InvalidArgument, "Invalid signature format"};
    }

    // Verify
    int result = secp256k1_ecdsa_verify(
        static_cast<secp256k1_context*>(ctx_),
        &sig, hash_result.Value().data(), &pubkey);

    return result == 1;
}

Result<bool> BitcoinSignature::VerifyDER(
    const std::vector<uint8_t>& public_key,
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& signature) {

    // Parse public key
    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_parse(static_cast<secp256k1_context*>(ctx_),
                                   &pubkey, public_key.data(),
                                   public_key.size()) != 1) {
        return Error{ErrorCode::InvalidArgument, "Invalid public key"};
    }

    // Hash the payload
    auto hash_result = Hash::DoubleSHA256(payload);
    if (hash_result.IsErr()) {
        return Error{hash_result.GetError()};
    }

    // Parse signature from DER format
    secp256k1_ecdsa_signature sig;
    if (secp256k1_ecdsa_signature_parse_der(
            static_cast<secp256k1_context*>(ctx_),
            &sig, signature.data(), signature.size()) != 1) {
        return Error{ErrorCode::InvalidArgument, "Invalid DER signature format"};
    }

    // Verify
    int result = secp256k1_ecdsa_verify(
        static_cast<secp256k1_context*>(ctx_),
        &sig, hash_result.Value().data(), &pubkey);

    return result == 1;
}

Result<bool> BitcoinSignature::VerifySchnorr(
    const std::vector<uint8_t>& xonly_pubkey,
    const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& signature) const {
    // BIP-340 schnorr (Taproot key-path). The account's 32-byte program is the x-only output key.
    if (xonly_pubkey.size() != 32)
        return Error{ErrorCode::InvalidArgument, "schnorr: x-only pubkey must be 32 bytes"};
    if (signature.size() != 64)
        return Error{ErrorCode::InvalidArgument, "schnorr: signature must be 64 bytes"};
    if (message.size() != 32)
        return Error{ErrorCode::InvalidArgument, "schnorr: message must be 32 bytes"};
    if (!ctx_)
        return Error{ErrorCode::CryptoError, "schnorr: secp256k1 context not initialized"};

    secp256k1_xonly_pubkey pk;
    if (!secp256k1_xonly_pubkey_parse(static_cast<secp256k1_context*>(ctx_), &pk, xonly_pubkey.data()))
        return Error{ErrorCode::InvalidPublicKey, "schnorr: invalid x-only pubkey"};

    int ok = secp256k1_schnorrsig_verify(
        static_cast<secp256k1_context*>(ctx_),
        signature.data(), message.data(), message.size(), &pk);
    return ok == 1;
}

Result<std::vector<uint8_t>> BitcoinSignature::Hash160(const std::vector<uint8_t>& data) {
    // HASH160 = RIPEMD160(SHA256(data))
    auto sha256_result = Hash::SHA256(data);
    if (sha256_result.IsErr()) {
        return Error{sha256_result.GetError()};
    }

    auto ripemd_result = Hash::RIPEMD160(sha256_result.Value());
    if (ripemd_result.IsErr()) {
        return Error{ripemd_result.GetError()};
    }

    return ripemd_result.Value();
}

std::string BitcoinSignature::Base58CheckEncode(const std::vector<uint8_t>& data) {
    // Add checksum (first 4 bytes of double SHA256)
    std::vector<uint8_t> with_checksum = data;

    auto hash1 = Hash::SHA256(data);
    if (hash1.IsOk()) {
        auto hash2 = Hash::SHA256(hash1.Value());
        if (hash2.IsOk()) {
            // Append first 4 bytes of checksum
            for (int i = 0; i < 4; ++i) {
                with_checksum.push_back(hash2.Value()[i]);
            }
        }
    }

    // Count leading zeros
    size_t leading_zeros = 0;
    for (auto byte : with_checksum) {
        if (byte == 0) {
            leading_zeros++;
        } else {
            break;
        }
    }

    // Convert to Base58
    std::string result;

    // Simple Base58 encoding
    std::vector<uint8_t> digits;
    for (auto byte : with_checksum) {
        uint32_t carry = byte;
        for (auto& digit : digits) {
            carry += static_cast<uint32_t>(digit) << 8;
            digit = carry % 58;
            carry /= 58;
        }
        while (carry > 0) {
            digits.push_back(carry % 58);
            carry /= 58;
        }
    }

    // Add leading '1's for leading zeros
    result.append(leading_zeros, '1');

    // Convert digits to Base58 characters (reverse order)
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        result += BASE58_ALPHABET[*it];
    }

    return result;
}

Result<std::vector<uint8_t>> BitcoinSignature::Base58CheckDecode(const std::string& encoded) {
    if (encoded.empty()) {
        return Error{ErrorCode::InvalidArgument, "Empty Base58 string"};
    }

    // Count leading '1's
    size_t leading_ones = 0;
    for (char c : encoded) {
        if (c == '1') {
            leading_ones++;
        } else {
            break;
        }
    }

    // Decode Base58
    std::vector<uint8_t> bytes;
    for (char c : encoded) {
        const char* p = std::strchr(BASE58_ALPHABET, c);
        if (!p) {
            return Error{ErrorCode::InvalidArgument, "Invalid Base58 character"};
        }

        uint32_t carry = static_cast<uint32_t>(p - BASE58_ALPHABET);
        for (auto& byte : bytes) {
            carry += static_cast<uint32_t>(byte) * 58;
            byte = carry & 0xFF;
            carry >>= 8;
        }
        while (carry > 0) {
            bytes.push_back(carry & 0xFF);
            carry >>= 8;
        }
    }

    // Add leading zeros
    bytes.insert(bytes.end(), leading_ones, 0);

    // Reverse
    std::reverse(bytes.begin(), bytes.end());

    // Verify checksum
    if (bytes.size() < 4) {
        return Error{ErrorCode::InvalidArgument, "Base58Check data too short"};
    }

    std::vector<uint8_t> data(bytes.begin(), bytes.end() - 4);
    std::vector<uint8_t> checksum(bytes.end() - 4, bytes.end());

    auto hash1 = Hash::SHA256(data);
    if (hash1.IsErr()) {
        return Error{hash1.GetError()};
    }
    auto hash2 = Hash::SHA256(hash1.Value());
    if (hash2.IsErr()) {
        return Error{hash2.GetError()};
    }

    for (int i = 0; i < 4; ++i) {
        if (hash2.Value()[i] != checksum[i]) {
            return Error{ErrorCode::InvalidArgument, "Invalid Base58Check checksum"};
        }
    }

    return data;
}

std::string BitcoinSignature::GetAddressFromPublicKey(
    const std::string& prefix,
    const std::vector<uint8_t>& public_key) {

    // Bitcoin P2PKH address: Base58Check(version + HASH160(pubkey))
    auto hash160_result = Hash160(public_key);
    if (hash160_result.IsErr()) {
        return "";
    }

    // Version byte: 0x00 for mainnet, 0x6F for testnet
    uint8_t version = 0x00;
    if (prefix == "t" || prefix == "testnet") {
        version = 0x6F;
    }

    std::vector<uint8_t> address_bytes;
    address_bytes.push_back(version);
    address_bytes.insert(address_bytes.end(),
                         hash160_result.Value().begin(),
                         hash160_result.Value().end());

    return Base58CheckEncode(address_bytes);
}

Result<std::vector<uint8_t>> BitcoinSignature::GetPublicKeyFromAddress(
    const std::string& /* address */) {
    // Bitcoin addresses are hashes - cannot recover public key
    return Error{ErrorCode::Unimplemented,
                 "Cannot recover public key from Bitcoin address"};
}

std::vector<uint8_t> BitcoinSignature::GetAccountAddress(
    const std::vector<uint8_t>& public_key) {

    // Account address = prefix byte + HASH160(public_key)
    auto hash160_result = Hash160(public_key);
    if (hash160_result.IsErr()) {
        return {};
    }

    std::vector<uint8_t> address;
    address.reserve(1 + hash160_result.Value().size());
    address.push_back(GetAddressPrefix());
    address.insert(address.end(),
                   hash160_result.Value().begin(),
                   hash160_result.Value().end());
    return address;
}

// ==================== Transaction Parsing ====================

namespace {

// Read variable-length integer (Bitcoin's VarInt)
std::pair<uint64_t, size_t> ReadVarInt(const std::vector<uint8_t>& data, size_t pos) {
    if (pos >= data.size()) {
        return {0, 0};
    }

    uint8_t first = data[pos];
    if (first < 0xFD) {
        return {first, 1};
    } else if (first == 0xFD) {
        if (pos + 3 > data.size()) return {0, 0};
        uint64_t val = data[pos + 1] | (static_cast<uint64_t>(data[pos + 2]) << 8);
        return {val, 3};
    } else if (first == 0xFE) {
        if (pos + 5 > data.size()) return {0, 0};
        uint64_t val = data[pos + 1] |
                       (static_cast<uint64_t>(data[pos + 2]) << 8) |
                       (static_cast<uint64_t>(data[pos + 3]) << 16) |
                       (static_cast<uint64_t>(data[pos + 4]) << 24);
        return {val, 5};
    } else {
        if (pos + 9 > data.size()) return {0, 0};
        uint64_t val = 0;
        for (int i = 0; i < 8; i++) {
            val |= static_cast<uint64_t>(data[pos + 1 + i]) << (i * 8);
        }
        return {val, 9};
    }
}

// Read little-endian uint32
uint32_t ReadLE32(const std::vector<uint8_t>& data, size_t pos) {
    return data[pos] |
           (static_cast<uint32_t>(data[pos + 1]) << 8) |
           (static_cast<uint32_t>(data[pos + 2]) << 16) |
           (static_cast<uint32_t>(data[pos + 3]) << 24);
}

// Read little-endian int64
int64_t ReadLE64(const std::vector<uint8_t>& data, size_t pos) {
    int64_t val = 0;
    for (int i = 0; i < 8; i++) {
        val |= static_cast<int64_t>(data[pos + i]) << (i * 8);
    }
    return val;
}

}  // anonymous namespace

Result<BitcoinSignature::ParsedTransaction> BitcoinSignature::ParseSignedTransaction(
    const std::vector<uint8_t>& raw_tx) {

    if (raw_tx.size() < 10) {
        return Error{ErrorCode::InvalidArgument, "Transaction too short"};
    }

    ParsedTransaction tx;
    size_t pos = 0;

    // Version (4 bytes)
    tx.version = ReadLE32(raw_tx, pos);
    pos += 4;

    // Check for SegWit marker
    tx.has_witness = false;
    if (pos + 2 <= raw_tx.size() && raw_tx[pos] == 0x00 && raw_tx[pos + 1] == 0x01) {
        tx.has_witness = true;
        pos += 2;  // Skip marker and flag
    }

    // Input count
    auto [input_count, input_count_size] = ReadVarInt(raw_tx, pos);
    if (input_count_size == 0) {
        return Error{ErrorCode::InvalidArgument, "Invalid input count"};
    }
    pos += input_count_size;

    // Parse inputs
    for (uint64_t i = 0; i < input_count; i++) {
        ParsedTransaction::TxInput input;

        // Previous txid (32 bytes, reversed)
        if (pos + 32 > raw_tx.size()) {
            return Error{ErrorCode::InvalidArgument, "Unexpected end of transaction"};
        }
        input.prev_txid = std::vector<uint8_t>(raw_tx.begin() + pos, raw_tx.begin() + pos + 32);
        pos += 32;

        // Previous output index (4 bytes)
        if (pos + 4 > raw_tx.size()) {
            return Error{ErrorCode::InvalidArgument, "Unexpected end of transaction"};
        }
        input.prev_vout = ReadLE32(raw_tx, pos);
        pos += 4;

        // ScriptSig length and data
        auto [script_len, script_len_size] = ReadVarInt(raw_tx, pos);
        if (script_len_size == 0) {
            return Error{ErrorCode::InvalidArgument, "Invalid script length"};
        }
        pos += script_len_size;

        if (pos + script_len > raw_tx.size()) {
            return Error{ErrorCode::InvalidArgument, "Script extends beyond transaction"};
        }
        input.script_sig = std::vector<uint8_t>(raw_tx.begin() + pos, raw_tx.begin() + pos + script_len);
        pos += script_len;

        // Sequence (4 bytes)
        if (pos + 4 > raw_tx.size()) {
            return Error{ErrorCode::InvalidArgument, "Unexpected end of transaction"};
        }
        input.sequence = ReadLE32(raw_tx, pos);
        pos += 4;

        tx.inputs.push_back(input);
    }

    // Output count
    auto [output_count, output_count_size] = ReadVarInt(raw_tx, pos);
    if (output_count_size == 0) {
        return Error{ErrorCode::InvalidArgument, "Invalid output count"};
    }
    pos += output_count_size;

    // Parse outputs
    for (uint64_t i = 0; i < output_count; i++) {
        ParsedTransaction::TxOutput output;

        // Value (8 bytes)
        if (pos + 8 > raw_tx.size()) {
            return Error{ErrorCode::InvalidArgument, "Unexpected end of transaction"};
        }
        output.value = ReadLE64(raw_tx, pos);
        pos += 8;

        // ScriptPubKey length and data
        auto [script_len, script_len_size] = ReadVarInt(raw_tx, pos);
        if (script_len_size == 0) {
            return Error{ErrorCode::InvalidArgument, "Invalid script length"};
        }
        pos += script_len_size;

        if (pos + script_len > raw_tx.size()) {
            return Error{ErrorCode::InvalidArgument, "Script extends beyond transaction"};
        }
        output.script_pubkey = std::vector<uint8_t>(raw_tx.begin() + pos, raw_tx.begin() + pos + script_len);
        pos += script_len;

        tx.outputs.push_back(output);
    }

    // Skip witness data if present
    if (tx.has_witness) {
        for (uint64_t i = 0; i < input_count; i++) {
            auto [witness_count, witness_count_size] = ReadVarInt(raw_tx, pos);
            if (witness_count_size == 0) {
                return Error{ErrorCode::InvalidArgument, "Invalid witness count"};
            }
            pos += witness_count_size;

            for (uint64_t j = 0; j < witness_count; j++) {
                auto [item_len, item_len_size] = ReadVarInt(raw_tx, pos);
                if (item_len_size == 0) {
                    return Error{ErrorCode::InvalidArgument, "Invalid witness item length"};
                }
                pos += item_len_size + item_len;
            }
        }
    }

    // Locktime (4 bytes)
    if (pos + 4 > raw_tx.size()) {
        return Error{ErrorCode::InvalidArgument, "Missing locktime"};
    }
    tx.locktime = ReadLE32(raw_tx, pos);

    return tx;
}

Result<std::vector<uint8_t>> BitcoinSignature::DecodeAddress(const std::string& address) {
    if (address.empty()) {
        return Error{ErrorCode::InvalidArgument, "Empty address"};
    }

    // Check for Bech32 address (bc1...)
    if (address.size() >= 3) {
        std::string prefix;
        prefix.reserve(5);
        for (size_t i = 0; i < std::min<size_t>(5, address.size()); i++) {
            prefix.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(address[i]))));
        }
        if (prefix.rfind("bc1", 0) == 0 || prefix.rfind("tb1", 0) == 0 || prefix.rfind("bcrt1", 0) == 0) {
            auto program_result = DecodeBech32SegwitProgram(address);
            if (program_result.IsErr()) {
                return Error{program_result.GetError()};
            }
            auto program = program_result.Value();

            // Legacy: ZooBC compact BTC addresses only support 20-byte payloads (P2WPKH).
            if (program.size() != 20) {
                return Error{ErrorCode::InvalidArgument,
                             "Unsupported BTC SegWit program size (expected 20 bytes)"};
            }
            return program;
        }
    }

    // Decode Base58Check
    auto decode_result = Base58CheckDecode(address);
    if (decode_result.IsErr()) {
        return Error{decode_result.GetError()};
    }

    auto& data = decode_result.Value();

    // P2PKH: version (1 byte) + pubkey hash (20 bytes)
    // P2SH: version (1 byte) + script hash (20 bytes)
    if (data.size() != 21) {
        return Error{ErrorCode::InvalidArgument,
            "Invalid address length: expected 21, got " + std::to_string(data.size())};
    }

    uint8_t version = data[0];

    // Verify version byte
    // Mainnet: 0x00 (P2PKH), 0x05 (P2SH)
    // Testnet: 0x6F (P2PKH), 0xC4 (P2SH)
    if (version != 0x00 && version != 0x05 && version != 0x6F && version != 0xC4) {
        return Error{ErrorCode::InvalidArgument,
            "Unknown address version: " + std::to_string(version)};
    }

    // Return the 20-byte hash (without version byte)
    return std::vector<uint8_t>(data.begin() + 1, data.end());
}

Result<BitcoinDecodedAddress> BitcoinSignature::DecodeAddressWithType(const std::string& address) {
    if (address.empty()) {
        return Error{ErrorCode::InvalidArgument, "Empty address"};
    }

    // Check for Bech32/Bech32m address (bc1..., tb1..., bcrt1...)
    if (address.size() >= 3) {
        std::string prefix;
        prefix.reserve(5);
        for (size_t i = 0; i < std::min<size_t>(5, address.size()); i++) {
            prefix.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(address[i]))));
        }
        if (prefix.rfind("bc1", 0) == 0 || prefix.rfind("tb1", 0) == 0 || prefix.rfind("bcrt1", 0) == 0) {
            auto decoded = DecodeBech32SegwitAddress(address);
            if (decoded.IsErr()) {
                return Error{decoded.GetError()};
            }
            auto segwit = decoded.Value();

            if (segwit.witness_version == 0) {
                if (segwit.program.size() == 20) {
                    return BitcoinDecodedAddress{BitcoinAddressScriptType::P2WPKH, std::move(segwit.program)};
                }
                if (segwit.program.size() == 32) {
                    return BitcoinDecodedAddress{BitcoinAddressScriptType::P2WSH, std::move(segwit.program)};
                }
                return Error{ErrorCode::InvalidArgument, "Unsupported v0 witness program length"};
            }

            if (segwit.witness_version == 1) {
                if (segwit.program.size() != 32) {
                    return Error{ErrorCode::InvalidArgument, "Unsupported v1 witness program length"};
                }
                return BitcoinDecodedAddress{BitcoinAddressScriptType::P2TR, std::move(segwit.program)};
            }

            return Error{ErrorCode::InvalidArgument, "Unsupported witness version"};
        }
    }

    // Decode Base58Check
    auto decode_result = Base58CheckDecode(address);
    if (decode_result.IsErr()) {
        return Error{decode_result.GetError()};
    }

    auto& data = decode_result.Value();

    if (data.size() != 21) {
        return Error{ErrorCode::InvalidArgument,
            "Invalid address length: expected 21, got " + std::to_string(data.size())};
    }

    uint8_t version = data[0];

    // Mainnet: 0x00 (P2PKH), 0x05 (P2SH)
    // Testnet: 0x6F (P2PKH), 0xC4 (P2SH)
    if (version == 0x00 || version == 0x6F) {
        return BitcoinDecodedAddress{
            BitcoinAddressScriptType::P2PKH,
            std::vector<uint8_t>(data.begin() + 1, data.end())
        };
    }
    if (version == 0x05 || version == 0xC4) {
        return BitcoinDecodedAddress{
            BitcoinAddressScriptType::P2SH,
            std::vector<uint8_t>(data.begin() + 1, data.end())
        };
    }

    return Error{ErrorCode::InvalidArgument,
        "Unknown address version: " + std::to_string(version)};
}

}  // namespace crypto
}  // namespace zoobc
