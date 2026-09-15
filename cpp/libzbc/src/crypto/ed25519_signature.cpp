// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/crypto/ed25519_signature.h"
#include "zoobc/crypto/hash.h"
#include <sodium.h>
#include <sstream>
#include <iomanip>

namespace zoobc {
namespace crypto {

Result<std::vector<uint8_t>> Ed25519Signature::GetPrivateKeyFromSeed(
    const std::string& seed) {

    // Hash seed to get 32-byte seed value
    std::vector<uint8_t> seed_bytes(seed.begin(), seed.end());
    auto hash_result = Hash::SHA3_256(seed_bytes);
    if (hash_result.IsErr()) {
        return Error{hash_result.GetError()};
    }

    // Generate Ed25519 key pair from seed
    std::vector<uint8_t> public_key(crypto_sign_PUBLICKEYBYTES);
    std::vector<uint8_t> private_key(crypto_sign_SECRETKEYBYTES);

    if (crypto_sign_seed_keypair(public_key.data(), private_key.data(),
                                   hash_result.Value().data()) != 0) {
        return Error{ErrorCode::CryptoError, "Failed to generate Ed25519 key pair"};
    }

    return private_key;
}

Result<std::vector<uint8_t>> Ed25519Signature::GetPublicKeyFromPrivateKey(
    const std::vector<uint8_t>& private_key) {

    if (private_key.size() != crypto_sign_SECRETKEYBYTES) {
        return Error{ErrorCode::InvalidArgument,
                     "Invalid private key size for Ed25519"};
    }

    // Ed25519 private key contains public key in last 32 bytes
    std::vector<uint8_t> public_key(private_key.begin() + 32, private_key.end());
    return public_key;
}

Result<std::vector<uint8_t>> Ed25519Signature::GetPublicKeyFromSeed(
    const std::string& seed) {

    auto private_key = GetPrivateKeyFromSeed(seed);
    if (private_key.IsErr()) {
        return Error{private_key.GetError()};
    }

    return GetPublicKeyFromPrivateKey(private_key.Value());
}

Result<std::vector<uint8_t>> Ed25519Signature::Sign(
    const std::vector<uint8_t>& private_key,
    const std::vector<uint8_t>& payload) {

    if (private_key.size() != crypto_sign_SECRETKEYBYTES) {
        return Error{ErrorCode::InvalidArgument,
                     "Invalid private key size for Ed25519"};
    }

    std::vector<uint8_t> signature(crypto_sign_BYTES);
    unsigned long long sig_len;

    if (crypto_sign_detached(signature.data(), &sig_len,
                              payload.data(), payload.size(),
                              private_key.data()) != 0) {
        return Error{ErrorCode::CryptoError, "Ed25519 signing failed"};
    }

    signature.resize(sig_len);
    return signature;
}

Result<bool> Ed25519Signature::Verify(
    const std::vector<uint8_t>& public_key,
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& signature) {

    if (public_key.size() != crypto_sign_PUBLICKEYBYTES) {
        return Error{ErrorCode::InvalidArgument,
                     "Invalid public key size for Ed25519"};
    }

    if (signature.size() != crypto_sign_BYTES) {
        return Error{ErrorCode::InvalidArgument,
                     "Invalid signature size for Ed25519"};
    }

    int result = crypto_sign_verify_detached(
        signature.data(),
        payload.data(), payload.size(),
        public_key.data());

    return result == 0;
}

std::string Ed25519Signature::GetAddressFromPublicKey(
    const std::string& prefix,
    const std::vector<uint8_t>& public_key) {

    // ZBC addresses are the public key encoded as hex with prefix
    std::ostringstream ss;
    ss << prefix;
    for (uint8_t byte : public_key) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

Result<std::vector<uint8_t>> Ed25519Signature::GetPublicKeyFromAddress(
    const std::string& address) {

    // Find the hex portion (after any prefix like "ZBC")
    size_t hex_start = 0;
    for (size_t i = 0; i < address.size(); ++i) {
        if (std::isxdigit(static_cast<unsigned char>(address[i]))) {
            hex_start = i;
            break;
        }
    }

    std::string hex_part = address.substr(hex_start);
    if (hex_part.size() != 64) {  // 32 bytes * 2 hex chars
        return Error{ErrorCode::InvalidArgument, "Invalid Ed25519 address format"};
    }

    std::vector<uint8_t> public_key;
    public_key.reserve(32);

    for (size_t i = 0; i < hex_part.size(); i += 2) {
        unsigned int byte;
        std::istringstream iss(hex_part.substr(i, 2));
        iss >> std::hex >> byte;
        public_key.push_back(static_cast<uint8_t>(byte));
    }

    return public_key;
}

std::vector<uint8_t> Ed25519Signature::GetAccountAddress(
    const std::vector<uint8_t>& public_key) {

    // Account address = prefix byte + public key
    std::vector<uint8_t> address;
    address.reserve(1 + public_key.size());
    address.push_back(GetAddressPrefix());
    address.insert(address.end(), public_key.begin(), public_key.end());
    return address;
}

}  // namespace crypto
}  // namespace zoobc
