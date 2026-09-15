// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/crypto/signature.h"
#include "zoobc/crypto/ethereum_signature.h"
#include "zoobc/crypto/bitcoin_signature.h"
#include "zoobc/crypto/sr25519.h"
#include "zoobc/crypto/hash.h"
#include <sodium.h>
#include <cstring>

namespace zoobc {
namespace crypto {

Result<KeyPair> Signature::GenerateKeyPair() {
    // Initialize libsodium (safe to call multiple times)
    if (sodium_init() < 0) {
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Failed to initialize libsodium");
    }

    KeyPair keypair;
    keypair.public_key.resize(crypto_sign_ed25519_PUBLICKEYBYTES);
    keypair.private_key.resize(crypto_sign_ed25519_SECRETKEYBYTES);

    if (crypto_sign_ed25519_keypair(keypair.public_key.data(), keypair.private_key.data()) != 0) {
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Failed to generate Ed25519 key pair");
    }

    return keypair;
}

Result<std::vector<uint8_t>> Signature::Sign(const std::vector<uint8_t>& message,
                                               const std::vector<uint8_t>& private_key) {
    // Validate private key size
    if (private_key.size() != crypto_sign_ed25519_SECRETKEYBYTES) {
        return ZOOBC_ERROR(ErrorCode::InvalidPrivateKey,
                           "Invalid private key size: expected " +
                               std::to_string(crypto_sign_ed25519_SECRETKEYBYTES) + " bytes, got " +
                               std::to_string(private_key.size()));
    }

    std::vector<uint8_t> signature(crypto_sign_ed25519_BYTES);

    if (crypto_sign_ed25519_detached(signature.data(), nullptr, message.data(), message.size(),
                                     private_key.data()) != 0) {
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Failed to sign message");
    }

    return signature;
}

Result<bool> Signature::Verify(const std::vector<uint8_t>& message,
                                const std::vector<uint8_t>& signature,
                                const std::vector<uint8_t>& public_key) {
    // Validate public key size
    if (public_key.size() != crypto_sign_ed25519_PUBLICKEYBYTES) {
        return ZOOBC_ERROR(ErrorCode::InvalidPublicKey,
                           "Invalid public key size: expected " +
                               std::to_string(crypto_sign_ed25519_PUBLICKEYBYTES) + " bytes, got " +
                               std::to_string(public_key.size()));
    }

    // Validate signature size
    if (signature.size() != crypto_sign_ed25519_BYTES) {
        return ZOOBC_ERROR(ErrorCode::InvalidSignature,
                           "Invalid signature size: expected " +
                               std::to_string(crypto_sign_ed25519_BYTES) + " bytes, got " +
                               std::to_string(signature.size()));
    }

    int result = crypto_sign_ed25519_verify_detached(signature.data(), message.data(),
                                                      message.size(), public_key.data());

    return (result == 0);
}

Result<std::vector<uint8_t>> Signature::ExtractPublicKey(
    const std::vector<uint8_t>& private_key) {
    // Validate private key size
    if (private_key.size() != crypto_sign_ed25519_SECRETKEYBYTES) {
        return ZOOBC_ERROR(ErrorCode::InvalidPrivateKey,
                           "Invalid private key size: expected " +
                               std::to_string(crypto_sign_ed25519_SECRETKEYBYTES) + " bytes, got " +
                               std::to_string(private_key.size()));
    }

    std::vector<uint8_t> public_key(crypto_sign_ed25519_PUBLICKEYBYTES);

    if (crypto_sign_ed25519_sk_to_pk(public_key.data(), private_key.data()) != 0) {
        return ZOOBC_ERROR(ErrorCode::CryptoError, "Failed to extract public key from private key");
    }

    return public_key;
}

Result<std::vector<uint8_t>> Signature::GenerateBlockSeed(
    const std::vector<uint8_t>& previous_seed_hash,
    const std::vector<uint8_t>& private_key) {
    // Validate private key size
    if (private_key.size() != crypto_sign_ed25519_SECRETKEYBYTES) {
        return ZOOBC_ERROR(ErrorCode::InvalidPrivateKey,
                           "Invalid private key size for block seed generation");
    }

    // Generate VRF signature of the previous seed hash
    // This acts as a Verifiable Random Function - deterministic but unpredictable
    auto signature_result = Sign(previous_seed_hash, private_key);
    if (signature_result.IsErr()) {
        return Error{signature_result.GetError()};
    }

    // The signature itself serves as the block seed
    // In the Go implementation, this is the zedSecret.Sign(payload) result
    return signature_result.Value();
}

// ==============================================================================
// Multi-type signature verification (matching Go common/crypto/signature.go)
// ==============================================================================

AccountType Signature::GetAccountType(const std::vector<uint8_t>& account_address) {
    if (account_address.size() < AccountAddressSize::TYPE_PREFIX) {
        return AccountType::ZbcAccount;  // Default fallback
    }

    // Read 4-byte little-endian int32 type prefix
    int32_t type_int = 0;
    std::memcpy(&type_int, account_address.data(), sizeof(int32_t));

    switch (type_int) {
        case 0: return AccountType::ZbcAccount;
        case 1: return AccountType::BTCAccount;
        case 2: return AccountType::EmptyAccount;
        case 3: return AccountType::EstoniaEidAccount;
        case 4: return AccountType::ETHAccount;
        case 5: return AccountType::BTCP2PKHAccount;
        case 6: return AccountType::BTCP2SHAccount;
        case 7: return AccountType::BTCP2WPKHAccount;
        case 8: return AccountType::BTCP2WSHAccount;
        case 9: return AccountType::BTCP2TRAccount;
        case 10: return AccountType::DataSetAccount;
        // NOTE: 11 (Solana) intentionally falls through to ZbcAccount so it verifies as ed25519.
        case 12: return AccountType::PolkadotAccount;
        // Mirrored crypto-coin types verify with the chain's signature primitive by reusing the
        // matching verifier: Cardano/Tezos = ed25519 (ZbcAccount); Ripple = secp256k1+HASH160 (BTC);
        // Tron = secp256k1+Keccak (ETH). The type tag (13-16) is preserved for display/codec.
        case 13: return AccountType::ZbcAccount;  // Cardano (ZADA) — ed25519
        case 14: return AccountType::BTCAccount;  // Ripple (ZXRP) — secp256k1 + HASH160 address
        case 15: return AccountType::ETHAccount;  // Tron (ZTRX) — secp256k1 + Keccak address
        case 16: return AccountType::ZbcAccount;  // Tezos (ZXTZ) — ed25519 (tz1)
        default: return AccountType::ZbcAccount;  // Unknown type defaults to ZBC
    }
}

std::vector<uint8_t> Signature::GetPublicKeyFromAddress(
    const std::vector<uint8_t>& account_address) {

    if (account_address.size() <= AccountAddressSize::TYPE_PREFIX) {
        return {};  // No public key data
    }

    // Return everything after the 4-byte type prefix
    return std::vector<uint8_t>(
        account_address.begin() + AccountAddressSize::TYPE_PREFIX,
        account_address.end());
}

size_t Signature::GetSignatureSize(AccountType account_type) {
    switch (account_type) {
        case AccountType::ZbcAccount:
            return SignatureSize::ZBC;  // 64 bytes
        case AccountType::ETHAccount:
            return SignatureSize::ETH;  // 65 bytes
        case AccountType::BTCAccount:
        case AccountType::BTCP2PKHAccount:
        case AccountType::BTCP2SHAccount:
        case AccountType::BTCP2WPKHAccount:
        case AccountType::BTCP2WSHAccount:
            return 0;  // Variable size (ECDSA + carried compressed pubkey)
        case AccountType::BTCP2TRAccount:
            return 64;  // Taproot: a bare BIP-340 schnorr signature
        case AccountType::PolkadotAccount:
            return 64;  // sr25519 (Schnorrkel) / ed25519 signature
        case AccountType::EstoniaEidAccount:
            return 96;  // Estonia eID signature
        default:
            return 0;  // Unknown
    }
}

bool Signature::IsValidSignatureSize(
    const std::vector<uint8_t>& signature,
    AccountType account_type) {

    size_t expected = GetSignatureSize(account_type);

    if (expected == 0) {
        // Variable size - just check non-empty for BTC
        if (account_type == AccountType::BTCAccount ||
            account_type == AccountType::BTCP2PKHAccount ||
            account_type == AccountType::BTCP2SHAccount ||
            account_type == AccountType::BTCP2WPKHAccount ||
            account_type == AccountType::BTCP2WSHAccount) {
            // BTC: [2 bytes pubkey len] + [pubkey] + [signature]
            // Minimum: 2 + 33 + 32 = 67 bytes (compressed key, compact sig)
            return signature.size() >= 67;
        }
        return !signature.empty();
    }

    return signature.size() == expected;
}

// ==============================================================================
// Two-phase address support (compact vs full)
// ==============================================================================

bool Signature::IsCompactAddress(const std::vector<uint8_t>& account_address) {
    if (account_address.size() < AccountAddressSize::TYPE_PREFIX) {
        return false;
    }

    AccountType type = GetAccountType(account_address);
    size_t data_size = account_address.size() - AccountAddressSize::TYPE_PREFIX;

    switch (type) {
        case AccountType::ETHAccount:
            // Compact: 20-byte hash, Full: 64-byte pubkey
            return data_size == AccountAddressSize::ETH_HASH;

        case AccountType::BTCAccount:
        case AccountType::BTCP2PKHAccount:
        case AccountType::BTCP2SHAccount:
        case AccountType::BTCP2WPKHAccount:
            // Compact: 20-byte payload, Full (where applicable): 33 or 65-byte pubkey
            return data_size == AccountAddressSize::BTC_HASH;

        case AccountType::BTCP2WSHAccount:
        case AccountType::BTCP2TRAccount:
            // Compact: 32-byte witness program only
            return data_size == AccountAddressSize::BTC_WITNESS32;

        default:
            // ZBC and others don't have compact format
            return false;
    }
}

std::vector<uint8_t> Signature::HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        if (i + 1 >= hex.size()) break;
        unsigned int byte = 0;
        char high = hex[i];
        char low = hex[i + 1];

        if (high >= '0' && high <= '9') byte = (high - '0') << 4;
        else if (high >= 'a' && high <= 'f') byte = (high - 'a' + 10) << 4;
        else if (high >= 'A' && high <= 'F') byte = (high - 'A' + 10) << 4;

        if (low >= '0' && low <= '9') byte |= (low - '0');
        else if (low >= 'a' && low <= 'f') byte |= (low - 'a' + 10);
        else if (low >= 'A' && low <= 'F') byte |= (low - 'A' + 10);

        bytes.push_back(static_cast<uint8_t>(byte));
    }
    return bytes;
}

Result<std::vector<uint8_t>> Signature::ParseEthAddress(const std::string& eth_address) {
    // Standard ETH address: "0x" + 40 hex chars = 20 bytes
    std::string addr = eth_address;

    // Remove 0x prefix if present
    if (addr.size() >= 2 && addr[0] == '0' && (addr[1] == 'x' || addr[1] == 'X')) {
        addr = addr.substr(2);
    }

    if (addr.size() != 40) {
        return ZOOBC_ERROR(ErrorCode::InvalidArgument,
                          "ETH address must be 40 hex characters (20 bytes)");
    }

    // Validate hex characters
    for (char c : addr) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return ZOOBC_ERROR(ErrorCode::InvalidArgument,
                              "Invalid hex character in ETH address");
        }
    }

    // Build compact address: [type=4] + [20-byte hash]
    std::vector<uint8_t> result;
    result.reserve(AccountAddressSize::ETH_COMPACT);

    // Type prefix (4 bytes, little-endian)
    int32_t type = static_cast<int32_t>(AccountType::ETHAccount);
    result.push_back(type & 0xFF);
    result.push_back((type >> 8) & 0xFF);
    result.push_back((type >> 16) & 0xFF);
    result.push_back((type >> 24) & 0xFF);

    // Address hash (20 bytes)
    std::vector<uint8_t> hash = HexToBytes(addr);
    result.insert(result.end(), hash.begin(), hash.end());

    return result;
}

Result<std::vector<uint8_t>> Signature::ParseBtcAddress(const std::string& btc_address) {
    if (btc_address.empty()) {
        return ZOOBC_ERROR(ErrorCode::InvalidArgument, "Empty BTC address");
    }

    BitcoinSignature btc_sig;

    // ZooBC extension: decode and preserve script type so the original Bitcoin
    // address can be reconstructed (bridge correctness).
    auto decode_result = btc_sig.DecodeAddressWithType(btc_address);
    if (decode_result.IsErr()) {
        return ZOOBC_ERROR(ErrorCode::InvalidArgument,
                          "Failed to decode BTC address: " + decode_result.GetError().message);
    }

    auto decoded = decode_result.Value();

    int32_t type = static_cast<int32_t>(AccountType::BTCAccount);  // legacy default
    switch (decoded.script_type) {
        case BitcoinAddressScriptType::P2PKH:
            type = static_cast<int32_t>(AccountType::BTCP2PKHAccount);
            break;
        case BitcoinAddressScriptType::P2SH:
            type = static_cast<int32_t>(AccountType::BTCP2SHAccount);
            break;
        case BitcoinAddressScriptType::P2WPKH:
            type = static_cast<int32_t>(AccountType::BTCP2WPKHAccount);
            break;
        case BitcoinAddressScriptType::P2WSH:
            type = static_cast<int32_t>(AccountType::BTCP2WSHAccount);
            break;
        case BitcoinAddressScriptType::P2TR:
            type = static_cast<int32_t>(AccountType::BTCP2TRAccount);
            break;
    }

    const bool is_20 = (decoded.payload.size() == AccountAddressSize::BTC_HASH);
    const bool is_32 = (decoded.payload.size() == AccountAddressSize::BTC_WITNESS32);
    if (!is_20 && !is_32) {
        return ZOOBC_ERROR(ErrorCode::InvalidArgument,
                          "Invalid BTC address payload size (expected 20 or 32 bytes)");
    }

    // Build compact address: [type] + [payload]
    std::vector<uint8_t> result;
    result.reserve(AccountAddressSize::TYPE_PREFIX + decoded.payload.size());

    result.push_back(type & 0xFF);
    result.push_back((type >> 8) & 0xFF);
    result.push_back((type >> 16) & 0xFF);
    result.push_back((type >> 24) & 0xFF);

    result.insert(result.end(), decoded.payload.begin(), decoded.payload.end());

    return result;
}

std::vector<uint8_t> Signature::GetAddressHash(const std::vector<uint8_t>& account_address) {
    if (account_address.size() < AccountAddressSize::TYPE_PREFIX) {
        return {};
    }

    AccountType type = GetAccountType(account_address);
    std::vector<uint8_t> data = GetPublicKeyFromAddress(account_address);

    if (IsCompactAddress(account_address)) {
        // Compact format - data IS the hash
        return data;
    }

    // Full format - compute hash from pubkey
    switch (type) {
        case AccountType::ETHAccount: {
            // ETH address = last 20 bytes of Keccak256(pubkey)
            EthereumSignature eth_sig;
            return eth_sig.GetAddress20(data);
        }

        case AccountType::BTCAccount: {
            // BTC address = HASH160(pubkey) = RIPEMD160(SHA256(pubkey))
            BitcoinSignature btc_sig;
            auto hash_result = btc_sig.Hash160(data);
            if (hash_result.IsOk()) {
                return hash_result.Value();
            }
            return {};
        }

        case AccountType::BTCP2PKHAccount:
        case AccountType::BTCP2WPKHAccount: {
            // Pubkey-hash based BTC accounts (HASH160(pubkey))
            BitcoinSignature btc_sig;
            auto hash_result = btc_sig.Hash160(data);
            if (hash_result.IsOk()) {
                return hash_result.Value();
            }
            return {};
        }

        default:
            return {};
    }
}

// ==============================================================================
// Main verification dispatcher
// ==============================================================================

Result<bool> Signature::VerifySignature(
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& account_address) {

    // Handle legacy 32-byte ZBC public key format (no type prefix)
    // This format is used for backward compatibility with clients that send
    // just the raw Ed25519 public key without the 4-byte type prefix
    if (account_address.size() == 32) {
        // A Cardano account is ALSO 32 bytes: 4-byte type 13 + 28-byte blake2b-224 key hash, and its
        // signature is the 98-byte key-carrying envelope. Both must hold before it is taken as one;
        // a bare 64-byte signature on a 32-byte address stays the legacy ZBC path below.
        int32_t raw_type = 0;
        std::memcpy(&raw_type, account_address.data(), sizeof(int32_t));
        if (raw_type == 13 && signature.size() == 2 + 32 + 64) {
            return VerifyCardanoSignature(payload, signature, account_address);
        }
        // Legacy format: treat entire 32 bytes as ZBC Ed25519 public key
        return VerifyZbcSignature(payload, signature, account_address);
    }

    if (account_address.size() < AccountAddressSize::TYPE_PREFIX) {
        return ZOOBC_ERROR(ErrorCode::InvalidArgument,
                          "Account address too short");
    }

    // Tezos (raw type 16) is dispatched BEFORE the AccountType switch. GetAccountType maps it to
    // ZbcAccount so it reuses the ed25519 primitive, but a tz1 account is not a ZBC account: its
    // payload is a 20-byte key hash, not a key, and its signature is 98 bytes rather than 64. Both
    // the IsValidSignatureSize check and the ZbcAccount branch below would reject a perfectly good
    // tz1 signature, so it must be handled here rather than inside that switch.
    if (account_address.size() >= AccountAddressSize::TYPE_PREFIX) {
        int32_t raw_type = 0;
        std::memcpy(&raw_type, account_address.data(), sizeof(int32_t));
        if (raw_type == 16) {
            return VerifyTezosSignature(payload, signature, account_address);
        }
        // Cardano (raw type 13): same shape as Tezos — a 28-byte blake2b-224 key hash in the address,
        // the key in the signature — so it is dispatched here for the same reasons.
        if (raw_type == 13) {
            return VerifyCardanoSignature(payload, signature, account_address);
        }
    }

    AccountType account_type = GetAccountType(account_address);
    bool is_compact = IsCompactAddress(account_address);

    // For non-compact addresses, extract public key
    std::vector<uint8_t> public_key;
    if (!is_compact) {
        public_key = GetPublicKeyFromAddress(account_address);
        if (public_key.empty()) {
            return ZOOBC_ERROR(ErrorCode::InvalidPublicKey,
                              "Cannot extract public key from account address");
        }
    }

    // Validate signature size for account type
    if (!IsValidSignatureSize(signature, account_type)) {
        return ZOOBC_ERROR(ErrorCode::InvalidSignature,
                          "Invalid signature size for account type");
    }

    // Dispatch to appropriate verifier based on account type
    switch (account_type) {
        case AccountType::ZbcAccount:
            // ZBC doesn't have compact format
            return VerifyZbcSignature(payload, signature, public_key);

        case AccountType::ETHAccount:
            return VerifyEthSignature(payload, signature, account_address, is_compact);

        case AccountType::BTCAccount:
            return VerifyBtcSignature(payload, signature, account_address, is_compact);

        case AccountType::BTCP2PKHAccount:
        case AccountType::BTCP2WPKHAccount:
            return VerifyBtcSignature(payload, signature, account_address, is_compact);

        case AccountType::BTCP2SHAccount:
            return VerifyBtcSignature(payload, signature, account_address, is_compact);

        case AccountType::BTCP2TRAccount:
            // Taproot key-path: BIP-340 schnorr over the tx hash, verified against the 32-byte
            // output key (the account's program). The wallet does the BIP-341 tweak.
            return VerifyTaprootSignature(payload, signature, account_address);

        case AccountType::BTCP2WSHAccount:
            return ZOOBC_ERROR(ErrorCode::InvalidArgument,
                              "Bitcoin P2WSH (script) accounts cannot sign transactions on ZooBC");

        case AccountType::EstoniaEidAccount:
            return ZOOBC_ERROR(ErrorCode::Unimplemented,
                              "Estonia eID signature verification not implemented");

        case AccountType::PolkadotAccount:
            // sr25519 (Schnorrkel) over the tx hash with signing context "substrate", against the
            // account's 32-byte AccountId. Verifier is a C++ port of schnorrkel+merlin (no Rust dep).
            return VerifyPolkadotSignature(payload, signature, account_address);

        case AccountType::EmptyAccount:
            return ZOOBC_ERROR(ErrorCode::InvalidArgument,
                              "Cannot verify signature for empty account");

        default:
            return ZOOBC_ERROR(ErrorCode::InvalidArgument,
                              "Unknown account type");
    }
}

// ==============================================================================
// Type-specific verification helpers
// ==============================================================================

Result<bool> Signature::VerifyZbcSignature(
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& public_key) {

    // ZBC uses Ed25519 - delegate to existing Verify method
    return Verify(payload, signature, public_key);
}

Result<bool> Signature::VerifyEthSignature(
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& account_address,
    bool is_compact) {

    // ETH uses ECDSA with Keccak256
    // Signature format: [r: 32 bytes] [s: 32 bytes] [v: 1 byte]
    if (signature.size() != SignatureSize::ETH) {
        return ZOOBC_ERROR(ErrorCode::InvalidSignature,
                          "Invalid Ethereum signature size");
    }

    EthereumSignature eth_sig;

    if (is_compact) {
        // COMPACT FORMAT: Recover public key from signature, verify hash matches
        // This is the key feature: we can verify signatures without knowing pubkey in advance!

        // Recover public key from signature
        auto recover_result = eth_sig.RecoverPublicKey(payload, signature);
        if (recover_result.IsErr()) {
            return ZOOBC_ERROR(ErrorCode::InvalidSignature,
                              "Failed to recover public key from ETH signature: " +
                              recover_result.GetError().message);
        }

        std::vector<uint8_t> recovered_pubkey = recover_result.Value();

        // Compute address hash from recovered pubkey
        std::vector<uint8_t> recovered_hash = eth_sig.GetAddress20(recovered_pubkey);
        if (recovered_hash.size() != AccountAddressSize::ETH_HASH) {
            return ZOOBC_ERROR(ErrorCode::CryptoError,
                              "Failed to compute address from recovered public key");
        }

        // Get stored address hash
        std::vector<uint8_t> stored_hash = GetAddressHash(account_address);

        // Compare hashes
        if (recovered_hash != stored_hash) {
            return ZOOBC_ERROR(ErrorCode::InvalidSignature,
                              "Recovered ETH public key does not match account address");
        }

        // Signature is valid! (public key recovery succeeded and hash matches)
        return true;
    } else {
        // FULL FORMAT: Use stored public key directly
        std::vector<uint8_t> public_key = GetPublicKeyFromAddress(account_address);
        return eth_sig.Verify(public_key, payload, signature);
    }
}

Result<bool> Signature::VerifyTezosSignature(
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& account_address) {
    // Envelope: [2-byte LE pubkey length] || pubkey || signature. Fixed at 32 + 64 for tz1, but the
    // length is read rather than assumed so a malformed blob is rejected explicitly instead of
    // being sliced at the wrong offset.
    constexpr size_t kPubLen = 32, kSigLen = 64, kHashLen = 20;

    if (account_address.size() != AccountAddressSize::TYPE_PREFIX + kHashLen) {
        return ZOOBC_ERROR(ErrorCode::InvalidArgument,
                           "Tezos account address must be 4-byte type + 20-byte key hash");
    }
    if (signature.size() != 2 + kPubLen + kSigLen) {
        return ZOOBC_ERROR(ErrorCode::InvalidSignature,
                           "Tezos signature must be 98 bytes: [32,0] + 32-byte pubkey + 64-byte signature");
    }
    const uint16_t declared = static_cast<uint16_t>(signature[0]) |
                              (static_cast<uint16_t>(signature[1]) << 8);
    if (declared != kPubLen) {
        return ZOOBC_ERROR(ErrorCode::InvalidSignature,
                           "Tezos signature declares a public key length other than 32");
    }

    const std::vector<uint8_t> pub(signature.begin() + 2, signature.begin() + 2 + kPubLen);
    const std::vector<uint8_t> sig(signature.begin() + 2 + kPubLen, signature.end());

    // BIND the key to the account before trusting it. Verifying the signature alone would prove
    // only that SOMEBODY signed with SOME key; it is this check that makes it the account owner.
    std::vector<uint8_t> hash(kHashLen);
    if (crypto_generichash_blake2b(hash.data(), hash.size(), pub.data(), pub.size(), nullptr, 0) != 0) {
        return ZOOBC_ERROR(ErrorCode::Internal, "blake2b-160 failed");
    }
    if (!std::equal(hash.begin(), hash.end(),
                    account_address.begin() + AccountAddressSize::TYPE_PREFIX)) {
        return ZOOBC_ERROR(ErrorCode::InvalidSignature,
                           "Tezos public key does not hash to the account address");
    }

    return VerifyZbcSignature(payload, sig, pub);
}

Result<bool> Signature::VerifyCardanoSignature(
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& account_address) {
    constexpr size_t kPubLen = 32, kSigLen = 64, kHashLen = 28;   // blake2b-224, as on Cardano

    if (account_address.size() != AccountAddressSize::TYPE_PREFIX + kHashLen) {
        return ZOOBC_ERROR(ErrorCode::InvalidArgument,
                           "Cardano account address must be 4-byte type + 28-byte key hash");
    }
    if (signature.size() != 2 + kPubLen + kSigLen) {
        return ZOOBC_ERROR(ErrorCode::InvalidSignature,
                           "Cardano signature must be 98 bytes: [32,0] + 32-byte pubkey + 64-byte signature");
    }
    const uint16_t declared = static_cast<uint16_t>(signature[0]) |
                              (static_cast<uint16_t>(signature[1]) << 8);
    if (declared != kPubLen) {
        return ZOOBC_ERROR(ErrorCode::InvalidSignature,
                           "Cardano signature declares a public key length other than 32");
    }
    const std::vector<uint8_t> pub(signature.begin() + 2, signature.begin() + 2 + kPubLen);
    const std::vector<uint8_t> sig(signature.begin() + 2 + kPubLen, signature.end());

    std::vector<uint8_t> hash(kHashLen);
    if (crypto_generichash_blake2b(hash.data(), hash.size(), pub.data(), pub.size(), nullptr, 0) != 0) {
        return ZOOBC_ERROR(ErrorCode::Internal, "blake2b-224 failed");
    }
    if (!std::equal(hash.begin(), hash.end(),
                    account_address.begin() + AccountAddressSize::TYPE_PREFIX)) {
        return ZOOBC_ERROR(ErrorCode::InvalidSignature,
                           "Cardano public key does not hash to the account address");
    }
    return VerifyZbcSignature(payload, sig, pub);
}

Result<bool> Signature::VerifyBtcSignature(
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& account_address,
    [[maybe_unused]] bool is_compact) {
    // Note: is_compact reserved for future non-compact signature handling
    const AccountType account_type = GetAccountType(account_address);

    // BTC signature format (from Go btcAccountType.go:VerifySignature):
    // [2 bytes pubkey length] + [pubkey bytes] + [signature bytes]
    // Note: BTC always includes pubkey in signature, so both compact and full
    //       verification extract pubkey from signature and verify against stored address

    if (signature.size() < 2) {
        return ZOOBC_ERROR(ErrorCode::InvalidSignature,
                          "Bitcoin signature too short");
    }

    // Extract public key length from first 2 bytes (little-endian uint16)
    uint16_t pubkey_len = 0;
    pubkey_len = signature[0] | (static_cast<uint16_t>(signature[1]) << 8);

    if (pubkey_len == 0 || pubkey_len > 65) {
        return ZOOBC_ERROR(ErrorCode::InvalidSignature,
                          "Invalid public key length in Bitcoin signature");
    }

    size_t sig_pubkey_start = 2;
    size_t sig_pubkey_end = sig_pubkey_start + pubkey_len;

    if (sig_pubkey_end >= signature.size()) {
        return ZOOBC_ERROR(ErrorCode::InvalidSignature,
                          "Bitcoin signature missing signature bytes");
    }

    // Extract public key from signature
    std::vector<uint8_t> sig_pubkey(
        signature.begin() + sig_pubkey_start,
        signature.begin() + sig_pubkey_end);

    // Extract actual signature bytes
    std::vector<uint8_t> sig_bytes(
        signature.begin() + sig_pubkey_end,
        signature.end());

    BitcoinSignature btc_sig;

    // Compute HASH160 from signature's public key
    auto sig_hash_result = btc_sig.Hash160(sig_pubkey);
    if (sig_hash_result.IsErr()) {
        return ZOOBC_ERROR(ErrorCode::InvalidSignature,
                          "Failed to compute HASH160 from signature public key");
    }
    std::vector<uint8_t> sig_hash = sig_hash_result.Value();

    // Get stored address hash (works for both compact and full formats)
    std::vector<uint8_t> stored_hash = GetAddressHash(account_address);

    // Hashes must match
    std::vector<uint8_t> expected_hash;
    switch (account_type) {
        case AccountType::BTCAccount:
        case AccountType::BTCP2PKHAccount:
        case AccountType::BTCP2WPKHAccount:
            expected_hash = sig_hash;
            break;
        case AccountType::BTCP2SHAccount: {
            // Assume P2SH-P2WPKH (BIP49) redeem script: 0x00 0x14 <hash160(pubkey)>
            std::vector<uint8_t> redeem_script;
            redeem_script.reserve(2 + sig_hash.size());
            redeem_script.push_back(0x00);
            redeem_script.push_back(0x14);
            redeem_script.insert(redeem_script.end(), sig_hash.begin(), sig_hash.end());
            auto script_hash_result = btc_sig.Hash160(redeem_script);
            if (script_hash_result.IsErr()) {
                return ZOOBC_ERROR(ErrorCode::InvalidSignature,
                                  "Failed to compute HASH160 from P2SH redeem script");
            }
            expected_hash = script_hash_result.Value();
            break;
        }
        default:
            return ZOOBC_ERROR(ErrorCode::InvalidSignature,
                              "Unsupported BTC account type for signature verification");
    }

    if (expected_hash != stored_hash) {
        return ZOOBC_ERROR(ErrorCode::InvalidSignature,
                          "Bitcoin signature public key does not match account address hash");
    }

    // Now verify the actual signature using the extracted public key
    return btc_sig.Verify(sig_pubkey, payload, sig_bytes);
}

Result<bool> Signature::VerifyTaprootSignature(
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& account_address) {
    // The Taproot account is [4-byte type][32-byte x-only output key]. The output key IS the program
    // (BIP-341 key-path: tweaked internal key); the wallet signs with the matching tweaked private key.
    if (account_address.size() != AccountAddressSize::TYPE_PREFIX + 32) {
        return ZOOBC_ERROR(ErrorCode::InvalidArgument, "Taproot account must be type + 32-byte key");
    }
    if (signature.size() != 64) {
        return ZOOBC_ERROR(ErrorCode::InvalidSignature, "Taproot signature must be 64 bytes (schnorr)");
    }
    std::vector<uint8_t> output_key(account_address.begin() + AccountAddressSize::TYPE_PREFIX,
                                    account_address.end());
    BitcoinSignature btc_sig;
    return btc_sig.VerifySchnorr(output_key, payload, signature);
}

Result<bool> Signature::VerifyPolkadotSignature(
    const std::vector<uint8_t>& payload,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& account_address) {
    // Account = [4-byte type][32-byte AccountId]; the AccountId is the sr25519 public key.
    if (account_address.size() != AccountAddressSize::TYPE_PREFIX + 32) {
        return ZOOBC_ERROR(ErrorCode::InvalidArgument, "Polkadot account must be type + 32-byte AccountId");
    }
    if (signature.size() != 64) {
        return ZOOBC_ERROR(ErrorCode::InvalidSignature, "Polkadot signature must be 64 bytes (sr25519)");
    }
    std::vector<uint8_t> account_id(account_address.begin() + AccountAddressSize::TYPE_PREFIX,
                                    account_address.end());
    static const std::vector<uint8_t> kSubstrateContext = {'s','u','b','s','t','r','a','t','e'};
    bool ok = Sr25519Verify(account_id, kSubstrateContext, payload, signature);
    return Result<bool>(ok);
}

}  // namespace crypto
}  // namespace zoobc
