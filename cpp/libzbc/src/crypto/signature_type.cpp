// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/crypto/signature_type.h"
#include "zoobc/crypto/ed25519_signature.h"
#include "zoobc/crypto/bitcoin_signature.h"
#include "zoobc/crypto/ethereum_signature.h"

namespace zoobc {
namespace crypto {

std::unique_ptr<SignatureType> SignatureTypeFactory::Create(SignatureTypeID type) {
    switch (type) {
        case SignatureTypeID::Ed25519:
            return std::make_unique<Ed25519Signature>();

        case SignatureTypeID::Bitcoin:
            return std::make_unique<BitcoinSignature>();

        case SignatureTypeID::Ethereum:
            return std::make_unique<EthereumSignature>();

        case SignatureTypeID::EstoniaEID:
            // Not implemented yet
            return nullptr;

        default:
            return nullptr;
    }
}

std::unique_ptr<SignatureType> SignatureTypeFactory::CreateFromAccountAddress(
    const std::vector<uint8_t>& address) {

    if (address.empty()) {
        return nullptr;
    }

    SignatureTypeID type = GetTypeFromPrefix(address[0]);
    return Create(type);
}

SignatureTypeID SignatureTypeFactory::GetTypeFromPrefix(uint8_t prefix) {
    switch (prefix) {
        case AccountPrefix::ZBC:
            return SignatureTypeID::Ed25519;

        case AccountPrefix::Bitcoin:
            return SignatureTypeID::Bitcoin;

        case AccountPrefix::Ethereum:
            return SignatureTypeID::Ethereum;

        case AccountPrefix::EstoniaEID:
            return SignatureTypeID::EstoniaEID;

        default:
            // Default to Ed25519 for unknown prefixes
            return SignatureTypeID::Ed25519;
    }
}

bool SignatureTypeFactory::IsSupported(SignatureTypeID type) {
    switch (type) {
        case SignatureTypeID::Ed25519:
        case SignatureTypeID::Bitcoin:
        case SignatureTypeID::Ethereum:
            return true;

        case SignatureTypeID::EstoniaEID:
            return false;  // Not implemented yet

        default:
            return false;
    }
}

std::vector<SignatureTypeID> SignatureTypeFactory::GetSupportedTypes() {
    return {
        SignatureTypeID::Ed25519,
        SignatureTypeID::Bitcoin,
        SignatureTypeID::Ethereum
    };
}

}  // namespace crypto
}  // namespace zoobc
