// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cstdlib>
#include <sodium.h>
#include "zoobc/crypto/signature.h"
#include "zoobc/crypto/slip10.h"
#include "gen_common.h"

// zbc-account-from-key — derive the ZBC account address from a 32-byte private key.
// Shared I/O standard: JSON default, human in a terminal, -v/--json/--help.

static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    if (hex.size() % 2) return bytes;
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        bytes.push_back(static_cast<uint8_t>(strtol(hex.substr(i, 2).c_str(), nullptr, 16)));
    return bytes;
}
static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    for (uint8_t b : bytes) ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return ss.str();
}

int main(int argc, char* argv[]) {
    auto mode = zbctool::parse_mode(argc, argv);
    if (mode.help) {
        std::cerr << "Usage: zbc-account-from-key <private_key_hex> [-v|--verbose] [--json]\n"
                  << "  Derive the ZBC account address from a 32-byte private key (64 hex chars).\n";
        return 0;
    }

    std::string privkey_hex;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (zbctool::is_mode_flag(a)) continue;
        if (!a.empty() && a[0] != '-') privkey_hex = a;
    }
    if (privkey_hex.empty()) { std::cerr << "Error: private key required (run with --help)\n"; return 1; }

    auto pk = hex_to_bytes(privkey_hex);
    if (pk.size() != 32) { std::cerr << "Error: private key must be 32 bytes (64 hex chars)\n"; return 1; }
    if (sodium_init() < 0) { std::cerr << "Error: libsodium init failed\n"; return 1; }

    std::vector<uint8_t> public_key(crypto_sign_ed25519_PUBLICKEYBYTES), secret(crypto_sign_ed25519_SECRETKEYBYTES);
    if (crypto_sign_ed25519_seed_keypair(public_key.data(), secret.data(), pk.data()) != 0) {
        std::cerr << "Error: failed to derive keypair from seed\n"; return 1;
    }
    std::string addr = zoobc::crypto::ZoobcAddress::Encode(public_key, "ZBC");
    if (addr.empty()) { std::cerr << "Error: address encoding failed\n"; return 1; }

    if (!mode.verbose) {
        std::cout << "{\"private_key\":\"" << privkey_hex << "\",\"public_key\":\"" << bytes_to_hex(public_key)
                  << "\",\"account_address\":\"" << addr << "\"}\n";
        return 0;
    }
    std::cout << "ZooBC Account Address from Private Key\n=====================================\n\n"
              << "Private key (seed): " << privkey_hex << "\n"
              << "Public key:         " << bytes_to_hex(public_key) << "\n"
              << "ZBC Account:        " << addr << "\n";
    return 0;
}
