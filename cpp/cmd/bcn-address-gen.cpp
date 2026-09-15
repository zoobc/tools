// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <sodium.h>
#include "zoobc/crypto/signature.h"
#include "zoobc/crypto/hash.h"
#include "zoobc/crypto/slip10.h"
#include "gen_common.h"

// zbc-node-gen — generate a ZooBC node keypair and EVERY role address for that key.
//
// The node (ZNK), account/owner (ZBC), relay (ZBR) and gateway (ZBG) forms are the SAME public key
// with a different 3-letter prefix; the checksum is recomputed per prefix, so you cannot swap prefixes
// by hand. This tool emits all four so a multi-role machine's genesis (node_public_key / owner_account
// / relay_key / gateway_key) can be filled from a single key.
//
// STANDARD (shared by the ZooBC CLI tools): default is machine-readable JSON in / JSON out; pass
// -v / --verbose for human-readable text.
//   default : [{"index":1,"public_key","private_key","address"(ZNK),"account_address"(ZBC),
//              "relay_key"(ZBR),"gateway_key"(ZBG)}]
//   -v      : labeled block.
// Use --from-privkey <hex> to print all role addresses for an EXISTING 32-byte key (no new key made).

namespace {

std::string to_hex(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    for (uint8_t b : data) ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return ss.str();
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0) return {};
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        int hi = val(hex[i]), lo = val(hex[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

struct RoleKeys {
    std::string public_key, private_key, node, account, relay, gateway;
    bool ok = false;
};

// Same public key, every role prefix (checksum recomputed per prefix by Encode()).
RoleKeys build_from_seed(const std::vector<uint8_t>& seed) {
    RoleKeys k;
    if (seed.size() != 32) return k;
    std::vector<uint8_t> pk(crypto_sign_ed25519_PUBLICKEYBYTES);
    std::vector<uint8_t> sk(crypto_sign_ed25519_SECRETKEYBYTES);
    if (crypto_sign_ed25519_seed_keypair(pk.data(), sk.data(), seed.data()) != 0) return k;
    k.public_key  = to_hex(pk);
    k.private_key = to_hex(seed);
    k.node    = zoobc::crypto::ZoobcAddress::Encode(pk, "ZNK");
    k.account = zoobc::crypto::ZoobcAddress::Encode(pk, "ZBC");
    k.relay   = zoobc::crypto::ZoobcAddress::Encode(pk, "ZBR");
    k.gateway = zoobc::crypto::ZoobcAddress::Encode(pk, "ZBG");
    k.ok = !(k.node.empty() || k.account.empty() || k.relay.empty() || k.gateway.empty());
    return k;
}

}  // namespace

int main(int argc, char* argv[]) {
    int num_keys = 1;
    std::string from_priv;
    auto mode = zbctool::parse_mode(argc, argv);   // shared: JSON default, human in a terminal, -v/--json
    const bool verbose = mode.verbose;

    if (mode.help) {
        std::cerr << "Usage: zbc-node-gen [count] [-v|--verbose] [--json] [--from-privkey <hex>]\n"
                  << "  Generates a ZooBC node keypair and every role address for each key:\n"
                  << "    node (ZNK), account/owner (ZBC), relay (ZBR), gateway (ZBG).\n"
                  << "  Default output JSON; human-readable in a terminal. count: 1..100 (default 1).\n"
                  << "  --from-privkey <hex>: print all role addresses for an EXISTING 32-byte key.\n";
        return 0;
    }
    for (int a = 1; a < argc; a++) {
        std::string arg = argv[a];
        if (zbctool::is_mode_flag(arg)) continue;
        if (arg == "--from-privkey" || arg == "-k") {
            if (a + 1 >= argc) { std::cerr << "Error: " << arg << " needs a 64-hex private key\n"; return 1; }
            from_priv = argv[++a]; continue;
        }
        int n = std::atoi(arg.c_str());
        if (n >= 1 && n <= 100) { num_keys = n; }
        else { std::cerr << "Error: count must be between 1 and 100\n"; return 1; }
    }

    if (sodium_init() < 0) { std::cerr << "Error: libsodium init failed\n"; return 1; }

    // Build everything BEFORE emitting, so an error can't leave half a JSON document.
    std::vector<RoleKeys> keys;
    if (!from_priv.empty()) {
        auto seed = hex_to_bytes(from_priv);
        if (seed.size() != 32) { std::cerr << "Error: --from-privkey must be 32 bytes (64 hex chars)\n"; return 1; }
        auto k = build_from_seed(seed);
        if (!k.ok) { std::cerr << "Error: could not derive addresses from the given key\n"; return 1; }
        keys.push_back(k);
    } else {
        for (int i = 0; i < num_keys; i++) {
            auto result = zoobc::crypto::Signature::GenerateKeyPair();
            if (!result.IsOk()) { std::cerr << "Error generating keypair: " << result.GetError().ToString() << "\n"; return 1; }
            auto kp = result.Value();
            std::vector<uint8_t> seed(kp.private_key.begin(), kp.private_key.begin() + 32);
            auto k = build_from_seed(seed);
            if (!k.ok) { std::cerr << "Error: address encoding failed\n"; return 1; }
            keys.push_back(k);
        }
    }

    if (!verbose) {
        // JSON (default). "address" stays the node/ZNK form for backward-compatible script parsing.
        std::cout << "[";
        for (size_t i = 0; i < keys.size(); i++) {
            const auto& k = keys[i];
            std::cout << (i ? "," : "")
                      << "{\"index\":" << (i + 1)
                      << ",\"public_key\":\"" << k.public_key << "\""
                      << ",\"private_key\":\"" << k.private_key << "\""
                      << ",\"address\":\"" << k.node << "\""
                      << ",\"account_address\":\"" << k.account << "\""
                      << ",\"relay_key\":\"" << k.relay << "\""
                      << ",\"gateway_key\":\"" << k.gateway << "\"}";
        }
        std::cout << "]\n";
        return 0;
    }

    // Human-readable (-v).
    std::cout << "ZooBC Node / Role Address Generator\n";
    std::cout << "===================================\n\n";
    for (size_t i = 0; i < keys.size(); i++) {
        const auto& k = keys[i];
        if (keys.size() > 1) std::cout << "Key " << (i + 1) << ":\n";
        std::cout << "Node (ZNK):        " << k.node << "\n";
        std::cout << "Account (ZBC):     " << k.account << "\n";
        std::cout << "Relay (ZBR):       " << k.relay << "\n";
        std::cout << "Gateway (ZBG):     " << k.gateway << "\n";
        std::cout << "Public Key (hex):  " << k.public_key << "\n";
        std::cout << "Private Key (hex): " << k.private_key << "\n";
        if (keys.size() > 1) std::cout << "\n";
    }
    std::cout << "\nNOTES:\n"
              << "  - node / account / relay / gateway are the SAME key with different prefixes\n"
              << "    (the checksum is recomputed per prefix — you cannot swap prefixes by hand).\n"
              << "  - genesis: node_public_key=ZNK, owner_account=ZBC, relay_key=ZBR, gateway_key=ZBG\n"
              << "    (the genesis-builder also accepts the plain 64-hex public key for any of these).\n"
              << "  - Keep the private key SECRET. Each machine needs a unique keypair.\n";
    return 0;
}
