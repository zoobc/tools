// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include "zoobc/crypto/signature.h"
#include "gen_common.h"

// zbc-key-gen — generate raw Ed25519 keypair(s). Shared I/O standard (gen_common.h):
// JSON by default (machine/script), human when run in a terminal, -v forces human, --json forces
// JSON, --help/-h prints help.

int main(int argc, char* argv[]) {
    auto mode = zbctool::parse_mode(argc, argv);
    if (mode.help) {
        std::cerr << "Usage: zbc-key-gen [count] [-v|--verbose] [--json]\n"
                  << "  Generate raw Ed25519 keypair(s). Default output JSON; human in a terminal.\n"
                  << "  count: 1..100 (default 1).\n";
        return 0;
    }

    int num_keys = 1;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (zbctool::is_mode_flag(a)) continue;
        int n = std::atoi(a.c_str());
        if (n >= 1 && n <= 100) num_keys = n;
        else { std::cerr << "Error: count must be between 1 and 100\n"; return 1; }
    }

    auto to_hex = [](const std::vector<uint8_t>& d) -> std::string {
        std::stringstream ss;
        for (uint8_t b : d) ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        return ss.str();
    };

    struct K { std::string pub, priv; };
    std::vector<K> keys;
    for (int i = 0; i < num_keys; ++i) {
        auto r = zoobc::crypto::Signature::GenerateKeyPair();
        if (!r.IsOk()) { std::cerr << "Error generating keypair: " << r.GetError().ToString() << "\n"; return 1; }
        auto kp = r.Value();
        std::vector<uint8_t> seed(kp.private_key.begin(), kp.private_key.begin() + 32);  // ZooBC uses the 32-byte seed
        keys.push_back({to_hex(kp.public_key), to_hex(seed)});
    }

    if (!mode.verbose) {
        std::cout << "[";
        for (size_t i = 0; i < keys.size(); ++i)
            std::cout << (i ? "," : "") << "{\"index\":" << (i + 1)
                      << ",\"public_key\":\"" << keys[i].pub << "\",\"private_key\":\"" << keys[i].priv << "\"}";
        std::cout << "]\n";
        return 0;
    }

    std::cout << "ZooBC Keypair Generator\n=======================\n\n";
    for (size_t i = 0; i < keys.size(); ++i) {
        if (keys.size() > 1) std::cout << "Keypair " << (i + 1) << ":\n";
        std::cout << "Public Key:  " << keys[i].pub << "\nPrivate Key: " << keys[i].priv << "\n";
        if (keys.size() > 1) std::cout << "\n";
    }
    std::cout << "\nIMPORTANT:\n  - Keep private keys SECRET\n  - Each node needs a unique keypair\n  - Back up these keys securely\n";
    return 0;
}
