// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include "zoobc/crypto/slip10.h"
#include "zoobc/crypto/signature.h"
#include "gen_common.h"

// zbc-wallet-gen — HD wallet (SLIP-10 + BIP-39) address generator.
// Shared I/O standard (gen_common.h): JSON by default, human-readable in a terminal, -v forces human,
// --json forces JSON, --help/-h prints help.

using namespace zoobc;
using namespace zoobc::crypto;

static std::string to_hex(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    for (uint8_t b : data) ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return ss.str();
}

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " [--mnemonic \"WORDS\"] [--random] [OPTIONS]\n"
              << "  HD wallet (SLIP-10 + BIP-39). Default output JSON; human in a terminal.\n"
              << "Options:\n"
              << "  --mnemonic \"WORDS\"   Use an existing BIP-39 mnemonic\n"
              << "  --random             Generate from a new random 24-word mnemonic\n"
              << "  --password \"PASS\"    Optional BIP-39 passphrase\n"
              << "  --account N          First account index (default 0)\n"
              << "  --count N            Number of addresses (default 1, max 100)\n"
              << "  --node               Derive ZNK node addresses (default ZBC wallet)\n"
              << "  -v/--verbose | --json | --help/-h\n";
}

int main(int argc, char* argv[]) {
    auto mode = zbctool::parse_mode(argc, argv);
    std::string mnemonic, password;
    uint32_t start_account = 0;
    int count = 1;
    bool is_node = false, use_random = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (zbctool::is_mode_flag(arg)) continue;
        else if (arg == "--mnemonic" && i + 1 < argc) mnemonic = argv[++i];
        else if (arg == "--password" && i + 1 < argc) password = argv[++i];
        else if (arg == "--account" && i + 1 < argc) start_account = std::atoi(argv[++i]);
        else if (arg == "--count" && i + 1 < argc) count = std::atoi(argv[++i]);
        else if (arg == "--node") is_node = true;
        else if (arg == "--random") use_random = true;
        else { std::cerr << "Unknown option: " << arg << "\n"; print_usage(argv[0]); return 1; }
    }
    if (mode.help) { print_usage(argv[0]); return 0; }

    if (mnemonic.empty() && !use_random) { std::cerr << "Error: provide --mnemonic or --random\n"; return 1; }
    if (!use_random && !BIP39::ValidateMnemonic(mnemonic)) {
        std::cerr << "Error: invalid mnemonic (must be 12, 15, 18, 21, or 24 words)\n"; return 1;
    }
    if (count < 1 || count > 100) { std::cerr << "Error: count must be between 1 and 100\n"; return 1; }

    if (use_random) {
        auto m = BIP39::GenerateMnemonic(24);
        if (!m.IsOk()) { std::cerr << "Error generating mnemonic: " << m.GetError().ToString() << "\n"; return 1; }
        mnemonic = m.Value();
    }

    auto seed_result = BIP39::MnemonicToSeed(mnemonic, password);
    if (!seed_result.IsOk()) { std::cerr << "Error: mnemonic->seed: " << seed_result.GetError().ToString() << "\n"; return 1; }
    auto seed = seed_result.Value();

    const std::string prefix = is_node ? "ZNK" : "ZBC";
    struct Acct { uint32_t index; std::string path, address, pub, priv; };
    std::vector<Acct> accts;
    for (int i = 0; i < count; ++i) {
        uint32_t idx = start_account + i;
        auto kr = SLIP10::DeriveZoobcAccount(idx, seed);
        if (!kr.IsOk()) { std::cerr << "Error deriving account " << idx << ": " << kr.GetError().ToString() << "\n"; return 1; }
        auto key = kr.Value();
        auto pub = key.GetPublicKey();
        std::string addr = ZoobcAddress::Encode(pub, prefix);
        if (addr.empty()) { std::cerr << "Error encoding address for account " << idx << "\n"; return 1; }
        std::vector<uint8_t> seed_32(key.key.begin(), key.key.end());
        accts.push_back({idx, "m/44'/883'/" + std::to_string(idx) + "'", addr, to_hex(pub), to_hex(seed_32)});
    }

    if (!mode.verbose) {
        std::cout << "{\"type\":\"" << (is_node ? "node" : "wallet") << "\"";
        if (use_random) std::cout << ",\"mnemonic\":\"" << mnemonic << "\"";
        std::cout << ",\"accounts\":[";
        for (size_t i = 0; i < accts.size(); ++i)
            std::cout << (i ? "," : "") << "{\"account\":" << accts[i].index << ",\"path\":\"" << accts[i].path
                      << "\",\"address\":\"" << accts[i].address << "\",\"public_key\":\"" << accts[i].pub
                      << "\",\"private_key\":\"" << accts[i].priv << "\"}";
        std::cout << "]}\n";
        return 0;
    }

    if (use_random) {
        std::cout << "New BIP-39 mnemonic (24 words) — BACK THIS UP:\n"
                  << "==============================================\n" << mnemonic
                  << "\n==============================================\n\n";
    }
    std::cout << "ZooBC " << (is_node ? "Node" : "Wallet") << " HD Addresses\n=========================\n\n";
    for (size_t i = 0; i < accts.size(); ++i) {
        if (accts.size() > 1) std::cout << "Account " << accts[i].index << ":\n";
        std::cout << "Path:        " << accts[i].path << "\nAddress:     " << accts[i].address
                  << "\nPublic Key:  " << accts[i].pub << "\nPrivate Key: " << accts[i].priv << "\n";
        if (accts.size() > 1 && i < accts.size() - 1) std::cout << "---\n";
    }
    std::cout << "\n  - Derivation path m/44'/883'/N' (ZooBC coin type 883). Keep the mnemonic + keys SECRET.\n";
    return 0;
}
