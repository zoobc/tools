// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// zbc-account-gen — generate a fresh keypair + address for any supported chain.
//
// BROAD tool: `zbc-account-gen --chain <name>` (default zbc). The per-chain tools
// (zbc-account-eth / -btc / -solana / -polkadot / …) are this same program with the chain fixed at
// build time (ZBC_ACCOUNT_FIXED_CHAIN) — broad + specific, per the "have both" rule.
//
// Output follows the shared standard (gen_common.h): JSON by default (machine), human-readable when
// run in a terminal, -v/--verbose forces human, --json forces JSON, --help/-h prints help.
//   zbc     -> ZooBC role forms: account (ZBC) / node (ZNK) / relay (ZBR) / gateway (ZBG), one key.
//   foreign -> ethereum, bitcoin, solana, tron, ripple, tezos, cardano, polkadot (address + privkey).
//   all     -> zbc forms + every foreign chain.
#include <cstdint>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <algorithm>
#include <sodium.h>
#include "bridge_keygen.h"   // bkg::deriveNode, EthereumSignature, BitcoinSignature, zoobc::crypto::ZoobcAddress
#include "gen_common.h"

namespace {

std::string to_hex(const std::vector<uint8_t>& d) {
    std::stringstream ss;
    for (uint8_t b : d) ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return ss.str();
}
std::vector<uint8_t> from_hex(const std::string& h) {
    if (h.size() % 2) return {};
    auto v = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1; };
    std::vector<uint8_t> o;
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        int hi = v(h[i]), lo = v(h[i + 1]);
        if (hi < 0 || lo < 0) return {};
        o.push_back((uint8_t)((hi << 4) | lo));
    }
    return o;
}
std::string norm_chain(std::string c) {
    std::transform(c.begin(), c.end(), c.begin(), ::tolower);
    if (c == "eth") return "ethereum";
    if (c == "btc") return "bitcoin";
    if (c == "sol") return "solana";
    if (c == "dot") return "polkadot";
    if (c == "xrp") return "ripple";
    if (c == "xtz") return "tezos";
    if (c == "ada") return "cardano";
    if (c == "zoobc") return "zbc";
    return c;
}
void print_help(const char* prog) {
    std::cerr << "Usage: " << prog << " [--chain <name>] [-v|--verbose] [--json] [--from-privkey <hex>]\n"
              << "  Generate a keypair + address for a chain. Default output JSON; human in a terminal.\n"
              << "  Chains: zbc, ethereum(eth), bitcoin(btc), solana(sol), tron, ripple(xrp),\n"
              << "          tezos(xtz), cardano(ada), polkadot(dot), all\n"
              << "  zbc prints all ZooBC role forms (account ZBC / node ZNK / relay ZBR / gateway ZBG).\n"
              << "  --from-privkey <hex>: derive from an existing 32-byte key (zbc only; foreign always random).\n";
}

// Emit the ZooBC role forms for `seed` (seed IS the private key).
void emit_zbc(std::ostream& o, bool json, const std::vector<uint8_t>& seed) {
    std::vector<uint8_t> pk(32), sk(64);
    crypto_sign_ed25519_seed_keypair(pk.data(), sk.data(), seed.data());
    std::string zbc = zoobc::crypto::ZoobcAddress::Encode(pk, "ZBC");
    std::string znk = zoobc::crypto::ZoobcAddress::Encode(pk, "ZNK");
    std::string zbr = zoobc::crypto::ZoobcAddress::Encode(pk, "ZBR");
    std::string zbg = zoobc::crypto::ZoobcAddress::Encode(pk, "ZBG");
    if (json)
        o << "{\"chain\":\"zbc\",\"address\":\"" << zbc << "\",\"account\":\"" << zbc
          << "\",\"node\":\"" << znk << "\",\"relay\":\"" << zbr << "\",\"gateway\":\"" << zbg
          << "\",\"public_key\":\"" << to_hex(pk) << "\",\"private_key\":\"" << to_hex(seed) << "\"}";
    else
        o << "Chain:          zbc\n  Account (ZBC): " << zbc << "\n  Node (ZNK):    " << znk
          << "\n  Relay (ZBR):   " << zbr << "\n  Gateway (ZBG): " << zbg
          << "\n  Public Key:    " << to_hex(pk) << "\n  Private Key:   " << to_hex(seed) << "\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) { std::cerr << "libsodium init failed\n"; return 1; }
    auto mode = zbctool::parse_mode(argc, argv);

#ifdef ZBC_ACCOUNT_FIXED_CHAIN
    std::string chain = ZBC_ACCOUNT_FIXED_CHAIN;
#else
    std::string chain = "zbc";
#endif
    std::string from_priv;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (zbctool::is_mode_flag(a)) continue;
        else if (a == "--chain" && i + 1 < argc) chain = argv[++i];
        else if (a == "--from-privkey" && i + 1 < argc) from_priv = argv[++i];
        else if (!a.empty() && a[0] != '-') chain = a;  // positional chain
    }
    if (mode.help) { print_help(argv[0]); return 0; }
    chain = norm_chain(chain);
    const bool json = !mode.verbose;

    std::vector<uint8_t> seed;
    if (!from_priv.empty()) {
        seed = from_hex(from_priv);
        if (seed.size() != 32) { std::cerr << "Error: --from-privkey must be 64 hex chars (32 bytes)\n"; return 1; }
    } else {
        seed.resize(32);
        randombytes_buf(seed.data(), seed.size());
    }

    std::ostringstream out;
    bool first = true;
    auto sep = [&]() { if (json && !first) out << ","; first = false; };

    if (json) out << "[";

    if (chain == "zbc" || chain == "all") { sep(); emit_zbc(out, json, seed); }

    if (chain != "zbc") {
        zoobc::crypto::EthereumSignature eth;
        zoobc::crypto::BitcoinSignature btc;
        auto ns = bkg::deriveNode(seed, eth, btc);
        bool matched = false;
        for (auto& c : ns.chains) {
            if (chain != "all" && c.chain != chain) continue;
            matched = true;
            sep();
            // Cardano: the bridge derivation makes a REAL Cardano enterprise address (0x61 + 28-byte key
            // hash), which is what the custody side needs. A ZooBC Cardano ACCOUNT is different: the
            // chain verifies the ed25519 key itself, so its address is bech32 "addr" over
            // [0x61 || 32-byte key], the form the wallet and explorer write and the node decodes.
            // Print the account form as the address, and keep the real one beside it.
            // Cardano: the bridge derivation makes a REAL enterprise address (0x61 + blake2b-224 of the
            // key) and since 2026-09-04 that IS the ZooBC account form too.
            std::string address = c.address, native;
            if (json) {
                out << "{\"chain\":\"" << c.chain << "\",\"address\":\"" << address
                    << "\",\"private_key\":\"" << c.privkey_hex << "\"";
                if (!native.empty()) out << ",\"native_address\":\"" << native << "\"";
                out << "}";
            } else
                out << "Chain:       " << c.chain << "\n  Address:     " << address
                    << (native.empty() ? "" : "\n  On Cardano:  " + native)
                    << "\n  Private Key: " << c.privkey_hex << "\n";
        }
        if (chain != "all" && !matched) {
            std::cerr << "Error: unknown chain '" << chain << "'. Run with --help for the list.\n";
            return 1;
        }
    }

    if (json) out << "]";
    std::cout << out.str();
    if (json) std::cout << "\n";
    return 0;
}
