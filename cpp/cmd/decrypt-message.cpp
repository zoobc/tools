// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// zbc-message-decrypt: decrypt an encrypted transaction message.
//
// Shared I/O standard (gen_common.h): JSON by default ({"message":"..."}), human-readable (the raw
// plaintext) when run in a terminal or with -v; --json forces JSON; --help/-h prints help.
//   Usage: zbc-message-decrypt <recipient_privkey_hex> <message_hex> [-v|--verbose] [--json]
//
// <recipient_privkey_hex> : the recipient's 32-byte Ed25519 seed (64 hex chars).
// <message_hex>           : the raw message field from the transaction (hex, magic-prefixed sealed).

#include <sodium.h>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>
#include "zoobc/crypto/message_encryption.h"
#include "gen_common.h"

static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> out;
    if (hex.size() % 2 != 0) return out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    return out;
}
// Minimal JSON string escape for the decrypted plaintext.
static std::string json_escape(const std::vector<uint8_t>& d) {
    std::string s;
    for (uint8_t c : d) {
        switch (c) {
            case '"': s += "\\\""; break;
            case '\\': s += "\\\\"; break;
            case '\n': s += "\\n"; break;
            case '\r': s += "\\r"; break;
            case '\t': s += "\\t"; break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof(b), "\\u%04x", c); s += b; }
                else s += static_cast<char>(c);
        }
    }
    return s;
}

int main(int argc, char* argv[]) {
    auto mode = zbctool::parse_mode(argc, argv);
    if (mode.help) {
        std::cerr << "Usage: zbc-message-decrypt <recipient_privkey_hex> <message_hex> [-v|--verbose] [--json]\n"
                  << "  Decrypt an encrypted transaction message. Default JSON; human (plaintext) in a terminal.\n";
        return 0;
    }
    if (sodium_init() < 0) { std::fprintf(stderr, "Failed to initialize libsodium\n"); return 1; }

    std::vector<std::string> pos;
    for (int i = 1; i < argc; ++i) { std::string a = argv[i]; if (!zbctool::is_mode_flag(a)) pos.push_back(a); }
    if (pos.size() != 2) {
        std::fprintf(stderr, "Usage: %s <recipient_privkey_hex> <message_hex> [-v] [--json]\n", argv[0]);
        return 1;
    }

    std::vector<uint8_t> seed = hex_to_bytes(pos[0]);
    std::vector<uint8_t> message = hex_to_bytes(pos[1]);

    if (!zoobc::crypto::MessageEncryption::IsEncrypted(message)) {
        std::fprintf(stderr, "Message is not encrypted (missing magic prefix)\n"); return 1;
    }
    auto result = zoobc::crypto::MessageEncryption::Decrypt(message, seed);
    if (!result.IsOk()) {
        std::fprintf(stderr, "Decrypt failed: %s\n", result.GetError().ToString().c_str()); return 1;
    }
    const auto& plaintext = result.Value();

    if (!mode.verbose) {
        std::cout << "{\"message\":\"" << json_escape(plaintext) << "\"}\n";
    } else {
        std::fwrite(plaintext.data(), 1, plaintext.size(), stdout);
        std::printf("\n");
    }
    return 0;
}
