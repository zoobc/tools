// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"

using namespace txc;

int main(int argc, char* argv[]) {
    // Optional: --liquid <minutes> turns this into a LiquidPayment that vests over time.
    uint64_t liquid_minutes = 0; bool liquid = false;
    std::vector<char*> av;
    for (int i = 0; i < argc; i++) {
        if (std::string(argv[i]) == "--liquid" && i + 1 < argc) {
            liquid = true; liquid_minutes = std::stoull(argv[i + 1]); i++; continue;
        }
        av.push_back(argv[i]);
    }
    argc = static_cast<int>(av.size()); argv = av.data();

    ToolConfig config;
    config.name = "ZooBC Transfer Tool";
    config.description = "Send ZBC coins from one account to another.";
    config.tx_type = static_cast<uint32_t>(liquid ? zoobc::TransactionType::LiquidPayment
                                                   : zoobc::TransactionType::SendZBC);
    config.has_recipient = true;
    config.supports_multi_key = true;
    config.params = {
        {"Sender private key", "sender_privkey", "Sender's private key (64 hex chars)", "", true, nullptr},
        {"Recipient address",  "recipient",      "Recipient address (ZBC_/0x/1.../bc1...)", "", true, nullptr},
        {"Amount (atomic units)", "amount",       "Amount (atomic units, 1 ZBC = 100000000)", "", true, nullptr},
    };

    ParsedParams params;
    auto emit_error = make_emitter(params.json_output);
    int rc = parse_params(config, argc, argv, params, [&](const std::string& msg) { emit_error(msg); });
    if (rc != 0) return rc == -1 ? 0 : rc;
    emit_error = make_emitter(params.json_output);  // Refresh after parse

    if (!init_sodium(emit_error)) return 1;

    try {
        // Derive sender keys
        auto keys_result = derive_sender_keys(params.values[0], params.sender_type);
        if (!keys_result.IsOk()) return fail(emit_error, exit_code::USAGE, keys_result.GetError().ToString());
        auto sender = keys_result.Value();

        // Parse recipient address
        auto recip_result = parse_address(params.values[1], params.chain);
        if (!recip_result.IsOk())
            return fail(emit_error, exit_code::USAGE, "Invalid recipient address: " + recip_result.GetError().ToString());
        auto recipient = recip_result.Value();

        // Parse amount
        int64_t amount = std::stoll(params.values[2]);
        if (amount < 0) return fail(emit_error, exit_code::USAGE, "Amount cannot be negative");

        // Build body (liquid payment carries amount + vesting minutes)
        auto body_bytes = liquid
            ? TransactionUtil::GetLiquidPaymentBodyBytes(amount, liquid_minutes)
            : TransactionUtil::GetSendZBCBodyBytes(amount);

        // Format recipient display
        std::string recipient_display = recipient.display;
        if (recipient.type == RecipientType::ZBC && recipient.address.size() == 36) {
            recipient_display = zoobc::crypto::ZoobcAddress::Encode(
                std::vector<uint8_t>(recipient.address.begin() + 4, recipient.address.end()), "ZBC");
        }

        // Extra fields for JSON success output
        json extra = {
            {"sender", sender.formatted},
            {"sender_type", sender.type_label},
            {"recipient", recipient_display},
            {"recipient_type", recipient.type_label},
            {"amount", amount},
            {"fee", params.fee}
        };

        std::string verbose_msg = "SUCCESS: Transfer transaction submitted!";

        return run_transaction(
            params, config.tx_type,
            sender.keypair.public_key,
            recipient.address,
            body_bytes,
            sender.keypair,
            sender.type,
            extra, emit_error, verbose_msg);

    } catch (const std::exception& e) {
        // Only argument parsing throws here (run_transaction reports its own errors): a usage error.
        return fail(emit_error, exit_code::USAGE, e.what());
    }
}
