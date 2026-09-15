// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"

using namespace txc;

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Setup Account Dataset Tool";
    config.description = "Create or update a key-value property on an account.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::SetupAccountDataset);
    config.has_recipient = true;
    config.params = {
        {"Setter private key",  "setter_privkey", "Setter's private key (64 hex chars)", "", true, nullptr},
        {"Recipient address",   "recipient",      "Account to set property on",          "", true, nullptr},
        {"Property name",       "property",       "Property name/key",                   "", true, nullptr},
        {"Property value",      "value",          "Property value",                      "", true, nullptr},
    };

    ParsedParams params;
    auto emit_error = make_emitter(params.json_output);
    int rc = parse_params(config, argc, argv, params, [&](const std::string& msg) { emit_error(msg); });
    if (rc != 0) return rc == -1 ? 0 : rc;
    emit_error = make_emitter(params.json_output);

    if (!init_sodium(emit_error)) return 1;

    try {
        auto setter_kp = derive_zbc_keypair(params.values[0]);
        if (!setter_kp.IsOk()) { emit_error(setter_kp.GetError().ToString()); return 1; }

        auto recip_result = parse_address(params.values[1]);
        if (!recip_result.IsOk()) { emit_error("Invalid recipient: " + recip_result.GetError().ToString()); return 1; }

        std::string property = params.values[2];
        std::string value = params.values[3];

        // Build setter account address
        auto setter_address = TransactionUtil::BuildAccountAddress(
            TransactionUtil::ACCOUNT_TYPE_ZBC, setter_kp.Value().public_key);

        auto body_bytes = TransactionUtil::GetSetupAccountDatasetBodyBytes(
            property, value, setter_address, recip_result.Value().address);

        std::string setter_addr = zoobc::crypto::ZoobcAddress::Encode(setter_kp.Value().public_key, "ZBC");

        json extra = {
            {"setter_address", setter_addr},
            {"recipient", recip_result.Value().display},
            {"property", property},
            {"value", value}
        };

        return run_transaction(
            params, config.tx_type,
            setter_kp.Value().public_key,
            recip_result.Value().address,
            body_bytes,
            setter_kp.Value(),
            KeyType::ZBC,
            extra, emit_error,
            "SUCCESS: Setup account dataset transaction submitted!");

    } catch (const std::exception& e) {
        emit_error(e.what());
        return 1;
    }
}
