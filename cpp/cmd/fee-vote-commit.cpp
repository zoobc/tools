// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"

using namespace txc;

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Fee Vote Commitment Tool";
    config.description = "Submit a hashed fee vote during the commit phase.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::FeeVoteCommitment);
    config.params = {
        {"Voter private key", "voter_privkey", "Voter's private key (64 hex chars)",       "", true, nullptr},
        {"Vote hash",         "vote_hash",     "SHA3-256 hash of FeeVoteInfo (64 hex chars)", "", true, nullptr},
    };

    ParsedParams params;
    auto emit_error = make_emitter(params.json_output);
    int rc = parse_params(config, argc, argv, params, [&](const std::string& msg) { emit_error(msg); });
    if (rc != 0) return rc == -1 ? 0 : rc;
    emit_error = make_emitter(params.json_output);

    if (!init_sodium(emit_error)) return 1;

    try {
        auto voter_kp = derive_zbc_keypair(params.values[0]);
        if (!voter_kp.IsOk()) { emit_error(voter_kp.GetError().ToString()); return 1; }

        if (params.values[1].length() != 64) {
            emit_error("Vote hash must be 64 hex characters (32 bytes)");
            return 1;
        }
        auto vote_hash = hex_to_bytes(params.values[1]);

        auto body_bytes = TransactionUtil::GetFeeVoteCommitBodyBytes(vote_hash);

        std::string voter_addr = zoobc::crypto::ZoobcAddress::Encode(voter_kp.Value().public_key, "ZBC");

        json extra = {
            {"voter_address", voter_addr},
            {"vote_hash", params.values[1]}
        };

        std::vector<uint8_t> empty_recipient;
        return run_transaction(
            params, config.tx_type,
            voter_kp.Value().public_key,
            empty_recipient,
            body_bytes,
            voter_kp.Value(),
            KeyType::ZBC,
            extra, emit_error,
            "SUCCESS: Fee vote commitment transaction submitted!");

    } catch (const std::exception& e) {
        emit_error(e.what());
        return 1;
    }
}
