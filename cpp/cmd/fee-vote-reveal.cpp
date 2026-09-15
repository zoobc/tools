// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"

using namespace txc;

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Fee Vote Reveal Tool";
    config.description = "Reveal the actual fee vote during the reveal phase.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::FeeVoteReveal);
    config.params = {
        {"Voter private key",    "voter_privkey",       "Voter's private key (64 hex chars)",    "", true, nullptr},
        {"Recent block hash",    "recent_block_hash",   "Reference block hash (64 hex chars)",   "", true, nullptr},
        {"Recent block height",  "recent_block_height", "Reference block height",                "", true, nullptr},
        {"Fee vote",             "fee_vote",            "Proposed fee multiplier (int64)",        "", true, nullptr},
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
            emit_error("Recent block hash must be 64 hex characters (32 bytes)");
            return 1;
        }

        zoobc::model::FeeVoteInfo vote_info;
        vote_info.recent_block_hash = hex_to_bytes(params.values[1]);
        vote_info.recent_block_height = static_cast<uint32_t>(std::stoul(params.values[2]));
        vote_info.fee_vote = std::stoll(params.values[3]);

        // voter_signature = Ed25519 by the voter over the 44 FeeVoteInfo bytes; the node verifies
        // exactly these bytes (TransactionUtil::GetFeeVoteInfoBytes), so use the same serializer.
        std::vector<uint8_t> vote_info_bytes = TransactionUtil::GetFeeVoteInfoBytes(vote_info);

        auto vote_sig_result = Signature::Sign(vote_info_bytes, voter_kp.Value().private_key);
        if (!vote_sig_result.IsOk()) {
            emit_error("Failed to sign fee vote info: " + vote_sig_result.GetError().ToString());
            return 1;
        }

        auto body_bytes = TransactionUtil::GetFeeVoteRevealBodyBytes(vote_info, vote_sig_result.Value());

        std::string voter_addr = zoobc::crypto::ZoobcAddress::Encode(voter_kp.Value().public_key, "ZBC");

        json extra = {
            {"voter_address", voter_addr},
            {"fee_vote", vote_info.fee_vote},
            {"recent_block_height", vote_info.recent_block_height}
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
            "SUCCESS: Fee vote reveal transaction submitted!");

    } catch (const std::exception& e) {
        emit_error(e.what());
        return 1;
    }
}
