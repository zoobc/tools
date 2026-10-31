// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"
using namespace txc;
static void putU64(std::vector<uint8_t>& b, int64_t v){ for(int i=0;i<8;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }

// Vote to close a transaction's longevity record (CloseLongevity, type 309, rule survival_field).
//
// A record lives while anyone pays for it (owner decision FP11). Every account whose money on the record
// is not used up yet (rent uses the oldest money first) votes to close it with this transaction; for a
// group member, the vote is its group's. The record closes in the block that brings the last missing
// vote, and whatever deposit is left goes to the longevity node pool: nothing comes back to anyone. A
// payer that tops the record up again withdraws its vote; GET /api/v1/accounts/<a>/survival shows the
// payers, their unused money and the votes.
int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Close Longevity Tool";
    config.description = "Vote to close a longevity record you paid into. It closes when every payer with "
                         "money left has voted; the remaining deposit goes to the longevity node pool. "
                         "Body = 8-byte target transaction id.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::CloseLongevity);
    config.has_recipient = false;
    config.params = {
        {"Sender private key","sender_privkey","The private key of an account with money left on the record (64 hex)","",true,nullptr},
        {"Target transaction id","target_tx_id","The transaction whose record to close (signed int64)","",true,nullptr},
    };

    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        int64_t target=parse_id_i64(params.values[1],"target_tx_id");
        if(target==0){emit_error("target transaction id must not be 0");return 1;}
        std::vector<uint8_t> body; putU64(body,target);
        std::string sender_addr=zoobc::crypto::ZoobcAddress::Encode(kp.Value().public_key,"ZBC");
        json extra={{"voter_address",sender_addr},{"target_tx_id",std::to_string(target)},
                    {"closes_when","every payer with money left has voted"},
                    {"leftover_goes_to","longevity node pool"}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,
                               kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: vote to close submitted (the record closes when every payer with money left has voted)");
    } catch(const std::exception& e){ const int c=last_exit_code(); emit_error(e.what()); return c; }
}
