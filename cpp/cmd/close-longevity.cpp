// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"
using namespace txc;
static void putU64(std::vector<uint8_t>& b, int64_t v){ for(int i=0;i<8;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }

// Close a transaction's longevity record (CloseLongevity, type 309, rule survival_field).
//
// Only the transaction's OWNER may close it: the account that sent it (for a group member, any member
// of that group). The record ends now and the transaction rejoins ordinary pruning. Whatever deposit is
// left — the owner's own survival and every stranger's top-up alike — goes to the longevity node pool.
// Nothing comes back to the owner or to any funder: top-ups cannot be taken back.
int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Close Longevity Tool";
    config.description = "Close the longevity record of a transaction you sent. The remaining deposit "
                         "goes to the longevity node pool. Body = 8-byte target transaction id.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::CloseLongevity);
    config.has_recipient = false;
    config.params = {
        {"Sender private key","sender_privkey","The private key of the account that sent the target (64 hex)","",true,nullptr},
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
        json extra={{"owner_address",sender_addr},{"target_tx_id",std::to_string(target)},
                    {"leftover_goes_to","longevity node pool"}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,
                               kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: longevity record closed, remainder paid to the node pool!");
    } catch(const std::exception& e){ const int c=last_exit_code(); emit_error(e.what()); return c; }
}
