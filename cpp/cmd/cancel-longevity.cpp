// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"
using namespace txc;
static void putU64(std::vector<uint8_t>& b, int64_t v){ for(int i=0;i<8;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }

// Stop paying to keep a transaction alive, and take back what is left.
//
// Only the FIRST sponsor may cancel. The remainder is refunded MINUS the period currently being
// consumed: withholding that period stops a sponsor pinning data across a rent boundary and
// withdrawing before paying for it, and the withheld amount goes to the pool that pays the nodes
// which carried the data through it.
//
// After this the transaction rejoins ordinary pruning and will disappear below the horizon.
int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Cancel Longevity Tool";
    config.description = "Cancel a sponsorship you created. Refunds the remainder less the current "
                         "period. Body = 8-byte target transaction id.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::CancelLongevity);
    config.has_recipient = false;
    config.params = {
        {"Sender private key","sender_privkey","The ORIGINAL sponsor's private key (64 hex)","",true,nullptr},
        {"Target transaction id","target_tx_id","The transaction to stop keeping alive (signed int64)","",true,nullptr},
    };

    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        int64_t target=std::stoll(params.values[1]);
        if(target==0){emit_error("target transaction id must not be 0");return 1;}
        std::vector<uint8_t> body; putU64(body,target);
        std::string sender_addr=zoobc::crypto::ZoobcAddress::Encode(kp.Value().public_key,"ZBC");
        json extra={{"sponsor_address",sender_addr},{"target_tx_id",std::to_string(target)}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,
                               kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: longevity cancelled, remainder refunded!");
    } catch(const std::exception& e){ emit_error(e.what()); return 1; }
}
