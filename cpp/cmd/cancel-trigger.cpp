// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"
using namespace txc;
static void putU64(std::vector<uint8_t>& b, int64_t v){ for(int i=0;i<8;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Cancel Trigger Tool";
    config.description = "Cancel a pending trigger you own; the locked amount is refunded. Body = 8-byte trigger_id.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::CancelTrigger);
    config.has_recipient = false;
    config.params = {
        {"Sender private key","sender_privkey","Trigger owner's private key (64 hex)","",true,nullptr},
        {"Trigger id","trigger_id","Trigger id to cancel (decimal int64)","",true,nullptr},
    };

    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        int64_t trigger_id=std::stoll(params.values[1]);
        std::vector<uint8_t> body; putU64(body,trigger_id);
        std::string sender_addr=zoobc::crypto::ZoobcAddress::Encode(kp.Value().public_key,"ZBC");
        json extra={{"sender_address",sender_addr},{"trigger_id",trigger_id}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,
                               kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: Trigger cancelled!");
    } catch(const std::exception& e){ emit_error(e.what()); return 1; }
}
