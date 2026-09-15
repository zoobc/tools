// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"
using namespace txc;
static void putU64(std::vector<uint8_t>& b, int64_t v){ for(int i=0;i<8;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }
static void putU32(std::vector<uint8_t>& b, uint32_t v){ for(int i=0;i<4;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Create Trigger Tool";
    config.description = "Schedule a SendZBC to fire at a future block height (or on an oracle event). "
                         "The amount is locked now. Body = fire_height(8B) + amount(8B) [+ u32 len + event_id].";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::CreateTrigger);
    config.has_recipient = true;
    config.params = {
        {"Sender private key","sender_privkey","Owner's private key (64 hex)","",true,nullptr},
        {"Recipient address","recipient","Where the scheduled SendZBC fires to","",true,nullptr},
        {"Fire height","fire_height","Block height to fire at (future; ignored if event-id set)","",true,nullptr},
        {"Amount","amount","Amount to lock now and release on fire (atomic ZBC)","",true,nullptr},
        {"Event id","event_id","Optional oracle event id; if set, fires on resolve not height","",false,nullptr},
    };

    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        auto recip=parse_address(params.values[1]); if(!recip.IsOk()){emit_error("Invalid recipient: "+recip.GetError().ToString());return 1;}
        int64_t fire_height=std::stoll(params.values[2]);
        int64_t amount=std::stoll(params.values[3]);
        std::string event_id=(params.values.size()>4)?params.values[4]:"";
        if(amount<=0){emit_error("amount must be > 0");return 1;}
        std::vector<uint8_t> body; putU64(body,fire_height); putU64(body,amount);
        if(!event_id.empty()){ putU32(body,(uint32_t)event_id.size()); body.insert(body.end(),event_id.begin(),event_id.end()); }
        std::string sender_addr=zoobc::crypto::ZoobcAddress::Encode(kp.Value().public_key,"ZBC");
        json extra={{"sender_address",sender_addr},{"recipient",recip.Value().display},
                    {"fire_height",fire_height},{"amount",amount},{"event_id",event_id}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,recip.Value().address,body,
                               kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: Trigger created!");
    } catch(const std::exception& e){ emit_error(e.what()); return 1; }
}
