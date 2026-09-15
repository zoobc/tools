// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"
using namespace txc;
static void putU64(std::vector<uint8_t>& b, int64_t v){ for(int i=0;i<8;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }
int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Exchange — Create Market";
    config.description = "Open a permissionless (base,quote) order-book market, paying a rent deposit.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::CreateMarket);
    config.has_recipient = false;
    config.params = {
        {"Sender private key","sender_privkey","Sender private key (64 hex)","",true,nullptr},
        {"Base token id","base_token","base token (0=ZBC)","",true,nullptr},
        {"Quote token id","quote_token","quote token (0=ZBC)","",true,nullptr},
        {"Deposit","deposit","IGNORED — the cost is the network's market_creation_cost (50 ZBC); kept for wire compatibility","0",false,nullptr},
    };
    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        int64_t base=std::stoll(params.values[1]), quote=std::stoll(params.values[2]);
        int64_t dep=params.values[3].empty()?0:std::stoll(params.values[3]);
        std::vector<uint8_t> body; putU64(body,base); putU64(body,quote); putU64(body,dep);
        json extra={{"base_token",base},{"quote_token",quote},{"deposit",dep}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: Market created!");
    } catch(const std::exception& e){ emit_error(e.what()); return 1; }
}
