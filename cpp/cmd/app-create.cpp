// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"
using namespace txc;
static void putU64(std::vector<uint8_t>& b, int64_t v){ for(int i=0;i<8;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }
static void putU16(std::vector<uint8_t>& b, int v){ b.push_back(v&0xff); b.push_back((v>>8)&0xff); }
int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC App — Create";
    config.description = "Open an app: type + stake (token,amount) + seats. (params/opponent omitted for v1.)";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::CreateApp);
    config.has_recipient = false;
    config.params = {
        {"Sender private key","sender_privkey","Sender private key (64 hex)","",true,nullptr},
        {"App type","app_type","1=ttt 3=connect4 6=gomoku","",true,nullptr},
        {"Stake token id","stake_token","token to stake (0=ZBC)","",true,nullptr},
        {"Stake amount","stake_amount","stake (atomic)","",true,nullptr},
        {"Seats","seats","2 for 1-v-1","2",false,nullptr},
        {"Channel","channel","1 = state-channel (off-chain play, on-chain SettleApp); needs seats=2","0",false,nullptr},
    };
    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        int gt=std::stoi(params.values[1]); int64_t stok=std::stoll(params.values[2]), samt=std::stoll(params.values[3]);
        int seats=params.values[4].empty()?2:std::stoi(params.values[4]);
        int channel=params.values[5].empty()?0:std::stoi(params.values[5]);
        std::vector<uint8_t> body; body.push_back((uint8_t)gt); putU64(body,stok); putU64(body,samt); body.push_back((uint8_t)seats); putU16(body,0);
        if(channel!=0) body.push_back((uint8_t)channel);  // a single trailing byte after params = the channel flag
        json extra={{"app_type",gt},{"stake_token",stok},{"stake_amount",samt},{"seats",seats},{"channel",channel}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: App created!");
    } catch(const std::exception& e){ emit_error(e.what()); return 1; }
}
