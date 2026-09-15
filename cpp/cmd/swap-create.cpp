// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"
using namespace txc;
static void putU64(std::vector<uint8_t>& b, int64_t v){ for(int i=0;i<8;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }
int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Swap Offer — Create";
    config.description = "Post an atomic swap offer: GIVE X of a token for WANT Y of another (give is held).";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::CreateSwapOffer);
    config.has_recipient = false;
    config.params = {
        {"Sender private key","sender_privkey","Sender private key (64 hex)","",true,nullptr},
        {"Give token id","give_token","token to GIVE (0=ZBC)","",true,nullptr},
        {"Give amount","give_amount","amount to give (atomic)","",true,nullptr},
        {"Want token id","want_token","token to WANT (0=ZBC)","",true,nullptr},
        {"Want amount","want_amount","amount wanted (atomic)","",true,nullptr},
        {"Expiry","expiry","expiry unix secs (0=GTC)","0",false,nullptr},
    };
    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        int64_t gt=std::stoll(params.values[1]), ga=std::stoll(params.values[2]);
        int64_t wt=std::stoll(params.values[3]), wa=std::stoll(params.values[4]);
        int64_t exp=params.values[5].empty()?0:std::stoll(params.values[5]);
        if(ga<=0||wa<=0){emit_error("amounts must be > 0");return 1;}
        std::vector<uint8_t> body; putU64(body,gt); putU64(body,ga); putU64(body,wt); putU64(body,wa); putU64(body,exp);
        json extra={{"give_token",gt},{"give_amount",ga},{"want_token",wt},{"want_amount",wa},{"expiry",exp}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: Swap offer created!");
    } catch(const std::exception& e){ emit_error(e.what()); return 1; }
}
