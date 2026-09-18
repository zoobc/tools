// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"
using namespace txc;
static void putU64(std::vector<uint8_t>& b, int64_t v){ for(int i=0;i<8;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }
int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Exchange — Place Order";
    config.description = "Place a limit/market buy/sell order on a market (price scaled 1e8).";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::PlaceOrder);
    config.has_recipient = false;
    config.params = {
        {"Sender private key","sender_privkey","Sender private key (64 hex)","",true,nullptr},
        {"Market id","market_id","the market id (decimal int64)","",true,nullptr},
        {"Side","side","0=buy, 1=sell","",true,nullptr},
        {"Price","price","price = quote per base * 1e8","",true,nullptr},
        {"Amount","amount","base amount (atomic)","",true,nullptr},
        {"Flags","flags","bit0=market order, bit1=post-only","0",false,nullptr},
        {"Expiry","expiry","expiry unix secs (0=GTC)","0",false,nullptr},
    };
    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        int64_t mkt=parse_id_i64(params.values[1],"market_id"); int side=std::stoi(params.values[2]);
        int64_t price=std::stoll(params.values[3]), amount=std::stoll(params.values[4]);
        uint8_t flags=(uint8_t)(params.values[5].empty()?0:std::stoi(params.values[5]));
        int64_t exp=params.values[6].empty()?0:std::stoll(params.values[6]);
        std::vector<uint8_t> body; putU64(body,mkt); body.push_back((uint8_t)side); putU64(body,price); putU64(body,amount); body.push_back(flags); putU64(body,exp);
        json extra={{"market_id",mkt},{"side",side},{"price",price},{"amount",amount}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: Order placed!");
    } catch(const std::exception& e){ const int c=last_exit_code(); emit_error(e.what()); return c; }
}
