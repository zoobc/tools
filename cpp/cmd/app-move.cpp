// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"
using namespace txc;
static void putU64(std::vector<uint8_t>& b, int64_t v){ for(int i=0;i<8;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }
static void putU16(std::vector<uint8_t>& b, int v){ b.push_back(v&0xff); b.push_back((v>>8)&0xff); }
int main(int argc, char* argv[]) {
    ToolConfig config; config.name="ZooBC App — Move"; config.description="Submit a move (app_id + move bytes as hex; e.g. ttt cell 4 = '04').";
    config.tx_type=static_cast<uint32_t>(zoobc::TransactionType::AppMove); config.has_recipient=false;
    config.params={{"Sender private key","sender_privkey","Sender private key (64 hex)","",true,nullptr},{"App id","app_id","the app id","",true,nullptr},{"Move (hex)","move_hex","move bytes hex (ttt: 1 byte cell 00..08)","",true,nullptr}};
    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try { auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        int64_t gid=parse_id_i64(params.values[1],"app_id"); std::string h=params.values[2];
        std::vector<uint8_t> mv; for(size_t i=0;i+1<h.size();i+=2) mv.push_back((uint8_t)std::stoi(h.substr(i,2),nullptr,16));
        std::vector<uint8_t> body; putU64(body,gid); putU16(body,(int)mv.size()); body.insert(body.end(),mv.begin(),mv.end());
        json extra={{"app_id",gid},{"move",h}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: Move submitted!");
    } catch(const std::exception& e){ const int c=last_exit_code(); emit_error(e.what()); return c; }
}
