// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"
using namespace txc;
static void putU64(std::vector<uint8_t>& b, int64_t v){ for(int i=0;i<8;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Finance Token Tool";
    config.description = "Top up a token's survival financing (the fee buys persistence). Body = 8-byte token_id.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::FinanceToken);
    config.has_recipient = false;
    config.params = {
        {"Sender private key","sender_privkey","Sender's private key (64 hex)","",true,nullptr},
        {"Token id","token_id","Token id (decimal int64)","",true,nullptr},
    };

    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        int64_t token_id=parse_id_i64(params.values[1],"token_id");
        std::vector<uint8_t> body; putU64(body,token_id);
        std::string sender_addr=zoobc::crypto::ZoobcAddress::Encode(kp.Value().public_key,"ZBC");
        json extra={{"sender_address",sender_addr},{"token_id",token_id}};
        // Note: the FEE funds persistence — set --fee to how much survival financing to add.
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,
                               kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: Token financing topped up!");
    } catch(const std::exception& e){ const int c=last_exit_code(); emit_error(e.what()); return c; }
}
