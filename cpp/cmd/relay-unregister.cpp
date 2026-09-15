// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// Withdraw a relay announcement (UnregisterRelay, tx type 49).
//
// Owner only.
#include "tx_common.h"
#include "registry_common.h"
using namespace txc;

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Registry - Unregister Relay";
    config.description = "Withdraw a relay announcement.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::UnregisterRelay);
    config.has_recipient = false;
    config.params = {
        {"Owner private key","owner_privkey","the OWNER's private key (64 hex) — only the owner may withdraw","",true,nullptr},
        {"Relay key","relay_key","the relay ZBR_ address or 64-hex key","",true,nullptr},
    };
    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        auto k=decode_registry_key(params.values[1]); if(!k.IsOk()){emit_error(k.GetError().ToString());return 1;}
        auto body=unreg_body(k.Value());
        json extra={{"relay_key",bytes_to_hex(k.Value())}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: Relay announcement withdrawn!");
    } catch(const std::exception& e){ emit_error(e.what()); return 1; }
}
