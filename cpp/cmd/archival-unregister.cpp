// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// Withdraw an archival announcement (UnregisterArchival, tx type 47).
//
// Owner only. The node stays in the node registry; it simply stops advertising archival service.
#include "tx_common.h"
#include "registry_common.h"
using namespace txc;

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Registry - Unregister Archival Node";
    config.description = "Withdraw an archival announcement (the node itself stays registered).";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::UnregisterArchival);
    config.has_recipient = false;
    config.params = {
        {"Owner private key","owner_privkey","the OWNER's private key (64 hex) — only the owner may withdraw","",true,nullptr},
        {"Node public key","node_public_key","the node ZNK_ address or 64-hex key","",true,nullptr},
    };
    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        auto k=decode_registry_key(params.values[1]); if(!k.IsOk()){emit_error(k.GetError().ToString());return 1;}
        auto body=unreg_body(k.Value());
        json extra={{"node_public_key",bytes_to_hex(k.Value())}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: Archival announcement withdrawn!");
    } catch(const std::exception& e){ emit_error(e.what()); return 1; }
}
