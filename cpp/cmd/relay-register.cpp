// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// Announce a relay a gateway runs (RegisterRelay, tx type 48).
//
// A relay carries voice/video/data passthrough and belongs to a gateway, so BOTH keys are in the
// body: the relay's own ZBR_ key and the ZBG_ key of the gateway it serves.
#include "tx_common.h"
#include "registry_common.h"
using namespace txc;

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Registry - Register Relay";
    config.description = "Announce a relay: relay_key + the gateway_key it belongs to + domain + url.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::RegisterRelay);
    config.has_recipient = false;
    config.params = {
        {"Owner private key","owner_privkey","the OWNER's private key (64 hex) — the account that pays and owns the record","",true,nullptr},
        {"Relay key","relay_key","the relay ZBR_ address or 64-hex key","",true,nullptr},
        {"Gateway key","gateway_key","the ZBG_ address or 64-hex key of the gateway this relay serves","",true,nullptr},
        {"Domain","domain","public domain, e.g. relay.example.org","",true,nullptr},
        {"URL","url","public base URL, e.g. https://relay.example.org","",true,nullptr},
    };
    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        auto rk=decode_registry_key(params.values[1]); if(!rk.IsOk()){emit_error(rk.GetError().ToString());return 1;}
        auto gk=decode_registry_key(params.values[2]); if(!gk.IsOk()){emit_error(gk.GetError().ToString());return 1;}
        auto gkv=gk.Value();
        std::string domain=params.values[3], url=params.values[4];
        if(domain.empty()){ emit_error("domain is required"); return 1; }
        if(url.empty()){ emit_error("url is required"); return 1; }
        auto body=reg_body(rk.Value(),domain,url,&gkv);
        json extra={{"relay_key",bytes_to_hex(rk.Value())},{"gateway_key",bytes_to_hex(gkv)},{"domain",domain},{"url",url}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: Relay registered!");
    } catch(const std::exception& e){ emit_error(e.what()); return 1; }
}
