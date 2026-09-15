// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// Register a gateway on-chain (RegisterGateway, tx type 36).
//
// Locks the gateway registration stake (refunded on unregister, or if the gateway is auto-pruned
// for missing heartbeats). The gateway_key is the ZBG_ identity captured at install; the prefix is
// display-only, so a 64-hex key works too.
#include "tx_common.h"
#include "registry_common.h"
using namespace txc;

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Registry - Register Gateway";
    config.description = "Announce a gateway you run: gateway_key + domain + url, locking the registration stake.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::RegisterGateway);
    config.has_recipient = false;
    config.params = {
        {"Owner private key","owner_privkey","the OWNER's private key (64 hex) — the account that pays and owns the record","",true,nullptr},
        {"Gateway key","gateway_key","the gateway ZBG_ address or 64-hex key","",true,nullptr},
        {"Domain","domain","public domain, e.g. gw.example.org","",true,nullptr},
        {"URL","url","public API base URL, e.g. https://gw.example.org","",true,nullptr},
    };
    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        auto gk=decode_registry_key(params.values[1]); if(!gk.IsOk()){emit_error(gk.GetError().ToString());return 1;}
        std::string domain=params.values[2], url=params.values[3];
        if(domain.empty()){ emit_error("domain is required"); return 1; }
        if(url.empty()){ emit_error("url is required"); return 1; }
        auto body=reg_body(gk.Value(),domain,url);
        json extra={{"gateway_key",bytes_to_hex(gk.Value())},{"domain",domain},{"url",url}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: Gateway registered!");
    } catch(const std::exception& e){ emit_error(e.what()); return 1; }
}
