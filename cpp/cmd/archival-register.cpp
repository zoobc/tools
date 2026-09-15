// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// Announce a registered node as archival (RegisterArchival, tx type 46).
//
// The node must already be in the node registry, and only its OWNER may declare it archival —
// both enforced at admission. node_public_key is the ZNK_ address or 64-hex.
#include "tx_common.h"
#include "registry_common.h"
using namespace txc;

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Registry - Register Archival Node";
    config.description = "Announce a registered node as archival (serves history + the read API): node_key + domain + url.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::RegisterArchival);
    config.has_recipient = false;
    config.params = {
        {"Owner private key","owner_privkey","the OWNER's private key (64 hex) — the account that pays and owns the record","",true,nullptr},
        {"Node public key","node_public_key","the node ZNK_ address or 64-hex key","",true,nullptr},
        {"Domain","domain","public domain, e.g. archive.example.org","",true,nullptr},
        {"URL","url","public API base URL, e.g. https://archive.example.org","",true,nullptr},
    };
    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        auto nk=decode_registry_key(params.values[1]); if(!nk.IsOk()){emit_error(nk.GetError().ToString());return 1;}
        std::string domain=params.values[2], url=params.values[3];
        if(domain.empty()){ emit_error("domain is required"); return 1; }
        if(url.empty()){ emit_error("url is required"); return 1; }
        auto body=reg_body(nk.Value(),domain,url);
        json extra={{"node_public_key",bytes_to_hex(nk.Value())},{"domain",domain},{"url",url}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: Archival node announced!");
    } catch(const std::exception& e){ emit_error(e.what()); return 1; }
}
