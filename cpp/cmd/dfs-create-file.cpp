// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"
#include <fstream>
#include <iterator>
using namespace txc;
static void putU32(std::vector<uint8_t>& b, uint32_t v){ for(int i=0;i<4;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }

// Create an on-chain DFS file from the command line.
//
// The body is the file itself — path and content — so this is the one ordinary transaction whose
// payload can be tens of kilobytes (the input validator caps a plain message at 256 bytes but a
// body at 64 KB). That makes it the natural target for exercising paid longevity: rent is sized
// by payload bytes, so a large file is the only way to watch a minimum deposit drain inside a day.
int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC DFS Create File Tool";
    config.description = "Create an on-chain file. Body = u32 path_len | path | u32 content_len | content.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::DFSCreateFile);
    config.has_recipient = false;
    config.params = {
        {"Sender private key","sender_privkey","Owner's private key (64 hex)","",true,nullptr},
        {"Path","path","Absolute DFS path, e.g. /docs/readme.txt","",true,nullptr},
        {"Content file","content_file","Local file whose bytes become the content","",true,nullptr},
    };

    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        const std::string& path=params.values[1];
        if(path.empty()||path[0]!='/'){emit_error("path must start with /");return 1;}
        std::ifstream in(params.values[2], std::ios::binary);
        if(!in){emit_error("cannot read content file: "+params.values[2]);return 1;}
        std::vector<uint8_t> content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        std::vector<uint8_t> body;
        putU32(body,(uint32_t)path.size()); body.insert(body.end(),path.begin(),path.end());
        putU32(body,(uint32_t)content.size()); body.insert(body.end(),content.begin(),content.end());
        std::string sender_addr=zoobc::crypto::ZoobcAddress::Encode(kp.Value().public_key,"ZBC");
        json extra={{"owner_address",sender_addr},{"path",path},{"content_bytes",content.size()},{"body_bytes",body.size()}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,
                               kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: file created!");
    } catch(const std::exception& e){ emit_error(e.what()); return 1; }
}
