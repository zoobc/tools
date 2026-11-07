// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"
using namespace txc;
static void putU32(std::vector<uint8_t>& b, uint32_t v){ for(int i=0;i<4;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Attest Event Tool";
    config.description = "Oracle attestation (Phase C): an authorized node attests an external (event_id -> value). "
                         "Resolves at 3-of-5 priority blocksmiths. Body = u32 len + event_id + u32 len + value.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::AttestEvent);
    config.has_recipient = false;
    config.params = {
        {"Sender private key","sender_privkey","Attesting node's private key (64 hex)","",true,nullptr},
        {"Event id","event_id","External event id being attested","",true,nullptr},
        {"Value","value","The attested value for that event","",true,nullptr},
    };

    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        std::string event_id=params.values[1], value=params.values[2];
        if(event_id.empty()){emit_error("event_id must not be empty");return 1;}
        if (event_id.rfind("ZBWDR1:", 0) == 0) {
            const txc::ApiTarget target = txc::parse_api_url(params.api_url);
            auto head = txc::with_api_client(target, [&](auto& client) {
                return client.Get((target.path_prefix + "/api/v1/bridge/withdrawal-requests").c_str());
            });
            if (!head || head->status != 200) { emit_error("cannot verify the bridge request table"); return 1; }
            auto rule = json::parse(head->body, nullptr, false);
            if (rule.is_discarded()) { emit_error("invalid bridge request-table response"); return 1; }
            if (rule.value("bridge_withdrawal_credit", false)) {
                auto response = txc::with_api_client(target, [&](auto& client) {
                    return client.Get((target.path_prefix + "/api/v1/bridge/withdrawals/" + event_id.substr(7)).c_str());
                });
                if (!response || response->status != 200) {
                    emit_error("withdrawal has no executed custody credit"); return 1;
                }
                auto outcome = json::parse(response->body, nullptr, false);
                if (outcome.is_discarded()) { emit_error("invalid withdrawal response"); return 1; }
                const auto bar = value.find('|');
                const std::string suffix = bar == std::string::npos ? std::string() : value.substr(bar + 1);
                if (suffix.empty()) {
                    if (outcome.value("resolved", false)) {
                        emit_error("a resolved withdrawal needs its referenced foreign signature"); return 1;
                    }
                } else {
                    const auto ref_end = suffix.find('|');
                    bool valid = suffix.size() > 3 && suffix[0] == 'R' && ref_end != std::string::npos &&
                                 ref_end + 1 < suffix.size() && outcome.value("resolved", false);
                    uint32_t height = 0;
                    if (valid) {
                        try { height = static_cast<uint32_t>(std::stoul(suffix.substr(1, ref_end - 1))); }
                        catch (...) { valid = false; }
                    }
                    if (!valid || height == 0 || height != outcome.value("oracle_result_height", 0u)) {
                        emit_error("foreign signatures require the matching oracle_result reference"); return 1;
                    }
                }
            }
        }
        std::vector<uint8_t> body;
        putU32(body,(uint32_t)event_id.size()); body.insert(body.end(),event_id.begin(),event_id.end());
        putU32(body,(uint32_t)value.size());    body.insert(body.end(),value.begin(),value.end());
        std::string sender_addr=zoobc::crypto::ZoobcAddress::Encode(kp.Value().public_key,"ZBC");
        json extra={{"sender_address",sender_addr},{"event_id",event_id},{"value",value}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,
                               kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: Event attested!");
    } catch(const std::exception& e){ emit_error(e.what()); return 1; }
}
