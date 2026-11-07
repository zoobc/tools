// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// Cast a governance vote on an economic consensus parameter (SetConsensusParam, tx type 51).
//
// A vote is NOT a yes/no ballot: each registered node DECLARES the value it wants. Once per snapshot
// cycle, at the cycle's last block, every votable price moves to the AVERAGE over the counted seats
// (registered and not suspended): a seat's latest vote of the cycle counts, first limited to +20 % up,
// half down and the price's bounds, and a seat that did not vote counts as today's value (owner decision
// FP3, 2026-10-26). So a vote moves a price by at most its 1/n share of the step, nobody voting changes
// nothing, and a vote counts only in the cycle it is cast in. Internally every vote is an attestation of
// the event id "ZBCGOV1:<parameter>:<value>".
//
// Signed by the NODE's private key, not the owner's: the sender must be the node attester account
// (00000000 + node_public_key), which is exactly what the ZBC key path already produces. The vote is
// FEE-EXEMPT (the node account holds no balance and never needs one), so the fee defaults to 0.
//
// GET /api/v1/governance/params shows each price's range a vote counts within, the votes of the cycle so
// far and the value the count would give now; /api/v1/governance/proposals lists every counted seat's vote.
#include "tx_common.h"
using namespace txc;

static void putU32(std::vector<uint8_t>& b, uint32_t v){ for(int i=0;i<4;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }
static void putU64(std::vector<uint8_t>& b, int64_t v){ for(int i=0;i<8;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Governance — Vote on a consensus parameter";
    config.description = "Declare the value this node wants for a governable parameter (counted at the snapshot cycle's end: the average over the counted registry nodes, each vote within +20 % / half of today's value).";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::SetConsensusParam);
    config.has_recipient = false;
    config.params = {
        {"Node private key","node_privkey","the NODE's private key (64 hex) — not the owner's","",true,nullptr},
        {"Parameter","parameter","governable parameter name (see /api/v1/governance/params)","",true,nullptr},
        {"Value","value","the value this node votes for (int64, raw units)","",true,nullptr},
    };
    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    // Fee-exempt: default to 0 rather than the usual tool default, so an operator does not have to
    // know to pass it. A non-zero fee would just be burned from an account that has no balance.
    params.fee = 0;
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        const std::string name=params.values[1];
        if(name.empty()||name.size()>128){ emit_error("parameter name must be 1..128 characters"); return 1; }
        int64_t value=whole_param(params.values, 2);
        std::vector<uint8_t> body;
        putU32(body,(uint32_t)name.size());
        body.insert(body.end(), name.begin(), name.end());
        putU64(body,value);
        json extra={{"parameter",name},{"value",value},
                    {"event_id","ZBCGOV1:"+name+":"+std::to_string(value)}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: Governance vote cast!");
    } catch(const std::exception& e){ emit_error(e.what()); return 1; }
}
