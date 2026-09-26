// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"
using namespace txc;
static void putU64(std::vector<uint8_t>& b, int64_t v){ for(int i=0;i<8;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }

// Pay to keep a transaction on the chain past the prune horizon.
//
// Every transaction survives free until it falls below snapshot N-1 — two snapshots. After that it
// is pruned. A deposit attached here exempts it from pruning while the deposit lasts; rent is drawn
// one payment per snapshot, sized by the payload's bytes at the price locked when it was funded.
//
// Anyone may sponsor anyone's transaction — it costs the target nothing and reveals nothing that was
// not already public. A second deposit on the same target TOPS UP rather than replacing, and the
// FIRST sponsor keeps the right to cancel, so a stranger cannot add dust and then cancel someone
// else's funding.
int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Fund Longevity Tool";
    config.description = "Attach a rent deposit to a transaction so pruning skips it. "
                         "Body = 8-byte target transaction id | 8-byte amount | 4-byte target height | "
                         "8-byte target bytes (the last two from rule longevity_stated_target; take them "
                         "from GET /api/v1/longevity/quote: state_target_height, state_target_bytes).";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::FundLongevity);
    config.has_recipient = false;
    config.params = {
        {"Sender private key","sender_privkey","Sponsor's private key (64 hex)","",true,nullptr},
        {"Target transaction id","target_tx_id","The transaction to keep alive (signed int64)","",true,nullptr},
        {"Amount","amount","Rent deposit in atomic ZBC (minimum 0.1 ZBC = 10000000)","",true,nullptr},
        {"Target height","target_height","Block height of the target (quote: state_target_height). "
         "Omit both this and target_bytes to take them from the node's quote","",false,nullptr},
        {"Target bytes","target_bytes","Billable size of the target: body + message bytes "
         "(quote: state_target_bytes; on a top-up, the funded record's size)","",false,nullptr},
    };

    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        // Signed, and deliberately so: transaction ids are the first 8 bytes of the hash read as a
        // little-endian int64, so half of them are negative. Parsing unsigned would reject them.
        int64_t target=parse_id_i64(params.values[1],"target_tx_id");
        int64_t amount=whole_param(params.values, 2);
        if(target==0){emit_error("target transaction id must not be 0");return 1;}
        if(amount<10000000){emit_error("amount is below the minimum deposit (10000000 = 0.1 ZBC)");return 1;}
        std::vector<uint8_t> body; putU64(body,target); putU64(body,amount);
        const std::string th=params.values.size()>3?params.values[3]:"", tb=params.values.size()>4?params.values[4]:"";
        if(th.empty()!=tb.empty()){emit_error("give both target_height and target_bytes, or neither");return 1;}
        std::string qh=th, qb=tb;
        if(qh.empty()){
            // Neither given: ask the node's quote for the two numbers the executor will compare with.
            // A node that predates longevity_stated_target reports neither, and gets the 16-byte body.
            try {
                const ApiTarget t=parse_api_url(params.api_url);
                auto res=with_api_client(t,[&](auto& cl){ return cl.Get((t.path_prefix+"/api/v1/longevity/quote?target="+std::to_string(target)).c_str()); });
                // A node that cannot be reached is exit 3 (4 on a timeout), like every other command, not
                // 1 "internal" (overnight devnet test 2026-09-25).
                if(!res) return fail(emit_error, classify_transport_error(res.error()),
                    "cannot read /api/v1/longevity/quote from "+params.api_url+" ("+httplib::to_string(res.error())+
                    "); pass target_height and target_bytes");
                if(res->status!=200) return fail(emit_error, classify_node_error(res->status, res->body),
                    "longevity quote: HTTP "+std::to_string(res->status)+": "+res->body);
                auto j=json::parse(res->body);
                if(j.contains("state_target_bytes")){
                    qh=std::to_string(j.value("state_target_height",0ull));
                    qb=std::to_string(j.value("state_target_bytes",0ll));
                }
            } catch(const std::exception& e){ emit_error(std::string("longevity quote: ")+e.what()); return 1; }
        }
        if(!qh.empty()){
            // Rule longevity_stated_target: the body states the target's height and billable size,
            // and a funding whose statement does not match the target is a fee-floor no-op.
            const unsigned long long h=std::stoull(qh); const long long n=std::stoll(qb);
            if(h>0xFFFFFFFFull){emit_error("target_height does not fit in 32 bits");return 1;}
            if(n<1){emit_error("target_bytes must be at least 1");return 1;}
            for(int i=0;i<4;i++) body.push_back(static_cast<uint8_t>((h>>(8*i))&0xff));
            putU64(body,n);
        }
        std::string sender_addr=zoobc::crypto::ZoobcAddress::Encode(kp.Value().public_key,"ZBC");
        json extra={{"sponsor_address",sender_addr},{"target_tx_id",std::to_string(target)},{"amount",amount}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,
                               kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: longevity funded!");
    } catch(const std::exception& e){ const int c=last_exit_code(); emit_error(e.what()); return c; }
}
