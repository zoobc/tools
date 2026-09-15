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
                         "Body = 8-byte target transaction id | 8-byte amount.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::FundLongevity);
    config.has_recipient = false;
    config.params = {
        {"Sender private key","sender_privkey","Sponsor's private key (64 hex)","",true,nullptr},
        {"Target transaction id","target_tx_id","The transaction to keep alive (signed int64)","",true,nullptr},
        {"Amount","amount","Rent deposit in atomic ZBC (minimum 0.1 ZBC = 10000000)","",true,nullptr},
    };

    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        // Signed, and deliberately so: transaction ids are the first 8 bytes of the hash read as a
        // little-endian int64, so half of them are negative. Parsing unsigned would reject them.
        int64_t target=std::stoll(params.values[1]);
        int64_t amount=std::stoll(params.values[2]);
        if(target==0){emit_error("target transaction id must not be 0");return 1;}
        if(amount<10000000){emit_error("amount is below the minimum deposit (10000000 = 0.1 ZBC)");return 1;}
        std::vector<uint8_t> body; putU64(body,target); putU64(body,amount);
        std::string sender_addr=zoobc::crypto::ZoobcAddress::Encode(kp.Value().public_key,"ZBC");
        json extra={{"sponsor_address",sender_addr},{"target_tx_id",std::to_string(target)},{"amount",amount}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,
                               kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: longevity funded!");
    } catch(const std::exception& e){ emit_error(e.what()); return 1; }
}
