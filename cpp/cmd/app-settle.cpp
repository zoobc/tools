// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// ZooBC App — Settle (state channel, Track B).
// Builds + submits a SettleApp transaction for a 1-vs-1 tic-tac-toe channel app (app_type 1): it
// replays the given move list OFF chain to reproduce each board state, signs a voucher per move with
// the mover's key (the node replays + verifies the same way), and packs the ordered voucher chain into
// the SettleApp body. For a real wallet the opponent's vouchers arrive off-chain; this tool holds both
// players' keys so it can produce a complete signed chain for testing.
//
// Voucher digest (must match app_rules::VoucherDigest exactly):
//   SHA3-256( app_id(8 LE) | seq(4 LE) | SHA3-256(prev_state) | move_bytes )
// SettleApp body (must match app_rules::ParseSettleAppBody):
//   app_id(8 LE) | final_seq(4 LE) | move_count(4 LE) | [ seat(1) | move_len(2 LE) | move | sig(64) ]*
#include "tx_common.h"
#include "zoobc/crypto/hash.h"
#include "zoobc/crypto/signature.h"
#include <sstream>
using namespace txc;

static void putU64(std::vector<uint8_t>& b, int64_t v){ for(int i=0;i<8;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }
static void putU16(std::vector<uint8_t>& b, int v){ b.push_back(v&0xff); b.push_back((v>>8)&0xff); }
static void putU32(std::vector<uint8_t>& b, uint32_t v){ for(int i=0;i<4;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC App — Settle (state channel)";
    config.description = "Settle a 1-v-1 tic-tac-toe channel app: replay moves, sign a voucher each, submit SettleApp.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::SettleApp);
    config.has_recipient = false;
    config.params = {
        {"Sender private key","sender_privkey","submitter privkey (64 hex) — pays fee + signs the tx","",true,nullptr},
        {"App id","app_id","the channel app id","",true,nullptr},
        {"Seat-0 private key","p0_privkey","seat-0 (creator) privkey (64 hex) — signs seat-0 vouchers","",true,nullptr},
        {"Seat-1 private key","p1_privkey","seat-1 (joiner) privkey (64 hex) — signs seat-1 vouchers","",true,nullptr},
        {"Opening seat","opening_turn","seat that moves first, 0 or 1 (from GET /apps/:id turn)","0",false,nullptr},
        {"Moves","moves","ttt cells in play order, comma-separated (e.g. 0,3,1,4,2)","",true,nullptr},
    };
    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto sender=derive_zbc_keypair(params.values[0]); if(!sender.IsOk()){emit_error(sender.GetError().ToString());return 1;}
        int64_t gid=parse_id_i64(params.values[1],"app_id");
        auto p0=derive_zbc_keypair(params.values[2]); if(!p0.IsOk()){emit_error(p0.GetError().ToString());return 1;}
        auto p1=derive_zbc_keypair(params.values[3]); if(!p1.IsOk()){emit_error(p1.GetError().ToString());return 1;}
        int turn=params.values[4].empty()?0:std::stoi(params.values[4]);
        if(turn!=0&&turn!=1){ emit_error("opening_turn must be 0 or 1"); return 1; }

        std::vector<int> cells;
        { std::stringstream ss(params.values[5]); std::string t; while(std::getline(ss,t,',')){ if(!t.empty()) cells.push_back(std::stoi(t)); } }
        if(cells.empty()){ emit_error("no moves given"); return 1; }

        // Replay tic-tac-toe (state = 9 cells; state[cell] = seat+1) and sign a voucher per move.
        std::vector<uint8_t> state(9,0);
        std::vector<std::vector<uint8_t>> moveEntries;  // packed [seat|mlen|move|sig] per ply
        json movesJson=json::array();
        for(size_t k=0;k<cells.size();k++){
            int seat=(turn+(int)k)%2;
            int cell=cells[k];
            if(cell<0||cell>8||state[cell]!=0){ emit_error("illegal move at seq "+std::to_string(k+1)+": cell "+std::to_string(cell)); return 1; }
            std::vector<uint8_t> move={(uint8_t)cell};
            // digest = SHA3( gid(8) | seq(4) | SHA3(prev_state) | move )
            auto ph=zoobc::crypto::Hash::SHA3_256(state); if(!ph.IsOk()){emit_error("hash failed");return 1;}
            std::vector<uint8_t> buf; putU64(buf,gid); putU32(buf,(uint32_t)(k+1));
            buf.insert(buf.end(),ph.Value().begin(),ph.Value().end()); buf.insert(buf.end(),move.begin(),move.end());
            auto dg=zoobc::crypto::Hash::SHA3_256(buf); if(!dg.IsOk()){emit_error("digest hash failed");return 1;}
            const auto& signer=(seat==0)?p0.Value():p1.Value();
            auto sig=zoobc::crypto::Signature::Sign(dg.Value(),signer.private_key);
            if(!sig.IsOk()){emit_error("voucher sign failed");return 1;}
            std::vector<uint8_t> s=sig.Value(); s.resize(64);  // ed25519 sig is 64 bytes
            std::vector<uint8_t> e; e.push_back((uint8_t)seat); putU16(e,(int)move.size());
            e.insert(e.end(),move.begin(),move.end()); e.insert(e.end(),s.begin(),s.end());
            moveEntries.push_back(std::move(e));
            state[cell]=(uint8_t)(seat+1);
            movesJson.push_back(json{{"seq",k+1},{"seat",seat},{"cell",cell}});
        }

        std::vector<uint8_t> body; putU64(body,gid);
        putU32(body,(uint32_t)cells.size()); putU32(body,(uint32_t)cells.size());  // final_seq == move_count
        for(const auto& e:moveEntries) body.insert(body.end(),e.begin(),e.end());

        json extra={{"app_id",gid},{"opening_turn",turn},{"final_seq",cells.size()},{"moves",movesJson}};
        return run_transaction(params,config.tx_type,sender.Value().public_key,std::vector<uint8_t>{},body,sender.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: Settlement submitted!");
    } catch(const std::exception& e){ const int c=last_exit_code(); emit_error(e.what()); return c; }
}
