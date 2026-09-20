// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "tx_common.h"
using namespace txc;

// Set, replace or clear the split policy of the SENDER's own account (SetSplitPolicy, type 54).
//
// From then on every credit that arrives at the account — a payment, a token transfer, an escrow
// release, a scheduled or triggered payment, a reward — is forwarded to the recipients below by their
// shares. Shares are percentages with up to two decimals (basis points on the wire). They may add up
// to less than 100%: the remainder stays in the account, and so does anything too small to divide
// (one unit of a 0-decimal token). A forwarded share is a plain credit on its recipient; the
// recipient's own policy does not cascade. Up to 10 recipients; not the account itself; no duplicates.
//
// Keep a share unassigned if the account must stay funded: it pays its own rent from what stays.
// docs/SPLIT_POLICY.md has the rules; the ledger shows each forward as split_out / split_in.
static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n"), b = s.find_last_not_of(" \t\r\n");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

int main(int argc, char* argv[]) {
    ToolConfig config;
    config.name = "ZooBC Split Policy Tool";
    config.description = "Forward every incoming credit of your account to up to 10 recipients by share. "
                         "Recipients: ADDRESS=PERCENT[,ADDRESS=PERCENT...] (any address format the "
                         "chain accepts; up to two decimals), or the word 'clear' to remove the policy. "
                         "Shares may sum below 100%: the rest stays in the account.";
    config.tx_type = static_cast<uint32_t>(zoobc::TransactionType::SetSplitPolicy);
    config.has_recipient = false;
    config.params = {
        {"Sender private key","sender_privkey","The account's private key (64 hex)","",true,nullptr},
        {"Recipients","recipients","ADDRESS=PERCENT,... or 'clear'","",true,nullptr},
    };

    ParsedParams params; auto emit_error=make_emitter(params.json_output);
    int rc=parse_params(config,argc,argv,params,[&](const std::string& m){emit_error(m);}); if(rc!=0) return rc==-1?0:rc;
    emit_error=make_emitter(params.json_output); if(!init_sodium(emit_error)) return 1;
    try {
        auto kp=derive_zbc_keypair(params.values[0]); if(!kp.IsOk()){emit_error(kp.GetError().ToString());return 1;}
        std::string sender_addr=zoobc::crypto::ZoobcAddress::Encode(kp.Value().public_key,"ZBC");

        std::vector<uint8_t> body;
        json entries_json = json::array();
        uint32_t sum_bp = 0;
        const std::string spec = trim(params.values[1]);
        if (spec == "clear" || spec == "none" || spec.empty()) {
            body.push_back(0);
        } else {
            std::vector<std::pair<std::vector<uint8_t>, uint32_t>> entries;
            size_t start = 0;
            while (start <= spec.size()) {
                size_t comma = spec.find(',', start);
                std::string item = trim(spec.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
                if (!item.empty()) {
                    size_t eq = item.find('=');
                    if (eq == std::string::npos) { emit_error("recipient '" + item + "' is not ADDRESS=PERCENT"); return 1; }
                    std::string addr = trim(item.substr(0, eq)), pct = trim(item.substr(eq + 1));
                    auto info = parse_address(addr);
                    if (!info.IsOk()) { emit_error("recipient '" + addr + "': " + info.GetError().ToString()); return 1; }
                    // percent with up to two decimals -> basis points, exactly (no float)
                    size_t dot = pct.find('.');
                    std::string ip = dot == std::string::npos ? pct : pct.substr(0, dot);
                    std::string fp = dot == std::string::npos ? "" : pct.substr(dot + 1);
                    if (fp.size() > 2) { emit_error("share '" + pct + "': at most two decimals"); return 1; }
                    while (fp.size() < 2) fp += '0';
                    for (char c : ip + fp) if (!std::isdigit(static_cast<unsigned char>(c))) { emit_error("share '" + pct + "' is not a number"); return 1; }
                    uint32_t bp = static_cast<uint32_t>(std::stoul(ip.empty() ? "0" : ip)) * 100 + static_cast<uint32_t>(std::stoul(fp));
                    if (bp == 0 || bp > 10000) { emit_error("share '" + pct + "' must be between 0.01 and 100"); return 1; }
                    entries.emplace_back(info.Value().address, bp);
                    entries_json.push_back({{"address", addr}, {"share_bp", bp}});
                    sum_bp += bp;
                }
                if (comma == std::string::npos) break;
                start = comma + 1;
            }
            if (entries.empty()) { emit_error("no recipients given (use 'clear' to remove the policy)"); return 1; }
            if (entries.size() > 10) { emit_error("at most 10 recipients"); return 1; }
            if (sum_bp > 10000) { emit_error("shares add up to more than 100%"); return 1; }
            body.push_back(static_cast<uint8_t>(entries.size()));
            for (const auto& e : entries) {
                body.push_back(static_cast<uint8_t>(e.first.size()));
                body.insert(body.end(), e.first.begin(), e.first.end());
                body.push_back(static_cast<uint8_t>(e.second & 0xff));
                body.push_back(static_cast<uint8_t>(e.second >> 8));
            }
        }
        json extra={{"account",sender_addr},{"recipients",entries_json},{"total_bp",sum_bp},{"remainder_bp",10000-sum_bp}};
        return run_transaction(params,config.tx_type,kp.Value().public_key,std::vector<uint8_t>{},body,
                               kp.Value(),KeyType::ZBC,extra,emit_error,
                               body.size()==1 ? "SUCCESS: split policy cleared" : "SUCCESS: split policy set!");
    } catch(const std::exception& e){ const int c=last_exit_code(); emit_error(e.what()); return c; }
}
