// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// ZooBC unified transaction CLI — one binary that builds+signs+submits every wired tx type.
//   zbc-cli <command> <params...> [--api URL] [--fee N]      # default: JSON in/out (for other apps)
//   zbc-cli <command> --verbose                              # interactive prompts + human-readable output
//   echo '{...}' | zbc-cli <command> --json-input            # JSON params on stdin
//   zbc-cli list                                             # list all commands
// Reuses tx_common.h (the same framework the individual tools use), so signing/submit/JSON are identical.
#include "tx_common.h"
#include "zoobc/transaction/multisignature_service.h"
#include "zoobc/crypto/hash.h"
#include "zoobc/crypto/signature.h"
#include <sstream>
#include <ctime>
using namespace txc;
using TT = zoobc::TransactionType;

static std::vector<std::string> split_csv(const std::string& s){ std::vector<std::string> o; std::stringstream ss(s); std::string it;
    while(std::getline(ss,it,',')){ size_t a=it.find_first_not_of(" \t"), b=it.find_last_not_of(" \t"); if(a!=std::string::npos) o.push_back(it.substr(a,b-a+1)); } return o; }
static std::string to_hex(const std::vector<uint8_t>& v){ std::ostringstream o; for(uint8_t b:v) o<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)b; return o.str(); }
static void u64(std::vector<uint8_t>& b, int64_t v){ for(int i=0;i<8;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }
static void u16(std::vector<uint8_t>& b, int v){ b.push_back(v&0xff); b.push_back((v>>8)&0xff); }
static void u32(std::vector<uint8_t>& b, uint32_t v){ for(int i=0;i<4;i++){ b.push_back((uint8_t)(v&0xff)); v>>=8; } }
static std::vector<uint8_t> hx(const std::string& h){ std::vector<uint8_t> v; for(size_t i=0;i+1<h.size();i+=2) v.push_back((uint8_t)std::stoi(h.substr(i,2),nullptr,16)); return v; }
// --chain <name>: read the envelope recipient as this chain (cli-contract.md). The builders have no
// access to ParsedParams, so main() parks the option here before calling them.
static std::string& chain_hint(){ static std::string s; return s; }
static ParamDef PK(){ return {"Sender private key","sender_privkey","Sender private key (64 hex)","",true,nullptr}; }
static ParamDef P(const char* n,const char* k,const char* pr,const char* d="",bool req=true){ return {n,k,pr,d,req,nullptr}; }
// Decode a hex string to bytes (for object ids). Throws on odd length / non-hex.
static std::vector<uint8_t> hexb(const std::string& s){
    if(s.size()%2) throw std::runtime_error("hex must be even length");
    auto nib=[](char c)->int{ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; };
    std::vector<uint8_t> v; for(size_t i=0;i<s.size();i+=2){ int hi=nib(s[i]),lo=nib(s[i+1]); if(hi<0||lo<0) throw std::runtime_error("bad hex"); v.push_back((uint8_t)((hi<<4)|lo)); }
    return v;
}

// builder: (values) -> fills recipient (decoded, or empty), body, extra-json
using Builder = std::function<void(std::vector<std::string>&, std::vector<uint8_t>&, std::vector<uint8_t>&, json&)>;
// custom: full self-contained handler (build+sign+submit) for txs that don't fit the simple body-builder
// (multisig's inner tx + signatures, node reg's ProofOfOwnership + 2nd key). Returns the process exit code.
// Added LAST so existing aggregate-initialized entries (no custom) still compile (value-initialized to empty).
using CustomHandler = std::function<int(std::vector<std::string>&, ParsedParams&)>;
struct Cmd { std::string desc; uint32_t tx_type; bool has_recipient; std::vector<ParamDef> params; Builder build; CustomHandler custom{}; };
// Category for `list`/`help` grouping (display only; unknown -> "other").
static std::string category_of(const std::string& c){
    static const std::map<std::string,std::string> cat = {
        {"send-zbc","value"},{"liquid-payment","value"},{"liquid-payment-stop","value"},
        {"transfer-token","tokens"},{"issue-token","tokens"},{"mint-token","tokens"},{"burn-token","tokens"},{"finance-token","tokens"},
        {"swap-create","exchange"},{"swap-accept","exchange"},{"swap-cancel","exchange"},{"market-create","exchange"},{"order-place","exchange"},{"order-cancel","exchange"},
        {"app-create","apps"},{"app-join","apps"},{"app-move","apps"},{"app-resign","apps"},{"app-claim","apps"},{"app-settle","apps"},
        {"store-file","storage"},{"add-prepaid-storage","storage"},
        {"setup-dataset","account"},{"remove-dataset","account"},{"transfer-dataset","account"},{"accept-dataset","account"},{"delete-dataset","account"},{"set-dataset-policy","account"},{"approve-escrow","account"},{"escrow-request","account"},{"create-trigger","account"},{"cancel-trigger","account"},{"attest-event","account"},{"multisig","account"},{"scheduled-transfer","account"},{"cancel-schedule","account"},{"reassign-schedule","account"},{"fee-vote-commit","account"},{"fee-vote-reveal","account"},
        {"register-node","node"},{"update-node","node"},{"remove-node","node"},{"claim-node","node"},
        {"register-gateway","gateway"},{"unregister-gateway","gateway"},
        {"register-release","governance"},{"revoke-release","governance"},{"release-authority-propose","governance"},{"release-authority-accept","governance"},
        {"sign-message","keys"},{"verify-message","keys"},
    };
    auto it = cat.find(c); return it==cat.end() ? "other" : it->second;
}

static std::map<std::string, Cmd> registry() {
    std::map<std::string, Cmd> m;
    // ---- value transfer ----
    m["send-zbc"] = {"Send ZBC to an address", (uint32_t)TT::SendZBC, true,
        {PK(), P("Recipient","recipient","recipient address (ZBC_/hex/eth)"), P("Amount","amount","amount (atomic)")},
        [](std::vector<std::string>& v, std::vector<uint8_t>& rec, std::vector<uint8_t>& body, json& ex){
            auto r=parse_address(v[1], chain_hint()); if(!r.IsOk()) throw std::runtime_error("invalid recipient address"); rec=r.Value().address;
            int64_t amt=std::stoll(v[2]); body=TransactionUtil::GetSendZBCBodyBytes(amt); ex={{"amount",amt}}; }};
    // ---- colored-coin tokens ----
    m["issue-token"] = {"Issue a colored-coin token", (uint32_t)TT::IssueToken, false,
        {PK(), P("Symbol","symbol","symbol e.g. GOLD"), P("Name","name","token name"), P("Decimals","decimals","0-8"),
         P("Supply","supply","total supply (atomic)"), P("Backing","backing","ZBC backing atomic (0=unbacked)"),
         P("Flags","flags","bit0 redeemable,bit1 mintable,bit3 unbacked","1",false)},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            int dec=std::stoi(v[3]); int fl=(v.size()>6&&!v[6].empty())?std::stoi(v[6]):1; int64_t sup=std::stoll(v[4]),bk=std::stoll(v[5]);
            if(dec<0||dec>8) throw std::runtime_error("decimals must be 0-8");
            body.push_back((uint8_t)dec); body.push_back((uint8_t)fl); u64(body,sup); u64(body,bk);
            u16(body,(int)v[1].size()); body.insert(body.end(),v[1].begin(),v[1].end());
            u16(body,(int)v[2].size()); body.insert(body.end(),v[2].begin(),v[2].end());
            ex={{"symbol",v[1]},{"supply",sup},{"backing",bk},{"decimals",dec},{"flags",fl}}; }};
    m["mint-token"] = {"Mint a mintable token (add backing)", (uint32_t)TT::MintToken, false,
        {PK(), P("Token id","token_id","token id"), P("Amount","amount","amount (atomic)")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            int64_t t=std::stoll(v[1]),a=std::stoll(v[2]); u64(body,t); u64(body,a); ex={{"token_id",t},{"amount",a}}; }};
    m["burn-token"] = {"Burn a token (redeem backing if redeemable)", (uint32_t)TT::BurnToken, false,
        {PK(), P("Token id","token_id","token id"), P("Amount","amount","amount (atomic)")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            int64_t t=std::stoll(v[1]),a=std::stoll(v[2]); u64(body,t); u64(body,a); ex={{"token_id",t},{"amount",a}}; }};
    m["finance-token"] = {"Top up a token's survival financing", (uint32_t)TT::FinanceToken, false,
        {PK(), P("Token id","token_id","token id")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            int64_t t=std::stoll(v[1]); u64(body,t); ex={{"token_id",t}}; }};
    // ---- exchange: swap offers ----
    m["swap-create"] = {"Create an atomic swap offer", (uint32_t)TT::CreateSwapOffer, false,
        {PK(), P("Give token","give_token","token to give (0=ZBC)"), P("Give amount","give_amount","atomic"),
         P("Want token","want_token","token to want (0=ZBC)"), P("Want amount","want_amount","atomic"), P("Expiry","expiry","unix secs (0=GTC)","0",false)},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            int64_t gt=std::stoll(v[1]),ga=std::stoll(v[2]),wt=std::stoll(v[3]),wa=std::stoll(v[4]),e=(v.size()>5&&!v[5].empty())?std::stoll(v[5]):0;
            u64(body,gt);u64(body,ga);u64(body,wt);u64(body,wa);u64(body,e); ex={{"give_token",gt},{"want_token",wt}}; }};
    m["swap-accept"] = {"Accept (fill) a swap offer", (uint32_t)TT::AcceptSwapOffer, false,
        {PK(), P("Offer id","offer_id","the swap offer id")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){ int64_t o=std::stoll(v[1]); u64(body,o); ex={{"offer_id",o}}; }};
    m["swap-cancel"] = {"Cancel an open swap offer", (uint32_t)TT::CancelSwapOffer, false,
        {PK(), P("Offer id","offer_id","the swap offer id")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){ int64_t o=std::stoll(v[1]); u64(body,o); ex={{"offer_id",o}}; }};
    // ---- exchange: order-book CLOB ----
    m["market-create"] = {"Open a (base,quote) CLOB market", (uint32_t)TT::CreateMarket, false,
        {PK(), P("Base token","base_token","base (0=ZBC)"), P("Quote token","quote_token","quote (0=ZBC)"), P("Deposit","deposit","rent atomic (0 ok)","0",false)},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            int64_t b=std::stoll(v[1]),q=std::stoll(v[2]),d=(v.size()>3&&!v[3].empty())?std::stoll(v[3]):0; u64(body,b);u64(body,q);u64(body,d); ex={{"base",b},{"quote",q}}; }};
    m["order-place"] = {"Place a limit/market order", (uint32_t)TT::PlaceOrder, false,
        {PK(), P("Market id","market_id","market id"), P("Side","side","0=buy 1=sell"), P("Price","price","quote per base * 1e8"),
         P("Amount","amount","base amount atomic"), P("Flags","flags","bit0 market,bit1 post-only","0",false), P("Expiry","expiry","unix secs (0=GTC)","0",false)},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            int64_t mk=std::stoll(v[1]); int side=std::stoi(v[2]); int64_t pr=std::stoll(v[3]),am=std::stoll(v[4]);
            int fl=(v.size()>5&&!v[5].empty())?std::stoi(v[5]):0; int64_t e=(v.size()>6&&!v[6].empty())?std::stoll(v[6]):0;
            u64(body,mk); body.push_back((uint8_t)side); u64(body,pr); u64(body,am); body.push_back((uint8_t)fl); u64(body,e);
            ex={{"market_id",mk},{"side",side},{"price",pr},{"amount",am}}; }};
    m["order-cancel"] = {"Cancel a resting order", (uint32_t)TT::CancelOrder, false,
        {PK(), P("Order id","order_id","order id")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){ int64_t o=std::stoll(v[1]); u64(body,o); ex={{"order_id",o}}; }};
    // ---- on-chain apps (docs/APPS_DESIGN.md) ----
    m["app-create"] = {"Create an app (2P or solo-vs-house)", (uint32_t)TT::CreateApp, false,
        {PK(), P("App type","app_type","1 ttt,3 c4,6 gomoku,16 dice,17 coinflip"), P("Stake token","stake_token","0=ZBC"),
         P("Stake amount","stake_amount","atomic"), P("Seats","seats","2=PvP, 1=solo","2",false),
         P("Params (hex)","params_hex","solo bet e.g. coinflip choice '00'","",false), P("Opponent (hex)","opponent_hex","36-byte opponent (open if empty)","",false)},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            int gt=std::stoi(v[1]); int64_t st=std::stoll(v[2]),sa=std::stoll(v[3]); int seats=(v.size()>4&&!v[4].empty())?std::stoi(v[4]):2;
            std::vector<uint8_t> prm=(v.size()>5&&!v[5].empty())?hx(v[5]):std::vector<uint8_t>();
            body.push_back((uint8_t)gt); u64(body,st); u64(body,sa); body.push_back((uint8_t)seats); u16(body,(int)prm.size()); body.insert(body.end(),prm.begin(),prm.end());
            if(v.size()>6&&!v[6].empty()){ auto op=hx(v[6]); body.insert(body.end(),op.begin(),op.end()); }
            ex={{"app_type",gt},{"stake_token",st},{"stake_amount",sa},{"seats",seats}}; }};
    m["app-join"] = {"Join an open app", (uint32_t)TT::JoinApp, false,
        {PK(), P("App id","app_id","app id")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){ int64_t g=std::stoll(v[1]); u64(body,g); ex={{"app_id",g}}; }};
    m["app-move"] = {"Submit a move (move bytes as hex)", (uint32_t)TT::AppMove, false,
        {PK(), P("App id","app_id","app id"), P("Move (hex)","move_hex","move bytes (ttt cell '04')")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            int64_t g=std::stoll(v[1]); auto mv=hx(v[2]); u64(body,g); u16(body,(int)mv.size()); body.insert(body.end(),mv.begin(),mv.end()); ex={{"app_id",g},{"move",v[2]}}; }};
    m["app-resign"] = {"Resign an app", (uint32_t)TT::ResignApp, false,
        {PK(), P("App id","app_id","app id")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){ int64_t g=std::stoll(v[1]); u64(body,g); ex={{"app_id",g}}; }};
    m["app-claim"] = {"Claim a timed-out app", (uint32_t)TT::ClaimAppTimeout, false,
        {PK(), P("App id","app_id","app id")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){ int64_t g=std::stoll(v[1]); u64(body,g); ex={{"app_id",g}}; }};
    // ---- liquid payments / escrow / triggers / storage / oracle ----
    m["liquid-payment"] = {"Stream ZBC over time (vesting)", (uint32_t)TT::LiquidPayment, true,
        {PK(), P("Recipient","recipient","recipient address"), P("Amount","amount","atomic"), P("Complete minutes","complete_minutes","full-vesting period (min)")},
        [](std::vector<std::string>& v, std::vector<uint8_t>& rec, std::vector<uint8_t>& body, json& ex){
            auto r=parse_address(v[1], chain_hint()); if(!r.IsOk()) throw std::runtime_error("invalid recipient"); rec=r.Value().address;
            int64_t amt=std::stoll(v[2]); uint64_t mins=std::stoull(v[3]);
            body=TransactionUtil::GetLiquidPaymentBodyBytes(amt, mins, 0); ex={{"amount",amt},{"complete_minutes",mins}}; }};
    m["liquid-payment-stop"] = {"Stop a liquid payment", (uint32_t)TT::LiquidPaymentStop, false,
        {PK(), P("Transaction id","transaction_id","the liquid payment tx id")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){ int64_t t=std::stoll(v[1]); body=TransactionUtil::GetLiquidPaymentStopBodyBytes(t); ex={{"transaction_id",t}}; }};
    m["approve-escrow"] = {"Approve/reject/expire an escrow", (uint32_t)TT::ApprovalEscrow, false,
        {PK(), P("Approval","approval","0=approve 1=reject 2=expire"), P("Transaction hash","transaction_hash","escrowed tx hash (64 hex)")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            int a=std::stoi(v[1]); if(a<0||a>2) throw std::runtime_error("approval must be 0/1/2");
            // Full 32-byte hash of the escrowed tx (2026-09-08); the 8-byte id is derived from it on chain.
            auto h=hex_to_bytes(v[2]); if(h.size()!=32) throw std::runtime_error("transaction hash must be 64 hex characters");
            // The escrowed transaction is reported as escrowed_transaction_hash / transaction_id; the
            // top-level transaction_hash stays the hash of THIS approval (it used to be overwritten
            // by the escrowed hash, so a caller could not track its own submission — 2026-09-15).
            body=TransactionUtil::GetApprovalEscrowBodyBytes((zoobc::model::EscrowApproval)a, h); ex={{"approval",a},{"escrowed_transaction_hash",v[2]},{"transaction_id",TransactionUtil::GetTransactionID(h)}}; }};
    m["create-trigger"] = {"Schedule a future SendZBC (keeper)", (uint32_t)TT::CreateTrigger, true,
        {PK(), P("Recipient","recipient","where the scheduled SendZBC fires"), P("Fire height","fire_height","future block height"),
         P("Amount","amount","atomic ZBC locked now"), P("Event id","event_id","optional oracle event id","",false)},
        [](std::vector<std::string>& v, std::vector<uint8_t>& rec, std::vector<uint8_t>& body, json& ex){
            auto r=parse_address(v[1], chain_hint()); if(!r.IsOk()) throw std::runtime_error("invalid recipient"); rec=r.Value().address;
            int64_t fh=std::stoll(v[2]), amt=std::stoll(v[3]); u64(body,fh); u64(body,amt);
            if(v.size()>4 && !v[4].empty()){ u32(body,(uint32_t)v[4].size()); body.insert(body.end(),v[4].begin(),v[4].end()); }
            ex={{"fire_height",fh},{"amount",amt}}; }};
    m["cancel-trigger"] = {"Cancel a pending trigger (refund)", (uint32_t)TT::CancelTrigger, false,
        {PK(), P("Trigger id","trigger_id","the trigger id")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){ int64_t t=std::stoll(v[1]); u64(body,t); ex={{"trigger_id",t}}; }};
    m["add-prepaid-storage"] = {"Fund dataset storage rent", (uint32_t)TT::AddPrepaidStorage, false,
        {PK(), P("Amount","amount","atomic ZBC")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){ int64_t a=std::stoll(v[1]); u64(body,a); ex={{"amount",a}}; }};
    m["attest-event"] = {"Attest an external event (oracle node)", (uint32_t)TT::AttestEvent, false,
        {PK(), P("Event id","event_id","external event id"), P("Value","value","attested value")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            u32(body,(uint32_t)v[1].size()); body.insert(body.end(),v[1].begin(),v[1].end());
            u32(body,(uint32_t)v[2].size()); body.insert(body.end(),v[2].begin(),v[2].end()); ex={{"event_id",v[1]},{"value",v[2]}}; }};
    // ---- account datasets / fee voting ----
    m["fee-vote-commit"] = {"Commit a fee vote (hash)", (uint32_t)TT::FeeVoteCommitment, false,
        {PK(), P("Vote hash","vote_hash","32-byte vote hash (64 hex)")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            auto h=hx(v[1]); if(h.size()!=32) throw std::runtime_error("vote_hash must be 32 bytes (64 hex)");
            body=TransactionUtil::GetFeeVoteCommitBodyBytes(h); ex={{"vote_hash",v[1]}}; }};
    m["setup-dataset"] = {"Set an account-dataset property", (uint32_t)TT::SetupAccountDataset, true,
        {PK(), P("Subject","recipient","dataset subject address (ZBC_)"), P("Property","property","key"), P("Value","value","value")},
        [](std::vector<std::string>& v, std::vector<uint8_t>& rec, std::vector<uint8_t>& body, json& ex){
            auto r=parse_address(v[1], chain_hint()); if(!r.IsOk()) throw std::runtime_error("invalid subject address"); rec=r.Value().address;
            auto kp=derive_zbc_keypair(v[0]); if(!kp.IsOk()) throw std::runtime_error("bad key");
            auto setter=TransactionUtil::BuildAccountAddress(TransactionUtil::ACCOUNT_TYPE_ZBC, kp.Value().public_key);
            body=TransactionUtil::GetSetupAccountDatasetBodyBytes(v[2], v[3], setter, rec); ex={{"property",v[2]},{"value",v[3]}}; }};
    m["remove-dataset"] = {"Remove an account-dataset property", (uint32_t)TT::RemoveAccountDataset, true,
        {PK(), P("Subject","recipient","dataset subject address (ZBC_)"), P("Property","property","key"), P("Value","value","value")},
        [](std::vector<std::string>& v, std::vector<uint8_t>& rec, std::vector<uint8_t>& body, json& ex){
            auto r=parse_address(v[1], chain_hint()); if(!r.IsOk()) throw std::runtime_error("invalid subject address"); rec=r.Value().address;
            auto kp=derive_zbc_keypair(v[0]); if(!kp.IsOk()) throw std::runtime_error("bad key");
            auto setter=TransactionUtil::BuildAccountAddress(TransactionUtil::ACCOUNT_TYPE_ZBC, kp.Value().public_key);
            body=TransactionUtil::GetRemoveAccountDatasetBodyBytes(v[2], v[3], setter, rec); ex={{"property",v[2]},{"value",v[3]}}; }};
    // ---- dataset objects: transfer / accept / policy / delete ----
    m["transfer-dataset"] = {"Propose transfer of a dataset object", (uint32_t)TT::TransferDataset, false,
        {PK(), P("Object id","object_id","dataset object id (64 hex = creating tx hash)"), P("New owner","new_owner","new owner address (ZBC_)")},
        [](std::vector<std::string>& v, std::vector<uint8_t>& rec, std::vector<uint8_t>& body, json& ex){
            (void)rec; auto oid=hexb(v[1]); if(oid.size()!=32) throw std::runtime_error("object_id must be 64 hex");
            auto no=parse_address(v[2]); if(!no.IsOk()) throw std::runtime_error("invalid new-owner address");
            body=oid; body.insert(body.end(), no.Value().address.begin(), no.Value().address.end());
            ex={{"object_id",v[1]},{"new_owner",v[2]}}; }};
    m["accept-dataset"] = {"Accept a pending dataset transfer", (uint32_t)TT::AcceptDataset, false,
        {PK(), P("Object id","object_id","dataset object id (64 hex)")},
        [](std::vector<std::string>& v, std::vector<uint8_t>& rec, std::vector<uint8_t>& body, json& ex){
            (void)rec; auto oid=hexb(v[1]); if(oid.size()!=32) throw std::runtime_error("object_id must be 64 hex");
            body=oid; ex={{"object_id",v[1]}}; }};
    m["delete-dataset"] = {"Delete a dataset object (refunds its deposit)", (uint32_t)TT::DeleteDataset, false,
        {PK(), P("Object id","object_id","dataset object id (64 hex)")},
        [](std::vector<std::string>& v, std::vector<uint8_t>& rec, std::vector<uint8_t>& body, json& ex){
            (void)rec; auto oid=hexb(v[1]); if(oid.size()!=32) throw std::runtime_error("object_id must be 64 hex");
            body=oid; ex={{"object_id",v[1]}}; }};
    m["set-dataset-policy"] = {"Set a dataset object's manage policy", (uint32_t)TT::SetDatasetPolicy, false,
        {PK(), P("Object id","object_id","64 hex"), P("Mode","mode","0 owner-only, 1 whitelist, 2 blacklist, 3 open"),
         P("Add accounts","add","comma-separated ZBC_ addresses (optional)","",false),
         P("Remove accounts","remove","comma-separated ZBC_ addresses (optional)","",false)},
        [](std::vector<std::string>& v, std::vector<uint8_t>& rec, std::vector<uint8_t>& body, json& ex){
            (void)rec; auto oid=hexb(v[1]); if(oid.size()!=32) throw std::runtime_error("object_id must be 64 hex");
            int mode=std::stoi(v[2]); if(mode<0||mode>3) throw std::runtime_error("mode must be 0-3");
            auto parse_list=[&](const std::string& s){ std::vector<std::vector<uint8_t>> out; std::string cur;
                auto flush=[&]{ if(cur.empty())return; auto a=parse_address(cur); if(!a.IsOk()) throw std::runtime_error("invalid acl address: "+cur); out.push_back(a.Value().address); cur.clear(); };
                for(char c:s){ if(c==','){flush();} else if(!isspace((unsigned char)c)) cur+=c; } flush(); return out; };
            auto adds=parse_list(v.size()>3?v[3]:""); auto rems=parse_list(v.size()>4?v[4]:"");
            if(adds.size()>255||rems.size()>255) throw std::runtime_error("max 255 acl entries per tx");
            body=oid; body.push_back((uint8_t)mode);
            body.push_back((uint8_t)adds.size()); for(auto&a:adds) body.insert(body.end(),a.begin(),a.end());
            body.push_back((uint8_t)rems.size()); for(auto&a:rems) body.insert(body.end(),a.begin(),a.end());
            ex={{"object_id",v[1]},{"mode",mode},{"add",adds.size()},{"remove",rems.size()}}; }};
    // ---- value / tokens ----
    m["transfer-token"] = {"Transfer a held token to a recipient", (uint32_t)TT::TransferToken, true,
        {PK(), P("Recipient","recipient","recipient address (ZBC_/hex/eth)"),
         P("Token id","token_id","token id (decimal int64)"), P("Amount","amount","amount (atomic)")},
        [](std::vector<std::string>& v, std::vector<uint8_t>& rec, std::vector<uint8_t>& body, json& ex){
            auto r=parse_address(v[1], chain_hint()); if(!r.IsOk()) throw std::runtime_error("invalid recipient address"); rec=r.Value().address;
            int64_t tid=std::stoll(v[2]), amt=std::stoll(v[3]);
            if(amt<=0) throw std::runtime_error("amount must be > 0");
            u64(body,tid); u64(body,amt); ex={{"token_id",tid},{"amount",amt}}; }};
    // ---- account / escrow ----
    m["escrow-request"] = {"Create a recipient-initiated escrow request", (uint32_t)TT::EscrowRequest, false,
        {PK(), P("Proposed sender","proposed_sender","proposed sender address"),
         P("Amount","amount","proposed amount (atomic)"),
         P("Approver","approver","third-party approver address"),
         P("Commission","commission","approver commission (atomic)","0",false),
         P("Timeout","timeout","escrow timeout (future unix seconds)"),
         P("Instruction","instruction","instructions (optional)","",false),
         P("Expiry","expiry","request expiry (0 = use timeout)","0",false)},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            auto s=parse_address(v[1]); if(!s.IsOk()) throw std::runtime_error("invalid proposed sender");
            auto a=parse_address(v[3]); if(!a.IsOk()) throw std::runtime_error("invalid approver");
            zoobc::model::EscrowRequestTransactionBody b;
            b.proposed_sender=s.Value().address; b.proposed_amount=std::stoll(v[2]);
            b.approver_address=a.Value().address;
            b.commission=(v.size()>4&&!v[4].empty())?std::stoll(v[4]):0;
            b.timeout=std::stoll(v[5]);
            b.instruction=(v.size()>6)?v[6]:std::string();
            b.expiry=(v.size()>7&&!v[7].empty())?std::stoll(v[7]):0;
            if(b.expiry<=0) b.expiry=b.timeout;
            body=TransactionUtil::GetEscrowRequestBodyBytes(b);
            ex={{"proposed_sender",s.Value().display},{"proposed_amount",b.proposed_amount},{"approver",a.Value().display}}; }};
    m["fee-vote-reveal"] = {"Reveal a fee vote (reveal phase)", (uint32_t)TT::FeeVoteReveal, false,
        {PK(), P("Recent block hash","recent_block_hash","reference block hash (64 hex)"),
         P("Recent block height","recent_block_height","reference block height"),
         P("Fee vote","fee_vote","proposed fee multiplier (int64)")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            if(v[1].size()!=64) throw std::runtime_error("recent_block_hash must be 64 hex chars (32 bytes)");
            auto kp=derive_zbc_keypair(v[0]); if(!kp.IsOk()) throw std::runtime_error("bad key");
            zoobc::model::FeeVoteInfo vi;
            vi.recent_block_hash=hx(v[1]); vi.recent_block_height=(uint32_t)std::stoul(v[2]); vi.fee_vote=std::stoll(v[3]);
            std::vector<uint8_t> vib = TransactionUtil::GetFeeVoteInfoBytes(vi);  // the bytes the node verifies voter_signature over
            auto sig=zoobc::crypto::Signature::Sign(vib, kp.Value().private_key);
            if(!sig.IsOk()) throw std::runtime_error("failed to sign fee vote info");
            body=TransactionUtil::GetFeeVoteRevealBodyBytes(vi, sig.Value());
            ex={{"fee_vote",vi.fee_vote},{"recent_block_height",vi.recent_block_height}}; }};
    // ---- scheduler ----
    m["scheduled-transfer"] = {"Schedule vesting/recurring transfers to a recipient", (uint32_t)TT::ScheduledTransfer, true,
        {PK(), P("Recipient","recipient","where each fire pays"),
         P("Token id","token_id","token to send (0 = ZBC)","0",false),
         P("Per-fire amount","per_fire_amount","amount per fire (atomic, >0)"),
         P("Interval seconds","interval_seconds","seconds between fires (required if >1 fire)","0",false),
         P("Remaining fires","remaining_fires","number of fires (>=1)"),
         P("Cliff seconds","cliff_seconds","delay before first fire","0",false),
         P("Funding mode","funding_mode","0 = pre-lock now, 1 = pull-at-fire","0",false),
         P("Cancel policy","cancel_policy","0 or 1","0",false),
         P("End time","end_time","unix-seconds cutoff (0 = none)","0",false)},
        [](std::vector<std::string>& v, std::vector<uint8_t>& rec, std::vector<uint8_t>& body, json& ex){
            auto r=parse_address(v[1], chain_hint()); if(!r.IsOk()) throw std::runtime_error("invalid recipient"); rec=r.Value().address;
            int64_t tid=(v.size()>2&&!v[2].empty())?std::stoll(v[2]):0;
            int64_t per=std::stoll(v[3]);
            int64_t iv=(v.size()>4&&!v[4].empty())?std::stoll(v[4]):0;
            int32_t fires=(int32_t)std::stol(v[5]);
            int64_t cliff=(v.size()>6&&!v[6].empty())?std::stoll(v[6]):0;
            int fm=(v.size()>7&&!v[7].empty())?std::stoi(v[7]):0;
            int cp=(v.size()>8&&!v[8].empty())?std::stoi(v[8]):0;
            int64_t endt=(v.size()>9&&!v[9].empty())?std::stoll(v[9]):0;
            u64(body,tid); u64(body,per); u64(body,iv); u32(body,(uint32_t)fires); u64(body,cliff);
            body.push_back((uint8_t)fm); body.push_back((uint8_t)cp); u64(body,endt); body.push_back(0);
            ex={{"token_id",tid},{"per_fire_amount",per},{"remaining_fires",fires}}; }};
    m["cancel-schedule"] = {"Cancel a pending scheduled transfer", (uint32_t)TT::CancelSchedule, false,
        {PK(), P("Schedule id","schedule_id","the schedule id")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            int64_t s=std::stoll(v[1]); u64(body,s); ex={{"schedule_id",s}}; }};
    m["reassign-schedule"] = {"Reassign a scheduled transfer to a new recipient", (uint32_t)TT::ReassignSchedule, false,
        {PK(), P("Schedule id","schedule_id","the schedule id"),
         P("New recipient","new_recipient","new recipient address")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            int64_t s=std::stoll(v[1]); u64(body,s);
            auto r=parse_address(v[2]); if(!r.IsOk()) throw std::runtime_error("invalid new recipient");
            body.insert(body.end(), r.Value().address.begin(), r.Value().address.end());
            ex={{"schedule_id",s},{"new_recipient",r.Value().display}}; }};
    // ---- storage / node / gateway ----
    m["store-file"] = {"Store a file manifest on-chain (pay storage rent)", (uint32_t)TT::StoreFile, false,
        {PK(), P("File root","file_root","manifest root hash (64 hex) — MUST equal ManifestRoot(pieces)"),
         P("Total size","total_size","total file size in bytes"),
         P("Piece size","piece_size","piece size in bytes (>0)"),
         P("Deposit","deposit","rent deposit (atomic ZBC, >= network minimum)"),
         P("Piece ids","piece_ids","piece-id hashes concatenated as one hex string (count x 32 bytes)")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            auto root=hx(v[1]); if(root.size()!=32) throw std::runtime_error("file_root must be 32 bytes (64 hex)");
            int64_t total=std::stoll(v[2]); uint32_t psz=(uint32_t)std::stoul(v[3]); int64_t dep=std::stoll(v[4]);
            auto pieces=hx(v[5]); if(pieces.empty()||pieces.size()%32!=0) throw std::runtime_error("piece_ids must be a nonzero multiple of 32 bytes");
            uint32_t pcount=(uint32_t)(pieces.size()/32);
            body.insert(body.end(), root.begin(), root.end());
            u64(body,total); u32(body,psz); u64(body,dep); u32(body,pcount);
            body.insert(body.end(), pieces.begin(), pieces.end());
            ex={{"total_size",total},{"piece_size",psz},{"deposit",dep},{"piece_count",pcount}}; }};
    m["remove-node"] = {"Remove a node registration (v[0] = OWNER key; signs the tx)", (uint32_t)TT::RemoveNodeRegistration, false,
        {PK(), P("Node private key","node_privkey","node's private key (64 hex) — its public key goes in the body")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            auto node=derive_zbc_keypair(v[1]); if(!node.IsOk()) throw std::runtime_error("bad node key");
            body=TransactionUtil::GetRemoveNodeRegistrationBodyBytes(node.Value().public_key);
            ex={{"action","remove node registration"}}; }};
    m["unregister-gateway"] = {"Unregister an on-chain gateway (refund stake)", (uint32_t)TT::UnregisterGateway, false,
        {PK(), P("Gateway key","gateway_key","gateway public key (64 hex, 32 bytes)")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            body=hx(v[1]); if(body.size()!=32) throw std::runtime_error("gateway_key must be 32 bytes (64 hex)");
            ex={{"gateway_key",v[1]}}; }};
    // Liveness proof for a registered gateway. The reference block must be RECENT and its hash
    // must match the real chain at that height, so a beat cannot be pre-generated or replayed —
    // it proves the gateway is both running and synced. Signed by the gateway's OWNER account.
    //
    // Height and hash are parameters rather than fetched here: this binary has no HTTP client, and
    // the scheduling agent (scripts/gateway-heartbeat.sh) already talks to a node to pick a fresh
    // reference. Keeping the fetch there also lets the agent choose which node it trusts.
    // The GATEWAY's private key signs the proof; the sender merely relays and pays the fee. That
    // separation is the point: a gateway host holds a key that can prove liveness and nothing else,
    // instead of the owner's account key. Sender and gateway key are deliberately independent here.
    m["gateway-heartbeat"] = {"Prove a gateway is alive (signed by the GATEWAY key; any sender may relay)", (uint32_t)TT::GatewayHeartbeat, false,
        {PK(), P("Gateway private key","gateway_privkey","the GATEWAY's own private key (64 hex) — not the owner's"),
         P("Reference height","reference_height","height of a recent confirmed block"),
         P("Reference hash","reference_block_hash","that block's hash (64 hex, 32 bytes)")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            auto gkp=derive_zbc_keypair(v[1]);
            if(gkp.IsErr()) throw std::runtime_error("gateway_privkey is not a valid key");
            const auto& gk = gkp.Value().public_key;
            long long h=0; try { h=std::stoll(v[2]); } catch(...) { throw std::runtime_error("reference_height must be a number"); }
            if(h<0||h>0xffffffffLL) throw std::runtime_error("reference_height out of range");
            auto rh=hx(v[3]); if(rh.size()!=32) throw std::runtime_error("reference_block_hash must be 32 bytes (64 hex)");
            body.insert(body.end(),gk.begin(),gk.end());
            u32(body,(uint32_t)h);
            body.insert(body.end(),rh.begin(),rh.end());
            auto sig = zoobc::crypto::Signature::Sign(body, gkp.Value().private_key);
            if(sig.IsErr()) throw std::runtime_error("could not sign the heartbeat");
            body.insert(body.end(), sig.Value().begin(), sig.Value().end());
            if(body.size()!=132) throw std::runtime_error("internal: heartbeat body must be exactly 132 bytes");
            ex={{"gateway_key",to_hex(gk)},{"reference_height",h},{"reference_block_hash",v[3]}}; }};
    // ---- state-channel app settle (TESTING: needs both seat keys) ----
    m["app-settle"] = {"Settle a 1-v-1 TTT channel app (replay + vouchers; TESTING, needs both seat keys)", (uint32_t)TT::SettleApp, false,
        {PK(), P("App id","app_id","the channel app id"),
         P("Seat-0 private key","p0_privkey","seat-0 privkey (64 hex) — signs seat-0 vouchers"),
         P("Seat-1 private key","p1_privkey","seat-1 privkey (64 hex) — signs seat-1 vouchers"),
         P("Opening seat","opening_turn","seat that moves first, 0 or 1","0",false),
         P("Moves","moves","ttt cells in play order, comma-separated e.g. 0,3,1,4,2")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            int64_t gid=std::stoll(v[1]);
            auto p0=derive_zbc_keypair(v[2]); if(!p0.IsOk()) throw std::runtime_error("bad seat-0 key");
            auto p1=derive_zbc_keypair(v[3]); if(!p1.IsOk()) throw std::runtime_error("bad seat-1 key");
            int turn=(v.size()>4&&!v[4].empty())?std::stoi(v[4]):0;
            if(turn!=0&&turn!=1) throw std::runtime_error("opening_turn must be 0 or 1");
            std::vector<int> cells; { std::stringstream ss(v[5]); std::string t;
                while(std::getline(ss,t,',')){ if(!t.empty()) cells.push_back(std::stoi(t)); } }
            if(cells.empty()) throw std::runtime_error("no moves given");
            std::vector<uint8_t> state(9,0); std::vector<std::vector<uint8_t>> entries;
            for(size_t k=0;k<cells.size();k++){
                int seat=(turn+(int)k)%2, cell=cells[k];
                if(cell<0||cell>8||state[cell]!=0) throw std::runtime_error("illegal move at seq "+std::to_string(k+1));
                std::vector<uint8_t> move={(uint8_t)cell};
                auto ph=zoobc::crypto::Hash::SHA3_256(state); if(!ph.IsOk()) throw std::runtime_error("hash failed");
                std::vector<uint8_t> buf; u64(buf,gid); u32(buf,(uint32_t)(k+1));
                buf.insert(buf.end(),ph.Value().begin(),ph.Value().end()); buf.insert(buf.end(),move.begin(),move.end());
                auto dg=zoobc::crypto::Hash::SHA3_256(buf); if(!dg.IsOk()) throw std::runtime_error("digest hash failed");
                const auto& signer=(seat==0)?p0.Value():p1.Value();
                auto sig=zoobc::crypto::Signature::Sign(dg.Value(),signer.private_key); if(!sig.IsOk()) throw std::runtime_error("voucher sign failed");
                std::vector<uint8_t> s=sig.Value(); s.resize(64);
                std::vector<uint8_t> e; e.push_back((uint8_t)seat); u16(e,(int)move.size());
                e.insert(e.end(),move.begin(),move.end()); e.insert(e.end(),s.begin(),s.end());
                entries.push_back(std::move(e)); state[cell]=(uint8_t)(seat+1);
            }
            u64(body,gid); u32(body,(uint32_t)cells.size()); u32(body,(uint32_t)cells.size());
            for(auto& e:entries) body.insert(body.end(),e.begin(),e.end());
            ex={{"app_id",gid},{"opening_turn",turn},{"final_seq",cells.size()}}; }};
    // ---- governance (signed releases) ----
    m["register-release"] = {"Register a signed release (release authority only)", (uint32_t)TT::RegisterRelease, false,
        {PK(), P("Version","version","release version string (1-256 chars)"),
         P("Manifest hash","manifest_hash","manifest hash (64 hex, 32 bytes)"),
         P("Release address","release_address","the release's on-chain address")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            const std::string& ver=v[1]; if(ver.empty()||ver.size()>256) throw std::runtime_error("version length must be 1-256");
            auto mh=hx(v[2]); if(mh.size()!=32) throw std::runtime_error("manifest_hash must be 32 bytes (64 hex)");
            auto ra=parse_address(v[3]); if(!ra.IsOk()) throw std::runtime_error("invalid release_address");
            u32(body,(uint32_t)ver.size()); body.insert(body.end(),ver.begin(),ver.end());
            body.insert(body.end(),mh.begin(),mh.end());
            body.insert(body.end(),ra.Value().address.begin(),ra.Value().address.end());
            ex={{"version",ver},{"release_address",ra.Value().display}}; }};
    m["revoke-release"] = {"Revoke a previously registered release", (uint32_t)TT::RevokeRelease, false,
        {PK(), P("Version","version","release version string to revoke (1-256 chars)")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            const std::string& ver=v[1]; if(ver.empty()||ver.size()>256) throw std::runtime_error("version length must be 1-256");
            u32(body,(uint32_t)ver.size()); body.insert(body.end(),ver.begin(),ver.end());
            ex={{"version",ver}}; }};
    m["release-authority-propose"] = {"Propose a new release authority", (uint32_t)TT::ReleaseAuthorityPropose, false,
        {PK(), P("New authority","new_authority","proposed new release-authority address")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            auto a=parse_address(v[1]); if(!a.IsOk()) throw std::runtime_error("invalid new authority address");
            body=a.Value().address; ex={{"new_authority",a.Value().display}}; }};
    m["release-authority-accept"] = {"Accept a pending release-authority handover", (uint32_t)TT::ReleaseAuthorityAccept, false,
        {PK()},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            (void)v; body.clear(); ex={{"action","accept release authority"}}; }};
    m["register-gateway"] = {"Register an on-chain gateway (key + domain + url, locks stake)", (uint32_t)TT::RegisterGateway, false,
        {PK(), P("Gateway key","gateway_key","gateway public key (64 hex, 32 bytes)"),
         P("Domain","domain","gateway domain (e.g. gw.example.com)"),
         P("URL","url","gateway base URL (e.g. https://gw.example.com)")},
        [](std::vector<std::string>& v, std::vector<uint8_t>&, std::vector<uint8_t>& body, json& ex){
            auto gk=hx(v[1]); if(gk.size()!=32) throw std::runtime_error("gateway_key must be 32 bytes (64 hex)");
            const std::string& dom=v[2]; const std::string& url=v[3];
            if(dom.empty()||dom.size()>256) throw std::runtime_error("domain length must be 1-256");
            body.insert(body.end(),gk.begin(),gk.end());
            u32(body,(uint32_t)dom.size()); body.insert(body.end(),dom.begin(),dom.end());
            u32(body,(uint32_t)url.size()); body.insert(body.end(),url.begin(),url.end());
            ex={{"gateway_key",v[1]},{"domain",dom},{"url",url}}; }};
    // ---- node lifecycle (custom handlers: ProofOfOwnership + owner-signed) ----
    m["register-node"] = {"Register a node (v[0]=OWNER/signer; + node key; builds ProofOfOwnership)", (uint32_t)TT::NodeRegistration, false,
        {PK(), P("Node private key","node_privkey","node's private key (64 hex)"),
         P("Locked balance","locked_balance","stake to lock (atomic)")},
        nullptr,
        [](std::vector<std::string>& v, ParsedParams& params) -> int {
            auto emit_error = make_emitter(params.json_output);
            auto owner_kp=derive_zbc_keypair(v[0]); if(!owner_kp.IsOk()){ emit_error(owner_kp.GetError().ToString()); return 1; }
            auto node_kp=derive_zbc_keypair(v[1]); if(!node_kp.IsOk()){ emit_error(node_kp.GetError().ToString()); return 1; }
            int64_t locked=std::stoll(v[2]); if(locked<=0){ emit_error("locked_balance must be positive"); return 1; }
            auto poown=build_proof_of_ownership(owner_kp.Value(), params.api_url); if(!poown.IsOk()){ emit_error(poown.GetError().ToString()); return 1; }
            auto owner_addr=TransactionUtil::BuildAccountAddress(TransactionUtil::ACCOUNT_TYPE_ZBC, owner_kp.Value().public_key);
            auto body=TransactionUtil::GetNodeRegistrationBodyBytes(node_kp.Value().public_key, owner_addr, locked, poown.Value());
            json extra={{"node_znk",zoobc::crypto::ZoobcAddress::Encode(node_kp.Value().public_key,"ZNK")},{"owner_zbc",zoobc::crypto::ZoobcAddress::Encode(owner_kp.Value().public_key,"ZBC")}};
            std::vector<uint8_t> er;
            return run_transaction(params,(uint32_t)TT::NodeRegistration,owner_kp.Value().public_key,er,body,owner_kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: node registration submitted!"); }};
    m["update-node"] = {"Update a node registration (v[0]=OWNER/signer; + node key; ProofOfOwnership)", (uint32_t)TT::NodeRegistrationUpdate, false,
        {PK(), P("Node private key","node_privkey","node's private key (64 hex)"),
         P("Locked balance","locked_balance","new stake to lock (atomic)")},
        nullptr,
        [](std::vector<std::string>& v, ParsedParams& params) -> int {
            auto emit_error = make_emitter(params.json_output);
            auto owner_kp=derive_zbc_keypair(v[0]); if(!owner_kp.IsOk()){ emit_error(owner_kp.GetError().ToString()); return 1; }
            auto node_kp=derive_zbc_keypair(v[1]); if(!node_kp.IsOk()){ emit_error(node_kp.GetError().ToString()); return 1; }
            int64_t locked=std::stoll(v[2]);
            auto poown=build_proof_of_ownership(owner_kp.Value(), params.api_url); if(!poown.IsOk()){ emit_error(poown.GetError().ToString()); return 1; }
            auto body=TransactionUtil::GetUpdateNodeRegistrationBodyBytes(node_kp.Value().public_key, locked, poown.Value());
            json extra={{"node_znk",zoobc::crypto::ZoobcAddress::Encode(node_kp.Value().public_key,"ZNK")}};
            std::vector<uint8_t> er;
            return run_transaction(params,(uint32_t)TT::NodeRegistrationUpdate,owner_kp.Value().public_key,er,body,owner_kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: node update submitted!"); }};
    m["claim-node"] = {"Claim a removed node registration (v[0]=OWNER/signer; + node key; ProofOfOwnership)", (uint32_t)TT::ClaimNodeRegistration, false,
        {PK(), P("Node private key","node_privkey","node's private key (64 hex)")},
        nullptr,
        [](std::vector<std::string>& v, ParsedParams& params) -> int {
            auto emit_error = make_emitter(params.json_output);
            auto owner_kp=derive_zbc_keypair(v[0]); if(!owner_kp.IsOk()){ emit_error(owner_kp.GetError().ToString()); return 1; }
            auto node_kp=derive_zbc_keypair(v[1]); if(!node_kp.IsOk()){ emit_error(node_kp.GetError().ToString()); return 1; }
            auto poown=build_proof_of_ownership(owner_kp.Value(), params.api_url); if(!poown.IsOk()){ emit_error(poown.GetError().ToString()); return 1; }
            auto body=TransactionUtil::GetClaimNodeRegistrationBodyBytes(node_kp.Value().public_key, poown.Value());
            json extra={{"node_znk",zoobc::crypto::ZoobcAddress::Encode(node_kp.Value().public_key,"ZNK")}};
            std::vector<uint8_t> er;
            return run_transaction(params,(uint32_t)TT::ClaimNodeRegistration,owner_kp.Value().public_key,er,body,owner_kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: node claim submitted!"); }};
    // ---- multisig (custom handler: inner tx + signatures) ----
    m["multisig"] = {"N-of-M multisig SendZBC (inner tx + participant signatures)", (uint32_t)TT::MultiSignature, false,
        { PK(), P("Participants","participants","comma-separated participant ZBC addresses"),
          P("Minimum signatures","min_signatures","required signatures (N of M)"),
          P("Nonce","nonce","multisig account nonce","0",false),
          P("Signer private keys","signer_privkeys","comma-separated participant keys that sign now"),
          P("Recipient","recipient","inner SendZBC recipient address"),
          P("Amount","amount","inner SendZBC amount (atomic units)"),
          P("Inner fee","inner_fee","inner SendZBC fee (atomic units)","10000000",false) },
        nullptr,
        [](std::vector<std::string>& v, ParsedParams& params) -> int {
            auto emit_error = make_emitter(params.json_output);
            auto submitter_kp = derive_zbc_keypair(v[0]);
            if(!submitter_kp.IsOk()){ emit_error(submitter_kp.GetError().ToString()); return 1; }
            std::vector<std::vector<uint8_t>> participants;
            for(auto& p: split_csv(v[1])){ auto pr=parse_address(p); if(!pr.IsOk()){ emit_error("Invalid participant address: "+p); return 1; } participants.push_back(pr.Value().address); }
            if(participants.empty()){ emit_error("Need at least one participant"); return 1; }
            uint32_t min_sigs=(uint32_t)std::stoul(v[2]); int64_t nonce=std::stoll(v[3]);
            auto signer_keys=split_csv(v[4]); if(signer_keys.empty()){ emit_error("Need at least one signer key"); return 1; }
            auto recip=parse_address(v[5]); if(!recip.IsOk()){ emit_error("Invalid recipient: "+recip.GetError().ToString()); return 1; }
            int64_t amount=std::stoll(v[6]), inner_fee=std::stoll(v[7]);
            auto multisig_addr=zoobc::transaction::MultisignatureService::GenerateMultisigAddress(participants, nonce, min_sigs);
            if(multisig_addr.empty()){ emit_error("Failed to generate multisig address"); return 1; }
            std::vector<uint8_t> inner_body; TransactionUtil::WriteUint64LE(inner_body,(uint64_t)amount);
            std::vector<uint8_t> empty;
            // Inner-tx sender = the multisig account as a ZBC-TYPED 36-byte address (prefix + 32-byte hash);
            // the node deserializes it this way (executor:5111). Bare hash -> "end of bytes (body)".
            std::vector<uint8_t> inner_sender; TransactionUtil::WriteInt32LE(inner_sender, ACCOUNT_TYPE_ZBC);
            inner_sender.insert(inner_sender.end(), multisig_addr.begin(), multisig_addr.end());
            auto inner_unsigned=build_transaction_bytes_multikey(1,transaction_timestamp(params),inner_sender,recip.Value().address,(uint32_t)TT::SendZBC,inner_fee,inner_body,empty,empty);
            auto inner_hash_r=zoobc::crypto::Hash::SHA3_256(inner_unsigned); if(inner_hash_r.IsErr()){ emit_error("Failed to hash inner tx"); return 1; }
            auto inner_hash=inner_hash_r.Value();   // the KEY the chain collects signatures under
            // Participants sign the chain-bound digest of the inner bytes (signing v2), not the key.
            if(!ensure_signing_context(params.api_url, params.genesis_hex, emit_error)) return last_exit_code();
            auto inner_digest_r=signing_digest(inner_unsigned); if(inner_digest_r.IsErr()){ emit_error("Failed to digest inner tx: "+inner_digest_r.GetError().ToString()); return 1; }
            auto inner_digest=inner_digest_r.Value();
            zoobc::model::SignatureInfo sig_info; sig_info.transaction_hash=inner_hash;
            for(auto& sk: signer_keys){ auto kp=derive_zbc_keypair(sk); if(!kp.IsOk()){ emit_error("Invalid signer key"); return 1; }
                auto sig=zoobc::crypto::Signature::Sign(inner_digest, kp.Value().private_key); if(sig.IsErr()){ emit_error("Failed to sign inner tx: "+sig.GetError().ToString()); return 1; }
                std::vector<uint8_t> sa; TransactionUtil::WriteInt32LE(sa, ACCOUNT_TYPE_ZBC); sa.insert(sa.end(), kp.Value().public_key.begin(), kp.Value().public_key.end());
                sig_info.signatures[to_hex(sa)]=sig.Value(); }
            zoobc::model::MultiSignatureTransactionBody mbody; zoobc::model::MultiSignatureInfo info;
            info.minimum_signatures=min_sigs; info.nonce=nonce; info.addresses=participants;
            mbody.multi_signature_info=info; mbody.unsigned_transaction_bytes=inner_unsigned; mbody.signature_info=sig_info;
            auto body_bytes=zoobc::transaction::MultisignatureService::GetBodyBytes(mbody);
            std::string ms_zbc=zoobc::crypto::ZoobcAddress::Encode(multisig_addr,"ZBC");
            json extra={{"multisig_address",to_hex(multisig_addr)},{"multisig_zbc_address",ms_zbc},{"min_signatures",min_sigs},{"inner_tx_hash",to_hex(inner_hash)},{"fund_hint","send ZBC to multisig_zbc_address before the signatures complete, else the inner tx stays in mempool"}};
            std::vector<uint8_t> empty_recip;
            return run_transaction(params,(uint32_t)TT::MultiSignature,submitter_kp.Value().public_key,empty_recip,body_bytes,submitter_kp.Value(),KeyType::ZBC,extra,emit_error,"SUCCESS: MultiSignature submitted!");
        }};
    // ---- off-chain: message signing (no transaction, no node) ----
    // Scheme ZBC-MSG-v1 (tx_common.h): digest = SHA3-256("ZBC-MSG" ‖ message), signature = Ed25519(seed, digest).
    // Lets an application prove control of a ZBC_ address off-chain ("this payout address is mine")
    // with a signature that can never be mistaken for a transaction, a proof-of-ownership or a
    // multisig participant signature. Verification needs only the address: it IS the public key.
    m["sign-message"] = {"Sign a message with a private key (ZBC-MSG-v1, off-chain, no node needed)", 0, false,
        {PK(), P("Message","message","text to sign (hex bytes with --hex)")},
        nullptr,
        [](std::vector<std::string>& v, ParsedParams& params) -> int {
            auto emit_error = make_emitter(params.json_output);
            auto kp=derive_zbc_keypair(v[0]); if(!kp.IsOk()) return fail(emit_error, exit_code::USAGE, kp.GetError().ToString());
            std::vector<uint8_t> msg;
            if(params.hex_input){ try { msg=hexb(v[1]); } catch(const std::exception& e){ return fail(emit_error, exit_code::USAGE, std::string("--hex message is not valid hex: ")+e.what()); } }
            else msg.assign(v[1].begin(), v[1].end());
            auto dg=message_signing_digest(msg); if(dg.IsErr()) { emit_error("digest failed: "+dg.GetError().ToString()); return exit_code::INTERNAL; }
            auto sig=zoobc::crypto::Signature::Sign(dg.Value(), kp.Value().private_key);
            if(sig.IsErr()) { emit_error("sign failed: "+sig.GetError().ToString()); return exit_code::INTERNAL; }
            std::string addr=zoobc::crypto::ZoobcAddress::Encode(kp.Value().public_key,"ZBC");
            if(params.json_output){
                json out={{"success",true},{"scheme",MESSAGE_SIGNING_SCHEME},{"address",addr},{"public_key",to_hex(kp.Value().public_key)},
                          {"message_hex",to_hex(msg)},{"digest",to_hex(dg.Value())},{"signature",to_hex(sig.Value())}};
                if(!params.hex_input) out["message"]=v[1];
                std::cout<<out.dump(2)<<std::endl;
            } else {
                std::cout<<"Address:   "<<addr<<"\nDigest:    "<<to_hex(dg.Value())<<"\nSignature: "<<to_hex(sig.Value())<<"\n";
            }
            return exit_code::OK; }};
    m["verify-message"] = {"Verify a ZBC-MSG-v1 message signature against a ZBC_ address (off-chain)", 0, false,
        {P("Address","address","signer's ZBC_ address (or 64-hex public key)"),
         P("Message","message","the signed text (hex bytes with --hex)"),
         P("Signature","signature","64-byte Ed25519 signature, 128 hex")},
        nullptr,
        [](std::vector<std::string>& v, ParsedParams& params) -> int {
            auto emit_error = make_emitter(params.json_output);
            auto a=parse_address(v[0]);
            if(!a.IsOk() || a.Value().type!=RecipientType::ZBC || a.Value().address.size()!=36)
                return fail(emit_error, exit_code::USAGE, "address must be a ZBC_ account (Ed25519) address");
            std::vector<uint8_t> pub(a.Value().address.begin()+4, a.Value().address.end());
            std::vector<uint8_t> msg, sig;
            if(params.hex_input){ try { msg=hexb(v[1]); } catch(const std::exception& e){ return fail(emit_error, exit_code::USAGE, std::string("--hex message is not valid hex: ")+e.what()); } }
            else msg.assign(v[1].begin(), v[1].end());
            try { sig=hexb(v[2]); } catch(const std::exception&){ return fail(emit_error, exit_code::USAGE, "signature must be hex"); }
            if(sig.size()!=64) return fail(emit_error, exit_code::USAGE, "signature must be 64 bytes (128 hex characters)");
            auto dg=message_signing_digest(msg); if(dg.IsErr()) { emit_error("digest failed: "+dg.GetError().ToString()); return exit_code::INTERNAL; }
            auto ok=zoobc::crypto::Signature::Verify(dg.Value(), sig, pub);
            const bool valid = ok.IsOk() && ok.Value();
            std::string addr=zoobc::crypto::ZoobcAddress::Encode(pub,"ZBC");
            if(params.json_output){
                json out={{"success",true},{"valid",valid},{"scheme",MESSAGE_SIGNING_SCHEME},{"address",addr},{"digest",to_hex(dg.Value())},
                          {"exit_code",valid?exit_code::OK:exit_code::VERIFY_FAILED},{"error_class",exit_code::name(valid?exit_code::OK:exit_code::VERIFY_FAILED)}};
                std::cout<<out.dump(2)<<std::endl;
            } else {
                std::cout<<(valid?"VALID":"INVALID")<<" signature for "<<addr<<"\n";
            }
            return valid ? exit_code::OK : exit_code::VERIFY_FAILED; }};
    return m;
}

int main(int argc, char* argv[]) {
    auto reg = registry();
    if (argc < 2) {
        std::cout << "ZooBC unified transaction CLI\nUsage: zbc-cli <command> <params...> [--api URL] [--fee N] [--timeout S] [--verbose] [--json-input]\n"
                  << "       zbc-cli list   (show all commands)      zbc-cli <command> --help  (options, env vars, exit codes)\n";
        return exit_code::USAGE;
    }
    std::string cmd = argv[1];
    // ---- `help <tx>` : print the JSON field schema for one command (what to send) ----
    if (cmd == "help" && argc >= 3) {
        auto hit = reg.find(argv[2]);
        if (hit == reg.end()) { std::cerr << "Unknown command: " << argv[2] << " (try `zbc-cli list`)\n"; return exit_code::USAGE; }
        const Cmd& c = hit->second;
        std::cout << argv[2] << " — " << c.desc << "  (tx type " << c.tx_type << ")\n";
        std::cout << "JSON fields (default: JSON in/out; --json-input reads them on stdin; positional order matches):\n";
        json sample = json::object();
        for (const auto& p : c.params) {
            std::cout << "  " << p.json_key;
            for (size_t i = p.json_key.size(); i < 18; i++) std::cout << ' ';
            std::cout << (p.required ? "(required) " : "(optional) ") << p.prompt;
            if (!p.default_value.empty()) std::cout << "  [default: " << p.default_value << "]";
            std::cout << "\n";
            sample[p.json_key] = p.default_value.empty() ? "..." : p.default_value;
        }
        std::cout << "Sample: " << sample.dump() << "\n";
        std::cout << "Run with --verbose to be prompted for each field and get human-readable output.\n";
        return 0;
    }
    // ---- `list` / `--help` : all commands, grouped by category ----
    if (cmd == "list" || cmd == "--help" || cmd == "-h" || cmd == "help") {
        std::cout << "ZooBC unified transaction CLI — " << reg.size() << " commands.\n"
                  << "  Default: JSON in, JSON out.   --verbose: prompt each field + text output.\n"
                  << "  echo '{...}' | zbc-cli <cmd> --json-input     zbc-cli help <cmd>  (fields for one tx)\n\n";
        const char* order[] = {"value","tokens","exchange","apps","storage","account","node","gateway","governance","keys","other"};
        for (const char* g : order) {
            bool header=false;
            for (auto& kv : reg) {
                if (category_of(kv.first) != g) continue;
                if (!header) { std::cout << "[" << g << "]\n"; header=true; }
                std::cout << "  " << kv.first;
                for (size_t i = kv.first.size(); i < 26; i++) std::cout << ' ';
                std::cout << kv.second.desc << "\n";
            }
            if (header) std::cout << "\n";
        }
        std::cout << "First param is the sender private key (or set ZBC_KEY and omit it / pass '-'); verify-message takes an address.\n"
                  << "`zbc-cli help <cmd>` shows a command's JSON fields; `zbc-cli <cmd> --help` the options, env vars and exit codes.\n";
        return 0;
    }
    auto it = reg.find(cmd);
    if (it == reg.end()) { std::cerr << "Unknown command: " << cmd << " (try `zbc-cli list`)\n"; return exit_code::USAGE; }
    Cmd& c = it->second;

    ToolConfig config;
    config.name = "zbc-cli " + cmd; config.description = c.desc; config.tx_type = c.tx_type;
    config.params = c.params; config.has_recipient = c.has_recipient;
    ParsedParams params; auto emit_error = make_emitter(params.json_output);
    // shift argv by 1 so parse_params consumes the subcommand as argv[0]
    int rc = parse_params(config, argc - 1, argv + 1, params, [&](const std::string& mm){ emit_error(mm); });
    if (rc != 0) return rc == -1 ? 0 : rc;
    emit_error = make_emitter(params.json_output);
    if (!init_sodium(emit_error)) return exit_code::INTERNAL;
    chain_hint() = params.chain;
    // Custom handler (multisig, node reg, sign/verify): fully self-contained.
    // A builder or handler throws only for arguments it cannot use (bad address, out-of-range
    // value, bad hex), so an exception here is a usage error, not an internal one.
    if (c.custom) { try { return c.custom(params.values, params); } catch (const std::exception& e) { return fail(emit_error, exit_code::USAGE, e.what()); } }
    try {
        auto kp = derive_zbc_keypair(params.values[0]);
        if (!kp.IsOk()) return fail(emit_error, exit_code::USAGE, kp.GetError().ToString());
        std::vector<uint8_t> recipient, body; json extra;
        c.build(params.values, recipient, body, extra);
        return run_transaction(params, c.tx_type, kp.Value().public_key, recipient, body, kp.Value(),
                               KeyType::ZBC, extra, emit_error, "SUCCESS: " + cmd + " submitted!");
    } catch (const std::exception& e) { return fail(emit_error, exit_code::USAGE, e.what()); }
}
